"""Admin CLI until the control plane ships (phase 4).

python -m app.cli create-tenant --id acme --name "Acme Corp"
python -m app.cli create-api-key --tenant acme --name support-bot --agent support-bot
python -m app.cli upsert-agent --tenant acme --agent support-bot --trust 80 --tools '*'
python -m app.cli upsert-action --tenant acme --action database.read --resource customer_db --risk 40
python -m app.cli upsert-modifier --tenant acme --kind classification --value PII --delta 20
python -m app.cli partitions
python -m app.cli bootstrap-dev --write /bootstrap/dev.env
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.audit.chain import CHAIN_FIELDS, ChainReport, ChainVerifier
from app.config import get_settings
from app.db.models import ActionCatalogEntry, AgentProfile, GatewayApiKey, ScoreModifier, Tenant
from app.db.session import make_engine, make_sessionmaker
from app.gateway.auth import generate_key, hash_key


async def create_tenant(sm: async_sessionmaker[AsyncSession], tenant_id: str, name: str) -> None:
    async with sm() as s:
        await s.execute(insert(Tenant).values(id=tenant_id, name=name).on_conflict_do_nothing())
        await s.commit()


async def create_api_key(
    sm: async_sessionmaker[AsyncSession], tenant: str, name: str, scopes: list[str], agent: str | None = None
) -> str:
    """`agent` binds the key to one agent_id (identity assurance A1); None accepts any (A0)."""
    raw = generate_key()
    async with sm() as s:
        s.add(
            GatewayApiKey(
                tenant_id=tenant, name=name, key_hash=hash_key(raw), prefix=raw[:12], scopes=scopes, agent_id=agent
            )
        )
        await s.commit()
    return raw


async def upsert_agent(
    sm: async_sessionmaker[AsyncSession], tenant: str, agent: str, trust: int, tools: list[str]
) -> None:
    stmt = insert(AgentProfile).values(tenant_id=tenant, agent_id=agent, base_trust_score=trust, allowed_tools=tools)
    stmt = stmt.on_conflict_do_update(
        index_elements=["tenant_id", "agent_id"],
        set_={"base_trust_score": trust, "allowed_tools": tools, "updated_at": text("now()")},
    )
    async with sm() as s:
        await s.execute(stmt)
        await s.commit()


async def upsert_action(
    sm: async_sessionmaker[AsyncSession], tenant: str, action: str, resource: str, risk: int
) -> None:
    stmt = insert(ActionCatalogEntry).values(
        tenant_id=tenant, action=action, resource_pattern=resource, base_risk_score=risk
    )
    stmt = stmt.on_conflict_do_update(constraint="uq_action_catalog", set_={"base_risk_score": risk})
    async with sm() as s:
        await s.execute(stmt)
        await s.commit()


async def upsert_modifier(sm: async_sessionmaker[AsyncSession], tenant: str, kind: str, value: str, delta: int) -> None:
    stmt = insert(ScoreModifier).values(tenant_id=tenant, kind=kind, value=value, delta=delta)
    stmt = stmt.on_conflict_do_update(constraint="uq_score_modifier", set_={"delta": delta})
    async with sm() as s:
        await s.execute(stmt)
        await s.commit()


DEV_PROJECT = {
    "project_name": "guardrail-demo-pii",
    "entities": ["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "CREDIT_CARD", "US_SSN", "IN_AADHAAR", "IN_PAN"],
    "customized": [{"regex": r"EMP-\d{6}", "redaction": "[EMPLOYEE_ID]"}],
    "redaction_type": "replace",
}


async def _ai_gateway_project(http: httpx.AsyncClient, base: str, project: dict[str, Any] | None = None) -> str:
    project = project or DEV_PROJECT
    resp = await http.post(f"{base}/ai-gateway/project/api/", json=project)
    if resp.status_code == 201:
        return str(resp.json()["project_id"])
    listing = await http.get(f"{base}/ai-gateway/project/api/")
    listing.raise_for_status()
    for p in listing.json():
        if p["project_name"] == project["project_name"]:
            return str(p["id"])
    raise RuntimeError(f"could not create or find the ai-gateway project: HTTP {resp.status_code}")


async def ai_gateway_credentials(project_service_url: str, project_name: str) -> dict[str, str]:
    """Create (or find) the redaction project and a `service` API key for the guardrail engine.

    For installs without the dev bootstrap (Kubernetes): put the printed values in the secrets
    file (AI_GATEWAY_PROJECT_ID, AI_GATEWAY_API_KEY). The key is shown once.
    """
    base = project_service_url.rstrip("/")
    async with httpx.AsyncClient(timeout=10) as http:
        project_id = await _ai_gateway_project(http, base, {**DEV_PROJECT, "project_name": project_name})
        key_resp = await http.post(
            f"{base}/ai-gateway/apikeys/api/", json={"name": f"guardrail-engine-{project_name}", "scope": "service"}
        )
        key_resp.raise_for_status()
    return {"AI_GATEWAY_PROJECT_ID": project_id, "AI_GATEWAY_API_KEY": key_resp.json()["key"]}


async def bootstrap_dev(sm: async_sessionmaker[AsyncSession], out: Path, project_service_url: str) -> None:
    """Idempotent dev seed. Writes the generated keys/ids to `out` (read by the gateway at start)."""
    if out.exists() and out.stat().st_size > 0:
        print(f"{out} exists; bootstrap already done")
        return
    tenant = "demo"
    await create_tenant(sm, tenant, "Demo tenant")
    gateway_key = await create_api_key(sm, tenant, "demo-agent", ["guard:invoke"])
    await upsert_agent(sm, tenant, "research-agent", 80, ["*"])
    await upsert_agent(sm, tenant, "support-bot", 70, ["crm.lookup", "database.read"])
    await upsert_agent(sm, tenant, "untrusted-agent", 20, [])
    for action, resource, risk in [
        ("llm.chat", "*", 10),
        ("retrieval.search", "*", 20),
        ("database.read", "*", 30),
        ("database.read", "customer_db", 40),
        ("database.write", "*", 60),
        ("crm.lookup", "*", 30),
    ]:
        await upsert_action(sm, tenant, action, resource, risk)
    for kind, value, delta in [
        ("classification", "PII", 20),
        ("classification", "CONFIDENTIAL", 10),
        ("environment", "production", 10),
    ]:
        await upsert_modifier(sm, tenant, kind, value, delta)

    base = project_service_url.rstrip("/")
    async with httpx.AsyncClient(timeout=10) as http:
        project_id = await _ai_gateway_project(http, base)
        key_resp = await http.post(
            f"{base}/ai-gateway/apikeys/api/", json={"name": "guardrail-engine", "scope": "service"}
        )
        key_resp.raise_for_status()
        ai_gateway_key = key_resp.json()["key"]

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "# Generated by `python -m app.cli bootstrap-dev`. Dev only. Do not commit.\n"
        f"AI_GATEWAY_PROJECT_ID={project_id}\n"
        f"AI_GATEWAY_API_KEY={ai_gateway_key}\n"
        f"DEMO_TENANT_ID={tenant}\n"
        f"DEMO_GATEWAY_API_KEY={gateway_key}\n",
        encoding="utf-8",
    )
    os.chmod(out, 0o600)
    print(f"Bootstrap complete. Keys written to {out}")


async def verify_audit_chain(sm: async_sessionmaker[AsyncSession], tenant: str | None, days: int) -> ChainReport:
    """Recompute the decision-record hash chains (app/audit/chain.py) for the last `days` days."""
    cols = ", ".join(CHAIN_FIELDS + ("record_hash",))
    q = (
        f"SELECT {cols} FROM audit.audit_events "  # noqa: S608 - fixed column list, values are bound
        "WHERE chain_id IS NOT NULL AND created_at > now() - make_interval(days => :d)"
    )
    params: dict[str, Any] = {"d": days}
    if tenant:
        q += " AND tenant_id = :t"
        params["t"] = tenant
    q += " ORDER BY chain_id, tenant_id, chain_seq"
    verifier = ChainVerifier()
    async with sm() as s:  # streamed (server-side cursor): constant memory however many rows
        result = await s.stream(text(q), params)
        async for row in result.mappings():
            verifier.add(row)
    return verifier.report


async def _main(args: argparse.Namespace) -> int:
    settings = get_settings()
    engine = make_engine(settings.postgres_dsn)
    sm = make_sessionmaker(engine)
    try:
        cmd: str = args.command
        if cmd == "create-tenant":
            await create_tenant(sm, args.id, args.name)
            print(f"tenant {args.id} ready")
        elif cmd == "create-api-key":
            key = await create_api_key(sm, args.tenant, args.name, args.scopes.split(","), args.agent)
            print(key)
            print("Store this key now; only its hash is kept.", file=sys.stderr)
        elif cmd == "upsert-agent":
            await upsert_agent(sm, args.tenant, args.agent, args.trust, [t for t in args.tools.split(",") if t])
        elif cmd == "upsert-action":
            await upsert_action(sm, args.tenant, args.action, args.resource, args.risk)
        elif cmd == "upsert-modifier":
            await upsert_modifier(sm, args.tenant, args.kind, args.value, args.delta)
        elif cmd == "verify-audit-chain":
            report = await verify_audit_chain(sm, args.tenant, args.days)
            print(f"checked {report.records} record(s) in {report.chains} chain(s)")
            for problem in report.problems or []:
                print(f"PROBLEM {problem}")
            return 0 if report.ok else 1
        elif cmd == "partitions":
            async with sm() as s:
                await s.execute(text("SELECT audit.ensure_partitions(3)"))
                dropped = (
                    await s.execute(
                        text("SELECT audit.drop_partitions_older_than(:m)"), {"m": settings.audit_retention_months}
                    )
                ).scalar()
                await s.commit()
            print(f"partitions ensured; dropped {dropped}")
        elif cmd == "bootstrap-dev":
            await bootstrap_dev(sm, Path(args.write), args.project_service_url)
        return 0
    finally:
        await engine.dispose()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m app.cli")
    sub = p.add_subparsers(dest="command", required=True)
    t = sub.add_parser("create-tenant")
    t.add_argument("--id", required=True)
    t.add_argument("--name", required=True)
    k = sub.add_parser("create-api-key")
    k.add_argument("--tenant", required=True)
    k.add_argument("--name", required=True)
    k.add_argument("--scopes", default="guard:invoke")
    k.add_argument("--agent", default=None, help="bind the key to this agent_id (recommended)")
    a = sub.add_parser("upsert-agent")
    a.add_argument("--tenant", required=True)
    a.add_argument("--agent", required=True)
    a.add_argument("--trust", type=int, required=True, choices=range(0, 101), metavar="0-100")
    a.add_argument("--tools", default="*", help="comma-separated tool names, or *")
    ac = sub.add_parser("upsert-action")
    ac.add_argument("--tenant", required=True)
    ac.add_argument("--action", required=True)
    ac.add_argument("--resource", default="*", help="glob pattern")
    ac.add_argument("--risk", type=int, required=True, choices=range(0, 101), metavar="0-100")
    m = sub.add_parser("upsert-modifier")
    m.add_argument("--tenant", required=True)
    m.add_argument("--kind", required=True, choices=["classification", "environment"])
    m.add_argument("--value", required=True)
    m.add_argument("--delta", type=int, required=True)
    sub.add_parser("partitions")
    v = sub.add_parser("verify-audit-chain", help="check the decision-record hash chains; exit 1 on problems")
    v.add_argument("--tenant", default=None)
    v.add_argument("--days", type=int, default=30)
    cred = sub.add_parser("ai-gateway-credentials", help="create the redaction project + service key; print them")
    cred.add_argument("--project-service-url", default="http://project-service:8000")
    cred.add_argument("--project-name", default="guardrail-pii")
    du = sub.add_parser("dev-user-token", help="development only: a user token for verification confirm")
    du.add_argument("--user", required=True, help="the user_id the agent sends")
    du.add_argument("--verification", default=None, help="the verification id (becomes the token's nonce)")
    du.add_argument("--ttl", type=int, default=300)
    b = sub.add_parser("bootstrap-dev")
    b.add_argument("--write", required=True)
    b.add_argument(
        "--project-service-url", default=os.environ.get("PROJECT_SERVICE_URL", "http://project-service:8000")
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args: Any = build_parser().parse_args(argv)
    if args.command == "ai-gateway-credentials":  # talks to project-service only; no database
        creds = asyncio.run(ai_gateway_credentials(args.project_service_url, args.project_name))
        print("\n".join(f"{k}={v}" for k, v in creds.items()))
        return 0
    if args.command == "dev-user-token":  # no database
        secret = os.environ.get("VERIFY_DEV_SECRET")
        if not secret:
            print("set VERIFY_DEV_SECRET (the same value the gateway uses)", file=sys.stderr)
            return 2
        if os.environ.get("GATEWAY_ENV", "dev") != "dev":
            print("dev-user-token only works with GATEWAY_ENV=dev", file=sys.stderr)
            return 2
        from app.verify.user_token import mint_dev_token

        aud = os.environ.get("VERIFY_OIDC_AUDIENCE") or "guardrail-dev"
        print(mint_dev_token(secret, args.user, nonce=args.verification, audience=aud, ttl=args.ttl))
        return 0
    return asyncio.run(_main(args))


if __name__ == "__main__":
    sys.exit(main())
