"""Control-plane admin CLI.

    python -m app.cli create-admin-key --name root --roles admin [--tenant acme] [--write file]
    python -m app.cli import-gateway --snapshot /snapshots/dev.json [--snapshot ...]
    python -m app.cli bootstrap-dev --snapshot /snapshots/dev.json --write /bootstrap/cp.env
    python -m app.cli dev-certs --out /certs --names guardrail-control-plane,guardrail-gateway
    python -m app.cli discovery-sync [--tenant acme] [--connector ID]   run connectors now (cron/CI)
    python -m app.cli discovery-reconcile [--tenant acme]                re-evaluate states and findings
    python -m app.cli advisor-training-set --out set.jsonl [--days 30] [--tenant acme] [--include-released]
                                         labelled advisor features for app.advise.calibrate (needs AUDIT_DSN)

`import-gateway` migrates an existing phase 1-3 deployment: it copies tenants, gateway API key
*hashes* (existing agent keys keep working), agents, actions and modifiers from the gateway's
`guardrail.*` tables, registers the gateway's installed manifests, and imports the snapshot
files as the first published version of each environment.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import text

from guardrail_sdk.documents import SnapshotDoc

from .config import get_settings
from .db.session import make_engine, make_sessionmaker
from .domain.crypto import PayloadCipher
from .domain.rbac import SYSTEM
from .domain.records import ActionRecord, AgentRecord, ApiKeyRecord, ModifierRecord, TenantRecord
from .events import NullPublisher, RedisPublisher
from .main import policy_from
from .services.admin import AdminKeyService
from .services.catalog import CatalogService
from .services.context import Ctx
from .services.publishing import PublishService
from .services.registry import RegistryService
from .store.postgres import PgStore


def _write_env(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    with path.open("a", encoding="utf-8") as fh:
        for k, v in values.items():
            if f"{k}=" not in existing:
                fh.write(f"{k}={v}\n")
    os.chmod(path, 0o600)


async def _import_gateway(ctx: Ctx, snapshots: list[Path], plugin_dirs: list[Path]) -> dict[str, Any]:
    """Idempotent migration from the gateway's own tables and snapshot files."""
    store = ctx.store
    assert isinstance(store, PgStore)
    report: dict[str, Any] = {"tenants": 0, "api_keys": 0, "agents": 0, "actions": 0, "modifiers": 0, "snapshots": []}
    catalog, registry, publishing = CatalogService(ctx), RegistryService(ctx), PublishService(ctx)

    for d in plugin_dirs:
        for path in sorted(d.glob("*/guardrail*.yaml")):
            await registry.register(SYSTEM, yaml.safe_load(path.read_text(encoding="utf-8")), source="gateway")

    async with store._sm() as s:  # read the gateway's legacy tables if they exist
        exists = (await s.execute(text("SELECT to_regclass('guardrail.tenants') IS NOT NULL"))).scalar()
        if exists:
            for row in (await s.execute(text("SELECT id, name, status FROM guardrail.tenants"))).mappings():
                if await store.get_tenant(row["id"]) is None:
                    await store.put_tenant(TenantRecord(id=row["id"], name=row["name"], status=row["status"]))
                    report["tenants"] += 1
            has_agent = (
                await s.execute(
                    text(
                        "SELECT 1 FROM information_schema.columns WHERE table_schema = 'guardrail' "
                        "AND table_name = 'api_keys' AND column_name = 'agent_id'"
                    )
                )
            ).first() is not None  # gateway migration 0002 adds it
            q = (
                "SELECT id, tenant_id, name, key_hash, prefix, scopes, is_active, expires_at"
                + (", agent_id" if has_agent else "")
                + " FROM guardrail.api_keys"
            )
            for row in (await s.execute(text(q))).mappings():
                await catalog.import_api_key(
                    SYSTEM,
                    ApiKeyRecord(
                        id=str(row["id"]),
                        tenant_id=row["tenant_id"],
                        name=row["name"],
                        key_hash=row["key_hash"],
                        prefix=row["prefix"],
                        scopes=list(row["scopes"]),
                        is_active=row["is_active"],
                        expires_at=row["expires_at"],
                        agent_id=row.get("agent_id"),
                    ),
                )
                report["api_keys"] += 1
            q = "SELECT tenant_id, agent_id, base_trust_score, allowed_tools, owner FROM guardrail.agent_profiles"
            for row in (await s.execute(text(q))).mappings():
                await store.put_agent(
                    AgentRecord(
                        tenant_id=row["tenant_id"],
                        agent_id=row["agent_id"],
                        base_trust_score=row["base_trust_score"],
                        allowed_tools=list(row["allowed_tools"]),
                        owner=row["owner"],
                    )
                )
                report["agents"] += 1
            q = "SELECT tenant_id, action, resource_pattern, base_risk_score FROM guardrail.action_catalog"
            for row in (await s.execute(text(q))).mappings():
                await store.put_action(
                    ActionRecord(
                        tenant_id=row["tenant_id"],
                        action=row["action"],
                        resource_pattern=row["resource_pattern"],
                        base_risk_score=row["base_risk_score"],
                    )
                )
                report["actions"] += 1
            for row in (
                await s.execute(text("SELECT tenant_id, kind, value, delta FROM guardrail.score_modifiers"))
            ).mappings():
                await store.put_modifier(
                    ModifierRecord(tenant_id=row["tenant_id"], kind=row["kind"], value=row["value"], delta=row["delta"])
                )
                report["modifiers"] += 1
    await catalog.publish()  # one catalog version for the whole import

    for path in snapshots:
        raw = json.loads(path.read_text(encoding="utf-8"))
        doc = SnapshotDoc.model_validate(raw)  # ${VAR} placeholders are kept; gateways expand them
        if await store.current_snapshot(doc.environment) is None:
            snap = await publishing.import_snapshot(SYSTEM, doc)
            report["snapshots"].append(snap.version)
    return report


async def _discovery(ctx: Ctx, args: argparse.Namespace, settings: Any) -> int:
    import httpx

    from .main import _sql_fetcher
    from .services.discovery import DiscoveryService

    audit_engine = make_engine(settings.audit_dsn) if settings.audit_dsn else None
    async with httpx.AsyncClient(timeout=30.0) as http:
        svc = DiscoveryService(
            ctx,
            http,
            audit_fetch=_sql_fetcher(make_sessionmaker(audit_engine)) if audit_engine else None,
            allow_http=settings.discovery_allow_http,
            max_observations=settings.discovery_max_observations,
        )
        try:
            tenants = [args.tenant] if args.tenant else [t.id for t in await ctx.store.list_tenants()]
            failed = 0
            for tenant in tenants:
                if args.command == "discovery-reconcile":
                    print(json.dumps({"tenant": tenant, **await svc.reconcile(SYSTEM, tenant)}))
                    continue
                for c in await ctx.store.list_connectors(tenant):
                    if args.connector and c.id != args.connector:
                        continue
                    run = await svc.run_connector(c, triggered_by="cli")
                    if run is None:
                        print(json.dumps({"connector": c.id, "status": "already running"}))
                        continue
                    failed += run.status == "error"
                    print(json.dumps(run.model_dump(mode="json")))
            return 1 if failed else 0
        finally:
            if audit_engine is not None:
                await audit_engine.dispose()


async def _training_set(ctx: Ctx, args: argparse.Namespace, settings: Any) -> int:
    from datetime import UTC, datetime, timedelta

    from .main import _sql_fetcher
    from .services.advisor_training import training_set

    if not settings.audit_dsn:
        print("advisor-training-set needs AUDIT_DSN (read access to the gateway's audit schema)", file=sys.stderr)
        return 2
    audit_engine = make_engine(settings.audit_dsn)
    try:
        rows, counts = await training_set(
            _sql_fetcher(make_sessionmaker(audit_engine)),
            ctx.store,
            since=datetime.now(UTC) - timedelta(days=max(1, args.days)),
            tenant_id=args.tenant,
            include_released=args.include_released,
        )
    finally:
        await audit_engine.dispose()
    with open(args.out, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    print(json.dumps({"out": args.out, **counts}))
    return 0


async def _main(args: argparse.Namespace) -> int:
    settings = get_settings()
    engine = make_engine(settings.postgres_dsn)
    events = RedisPublisher(settings.redis_url) if settings.redis_url else NullPublisher()
    ctx = Ctx(
        store=PgStore(make_sessionmaker(engine)),
        events=events,
        cipher=PayloadCipher(settings.review_encryption_key),
        policy=policy_from(settings),
    )
    admin = AdminKeyService(ctx)
    try:
        if args.command == "create-admin-key":
            key, raw = await admin.create(None, args.name, args.roles.split(","), args.tenant)
            if args.write:
                _write_env(Path(args.write), {args.env_name: raw})
                print(f"admin key {key.prefix}... written to {args.write}")
            else:
                print(raw)
        elif args.command in ("discovery-sync", "discovery-reconcile"):
            return await _discovery(ctx, args, settings)
        elif args.command == "advisor-training-set":
            return await _training_set(ctx, args, settings)
        elif args.command == "import-gateway":
            report = await _import_gateway(ctx, [Path(p) for p in args.snapshot], [Path(p) for p in args.plugin_dir])
            print(json.dumps(report, indent=2))
        elif args.command == "bootstrap-dev":
            # First run only: afterwards the control plane is the source of truth, and re-importing
            # would overwrite edits made through the API.
            if await ctx.store.list_tenants() or await ctx.store.current_snapshot("dev"):
                print("control plane already initialised; skipping import")
            else:
                report = await _import_gateway(
                    ctx, [Path(p) for p in args.snapshot], [Path(p) for p in args.plugin_dir]
                )
                print(json.dumps(report, indent=2))
            out = Path(args.write)
            if "CP_ADMIN_KEY=" not in (out.read_text(encoding="utf-8") if out.exists() else ""):
                _, root = await admin.create(None, "dev-root", ["admin"])
                _, second = await admin.create(None, "dev-approver", ["admin"])
                _write_env(out, {"CP_ADMIN_KEY": root, "CP_APPROVER_KEY": second})
                print(f"dev admin keys written to {out}")
        return 0
    finally:
        if isinstance(events, RedisPublisher):
            await events.close()
        await engine.dispose()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.cli")
    sub = p.add_subparsers(dest="command", required=True)
    d = sub.add_parser("dev-certs", help="private CA + per-service certificates for mTLS in development")
    d.add_argument("--out", required=True)
    d.add_argument("--names", required=True, help="comma-separated service (DNS) names")
    d.add_argument("--days", type=int, default=30)
    d.add_argument("--owner-uid", type=int, default=None, help="chown the files (when run as root)")
    d.add_argument("--force", action="store_true")
    k = sub.add_parser("create-admin-key")
    k.add_argument("--name", required=True)
    k.add_argument("--roles", default="admin", help="comma-separated: admin, editor, reviewer, reviewer-raw, viewer")
    k.add_argument("--tenant", default=None, help="limit the key to one tenant")
    k.add_argument("--write", help="append KEY=value to this env file instead of printing")
    k.add_argument("--env-name", default="CP_ADMIN_KEY")
    for name in ("import-gateway", "bootstrap-dev"):
        c = sub.add_parser(name)
        c.add_argument("--snapshot", action="append", default=[], help="snapshot JSON file (repeatable)")
        c.add_argument("--plugin-dir", action="append", default=[], help="gateway plugin dir with guardrail*.yaml")
        if name == "bootstrap-dev":
            c.add_argument("--write", required=True, help="env file for the generated dev admin keys")
    for name in ("discovery-sync", "discovery-reconcile"):
        ds = sub.add_parser(name)
        ds.add_argument("--tenant", default=None, help="default: every tenant")
        if name == "discovery-sync":
            ds.add_argument("--connector", default=None, help="one connector id")
    ts = sub.add_parser("advisor-training-set", help="labelled advisor features for calibration (needs AUDIT_DSN)")
    ts.add_argument("--out", required=True, help="JSON Lines file to write")
    ts.add_argument("--days", type=int, default=30)
    ts.add_argument("--tenant", default=None, help="default: every tenant")
    ts.add_argument(
        "--include-released", action="store_true", help="add released, unreviewed requests as weak negatives"
    )
    args = p.parse_args(argv)
    if args.command == "dev-certs":  # no database needed
        from guardrail_sdk.devcerts import generate

        names = [n.strip() for n in args.names.split(",") if n.strip()]
        written = generate(Path(args.out), names, days=args.days, force=args.force, owner_uid=args.owner_uid)
        print(f"wrote {len(written)} certificate(s) to {args.out}" if written else "certificates already present")
        return 0
    return asyncio.run(_main(args))


if __name__ == "__main__":
    sys.exit(main())
