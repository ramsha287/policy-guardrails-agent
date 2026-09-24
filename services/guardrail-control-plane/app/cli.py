"""Control-plane admin CLI.

    python -m app.cli create-admin-key --name root --roles admin [--tenant acme] [--write file]
    python -m app.cli import-gateway --snapshot /snapshots/dev.json [--snapshot ...]
    python -m app.cli bootstrap-dev --snapshot /snapshots/dev.json --write /bootstrap/cp.env
    python -m app.cli dev-certs --out /certs --names guardrail-control-plane,guardrail-gateway

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
            q = "SELECT id, tenant_id, name, key_hash, prefix, scopes, is_active, expires_at FROM guardrail.api_keys"
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
