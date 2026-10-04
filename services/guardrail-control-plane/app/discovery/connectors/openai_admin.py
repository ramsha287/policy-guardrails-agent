"""OpenAI organization (Admin API): projects, service accounts and API keys.

There is no OpenAI API that lists "agents": Agents SDK agents exist only in code and traces. What
the Admin API does show is which machine identities (project service accounts) hold keys, and
whether those keys are used. A service account with a recently used key is a probable agent; a
user's key is a person's and is reported only with `include_user_keys`.

Needs an Admin key (`sk-admin-...`) in a DISCOVERY_SECRET_* variable. Read-only endpoints:
GET /organization/projects, /organization/projects/{id}/service_accounts,
/organization/projects/{id}/api_keys.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

import httpx
from pydantic import Field, field_validator

from ..model import CollectContext, ConnectorConfig, ConnectorError, EdgeFact, EntityFact, Observation
from ..safety import validate_secret_name


class OpenAIAdminConfig(ConnectorConfig):
    admin_key_env: str
    base_url: str = "https://api.openai.com/v1"
    include_user_keys: bool = False
    include_archived: bool = False
    active_days: int = Field(default=30, ge=1, le=365, description="a key used within this many days is active")
    # Project service-account names that equal a registered agent id are linked to it.
    match_agent_names: bool = True

    @field_validator("admin_key_env")
    @classmethod
    def _secret(cls, v: str) -> str:
        validate_secret_name(v)
        return v


class OpenAIAdminConnector:
    kind: ClassVar[str] = "openai_admin"
    title: ClassVar[str] = "OpenAI organization"
    description: ClassVar[str] = (
        "Projects, service accounts and API keys (with last use) from the OpenAI Admin API. Machine "
        "identities with active keys are probable agents."
    )
    full_snapshot: ClassVar[bool] = True
    Config: ClassVar[type[ConnectorConfig]] = OpenAIAdminConfig

    async def collect(self, config: OpenAIAdminConfig, ctx: CollectContext) -> AsyncIterator[Observation]:
        base = config.base_url.rstrip("/")
        await ctx.check_url(base)
        headers = {"Authorization": f"Bearer {ctx.secrets(config.admin_key_env)}", "Accept": "application/json"}
        http = ctx.clients.get("openai_http") or ctx.http
        active_after = ctx.now - timedelta(days=config.active_days)

        projects = await _paged(
            http, f"{base}/organization/projects", headers, {"include_archived": config.include_archived}
        )
        for project in projects:
            pid = str(project.get("id"))
            accounts = await _paged(http, f"{base}/organization/projects/{pid}/service_accounts", headers)
            keys = await _paged(http, f"{base}/organization/projects/{pid}/api_keys", headers)
            yield _project_observation(config, project, accounts, keys, active_after)


async def _paged(
    http: httpx.AsyncClient, url: str, headers: dict[str, str], extra: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    after: str | None = None
    for _ in range(100):
        params: dict[str, Any] = {"limit": 100, **(extra or {})}
        if after:
            params["after"] = after
        try:
            resp = await http.get(url, headers=headers, params=params, follow_redirects=False)
        except httpx.HTTPError as exc:
            raise ConnectorError(f"OpenAI Admin API unreachable: {exc.__class__.__name__}") from exc
        if resp.status_code in (401, 403):
            raise ConnectorError(f"OpenAI Admin API refused the key ({resp.status_code}); it must be an Admin key")
        if resp.status_code != 200:
            raise ConnectorError(f"OpenAI Admin API answered {resp.status_code} for {url.rsplit('/v1', 1)[-1]}")
        body = resp.json()
        data = body.get("data") or []
        out.extend(data)
        if not body.get("has_more") or not data:
            break
        after = body.get("last_id") or data[-1].get("id")
    return out


def _ts(v: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(v), tz=UTC) if v is not None else None
    except (TypeError, ValueError):
        return None


def _project_observation(
    config: OpenAIAdminConfig,
    project: dict[str, Any],
    accounts: list[dict[str, Any]],
    keys: list[dict[str, Any]],
    active_after: datetime,
) -> Observation:
    pid, pname = str(project.get("id")), str(project.get("name") or project.get("id"))
    facts = [
        EntityFact(
            "self",
            "project",
            f"openai/{pname}",
            [f"openai-project:{pid}"],
            attrs={"provider": "openai", "status": project.get("status"), "project_id": pid},
        ),
        EntityFact("provider", "model_provider", "openai", ["provider:openai"]),
    ]
    edges: list[EdgeFact] = []
    accounts_by_id = {str(a.get("id")): a for a in accounts}
    key_use: dict[str, list[dict[str, Any]]] = {}

    for k in keys:
        owner = k.get("owner") or {}
        otype = owner.get("type")
        who = owner.get(otype) if isinstance(owner.get(otype), dict) else {}
        oid = str((who or {}).get("id") or "")
        if otype == "user" and not config.include_user_keys:
            continue
        key_use.setdefault(f"{otype}:{oid}", []).append(k)

    for owner_key, owned in sorted(key_use.items()):
        otype, oid = owner_key.split(":", 1)
        last_used = max((t for t in (_ts(k.get("last_used_at")) for k in owned) if t is not None), default=None)
        active = last_used is not None and last_used >= active_after
        if otype == "service_account":
            acct = accounts_by_id.get(oid, {"id": oid, "name": oid})
            name = str(acct.get("name") or oid)
            strong = [f"openai-sa:{oid}"]
            if config.match_agent_names:
                strong.append(f"agent-name:{name}")
            signals = {"calls_model"} if active else set()
            ref = f"sa:{oid}"
            facts.append(
                EntityFact(
                    ref,
                    "identity",
                    f"openai/{pname}/{name}",
                    strong,
                    signals=signals,
                    attrs={
                        "provider": "openai",
                        "project": pname,
                        "role": acct.get("role"),
                        "keys": len(owned),
                        "last_used_at": last_used.isoformat() if last_used else None,
                        "active": active,
                    },
                )  # fmt: skip
            )
        else:
            ref = f"user:{oid}"
            facts.append(
                EntityFact(
                    ref,
                    "identity",
                    f"openai/{pname}/user:{oid}",
                    [f"openai-user:{oid}"],
                    signals={"human_identity"},
                    attrs={"provider": "openai", "project": pname, "keys": len(owned), "active": active},
                )
            )
        edges.append(EdgeFact(ref, "self", "member_of"))
        if active:
            edges.append(EdgeFact(ref, "provider", "calls_model", {"via": "direct"}))
        for k in owned:
            kref = f"key:{k.get('id')}"
            facts.append(
                EntityFact(
                    kref,
                    "credential",
                    f"openai/{pname}/{k.get('name') or k.get('id')}",
                    [f"openai-key:{k.get('id')}"],
                    attrs={
                        "provider": "openai",
                        "redacted": k.get("redacted_value"),  # the API's own redaction, e.g. sk-...abcd
                        "created_at": _iso(_ts(k.get("created_at"))),
                        "last_used_at": _iso(_ts(k.get("last_used_at"))),
                    },
                )
            )
            edges.append(EdgeFact(ref, kref, "holds_credential"))
    return Observation(
        kind="openai.project",
        source_ref=f"openai/organization/projects/{pid}",
        entities=facts,
        edges=edges,
        attrs={"project": pname, "service_accounts": len(accounts), "api_keys": len(keys)},
    )


def _iso(t: datetime | None) -> str | None:
    return t.isoformat() if t else None
