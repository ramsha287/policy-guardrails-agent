import json
from datetime import timedelta

import pytest

from app.domain.rbac import Forbidden
from app.domain.records import utcnow
from app.errors import NotFound, StateConflict, ValidationFailed
from app.events import CATALOG_CHANNEL, SNAPSHOT_CHANNEL
from app.services.admin import AdminKeyService
from app.services.assignments import AssignmentService
from app.services.catalog import CatalogService, hash_key
from app.services.gateways import GatewayService
from app.services.publishing import PublishService
from app.services.registry import RegistryService
from app.services.reviews import ReviewService
from app.store.base import Conflict
from guardrail_sdk.documents import CatalogDoc, SnapshotDoc
from tests.helpers import (
    ACME_ADMIN,
    ACME_RAW,
    ACME_REVIEWER,
    ALICE,
    BOB,
    EDITOR,
    NOOP,
    PII_10,
    PII_11,
    VIEWER,
    make_ctx,
    pii_assignment,
)
from tests.helpers import (
    PLUGINS as PLUGINS_DIR,
)


async def setup_registry(ctx):
    reg = RegistryService(ctx)
    for m in (PII_10, PII_11, NOOP):
        await reg.register(ALICE, m)
    return reg


# ---- catalog --------------------------------------------------------------------------------


async def test_catalog_publishes_hashes_only_and_revocation_republishes():
    ctx, store, events = make_ctx()
    cat = CatalogService(ctx)
    await cat.create_tenant(ALICE, "acme", "Acme")
    key, raw = await cat.create_api_key(ALICE, "acme", "support-bot")
    await cat.put_agent(ALICE, "acme", "support-bot", 70, ["crm.lookup"])
    await cat.put_action(ALICE, "acme", "crm.lookup", "*", 30)
    await cat.put_modifier(ALICE, "acme", "classification", "PII", 20)

    doc, _ = await cat.current_document()
    parsed = CatalogDoc.model_validate(doc)
    tenant = parsed.tenants[0]
    assert tenant.api_keys[0].key_hash == hash_key(raw) and raw not in str(doc)
    assert tenant.agents[0].base_trust_score == 70 and tenant.actions[0].base_risk_score == 30
    v1 = parsed.version

    await cat.revoke_api_key(ALICE, "acme", key.id)
    doc2, _ = await cat.current_document()
    assert CatalogDoc.model_validate(doc2).tenants[0].api_keys == []
    assert CatalogDoc.model_validate(doc2).version != v1
    assert [c for c, _ in events.events].count(CATALOG_CHANNEL) == 6


async def test_catalog_unchanged_content_keeps_version():
    ctx, store, _ = make_ctx()
    cat = CatalogService(ctx)
    await cat.create_tenant(ALICE, "acme", "Acme")
    a = await cat.publish()
    b = await cat.publish()
    assert a.version == b.version and (await store.current_catalog()).version == a.version


async def test_upserts_are_idempotent():
    ctx, store, _ = make_ctx()
    cat = CatalogService(ctx)
    await cat.create_tenant(ALICE, "acme", "Acme")
    a1 = await cat.put_action(ALICE, "acme", "db.read", "*", 30)
    a2 = await cat.put_action(ALICE, "acme", "db.read", "*", 45)
    actions = await store.list_actions("acme")
    assert a1.id == a2.id and len(actions) == 1 and actions[0].base_risk_score == 45


async def test_tenant_keys_are_confined_to_their_tenant():
    ctx, _, _ = make_ctx()
    cat = CatalogService(ctx)
    await cat.create_tenant(ALICE, "acme", "Acme")
    await cat.create_tenant(ALICE, "globex", "Globex")
    await cat.put_agent(ACME_ADMIN, "acme", "bot", 60, ["*"])
    with pytest.raises(Forbidden):
        await cat.put_agent(ACME_ADMIN, "globex", "bot", 60, ["*"])
    with pytest.raises(Forbidden):
        await cat.create_tenant(ACME_ADMIN, "initech", "Initech")
    assert [t.id for t in await cat.list_tenants(ACME_ADMIN)] == ["acme"]
    with pytest.raises(Forbidden):
        await cat.put_agent(VIEWER, "acme", "bot", 60, ["*"])
    with pytest.raises(Conflict):
        await cat.create_tenant(ALICE, "acme", "again")


# ---- registry -------------------------------------------------------------------------------


async def test_registry_versions_are_immutable():
    ctx, _, _ = make_ctx()
    reg = RegistryService(ctx)
    await reg.register(ALICE, PII_11)
    assert (await reg.register(ALICE, PII_11)).version == "1.1.0"  # identical: fine
    changed = {**PII_11, "description": "sneaky change"}
    with pytest.raises(Conflict):
        await reg.register(ALICE, changed)
    with pytest.raises(ValidationFailed):
        await reg.register(ALICE, {**PII_11, "id": "Bad Id"})
    with pytest.raises(Forbidden):
        await reg.register(ACME_ADMIN, NOOP)  # registry is platform-only
    with pytest.raises(ValidationFailed):
        await reg.register(ALICE, NOOP, conformance_report={"passed": False})


async def test_gateway_heartbeat_registers_installed_manifests():
    ctx, store, _ = make_ctx()
    gw = await GatewayService(ctx).heartbeat(
        gateway_id="gw-1",
        environment="dev",
        manifests=[PII_11, NOOP, {"id": "broken"}],
        snapshot_version=None,
        catalog_version=None,
        last_error=None,
    )
    assert gw.installed == ["ai-gateway-pii@1.1.0", "noop@1.0.0"]
    assert "broken" in (gw.last_error or "")
    assert (await store.get_version("noop", "1.0.0")).source == "gateway"


# ---- assignments ---------------------------------------------------------------------------


async def test_assignment_rules():
    ctx, _, _ = make_ctx()
    await setup_registry(ctx)
    svc = AssignmentService(ctx)
    await svc.put(EDITOR, "dev", pii_assignment())
    with pytest.raises(ValidationFailed):
        await svc.put(EDITOR, "dev", pii_assignment(id="x", guardrail_version="9.9.9"))
    with pytest.raises(Forbidden):
        await svc.put(ACME_ADMIN, "dev", pii_assignment(id="global-by-tenant"))  # global needs platform
    await svc.put(ACME_ADMIN, "dev", pii_assignment(id="acme-pii", scope_type="tenant", scope_id="acme"))
    with pytest.raises(Forbidden):
        await svc.put(ACME_ADMIN, "dev", pii_assignment(id="globex-pii", scope_type="tenant", scope_id="globex"))
    assert [r.assignment.id for r in await svc.list(ACME_ADMIN, "dev")] == ["acme-pii"]

    patched = await svc.patch(EDITOR, "dev", "global-pii", {"mode": "shadow", "order": 5})
    assert patched.assignment.mode == "shadow" and patched.assignment.order == 5
    with pytest.raises(ValidationFailed):
        await svc.patch(EDITOR, "dev", "global-pii", {"guardrail_id": "noop"})
    with pytest.raises(NotFound):
        await svc.patch(EDITOR, "qa", "global-pii", {"mode": "shadow"})


# ---- publishing -----------------------------------------------------------------------------


async def prepared(**policy):
    ctx, store, events = make_ctx(**policy)
    await setup_registry(ctx)
    await AssignmentService(ctx).put(EDITOR, "dev", pii_assignment())
    await AssignmentService(ctx).put(EDITOR, "production", pii_assignment())
    return ctx, store, events, PublishService(ctx)


async def test_dev_publish_is_direct_and_noop_when_unchanged():
    ctx, store, events, pub = await prepared()
    out = await pub.publish(ALICE, "dev")
    assert out.status == "published" and out.snapshot.version.startswith("dev-")
    doc = SnapshotDoc.model_validate(out.snapshot.document)
    assert doc.published_by == ALICE.actor and doc.assignments[0].id == "global-pii"
    assert (SNAPSHOT_CHANNEL, {"environment": "dev", "version": out.snapshot.version}) in events.events
    again = await pub.publish(ALICE, "dev")
    assert again.status == "unchanged" and again.snapshot.version == out.snapshot.version
    with pytest.raises(Forbidden):
        await pub.publish(ACME_ADMIN, "dev")  # publishing is platform-only


async def test_invalid_config_blocks_publish():
    ctx, store, _, pub = await prepared()
    await AssignmentService(ctx).put(EDITOR, "dev", pii_assignment(config={"project_id": PROJECT_BAD}))
    with pytest.raises(ValidationFailed) as e:
        await pub.publish(ALICE, "dev")
    assert any("config" in err for err in e.value.errors)
    await AssignmentService(ctx).put(EDITOR, "dev", pii_assignment(config={}))
    with pytest.raises(ValidationFailed) as e:
        await pub.publish(ALICE, "dev")
    assert any("project_id" in err for err in e.value.errors)


PROJECT_BAD = 12345  # wrong type: must be a string


async def test_unsupported_stage_and_parallel_rules():
    ctx, _, _, pub = await prepared()
    svc = AssignmentService(ctx)
    await svc.put(EDITOR, "dev", pii_assignment(guardrail_version="1.0.0", stages=["retrieval"]))
    with pytest.raises(ValidationFailed, match="invalid"):
        await pub.publish(ALICE, "dev")
    await svc.put(EDITOR, "dev", pii_assignment(parallel_group="g"))
    with pytest.raises(ValidationFailed) as e:
        await pub.publish(ALICE, "dev")
    assert any("parallel_safe" in err for err in e.value.errors)


async def test_version_must_be_installed_on_live_gateways():
    ctx, _, _, pub = await prepared()
    await GatewayService(ctx).heartbeat(
        gateway_id="gw-old",
        environment="dev",
        manifests=[PII_10, NOOP],
        snapshot_version=None,
        catalog_version=None,
        last_error=None,
    )
    with pytest.raises(ValidationFailed) as e:
        await pub.publish(ALICE, "dev")
    assert any("not installed on gateway(s) gw-old" in err for err in e.value.errors)
    out = await pub.publish(ALICE, "dev", force=True)
    assert out.status == "published" and any("gw-old" in w for w in out.warnings)


async def test_production_needs_a_second_admin():
    ctx, store, events, pub = await prepared()
    out = await pub.publish(ALICE, "production", note="enable PII")
    assert out.status == "pending_approval" and await store.current_snapshot("production") is None
    with pytest.raises(StateConflict, match="two-person"):
        await pub.approve(ALICE, out.request.id)
    with pytest.raises(Forbidden):
        await pub.approve(EDITOR, out.request.id)
    snap = await pub.approve(BOB, out.request.id, note="looks good")
    assert snap.approved_by == BOB.actor and snap.published_by == ALICE.actor
    assert (await store.current_snapshot("production")).version == snap.version
    req = await store.get_publish_request(out.request.id)
    assert req.status == "approved" and req.published_version == snap.version
    with pytest.raises(StateConflict):
        await pub.approve(BOB, out.request.id)


async def test_stale_and_expired_requests():
    ctx, store, _, pub = await prepared()
    first = await pub.publish(ALICE, "production")
    await AssignmentService(ctx).patch(EDITOR, "production", "global-pii", {"mode": "shadow"})
    second = await pub.publish(ALICE, "production")
    await pub.approve(BOB, second.request.id)
    with pytest.raises(StateConflict, match="changed"):
        await pub.approve(BOB, first.request.id)
    assert (await store.get_publish_request(first.request.id)).status == "stale"

    await AssignmentService(ctx).patch(EDITOR, "production", "global-pii", {"mode": "enforce"})
    third = await pub.publish(ALICE, "production")
    old = await store.get_publish_request(third.request.id)
    await store.put_publish_request(old.model_copy(update={"requested_at": utcnow() - timedelta(hours=25)}))
    with pytest.raises(StateConflict, match="expired"):
        await pub.approve(BOB, third.request.id)
    assert (await store.get_publish_request(third.request.id)).status == "expired"

    fourth = await pub.publish(ALICE, "production")
    rejected = await pub.reject(BOB, fourth.request.id, note="not now")
    assert rejected.status == "rejected"


async def test_rollback_restores_content_and_working_set():
    ctx, store, _, pub = await prepared()
    v1 = (await pub.publish(ALICE, "dev")).snapshot
    await AssignmentService(ctx).patch(EDITOR, "dev", "global-pii", {"mode": "shadow"})
    v2 = (await pub.publish(ALICE, "dev")).snapshot
    assert v2.version != v1.version
    rb = await pub.rollback(ALICE, "dev", v1.version)
    assert rb.status == "published" and rb.snapshot.kind == "rollback" and rb.snapshot.rolled_back_from == v1.version
    assert rb.snapshot.version not in (v1.version, v2.version)  # snapshots are immutable
    live = SnapshotDoc.model_validate(rb.snapshot.document)
    assert live.assignments[0].mode == "enforce"
    working = await store.list_assignments("dev")
    assert working[0].assignment.mode == "enforce"  # next publish won't undo the rollback
    assert (await pub.publish(ALICE, "dev")).status == "unchanged"
    history = [s.version for s in await pub.history(VIEWER, "dev")]
    assert history[0] == rb.snapshot.version and len(history) == 3


async def test_rollback_in_production_needs_approval():
    ctx, store, _, pub = await prepared()
    v1 = await pub.approve(BOB, (await pub.publish(ALICE, "production")).request.id)
    await AssignmentService(ctx).patch(EDITOR, "production", "global-pii", {"enabled": False})
    await pub.approve(BOB, (await pub.publish(ALICE, "production")).request.id)
    rb = await pub.rollback(ALICE, "production", v1.version)
    assert rb.status == "pending_approval" and rb.request.kind == "rollback"
    snap = await pub.approve(BOB, rb.request.id)
    assert SnapshotDoc.model_validate(snap.document).assignments[0].enabled is True


async def test_deprecated_version_blocks_new_publish_but_not_rollback():
    ctx, store, _, pub = await prepared()
    v1 = (await pub.publish(ALICE, "dev")).snapshot
    await RegistryService(ctx).deprecate(ALICE, "ai-gateway-pii", "1.1.0")
    await AssignmentService(ctx).patch(EDITOR, "dev", "global-pii", {"mode": "shadow"})
    with pytest.raises(ValidationFailed, match="invalid"):
        await pub.publish(ALICE, "dev")
    rb = await pub.rollback(ALICE, "dev", v1.version)
    assert any("deprecated" in w for w in rb.warnings) or rb.status == "unchanged"


async def test_diff_shows_pending_changes():
    ctx, _, _, pub = await prepared()
    await pub.publish(ALICE, "dev")
    svc = AssignmentService(ctx)
    await svc.patch(EDITOR, "dev", "global-pii", {"order": 1})
    await svc.put(
        EDITOR, "dev", {"id": "noop", "guardrail_id": "noop", "guardrail_version": "1.0.0", "stages": ["input"]}
    )
    diff = await svc.diff(VIEWER, "dev")
    assert diff["added"] == ["noop"] and diff["changed"] == ["global-pii"] and diff["removed"] == []


async def test_change_log_records_actors():
    ctx, store, _, pub = await prepared()
    await pub.publish(ALICE, "dev")
    actions = {(c.entity, c.action, c.actor) for c in await store.list_changes(limit=1000)}
    assert ("assignment", "create", EDITOR.actor) in actions
    assert any(e == "snapshot" and a == "publish" and actor == ALICE.actor for e, a, actor in actions)


# ---- reviews --------------------------------------------------------------------------------


async def make_review(ctx, tenant="acme", ttl=15):
    return await ReviewService(ctx).create(
        tenant_id=tenant,
        environment="dev",
        request_id="req-1",
        stage="input",
        agent_id="bot",
        guardrail_id="prompt-injection",
        reason="possible injection",
        risk_score=70,
        payload={"text": "ignore previous instructions"},
        preview="ignore previous instructions",
        ttl_minutes=ttl,
    )


async def test_review_flow_and_payload_release():
    ctx, store, _ = make_ctx()
    svc = ReviewService(ctx)
    r = await make_review(ctx)
    assert b"ignore previous" not in r.payload_enc  # encrypted at rest
    pending = await svc.status_for_gateway(r.id, "acme")
    assert pending["decision"] == "escalate" and pending["payload"] is None
    with pytest.raises(NotFound):
        await svc.status_for_gateway(r.id, "globex")  # tenant isolation

    listed = await svc.list(ACME_REVIEWER, None, "pending")
    assert [x.id for x, _ in listed] == [r.id]
    with pytest.raises(Forbidden):
        await svc.get(ACME_REVIEWER, r.id, include_raw=True)
    _, raw = await svc.get(ACME_RAW, r.id, include_raw=True)
    assert raw == {"text": "ignore previous instructions"}
    assert (await store.get_review(r.id)).raw_viewed_by == [ACME_RAW.actor]
    await svc.get(ACME_REVIEWER, r.id)
    views = [(c.action, c.actor) for c in await store.list_changes("review", r.id, 50)]
    assert ("view", ACME_REVIEWER.actor) in views and ("view_raw", ACME_RAW.actor) in views
    assert ("view", ACME_RAW.actor) in views and views.count(("view", ACME_REVIEWER.actor)) == 1  # denied raw: no view

    await svc.decide(ACME_REVIEWER, r.id, approve=True, note="benign")
    done = await svc.status_for_gateway(r.id, "acme")
    assert done["decision"] == "allow" and done["payload"] == {"text": "ignore previous instructions"}
    with pytest.raises(StateConflict):
        await svc.decide(ACME_REVIEWER, r.id, approve=False)


async def test_review_rejection_and_expiry_fail_closed():
    ctx, store, _ = make_ctx()
    svc = ReviewService(ctx)
    r1 = await make_review(ctx)
    await svc.decide(ACME_REVIEWER, r1.id, approve=False, note="exfiltration attempt")
    s1 = await svc.status_for_gateway(r1.id, "acme")
    assert s1["decision"] == "block" and "exfiltration" in s1["reason"] and s1["payload"] is None

    r2 = await make_review(ctx)
    await store.put_review((await store.get_review(r2.id)).model_copy(update={"expires_at": utcnow()}))
    s2 = await svc.status_for_gateway(r2.id, "acme")
    assert s2["status"] == "expired" and s2["decision"] == "block"
    with pytest.raises(StateConflict):
        await svc.decide(ACME_REVIEWER, r2.id, approve=True)
    assert [x.id for x, s in await svc.list(ACME_REVIEWER, None, "expired")] == [r2.id]

    other = await make_review(ctx, tenant="globex")
    with pytest.raises(Forbidden):
        await svc.decide(ACME_REVIEWER, other.id, approve=True)


# ---- admin keys -----------------------------------------------------------------------------


async def test_admin_keys():
    ctx, _, _ = make_ctx()
    svc = AdminKeyService(ctx)
    key, raw = await svc.create(None, "root", ["admin"])
    p = await svc.authenticate(raw)
    assert p is not None and p.is_platform and "admin" in p.roles
    assert await svc.authenticate("cpk_wrong") is None
    _, tenant_raw = await svc.create(p, "acme-admin", ["admin"], tenant_id="acme")
    acme = await svc.authenticate(tenant_raw)
    assert acme.tenant_id == "acme"
    with pytest.raises((Forbidden, ValidationFailed)):
        await svc.create(acme, "escalate-me", ["admin"], tenant_id=None)
    with pytest.raises(ValidationFailed):
        await svc.create(p, "x", ["superuser"])
    await svc.revoke(p, key.id)
    assert await svc.authenticate(raw) is None


async def test_diff_details_and_tenant_view():
    ctx, _, _ = make_ctx()
    await setup_registry(ctx)
    svc = AssignmentService(ctx)
    await svc.put(EDITOR, "dev", pii_assignment())
    await PublishService(ctx).publish(ALICE, "dev")
    await svc.patch(EDITOR, "dev", "global-pii", {"mode": "shadow"})
    acme = pii_assignment(id="acme-pii", scope_type="tenant", scope_id="acme")
    await svc.put(EDITOR, "dev", acme)
    d = await svc.diff(ALICE, "dev")
    assert d["changed"] == ["global-pii"] and d["added"] == ["acme-pii"]
    assert d["details"]["global-pii"]["live"]["mode"] == "enforce"
    assert d["details"]["global-pii"]["working"]["mode"] == "shadow"
    assert d["details"]["acme-pii"]["live"] is None
    tenant_view = await svc.diff(ACME_ADMIN, "dev")
    assert tenant_view["added"] == ["acme-pii"] and tenant_view["changed"] == []
    assert set(tenant_view["details"]) == {"acme-pii"}


def test_manifest_yaml_loader():
    from app.services.registry import load_manifest_yaml

    text = (PLUGINS_DIR / "noop" / "guardrail.yaml").read_text()
    assert load_manifest_yaml(text)["id"] == "noop"
    for bad in ("id: [unclosed", "- just\n- a list", "!!python/object:os.system {}"):
        with pytest.raises(ValidationFailed):
            load_manifest_yaml(bad)


async def test_api_key_rate_limit_is_published():
    ctx, _, _ = make_ctx()
    cat = CatalogService(ctx)
    await cat.create_tenant(ALICE, "acme", "Acme")
    key, _ = await cat.create_api_key(ALICE, "acme", "bot", rate_limit_per_minute=120)
    doc, _ = await cat.current_document()
    assert CatalogDoc.model_validate(doc).tenants[0].api_keys[0].rate_limit_per_minute == 120
    await cat.set_api_key_rate_limit(ACME_ADMIN, "acme", key.id, 0)  # 0 = unlimited for this key
    doc, _ = await cat.current_document()
    assert CatalogDoc.model_validate(doc).tenants[0].api_keys[0].rate_limit_per_minute == 0
    await cat.set_api_key_rate_limit(ALICE, "acme", key.id, None)  # back to the gateway default
    doc, _ = await cat.current_document()
    assert CatalogDoc.model_validate(doc).tenants[0].api_keys[0].rate_limit_per_minute is None
    with pytest.raises(Forbidden):
        await cat.set_api_key_rate_limit(VIEWER, "acme", key.id, 5)
    with pytest.raises(NotFound):
        await cat.set_api_key_rate_limit(ALICE, "other", key.id, 5)


async def test_metrics_refresh_runs_on_the_store():
    from app.metrics import refresh_gauges

    ctx, store, _ = make_ctx()
    await make_review(ctx)
    await GatewayService(ctx).heartbeat(
        gateway_id="gw-1", environment="dev", manifests=[], snapshot_version=None, catalog_version=None, last_error=None
    )
    await refresh_gauges(ctx)  # no exceptions with reviews, gateways and no snapshots


async def test_concurrent_review_decisions_have_one_winner():
    import asyncio as _asyncio

    ctx, store, _ = make_ctx()
    svc = ReviewService(ctx)
    r = await make_review(ctx)
    results = await _asyncio.gather(
        svc.decide(ACME_REVIEWER, r.id, approve=True),
        svc.decide(ACME_REVIEWER, r.id, approve=False),
        return_exceptions=True,
    )
    assert sum(1 for x in results if isinstance(x, StateConflict)) == 1
    final = await store.get_review(r.id)
    winner = next(x for x in results if not isinstance(x, Exception))
    assert final.status == winner.status  # the loser never overwrote the winner

    # a raw view recorded concurrently with a decision does not undo the decision
    r2 = await make_review(ctx)
    await _asyncio.gather(svc.get(ACME_RAW, r2.id, include_raw=True), svc.decide(ACME_REVIEWER, r2.id, approve=True))
    after = await store.get_review(r2.id)
    assert after.status == "approved" and after.raw_viewed_by == [ACME_RAW.actor]

    # the TTL is checked atomically with the write
    r3 = await make_review(ctx)
    assert not await store.decide_review(
        r3.id, status="approved", reviewer="x", decided_at=r3.expires_at, decision_note=""
    )


async def test_tenant_diff_hides_the_other_tenants_side():
    ctx, _, _ = make_ctx()
    await setup_registry(ctx)
    svc = AssignmentService(ctx)
    other = pii_assignment(id="moved", scope_type="tenant", scope_id="globex")
    await svc.put(EDITOR, "dev", other)
    await PublishService(ctx).publish(ALICE, "dev")
    await svc.put(EDITOR, "dev", {**other, "scope_id": "acme"})  # platform re-scopes it to acme
    d = await svc.diff(ACME_ADMIN, "dev")
    assert d["changed"] == ["moved"]
    assert d["details"]["moved"]["live"] is None  # globex's config is not shown to acme
    assert d["details"]["moved"]["working"]["scope_id"] == "acme"


async def test_catalog_versions_stay_unique_when_content_returns_to_an_earlier_state():
    ctx, store, _ = make_ctx()
    cat = CatalogService(ctx)
    await cat.create_tenant(ALICE, "acme", "Acme")
    before = await store.current_catalog()
    key, _ = await cat.create_api_key(ALICE, "acme", "short-lived")
    await cat.revoke_api_key(ALICE, "acme", key.id)  # same content as `before`, within the same second
    after = await store.current_catalog()
    assert after.content_hash == before.content_hash and after.version != before.version


async def test_api_keys_can_be_bound_to_one_agent():
    ctx, store, _ = make_ctx()
    cat = CatalogService(ctx)
    await cat.create_tenant(ALICE, "acme", "Acme")
    with pytest.raises(ValidationFailed):  # the agent must be registered first
        await cat.create_api_key(ALICE, "acme", "bot", agent_id="support-bot")
    await cat.put_agent(ALICE, "acme", "support-bot", 70, ["*"])
    bound, _ = await cat.create_api_key(ALICE, "acme", "bot", agent_id="support-bot")
    legacy, _ = await cat.create_api_key(ALICE, "acme", "legacy")
    doc, _ = await cat.current_document()
    keys = {k.name: k for k in CatalogDoc.model_validate(doc).tenants[0].api_keys}
    assert keys["bot"].agent_id == "support-bot" and keys["legacy"].agent_id is None
    published = {k["name"]: k for k in doc["tenants"][0]["api_keys"]}
    assert "agent_id" not in published["legacy"]  # older gateways keep loading the catalog

    await cat.bind_api_key(ACME_ADMIN, "acme", legacy.id, "support-bot")  # upgrade a legacy key to A1
    doc, _ = await cat.current_document()
    assert all(k.agent_id == "support-bot" for k in CatalogDoc.model_validate(doc).tenants[0].api_keys)
    await cat.bind_api_key(ALICE, "acme", legacy.id, None)
    with pytest.raises(ValidationFailed):
        await cat.bind_api_key(ALICE, "acme", legacy.id, "ghost")
    with pytest.raises(Forbidden):
        await cat.bind_api_key(VIEWER, "acme", legacy.id, "support-bot")
    with pytest.raises(NotFound):
        await cat.bind_api_key(ALICE, "other", legacy.id, "support-bot")
    actions = [c.action for c in await store.list_changes("api_key", legacy.id)]
    assert {"bind", "unbind"} <= set(actions)


async def test_binding_waits_until_every_live_gateway_supports_it():
    ctx, _, _ = make_ctx()
    cat, gws = CatalogService(ctx), GatewayService(ctx)
    await cat.create_tenant(ALICE, "acme", "Acme")
    await cat.put_agent(ALICE, "acme", "bot", 70, ["*"])
    common = dict(environment="dev", manifests=[], snapshot_version=None, catalog_version=None, last_error=None)
    await gws.heartbeat(gateway_id="gw-old", **common)  # 0.5 gateway: reports no capabilities
    await gws.heartbeat(gateway_id="gw-new", capabilities=["agent_bound_keys"], **common)
    with pytest.raises(ValidationFailed, match="gw-old"):
        await cat.create_api_key(ALICE, "acme", "bot", agent_id="bot")
    key, _ = await cat.create_api_key(ALICE, "acme", "legacy")  # unbound keys are fine meanwhile
    await gws.heartbeat(gateway_id="gw-old", capabilities=["agent_bound_keys"], **common)  # upgraded
    await cat.bind_api_key(ALICE, "acme", key.id, "bot")
    await cat.revoke_api_key(ALICE, "acme", key.id)
    with pytest.raises(ValidationFailed, match="revoked"):
        await cat.bind_api_key(ALICE, "acme", key.id, "bot")


async def test_tenant_advisor_policy_is_opt_in_and_published():
    ctx, store, _ = make_ctx()
    cat, gws = CatalogService(ctx), GatewayService(ctx)
    await cat.create_tenant(ALICE, "acme", "Acme")
    doc, _ = await cat.current_document()
    assert "advisor_data_classes" not in doc["tenants"][0]  # default: hosted advisors see nothing
    common = dict(environment="dev", manifests=[], snapshot_version=None, catalog_version=None, last_error=None)
    await gws.heartbeat(gateway_id="gw-old", capabilities=["agent_bound_keys"], **common)
    with pytest.raises(ValidationFailed, match="gw-old"):  # it would reject the catalog
        await cat.set_advisor_policy(ACME_ADMIN, "acme", ["INTERNAL"])
    await gws.heartbeat(gateway_id="gw-old", capabilities=["agent_bound_keys", "advisors_v1"], **common)
    t = await cat.set_advisor_policy(ACME_ADMIN, "acme", ["PII", "INTERNAL", "INTERNAL"])
    assert t.advisor_data_classes == ["INTERNAL", "PII"]
    doc, _ = await cat.current_document()
    assert CatalogDoc.model_validate(doc).tenants[0].advisor_data_classes == ["INTERNAL", "PII"]
    with pytest.raises(ValidationFailed):
        await cat.set_advisor_policy(ALICE, "acme", ["SECRET"])
    with pytest.raises(Forbidden):
        await cat.set_advisor_policy(VIEWER, "acme", [])
    await cat.create_tenant(ALICE, "other", "Other")
    with pytest.raises(Forbidden):
        await cat.set_advisor_policy(ACME_ADMIN, "other", ["INTERNAL"])
    await cat.set_advisor_policy(ALICE, "acme", [])  # turning it off needs no gateway check
    doc, _ = await cat.current_document()
    assert "advisor_data_classes" not in doc["tenants"][0]
    actions = [c.action for c in await store.list_changes("tenant", "acme")]
    assert actions.count("advisor_policy") == 2


async def test_advisor_pilot_analytics_shapes_the_audit_rows():
    from app.services.analytics import AnalyticsService, AnalyticsUnavailable

    seen = []

    async def fetch(sql, params):
        seen.append((sql, params))
        if "flagged, stopped" in sql:
            return [
                {"advisor": "jev", "mode": "shadow", "flagged": True, "stopped": False, "n": 3},
                {"advisor": "jev", "mode": "shadow", "flagged": True, "stopped": True, "n": 5},
                {"advisor": "jev", "mode": "shadow", "flagged": False, "stopped": False, "n": 40},
            ]
        row = dict(provider="http", mode="shadow", question="exfiltration", avg_latency_ms=80.0, p95_latency_ms=150.0)
        return [
            {**row, "advisor": "jev", "status": "answered", "label": "benign", "n": 40, "avg_confidence": 0.9,
             "points": 0, "verify_requests": 0},
            {**row, "advisor": "jev", "status": "answered", "label": "malicious", "n": 8, "avg_confidence": 0.8,
             "points": 64, "verify_requests": 2},
            {**row, "advisor": "jev", "status": "timeout", "label": "none", "n": 2, "avg_confidence": None,
             "points": 0, "verify_requests": 0},
        ]  # fmt: skip

    out = await AnalyticsService(fetch).advisors(ACME_ADMIN, hours=48)
    [jev] = out["advisors"]
    assert out["tenant_id"] == "acme" and seen[0][1]["tenant_id"] == "acme"  # a tenant key sees its own tenant
    assert jev["questions"] == 50 and jev["by_status"] == {"answered": 48, "timeout": 2}
    assert jev["by_label"] == {"benign": 40, "malicious": 8} and jev["no_signal_rate"] == 0.04
    assert jev["agreement"] == {"flagged_stopped": 5, "flagged_released": 3, "benign_stopped": 0, "benign_released": 40}
    with pytest.raises(Forbidden):
        await AnalyticsService(fetch).advisors(ACME_ADMIN, tenant_id="other")
    with pytest.raises(AnalyticsUnavailable):
        await AnalyticsService(None).advisors(ALICE)


async def test_advisor_training_set_labels_from_people_only():
    from datetime import timedelta as td

    from app.domain.records import ReviewRecord
    from app.services.advisor_training import training_set

    ctx, store, _ = make_ctx()
    now = utcnow()
    for rid, status in (("r-rej", "rejected"), ("r-app", "approved"), ("r-pend", "pending")):
        await store.add_review(
            ReviewRecord(tenant_id="acme", environment="production", request_id=rid, stage="tool", agent_id="a",
                         guardrail_id="gateway-risk", reason="held", payload_enc=b"x", status=status,
                         expires_at=now + td(minutes=15))
        )  # fmt: skip
    features = {"stage": "tool", "kind": "http"}

    def row(rid, outcome="hold", codes=(), f=features):
        return {"request_id": rid, "tenant_id": "acme", "outcome": outcome, "reason_codes": list(codes),
                "features": json.dumps(f) if isinstance(f, dict) else f}  # fmt: skip

    audit = [
        row("r-rej"), row("r-app"), row("r-pend"),
        row("u-no", "deny", ["USER_REJECTED"]), row("u-yes", "allow", ["VERIFIED", "EVIDENCE_USER_CONFIRMATION"]),
        row("dry-run", "allow", ["VERIFIED", "EVIDENCE_SQL_DRY_RUN"]),
        row("plain", "allow"), row("broken", "allow", ["VERIFIED"], f="null"),
    ]  # fmt: skip
    seen = []

    async def fetch(sql, params):
        seen.append(params)
        return audit

    rows, counts = await training_set(fetch, store, since=now - td(days=30), tenant_id="acme")
    labels = {r["request_id"]: r["label"] for r in rows}
    assert labels == {"r-rej": 1, "r-app": 0, "u-no": 1, "u-yes": 0}  # pending and unreviewed: no label
    assert counts == {"rows": 8, "positive": 2, "negative": 2, "weak": 0, "skipped": 4}  # a dry run isn't a person
    assert seen[0]["tenant_id"] == "acme"
    rows, counts = await training_set(fetch, store, since=now - td(days=30), include_released=True)
    weak = [r for r in rows if r["weak"]]
    assert [r["request_id"] for r in weak] == ["dry-run", "plain"] and counts["weak"] == 2
