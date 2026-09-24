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
