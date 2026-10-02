import asyncio
import json

from app.audit.chain import GENESIS, AuditChain, verify
from app.context.descriptors import describe
from app.risk.decision import decide, to_legacy
from app.risk.engine import RiskConfig, assess, band_for, current_trust
from app.session.store import MemorySessionStore, Penalty, RedisSessionStore, SessionUpdate, SessionView, p95
from guardrail_sdk import Decision

CFG = RiskConfig()
NOW = 1_800_000_000.0


def sql(query, **args):
    return describe(
        stage="tool", action="db.query", resource=None, tool_name="db.query",
        tool_arguments={"sql": query, **args}, request_arguments=None, tool_metadata=None,
    )  # fmt: skip


def run(coro):
    return asyncio.run(coro)


# ---- risk engine ---------------------------------------------------------------------------------


def test_worked_example_is_critical_despite_high_trust():
    d = sql("SELECT email, phone, address FROM public.customers ORDER BY id DESC LIMIT 10000")
    view = SessionView(
        has_session=True, age_seconds=180, labels=frozenset({"untrusted_input"}), first_seen_target=True,
        volume_p95=250, volume_samples=50,
    )  # fmt: skip
    a = assess(
        inherent=40, base_trust=80, descriptor=d, view=view, stage="tool", environment="production",
        assurance="A1", data_classification="PII", has_session_id=True, cfg=CFG, now=NOW,
    )  # fmt: skip
    assert a.codes == ["NEW_RESOURCE", "VOLUME_40X", "TAINTED_SESSION", "NEW_SESSION"]
    assert a.score == 100 and a.band == "critical" and a.trust == 80 and a.confidence == 1.0


def test_routine_request_is_low_and_explained():
    d = sql("SELECT id FROM orders WHERE customer_id = 7 LIMIT 20")
    view = SessionView(has_session=True, age_seconds=3600, first_seen_target=False, volume_p95=20, volume_samples=40)
    a = assess(
        inherent=20, base_trust=80, descriptor=d, view=view, stage="tool", environment="production",
        assurance="A1", data_classification="INTERNAL", has_session_id=True, cfg=CFG, now=NOW,
    )  # fmt: skip
    assert a.signals == () and a.score == 20 and a.band == "low"


def test_missing_context_raises_risk_never_lowers_it():
    d = sql("SELECT id FROM orders WHERE id = 1 LIMIT 1")
    full = assess(
        inherent=20, base_trust=80, descriptor=d, view=SessionView(has_session=True, age_seconds=9999),
        stage="tool", environment="dev", assurance="A1", data_classification="INTERNAL", has_session_id=True,
        cfg=CFG, now=NOW,
    )  # fmt: skip
    blind = assess(
        inherent=20, base_trust=80, descriptor=d, view=SessionView(available=False), stage="tool", environment="dev",
        assurance="A1", data_classification="INTERNAL", has_session_id=False, cfg=CFG, now=NOW,
    )  # fmt: skip
    assert blind.score > full.score and blind.confidence < full.confidence
    assert {"NO_SESSION", "LOW_CONFIDENCE"} <= set(blind.codes)


def test_sensitive_data_to_external_destination():
    d = describe(
        stage="tool", action="http.post", resource=None, tool_name="http.post",
        tool_arguments={"url": "https://paste.example.net/new", "method": "POST", "body": "x"},
        request_arguments=None, tool_metadata=None, internal_domains=["acme.com"],
    )  # fmt: skip
    view = SessionView(has_session=True, age_seconds=999, labels=frozenset({"holds:PII"}))
    a = assess(
        inherent=30, base_trust=80, descriptor=d, view=view, stage="tool", environment="dev", assurance="A1",
        data_classification="INTERNAL", has_session_id=True, cfg=CFG, now=NOW,
    )  # fmt: skip
    assert "SENSITIVE_THEN_EXTERNAL" in a.codes


def test_a0_keys_cost_risk_in_production_only():
    d = describe(stage="input", action="llm.chat", resource=None, tool_name=None, tool_arguments=None,
                 request_arguments=None, tool_metadata=None)  # fmt: skip
    kw = dict(inherent=10, base_trust=80, descriptor=d, view=SessionView(has_session=True, age_seconds=999),
              stage="input", data_classification="INTERNAL", has_session_id=True, cfg=CFG, now=NOW)  # fmt: skip
    assert "LOW_ASSURANCE" in assess(environment="production", assurance="A0", **kw).codes
    assert "LOW_ASSURANCE" not in assess(environment="dev", assurance="A0", **kw).codes
    assert "LOW_ASSURANCE" not in assess(environment="production", assurance="A1", **kw).codes


def test_bands_move_with_trust_but_80_is_always_critical():
    assert band_for(45, 80) == "low" and band_for(45, 20) == "elevated"
    assert band_for(79, 100) == "high" and band_for(80, 100) == "critical"
    assert band_for(60, 0) == "high"


def test_trust_penalties_fade_and_never_exceed_the_ceiling():
    pen = Penalty("REPEATED_DENIALS", 30, 30.0, NOW)
    v = SessionView(penalties=(pen,))
    assert current_trust(80, v, NOW) == 50
    assert current_trust(80, v, NOW + 30 * 86400) == 65
    assert current_trust(80, v, NOW + 3650 * 86400) == 80  # recovered to, never above, the base
    assert current_trust(80, SessionView(), NOW) == 80


# ---- decision table ------------------------------------------------------------------------------


def table(band, engine=Decision.ALLOW, d=None, **kw):
    params = dict(policy_allow=True, quarantined=False, accepts_obligations=False, cfg=CFG)
    params.update(kw)
    return decide(engine_decision=engine, band=band, descriptor=d or sql("select 1 from t where x=1 limit 1"), **params)


def test_policy_deny_and_quarantine_are_final():
    assert table("low", policy_allow=False).outcome == "deny"
    assert table("low", quarantined=True).outcome == "quarantine_session"


def test_bands_map_to_outcomes():
    assert table("low").outcome == "allow"
    assert table("elevated").outcome == "allow"
    r = table("high")
    assert r.outcome == "hold" and "VERIFY_AS_HOLD" in r.reason_codes  # until verifiers exist
    assert table("critical").outcome == "hold"


def test_obligations_only_for_callers_that_apply_them():
    big = sql("select * from customers")
    r = table("elevated", d=big, accepts_obligations=True)
    assert r.outcome == "allow_restricted" and r.obligations == {"row_limit": 1000}
    r = table("elevated", d=big, accepts_obligations=False)
    assert r.outcome == "hold" and "OBLIGATIONS_UNSUPPORTED" in r.reason_codes and r.obligations == {}


def test_guardrail_decisions_are_never_weakened():
    assert table("low", engine=Decision.BLOCK).outcome == "deny"
    assert table("low", engine=Decision.ESCALATE).outcome == "hold"
    assert table("low", engine=Decision.MODIFY).outcome == "modify"
    assert table("critical", engine=Decision.MODIFY).outcome == "hold"


def test_legacy_mapping():
    assert to_legacy("allow_restricted") == Decision.ALLOW
    assert to_legacy("allow_restricted", modified=True) == Decision.MODIFY
    assert to_legacy("verify") == Decision.ESCALATE and to_legacy("quarantine_session") == Decision.BLOCK


# ---- session stores ------------------------------------------------------------------------------


class Clock:
    def __init__(self):
        self.t = NOW

    def __call__(self):
        return self.t


def exercise_store(store, clock):
    async def go():
        v = await store.view("t", "a", "s1", target="crm.customers", volume_key="sql:read:crm.customers")
        assert not v.has_session and v.first_seen_target is True and v.volume_p95 is None
        for rows in (10, 20, 30):
            await store.record("t", "a", "s1", SessionUpdate(
                allowed=True, labels={"holds:PII"}, target="crm.customers",
                volume_key="sql:read:crm.customers", rows=rows,
            ))  # fmt: skip
        await store.record("t", "a", "s1", SessionUpdate(denied=True))
        clock.t += 60
        v = await store.view("t", "a", "s1", target="crm.customers", volume_key="sql:read:crm.customers")
        assert v.has_session and v.steps == 4 and v.denials == 1 and v.age_seconds == 60
        assert v.labels == frozenset({"holds:PII"}) and v.first_seen_target is False
        assert v.volume_samples == 3 and v.volume_p95 == 30
        # denied requests never feed the baseline or the first-seen set
        await store.record("t", "a", "s1", SessionUpdate(denied=True, target="x", volume_key="k", rows=9))
        v = await store.view("t", "a", "s1", target="x", volume_key="k")
        assert v.first_seen_target is True and v.volume_samples == 0
        # quarantine and penalties
        await store.record("t", "a", "s1", SessionUpdate(denied=True, quarantine_seconds=900,
                                                         penalty=Penalty("P", 10, 7, clock.t)))  # fmt: skip
        v = await store.view("t", "a", "s1", target=None, volume_key=None)
        assert v.quarantined(clock.t) and not v.quarantined(clock.t + 901) and v.penalised
        assert [p.code for p in v.penalties] == ["P"]
        # tenants are isolated, and another agent can't see (or taint) this agent's session id
        other = await store.view("other", "a", "s1", target="crm.customers", volume_key="sql:read:crm.customers")
        assert not other.has_session and other.first_seen_target is True and other.penalties == ()
        assert not (await store.view("t", "b", "s1", target=None, volume_key=None)).has_session
        # agent-level memory survives a new session id
        fresh = await store.view("t", "a", "s-new", target=None, volume_key=None)
        assert not fresh.has_session and fresh.agent_recent_denials == 3
        await store.record("t", "a", None, SessionUpdate(denied=True, agent_quarantine_seconds=900))
        assert (await store.view("t", "a", "s-other", target=None, volume_key=None)).quarantined(clock.t)
        clock.t += 16 * 60
        assert (await store.view("t", "a", "s-new", target=None, volume_key=None)).agent_recent_denials == 0

    run(go())


def test_memory_session_store():
    clock = Clock()
    exercise_store(MemorySessionStore(clock=clock), clock)


def test_memory_store_is_bounded():
    s = MemorySessionStore(max_entries=100)
    for i in range(500):
        run(s.record("t", "a", f"s{i}", SessionUpdate()))
    assert len(s._sessions) == 100


class FakeRedis:
    """The handful of commands RedisSessionStore uses, with real semantics."""

    def __init__(self, clock, fail=False):
        self.data, self.clock, self.fail = {}, clock, fail

    def pipeline(self, transaction=False):
        return FakePipe(self)


class FakePipe:
    def __init__(self, r):
        self.r, self.ops = r, []

    def __getattr__(self, name):
        def op(*a, **kw):
            self.ops.append((name, a))
            return self

        return op

    async def execute(self):
        if self.r.fail:
            raise ConnectionError("redis down")
        d, out = self.r.data, []
        for name, a in self.ops:
            k = a[0]
            if name == "hget":
                out.append(d.get(k, {}).get(a[1]))
            elif name == "hgetall":
                out.append(dict(d.get(k, {})))
            elif name in ("hset", "hsetnx"):
                h = d.setdefault(k, {})
                if name == "hset" or a[1] not in h:
                    h[a[1]] = a[2]
                out.append(1)
            elif name == "hincrby":
                h = d.setdefault(k, {})
                h[a[1]] = str(int(h.get(a[1], 0)) + a[2])
                out.append(int(h[a[1]]))
            elif name == "lpush":
                d.setdefault(k, [])[:0] = list(reversed(a[1:]))
                out.append(len(d[k]))
            elif name == "ltrim":
                d[k] = d.get(k, [])[a[1] : a[2] + 1]
                out.append(True)
            elif name == "lrange":
                out.append(d.get(k, [])[a[1] : a[2] + 1])
            elif name == "sadd":
                d.setdefault(k, set()).update(a[1:])
                out.append(1)
            elif name == "smembers":
                out.append(set(d.get(k, set())))
            elif name == "expire":
                out.append(True)
            elif name == "get":
                out.append(d.get(k))
            elif name == "set":
                d[k] = a[1]
                out.append(True)
            else:
                raise AssertionError(name)
        return out


def test_redis_session_store_matches_memory_semantics():
    clock = Clock()
    exercise_store(RedisSessionStore(FakeRedis(clock), clock=clock), clock)


def test_slow_redis_costs_confidence_not_latency():
    import time as _t

    class Slow(FakeRedis):
        def pipeline(self, transaction=False):
            p = FakePipe(self)

            async def execute():
                await asyncio.sleep(5)

            p.execute = execute
            return p

    store = RedisSessionStore(Slow(Clock()), timeout_seconds=0.05)
    t0 = _t.monotonic()
    v = run(store.view("t", "a", "s", target=None, volume_key=None))
    assert v.available is False and _t.monotonic() - t0 < 1


def test_redis_outage_degrades_to_stricter_view_and_never_raises():
    clock = Clock()
    store = RedisSessionStore(FakeRedis(clock, fail=True), clock=clock)
    v = run(store.view("t", "a", "s", target="x", volume_key="k"))
    assert v.available is False
    run(store.record("t", "a", "s", SessionUpdate(allowed=True)))  # no exception


def test_p95():
    assert p95([]) is None and p95([5]) == 5 and p95(list(range(1, 101))) == 95


# ---- hash chain ----------------------------------------------------------------------------------


def events(n, tenant="t"):
    import uuid
    from datetime import UTC, datetime

    return [
        {"id": uuid.uuid4(), "created_at": datetime.now(UTC), "tenant_id": tenant, "request_id": f"r{i}",
         "stage": "input", "agent_id": "a", "decision": "allow", "outcome": "allow", "reason": "ok",
         "risk_score": 10, "payload_sha256": "0" * 64, "snapshot_version": "v1"}
        for i in range(n)
    ]  # fmt: skip


def test_chain_links_records_per_tenant_and_verifies():
    chain = AuditChain("c1")
    rows = events(3) + events(2, tenant="u")
    for e in rows:
        chain.stamp(e)
    assert [e["chain_seq"] for e in rows] == [1, 2, 3, 1, 2]
    assert rows[0]["prev_hash"] == GENESIS and rows[1]["prev_hash"] == rows[0]["record_hash"]
    report = verify(reversed(rows))
    assert report.ok and report.records == 5 and report.chains == 2


def test_chain_survives_a_json_round_trip_like_the_spool_and_database():
    from datetime import datetime

    chain = AuditChain()
    rows = events(2)
    for e in rows:
        chain.stamp(e)
    back = [json.loads(json.dumps(e, default=str)) for e in rows]
    for e in back:
        e["created_at"] = datetime.fromisoformat(e["created_at"])
    assert verify(back).ok


def test_chain_detects_edits_deletions_and_relinks():
    chain = AuditChain()
    rows = events(4)
    for e in rows:
        chain.stamp(e)
    edited = [dict(e) for e in rows]
    edited[1]["decision"] = "block"
    assert any("hash mismatch" in p for p in verify(edited).problems)
    assert any("missing" in p for p in verify([rows[0], rows[2], rows[3]]).problems)
    legacy = {k: v for k, v in rows[0].items() if not k.startswith(("chain", "prev", "record"))}
    assert verify([legacy]).records == 0  # pre-chain rows are skipped, not errors
