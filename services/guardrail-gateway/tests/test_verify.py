"""Verification engine units: assurance model, planner, stores, user tokens, SQL dry run, engine."""

import asyncio
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.context.descriptors import ActionDescriptor, describe, sql_text
from app.verify.dryrun import DryRunResult, SqlDryRun
from app.verify.engine import VerificationClosed, VerificationEngine, VerificationNotFound, VerifyContext
from app.verify.model import Evidence, current, gap, request_hash, required, summary_for
from app.verify.planner import DRY_RUN, HUMAN_APPROVAL, USER_CONFIRMATION, plan
from app.verify.store import MemoryVerificationStore, RedisVerificationStore
from app.verify.user_token import TokenRejected, UserTokenConfig, UserTokenVerifier, mint_dev_token
from tests.test_risk import FakePipe, FakeRedis

SQL_READ = ActionDescriptor("sql", "read", target="public.customers", tables=("public.customers",), columns=("email",))
DEV = "dev-secret-for-tests-0123456789abcdef"
EXT_SEND = ActionDescriptor("http", "send", target="evil.example.org", destination="external",
                            destination_host="evil.example.org")  # fmt: skip


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def run(coro):
    return asyncio.run(coro)


# ---- model ------------------------------------------------------------------------------------


def test_request_hash_binds_every_field():
    base = dict(tenant="t", agent_id="a", stage="tool", action="db.query", resource=None, user_id="u1",
                session_id="s", payload_sha256="p")  # fmt: skip
    h = request_hash(**base)
    assert h == request_hash(**base)
    for k, v in (("user_id", "u2"), ("payload_sha256", "q"), ("tenant", "t2"), ("session_id", None)):
        assert request_hash(**{**base, k: v}) != h


def test_required_and_current_levels():
    assert required(SQL_READ, [], "dev") == {"resource": 2, "effect": 1}
    assert required(EXT_SEND, ["TAINTED_SESSION"], "production") == {
        "authorization": 2, "behaviour": 1, "identity": 1,
    }  # fmt: skip
    unknown = ActionDescriptor("unknown", "unknown")
    assert required(unknown, [], "dev") == {"authorization": 2}
    model = ActionDescriptor("model", "read", target="x")  # nothing machine-checkable: ask the person
    assert required(model, [], "dev") == {"authorization": 2}

    have = current(assurance="A1", d=SQL_READ, codes=["REPEATED_DENIALS"], evidence=[])
    assert have == {"identity": 1, "authorization": 0, "resource": 1, "behaviour": 0, "effect": 0}
    ev = Evidence("dry_run", "h", True, {"resource": 2, "effect": 1}, {}, 0, 1)
    failed = Evidence("dry_run", "h", False, {"resource": 2, "effect": 1}, {}, 0, 1)
    have = current(assurance="A0", d=SQL_READ, codes=[], evidence=[ev, failed])
    assert have["resource"] == 2 and have["effect"] == 1 and have["identity"] == 0
    assert gap({"resource": 2, "effect": 1}, have) == {}


def test_summary_names_never_values():
    d = describe(stage="tool", action="db.query", resource=None, tool_name="db.query",
                 tool_arguments={"sql": "SELECT email FROM public.customers WHERE email = 'jane@example.com'"},
                 request_arguments=None, tool_metadata=None)  # fmt: skip
    s = summary_for("research-agent", d)
    assert "public.customers" in s and "email" in s and "jane@example.com" not in s
    assert "evil.example.org" in summary_for("a", EXT_SEND)


def test_sql_text_uses_the_same_keys_as_the_descriptor():
    assert sql_text({"sql": "SELECT 1"}, {"sql": "SELECT 2"}) == "SELECT 1"  # tool args win, like describe()
    assert sql_text(None, {"statement": "SELECT 3"}) == "SELECT 3"
    assert sql_text({"text": "hello"}, None) is None


# ---- planner ----------------------------------------------------------------------------------


def test_planner_picks_cheapest_machine_plan_else_human():
    assert plan({}, [DRY_RUN]) is None
    p = plan({"resource": 2, "effect": 1}, [DRY_RUN, USER_CONFIRMATION])
    assert p is not None and p.kinds == ["dry_run"] and p.inline and not p.pending
    p = plan({"resource": 2, "authorization": 2}, [DRY_RUN, USER_CONFIRMATION])
    assert p is not None and p.kinds == ["dry_run", "user_confirmation"] and p.pending == (USER_CONFIRMATION,)
    p = plan({"authorization": 2}, [DRY_RUN])
    assert p is not None and p.steps == (HUMAN_APPROVAL,) and p.needs_human_review
    p = plan({"identity": 1}, [DRY_RUN, USER_CONFIRMATION])  # no machine closes identity
    assert p is not None and p.needs_human_review


# ---- stores -----------------------------------------------------------------------------------


class VerifyRedis(FakeRedis):
    def pipeline(self, transaction=False):
        return VerifyPipe(self)


class VerifyPipe(FakePipe):
    """FakePipe plus rpush/delete, executed strictly in order (MULTI/EXEC or not)."""

    async def execute(self):
        if self.r.fail:
            raise ConnectionError("redis down")
        ops, out = self.ops, []
        for name, a in ops:
            if name == "rpush":
                self.r.data.setdefault(a[0], []).extend(a[1:])
                out.append(len(self.r.data[a[0]]))
            elif name == "delete":
                out.append(1 if self.r.data.pop(a[0], None) is not None else 0)
            else:
                self.ops = [(name, a)]
                out.extend(await super().execute())
        return out


def exercise_verification_store(store, clock):
    from app.verify.model import Verification

    async def go():
        v = Verification("v1", "t", "h1", "user_confirmation", "a", "u1", "s", "pending", clock(), clock() + 600)
        await store.put_verification(v)
        assert (await store.get_verification("t", "v1")).status == "pending"
        assert await store.get_verification("other-tenant", "v1") is None
        assert (await store.pending_for("t", "h1")).id == "v1"
        await store.add_evidence("t", Evidence("dry_run", "h1", True, {"resource": 2}, {}, clock(), clock() + 600))
        assert [e.kind for e in await store.evidence("t", "h1")] == ["dry_run"]
        assert await store.evidence("t", "h2") == []
        await store.put_verification(Verification(**{**v.__dict__, "status": "confirmed"}))
        assert await store.pending_for("t", "h1") is None
        await store.consume_evidence("t", "h1")
        assert await store.evidence("t", "h1") == []
        await store.add_evidence("t", Evidence("dry_run", "h1", True, {}, {}, clock(), clock() + 600))
        assert [e.kind for e in await store.take_evidence("t", "h1")] == ["dry_run"]
        assert await store.take_evidence("t", "h1") == []
        # expiry
        v2 = Verification("v2", "t", "h3", "user_confirmation", "a", "u1", "s", "pending", clock(), clock() + 600)
        await store.put_verification(v2)
        await store.add_evidence("t", Evidence("dry_run", "h3", True, {}, {}, clock(), clock() + 600))
        clock.t += 601
        assert (await store.get_verification("t", "v2")).status == "expired"
        assert await store.pending_for("t", "h3") is None
        assert await store.evidence("t", "h3") == []

    run(go())


def test_memory_verification_store():
    clock = Clock()
    exercise_verification_store(MemoryVerificationStore(clock=clock), clock)


def test_redis_verification_store():
    clock = Clock()
    exercise_verification_store(RedisVerificationStore(VerifyRedis(clock), clock=clock), clock)


def test_redis_down_means_no_evidence_and_not_found():
    clock = Clock()
    store = RedisVerificationStore(VerifyRedis(clock, fail=True), clock=clock)
    assert run(store.evidence("t", "h")) == []
    assert run(store.get_verification("t", "v")) is None
    assert run(store.pending_for("t", "h")) is None


# ---- user tokens ------------------------------------------------------------------------------


def test_dev_tokens_must_match_the_user_and_be_fresh():
    clock = Clock(time.time())
    v = UserTokenVerifier(UserTokenConfig(dev_secret=DEV), clock=clock)
    tok = mint_dev_token(DEV, "u1", nonce="n1")
    assert run(v.verify(tok, "u1", "n1"))["sub"] == "u1"
    with pytest.raises(TokenRejected, match="different user"):
        run(v.verify(tok, "u2", "n1"))
    with pytest.raises(TokenRejected):
        run(v.verify(mint_dev_token("w" * 40, "u1", nonce="n1"), "u1", "n1"))
    with pytest.raises(TokenRejected):
        run(v.verify("not-a-jwt", "u1"))
    clock.t += 700  # still unexpired with a long ttl, but the sign-in is too old for a confirmation
    with pytest.raises(TokenRejected, match="sign in again"):
        run(v.verify(mint_dev_token(DEV, "u1", nonce="n1", ttl=3600), "u1", "n1"))


def test_disabled_verifier_rejects_everything():
    v = UserTokenVerifier(UserTokenConfig())
    assert not v.enabled
    with pytest.raises(TokenRejected, match="not configured"):
        run(v.verify(mint_dev_token("x" * 40, "u1"), "u1"))


def _rsa_setup():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "k1", "alg": "RS256", "use": "sig"})
    return key, json.dumps({"keys": [jwk]})


def test_oidc_tokens_checked_against_jwks_issuer_audience_and_acr():
    key, jwks = _rsa_setup()
    cfg = UserTokenConfig(issuer="https://idp.example", audience="guardrail", jwks_json=jwks, required_acr=("mfa",))
    v = UserTokenVerifier(cfg)
    now = int(time.time())
    claims = {"sub": "u1", "iss": "https://idp.example", "aud": "guardrail", "iat": now, "exp": now + 300,
              "acr": "mfa", "nonce": "n1"}  # fmt: skip

    def sign(c, k=key, kid="k1"):
        return jwt.encode(c, k, algorithm="RS256", headers={"kid": kid})

    assert run(v.verify(sign(claims), "u1", "n1"))["sub"] == "u1"
    with pytest.raises(TokenRejected):
        run(v.verify(sign({**claims, "aud": "other"}), "u1", "n1"))
    with pytest.raises(TokenRejected):
        run(v.verify(sign({**claims, "iss": "https://evil"}), "u1", "n1"))
    with pytest.raises(TokenRejected, match="stronger sign-in"):
        run(v.verify(sign({**claims, "acr": "pwd"}), "u1", "n1"))
    with pytest.raises(TokenRejected, match="signing key"):
        run(v.verify(sign(claims, kid="other"), "u1", "n1"))
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(TokenRejected):
        run(v.verify(sign(claims, k=other), "u1", "n1"))
    # HS256 is refused without a dev secret (no algorithm confusion with the public key)
    with pytest.raises(TokenRejected, match="not accepted"):
        run(v.verify(jwt.encode(claims, "x" * 32, algorithm="HS256"), "u1", "n1"))


def test_tokens_must_be_issued_for_this_confirmation():
    v = UserTokenVerifier(UserTokenConfig(dev_secret=DEV))
    with pytest.raises(TokenRejected, match="nonce"):
        run(v.verify(mint_dev_token(DEV, "u1"), "u1", "v1"))  # an everyday token: no nonce
    with pytest.raises(TokenRejected, match="nonce"):
        run(v.verify(mint_dev_token(DEV, "u1", nonce="v2"), "u1", "v1"))  # issued for another one
    loose = UserTokenVerifier(UserTokenConfig(dev_secret=DEV, require_nonce=False))
    assert run(loose.verify(mint_dev_token(DEV, "u1"), "u1", "v1"))["sub"] == "u1"


def test_agent_key_cannot_confirm_without_nonce_binding():
    clock = Clock(time.time())
    e = VerificationEngine(
        MemoryVerificationStore(clock=clock),
        user_tokens=UserTokenVerifier(UserTokenConfig(dev_secret=DEV, require_nonce=False), clock=clock),
        clock=clock,
    )
    vid = run(e.resolve(ctx(EXT_SEND, channels=("user_confirmation",)))).verification.id
    tok = mint_dev_token(DEV, "u1")
    with pytest.raises(TokenRejected, match="own key"):
        run(e.confirm("t", vid, user_token=tok, approve=True, caller_agent_id="agent"))
    assert run(e.confirm("t", vid, user_token=tok, approve=True, caller_agent_id="host-app")).status == "confirmed"


def test_jwks_skips_encryption_and_broken_keys_and_limits_refetches():
    key, jwks = _rsa_setup()
    keys = json.loads(jwks)["keys"]
    enc = {**keys[0], "kid": "enc1", "use": "enc", "alg": "RSA-OAEP"}
    broken = {"kty": "RSA", "kid": "bad", "n": "!!", "e": "AQAB"}
    fetches = []

    class Http:
        async def get(self, url, **kw):
            fetches.append(url)

            class R:
                def raise_for_status(self):
                    return None

                def json(self):
                    return {"keys": [enc, broken, *keys]}

            return R()

    clock = Clock(time.time())
    cfg = UserTokenConfig(issuer="https://idp", audience="aud", jwks_url="https://idp/jwks", require_nonce=False)
    v = UserTokenVerifier(cfg, http=Http(), clock=clock)  # type: ignore[arg-type]
    now = int(clock())
    claims = {"sub": "u1", "iss": "https://idp", "aud": "aud", "iat": now, "exp": now + 300}
    assert run(v.verify(jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"}), "u1"))["sub"] == "u1"
    for _ in range(5):  # made-up kids don't trigger a fetch each time
        with pytest.raises(TokenRejected):
            run(v.verify(jwt.encode(claims, key, algorithm="RS256", headers={"kid": "nope"}), "u1"))
    assert len(fetches) == 1
    clock.t += 31
    with pytest.raises(TokenRejected):
        run(v.verify(jwt.encode(claims, key, algorithm="RS256", headers={"kid": "nope"}), "u1"))
    assert len(fetches) == 2


# ---- dry run ----------------------------------------------------------------------------------


class Explainer:
    def __init__(self, rows=10, fail=False):
        self.rows, self.fail, self.calls = rows, fail, []

    async def explain(self, dsn, sql, timeout_seconds):
        self.calls.append((dsn, sql))
        if self.fail:
            raise OSError("replica down")
        return self.rows


def test_dry_run_only_for_clean_single_reads_with_a_target():
    dr = SqlDryRun({"db.query": "postgresql://replica/db"}, Explainer())
    assert dr.applicable(SQL_READ, "db.query", None)
    assert not dr.applicable(SQL_READ, "other.tool", None)
    assert not dr.applicable(ActionDescriptor("sql", "write", target="t"), "db.query", None)
    assert not dr.applicable(ActionDescriptor("sql", "read", target="t", statements=2), "db.query", None)
    assert not dr.applicable(ActionDescriptor("sql", "read", target="t", notes=("x",)), "db.query", None)
    assert run(dr.run("SELECT 1", "db.query", None)) == DryRunResult(True, estimated_rows=10)
    assert run(SqlDryRun({"db.query": "x"}, Explainer(fail=True)).run("SELECT 1", "db.query", None)).ok is False


# ---- engine -----------------------------------------------------------------------------------


def ctx(
    d=SQL_READ, *, channels=(), user_id="u1", codes=(), env="dev", h="h1", sql="SELECT email FROM public.customers"
):
    return VerifyContext("t", "agent", user_id, h, d, tuple(codes), env, "A1", tuple(channels), "db.query", None, sql)


def engine(rows=10, fail=False, secret=DEV, clock=None):
    clock = clock or Clock(time.time())
    return VerificationEngine(
        MemoryVerificationStore(clock=clock),
        dry_run=SqlDryRun({"db.query": "postgresql://replica/db"}, Explainer(rows, fail)),
        user_tokens=UserTokenVerifier(UserTokenConfig(dev_secret=secret), clock=clock) if secret else None,
        max_dry_run_rows=1000,
        clock=clock,
    )


def test_engine_dry_run_allows_small_reads_and_holds_big_or_failed_ones():
    r = run(engine().resolve(ctx()))
    assert r.outcome == "allow" and "VERIFIED" in r.codes and "EVIDENCE_DRY_RUN" in r.codes
    assert run(engine(rows=50_000).resolve(ctx())).codes == ("DRY_RUN_TOO_MANY_ROWS",)
    assert run(engine(fail=True).resolve(ctx())).codes == ("DRY_RUN_FAILED",)


def test_engine_user_confirmation_round_trip():
    e = engine()
    c = ctx(EXT_SEND, channels=("user_confirmation",))
    r = run(e.resolve(c))
    assert r.outcome == "verify" and r.verification is not None and r.verification.status == "pending"
    vid = r.verification.id
    assert run(e.resolve(c)).verification.id == vid  # a retry before the answer reuses it
    with pytest.raises(TokenRejected):
        run(e.confirm("t", vid, user_token=mint_dev_token(DEV, "someone-else", nonce=vid), approve=True))
    with pytest.raises(VerificationNotFound):
        run(e.confirm("other-tenant", vid, user_token=mint_dev_token(DEV, "u1", nonce=vid), approve=True))
    assert run(e.confirm("t", vid, user_token=mint_dev_token(DEV, "u1", nonce=vid), approve=True)).status == "confirmed"
    with pytest.raises(VerificationClosed):
        run(e.confirm("t", vid, user_token=mint_dev_token(DEV, "u1", nonce=vid), approve=True))
    r = run(e.resolve(c))
    assert r.outcome == "allow" and "EVIDENCE_USER_CONFIRMATION" in r.codes
    r = run(e.resolve(c))  # evidence is used once: the next identical request asks again
    assert r.outcome == "verify" and r.verification.id != vid
    # a different request (other payload hash) never benefits from the confirmation
    run(e.confirm("t", r.verification.id, user_token=mint_dev_token(DEV, "u1", nonce=r.verification.id), approve=True))
    assert run(e.resolve(ctx(EXT_SEND, channels=("user_confirmation",), h="h2"))).outcome == "verify"


def test_concurrent_retries_use_a_confirmation_once():
    e = engine()
    c = ctx(EXT_SEND, channels=("user_confirmation",))
    vid = run(e.resolve(c)).verification.id
    run(e.confirm("t", vid, user_token=mint_dev_token(DEV, "u1", nonce=vid), approve=True))

    async def both():
        return await asyncio.gather(e.resolve(c), e.resolve(c))

    outcomes = sorted(r.outcome for r in run(both()))
    assert outcomes == ["allow", "verify"]


def test_engine_user_rejection_denies():
    e = engine()
    c = ctx(EXT_SEND, channels=("user_confirmation",))
    vid = run(e.resolve(c)).verification.id
    run(e.confirm("t", vid, user_token=mint_dev_token(DEV, "u1", nonce=vid), approve=False))
    assert run(e.resolve(c)).outcome == "deny"


def test_engine_falls_back_to_a_human():
    # no channel declared, no user, or no token verifier: the review queue
    for e, c in (
        (engine(), ctx(EXT_SEND)),
        (engine(), ctx(EXT_SEND, channels=("user_confirmation",), user_id=None)),
        (engine(secret=None), ctx(EXT_SEND, channels=("user_confirmation",))),
        (engine(), ctx(SQL_READ, env="dev", codes=(), sql=None)),  # no SQL text: no dry run
    ):
        assert run(e.resolve(c)).codes == ("VERIFY_NEEDS_HUMAN",)


def test_engine_errors_fail_closed():
    class Broken(MemoryVerificationStore):
        async def evidence(self, tenant, request_hash):
            raise RuntimeError("boom")

    e = VerificationEngine(Broken())
    assert run(e.resolve(ctx())).outcome == "hold"


def test_shadow_describe_runs_and_stores_nothing():
    e = engine()
    r = e.describe(ctx(EXT_SEND, channels=("user_confirmation",)))
    assert r.outcome == "verify" and r.verification is None and r.codes == ("VERIFY_PLAN_USER_CONFIRMATION",)
    assert e.dry_run._explainer.calls == []  # type: ignore[union-attr]
    assert e.describe(ctx()).codes == ("VERIFY_PLAN_DRY_RUN",)
    assert e.dry_run._explainer.calls == []  # type: ignore[union-attr]
