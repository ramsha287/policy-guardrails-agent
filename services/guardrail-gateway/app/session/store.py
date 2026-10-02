"""Session and behaviour state for contextual decisions.

What the gateway remembers between requests, per tenant and agent:

- per session (keyed by tenant, agent and session_id, so one agent can't taint or quarantine
  another agent's session by reusing its id): when it started, steps, denials, taint labels
  (`untrusted_input`, `holds:PII`...) and whether it is quarantined;
- per agent: which targets (tables, hosts, paths) it touched in the last 90 days, recent request
  volumes per target (for "40x its usual volume"), trust penalties, denials in the last
  15 minutes and an agent-wide quarantine. The agent-level part means starting a new session (or
  sending none) doesn't wipe the slate.

Everything here is a cache that can be lost: an empty or unreachable store makes the gateway
*stricter* (no baseline, new session, lower confidence), never looser. Redis is used when
REDIS_URL is set, so all replicas share it; otherwise each replica keeps its own bounded copy.
Redis calls have a short deadline: a slow Redis costs confidence, not latency.

Baselines learn slowly on purpose: a volume is recorded only after a request was allowed, and the
p95 is taken over the last `VOLUME_WINDOW` requests, so one burst can't make itself look normal.
"""

from __future__ import annotations

import asyncio
import json
import math
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Protocol

SESSION_TTL_SECONDS = 8 * 3600
SEEN_TTL_SECONDS = 90 * 86400
VOLUME_TTL_SECONDS = 30 * 86400
PENALTY_TTL_SECONDS = 90 * 86400
DENIAL_WINDOW_SECONDS = 15 * 60
VOLUME_WINDOW = 200
MAX_PENALTIES = 50
MAX_RECENT_DENIALS = 100


@dataclass(frozen=True)
class Penalty:
    code: str
    points: int
    half_life_days: float
    at: float  # unix time

    def remaining(self, now: float) -> float:
        age_days = max(0.0, now - self.at) / 86400
        return self.points * math.pow(2, -age_days / self.half_life_days)


@dataclass(frozen=True)
class SessionView:
    """Read-only view used by the risk engine. `available` is False when no state could be read."""

    available: bool = True
    has_session: bool = False
    age_seconds: float = 0.0
    steps: int = 0
    denials: int = 0
    labels: frozenset[str] = frozenset()
    quarantined_until: float = 0.0
    first_seen_target: bool | None = None  # None = no target to check
    volume_p95: float | None = None
    volume_samples: int = 0
    penalties: tuple[Penalty, ...] = ()
    penalised: bool = False  # this session already caused a trust penalty
    agent_recent_denials: int = 0  # across all of the agent's sessions, last 15 minutes
    agent_quarantined_until: float = 0.0

    def quarantined(self, now: float) -> bool:
        return self.quarantined_until > now or self.agent_quarantined_until > now


@dataclass
class SessionUpdate:
    denied: bool = False
    allowed: bool = False
    labels: set[str] = field(default_factory=set)
    target: str | None = None
    volume_key: str | None = None
    rows: int | None = None
    quarantine_seconds: int = 0  # this session
    agent_quarantine_seconds: int = 0  # every session of this agent
    penalty: Penalty | None = None


class SessionStore(Protocol):
    async def view(
        self, tenant: str, agent: str, session_id: str | None, *, target: str | None, volume_key: str | None
    ) -> SessionView: ...

    async def record(self, tenant: str, agent: str, session_id: str | None, update: SessionUpdate) -> None: ...


def p95(values: list[float]) -> float | None:
    if not values:
        return None
    s = sorted(values)
    return s[min(len(s) - 1, math.ceil(0.95 * len(s)) - 1)]


# ---- in-memory ----------------------------------------------------------------------------------


class MemorySessionStore:
    """Per-replica store, bounded (LRU) so a flood of session ids can't exhaust memory."""

    def __init__(self, max_entries: int = 50_000, clock: Any = time.time) -> None:
        self._max = max_entries
        self._now = clock
        self._sessions: OrderedDict[tuple[str, str, str], dict[str, Any]] = OrderedDict()
        self._agents: OrderedDict[tuple[str, str], dict[str, Any]] = OrderedDict()

    def _touch(self, d: OrderedDict[Any, dict[str, Any]], key: Any, ttl: float) -> dict[str, Any]:
        now = self._now()
        entry = d.get(key)
        if entry is None or entry["_exp"] <= now:
            entry = {"_exp": now + ttl}
            d[key] = entry
        d.move_to_end(key)
        while len(d) > self._max:
            d.popitem(last=False)
        return entry

    async def view(
        self, tenant: str, agent: str, session_id: str | None, *, target: str | None, volume_key: str | None
    ) -> SessionView:
        now = self._now()
        a = self._agents.get((tenant, agent))
        if a is not None and a["_exp"] <= now:
            a = None
        a = a or {}
        seen: dict[str, float] = a.get("seen", {})
        vols: list[float] = a.get("vol", {}).get(volume_key, []) if volume_key else []
        agent_part: dict[str, Any] = dict(
            first_seen_target=None if not target else (seen.get(target, 0) <= now - SEEN_TTL_SECONDS),
            volume_p95=p95(vols),
            volume_samples=len(vols),
            penalties=tuple(a.get("pen", [])),
            agent_recent_denials=sum(1 for t in a.get("den", []) if t > now - DENIAL_WINDOW_SECONDS),
            agent_quarantined_until=a.get("aq", 0.0),
        )
        s = self._sessions.get((tenant, agent, session_id)) if session_id else None
        if s is not None and s["_exp"] <= now:
            s = None
        if s is None:
            return SessionView(has_session=False, **agent_part)
        return SessionView(
            has_session=True,
            age_seconds=now - s["started"],
            steps=s["steps"],
            denials=s["denials"],
            labels=frozenset(s["labels"]),
            quarantined_until=s["quarantined_until"],
            penalised=s["penalised"],
            **agent_part,
        )

    async def record(self, tenant: str, agent: str, session_id: str | None, update: SessionUpdate) -> None:
        now = self._now()
        a = self._touch(self._agents, (tenant, agent), SEEN_TTL_SECONDS)
        a["_exp"] = now + SEEN_TTL_SECONDS
        if update.allowed and update.target:
            a.setdefault("seen", {})[update.target] = now
        if update.allowed and update.volume_key and update.rows is not None:
            window = a.setdefault("vol", {}).setdefault(update.volume_key, [])
            window.append(float(update.rows))
            del window[:-VOLUME_WINDOW]
        if update.penalty is not None:
            pens = a.setdefault("pen", [])
            pens.insert(0, update.penalty)
            del pens[MAX_PENALTIES:]
        if update.denied:
            den = a.setdefault("den", [])
            den.append(now)
            del den[:-MAX_RECENT_DENIALS]
        if update.agent_quarantine_seconds:
            a["aq"] = max(a.get("aq", 0.0), now + update.agent_quarantine_seconds)
        if not session_id:
            return
        s = self._touch(self._sessions, (tenant, agent, session_id), SESSION_TTL_SECONDS)
        if "started" not in s:
            s.update(started=now, steps=0, denials=0, labels=set(), quarantined_until=0.0, penalised=False)
        s["_exp"] = now + SESSION_TTL_SECONDS
        s["steps"] += 1
        s["denials"] += 1 if update.denied else 0
        s["labels"] |= update.labels
        if update.quarantine_seconds:
            s["quarantined_until"] = max(s["quarantined_until"], now + update.quarantine_seconds)
        if update.penalty is not None:
            s["penalised"] = True


# ---- Redis --------------------------------------------------------------------------------------


class RedisSessionStore:
    """Shared across replicas. Keys (prefix "grg"):

      sess:{t}:{agent}:{sid}          hash: started, steps, denials, quarantined_until, penalised
      sess:{t}:{agent}:{sid}:labels   set
      seen:{t}:{agent}                hash target -> last seen (unix time)
      vol:{t}:{agent}:{key}           list of recent row counts
      pen:{t}:{agent}                 list of penalties (JSON)
      den:{t}:{agent}                 list of recent denial times
      aq:{t}:{agent}                  agent quarantine end time (expires by itself)

    Any Redis error or a call slower than `timeout_seconds` makes `view` return an "unavailable"
    view (stricter decisions) and `record` a no-op; the request path never fails because of it.
    """

    def __init__(self, redis: Any, prefix: str = "grg", clock: Any = time.time, timeout_seconds: float = 0.15) -> None:
        self._r = redis
        self._p = prefix
        self._now = clock
        self._timeout = timeout_seconds

    def _k(self, *parts: str) -> str:
        return ":".join((self._p, *parts))

    async def view(
        self, tenant: str, agent: str, session_id: str | None, *, target: str | None, volume_key: str | None
    ) -> SessionView:
        now = self._now()
        try:
            pipe = self._r.pipeline(transaction=False)
            pipe.hget(self._k("seen", tenant, agent), target or "")
            pipe.lrange(self._k("vol", tenant, agent, volume_key or "-"), 0, VOLUME_WINDOW - 1)
            pipe.lrange(self._k("pen", tenant, agent), 0, MAX_PENALTIES - 1)
            pipe.lrange(self._k("den", tenant, agent), 0, MAX_RECENT_DENIALS - 1)
            pipe.get(self._k("aq", tenant, agent))
            if session_id:
                pipe.hgetall(self._k("sess", tenant, agent, session_id))
                pipe.smembers(self._k("sess", tenant, agent, session_id, "labels"))
            res = await asyncio.wait_for(pipe.execute(), self._timeout)

            seen_at, vols_raw, pens_raw, den_raw, aq = res[0], res[1], res[2], res[3], res[4]
            vols = [float(v) for v in vols_raw] if volume_key else []
            agent_part: dict[str, Any] = dict(
                first_seen_target=None if not target else (seen_at is None or float(seen_at) <= now - SEEN_TTL_SECONDS),
                volume_p95=p95(vols),
                volume_samples=len(vols),
                penalties=tuple(p for p in (_penalty(raw) for raw in pens_raw) if p is not None),
                agent_recent_denials=sum(1 for t in den_raw if float(t) > now - DENIAL_WINDOW_SECONDS),
                agent_quarantined_until=float(aq) if aq else 0.0,
            )
            if not session_id or not res[5]:
                return SessionView(has_session=False, **agent_part)
            h = {_s(k): _s(v) for k, v in res[5].items()}
            return SessionView(
                has_session=True,
                age_seconds=now - float(h.get("started") or now),
                steps=int(h.get("steps") or 0),
                denials=int(h.get("denials") or 0),
                labels=frozenset(_s(x) for x in res[6]),
                quarantined_until=float(h.get("quarantined_until") or 0),
                penalised=h.get("penalised") == "1",
                **agent_part,
            )
        except Exception:  # noqa: BLE001 - see class docstring (includes TimeoutError and bad values)
            return SessionView(available=False)

    async def record(self, tenant: str, agent: str, session_id: str | None, update: SessionUpdate) -> None:
        now = self._now()
        try:
            pipe = self._r.pipeline(transaction=False)
            if update.allowed and update.target:
                k = self._k("seen", tenant, agent)
                pipe.hset(k, update.target, str(now))
                pipe.expire(k, SEEN_TTL_SECONDS)
            if update.allowed and update.volume_key and update.rows is not None:
                k = self._k("vol", tenant, agent, update.volume_key)
                pipe.lpush(k, str(update.rows))
                pipe.ltrim(k, 0, VOLUME_WINDOW - 1)
                pipe.expire(k, VOLUME_TTL_SECONDS)
            if update.penalty is not None:
                k = self._k("pen", tenant, agent)
                p = update.penalty
                pipe.lpush(k, json.dumps({"code": p.code, "points": p.points, "h": p.half_life_days, "at": p.at}))
                pipe.ltrim(k, 0, MAX_PENALTIES - 1)
                pipe.expire(k, PENALTY_TTL_SECONDS)
            if update.denied:
                k = self._k("den", tenant, agent)
                pipe.lpush(k, str(now))
                pipe.ltrim(k, 0, MAX_RECENT_DENIALS - 1)
                pipe.expire(k, DENIAL_WINDOW_SECONDS)
            if update.agent_quarantine_seconds:
                pipe.set(self._k("aq", tenant, agent), str(now + update.agent_quarantine_seconds),
                         ex=update.agent_quarantine_seconds)  # fmt: skip
            if session_id:
                k = self._k("sess", tenant, agent, session_id)
                pipe.hsetnx(k, "started", str(now))
                pipe.hincrby(k, "steps", 1)
                if update.denied:
                    pipe.hincrby(k, "denials", 1)
                if update.quarantine_seconds:
                    pipe.hset(k, "quarantined_until", str(now + update.quarantine_seconds))
                if update.penalty is not None:
                    pipe.hset(k, "penalised", "1")
                pipe.expire(k, SESSION_TTL_SECONDS)
                if update.labels:
                    lk = self._k("sess", tenant, agent, session_id, "labels")
                    pipe.sadd(lk, *sorted(update.labels))
                    pipe.expire(lk, SESSION_TTL_SECONDS)
            await asyncio.wait_for(pipe.execute(), self._timeout)
        except Exception:  # noqa: BLE001 - see class docstring
            return


def _s(v: Any) -> str:
    return v.decode() if isinstance(v, bytes) else str(v)


def _penalty(raw: Any) -> Penalty | None:
    try:
        d = json.loads(_s(raw))
        return Penalty(str(d["code"]), int(d["points"]), float(d["h"]), float(d["at"]))
    except (ValueError, KeyError, TypeError):
        return None
