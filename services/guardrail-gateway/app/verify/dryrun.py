"""SQL dry run: ask the database's planner what a read would touch, without running it.

`EXPLAIN (FORMAT JSON)` (no ANALYZE) plans the statement and returns the estimated row count; the
query itself never executes. On top of that the connection is read-only with a short statement
timeout, and only single-statement reads that the descriptor parser fully understood are sent.
Point it at a read replica (VERIFY_SQL_DRY_RUN maps a tool name or resource to a DSN), never at
the primary.

The estimate is the planner's guess, not a count: it is good at "about 10 vs about a million",
which is what the verification needs, and it can be off by a lot for skewed data.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from app.context.descriptors import ActionDescriptor


@dataclass(frozen=True)
class DryRunResult:
    ok: bool
    estimated_rows: int | None = None
    error: str | None = None


class SqlExplainer(Protocol):
    async def explain(self, dsn: str, sql: str, timeout_seconds: float) -> int: ...


class AsyncpgExplainer:
    """One small pool per DSN; read-only transaction; statement timeout."""

    def __init__(self) -> None:
        self._pools: dict[str, Any] = {}
        self._lock = asyncio.Lock()

    async def _pool(self, dsn: str) -> Any:
        import asyncpg  # the gateway already depends on it (audit database)

        async with self._lock:
            if dsn not in self._pools:
                self._pools[dsn] = await asyncpg.create_pool(dsn, min_size=0, max_size=2, command_timeout=5)
            return self._pools[dsn]

    async def explain(self, dsn: str, sql: str, timeout_seconds: float) -> int:
        pool = await self._pool(dsn)
        async with pool.acquire() as conn, conn.transaction(readonly=True):
            await conn.execute(f"SET LOCAL statement_timeout = {int(timeout_seconds * 1000)}")
            raw = await conn.fetchval("EXPLAIN (FORMAT JSON) " + sql)
        plan = json.loads(raw) if isinstance(raw, str) else raw
        return int(plan[0]["Plan"]["Plan Rows"])

    async def close(self) -> None:
        for pool in self._pools.values():
            await pool.close()


class SqlDryRun:
    def __init__(self, targets: Mapping[str, str], explainer: SqlExplainer | None = None, timeout_seconds: float = 2.0):
        self.targets = dict(targets)
        self._explainer = explainer or AsyncpgExplainer()
        self._timeout = timeout_seconds

    async def close(self) -> None:
        close = getattr(self._explainer, "close", None)
        if close is not None:
            await close()

    def dsn_for(self, tool_name: str | None, resource: str | None) -> str | None:
        for key in (tool_name, resource):
            if key and key in self.targets:
                return self.targets[key]
        return None

    def applicable(self, d: ActionDescriptor, tool_name: str | None, resource: str | None) -> bool:
        return (
            d.kind == "sql" and d.verb == "read" and d.statements == 1 and d.parsed and not d.notes
            and self.dsn_for(tool_name, resource) is not None
        )  # fmt: skip

    async def run(self, sql: str, tool_name: str | None, resource: str | None) -> DryRunResult:
        dsn = self.dsn_for(tool_name, resource)
        if dsn is None:
            return DryRunResult(False, error="no dry-run target configured")
        try:
            rows = await asyncio.wait_for(self._explainer.explain(dsn, sql, self._timeout), self._timeout + 1)
        except Exception as exc:  # noqa: BLE001 - a failed dry run is "no evidence", never an allow
            return DryRunResult(False, error=exc.__class__.__name__)
        return DryRunResult(True, estimated_rows=rows)
