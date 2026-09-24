"""AuditWriter never silently loses events: outage, overflow and shutdown mid-batch all end on disk."""

import asyncio

from app.audit.spool import AuditSpool
from app.audit.writer import AuditWriter


class DownSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, *a, **k):
        raise ConnectionRefusedError("postgres is down")

    async def commit(self):
        pass


class SlowSession(DownSession):
    started = None

    async def execute(self, *a, **k):
        SlowSession.started.set()
        await asyncio.sleep(3600)  # stuck until cancelled


def ev(n):
    return {"tenant_id": "t", "request_id": f"r{n}"}


def spooled(spool):
    return sorted(e["request_id"] for f in spool.files() for e in AuditSpool.read(f))


async def test_outage_goes_to_the_spool_instead_of_being_dropped(tmp_path):
    spool = AuditSpool(tmp_path)
    w = AuditWriter(lambda: DownSession(), flush_seconds=0.01, maintenance=False, spool=spool, replay_seconds=3600)
    await w.start()
    for n in range(3):
        w.submit(ev(n))
    await asyncio.sleep(3.2)  # three attempts with backoff, then spilled
    await w.stop()
    assert spooled(spool) == ["r0", "r1", "r2"]


async def test_overflow_is_spooled_off_the_request_path(tmp_path):
    spool = AuditSpool(tmp_path)
    w = AuditWriter(lambda: DownSession(), queue_size=1, maintenance=False, spool=spool, replay_seconds=3600)
    # not started: the queue holds 1, the rest overflows into memory; nothing touches the disk yet
    for n in range(4):
        w.submit(ev(n))
    assert spool.files() == [] and len(w._overflow) == 3
    await w.stop()  # drain: in-flight + queue + overflow -> write fails -> spool
    assert spooled(spool) == ["r0", "r1", "r2", "r3"]


async def test_shutdown_in_the_middle_of_a_batch_keeps_it(tmp_path):
    spool = AuditSpool(tmp_path)
    SlowSession.started = asyncio.Event()
    w = AuditWriter(
        lambda: SlowSession(),
        flush_seconds=0.01,
        maintenance=False,
        spool=spool,
        replay_seconds=3600,
        drain_timeout_seconds=0.2,
    )
    await w.start()
    w.submit(ev(1))
    w.submit(ev(2))
    await asyncio.wait_for(SlowSession.started.wait(), 5)
    await w.stop()  # cancels the stuck write; the in-flight batch must not vanish
    assert spooled(spool) == ["r1", "r2"]
