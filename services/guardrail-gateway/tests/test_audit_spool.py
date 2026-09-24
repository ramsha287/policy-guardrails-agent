"""Audit events survive a Postgres outage on disk and are replayed in order."""

import uuid
from datetime import UTC, datetime

from app.audit.spool import AuditSpool


def event(n):
    return {
        "id": uuid.uuid4(),
        "created_at": datetime(2026, 9, 24, 12, 0, n, tzinfo=UTC),
        "tenant_id": "demo",
        "request_id": f"r{n}",
        "guardrail_results": [{"guardrail_id": "g", "latency_ms": 1.5, "error": None}],
    }


def test_round_trip_keeps_types_and_order(tmp_path):
    spool = AuditSpool(tmp_path)
    first, second = [event(1), event(2)], [event(3)]
    assert spool.append(first) and spool.append(second)
    files = spool.files()
    assert len(files) == 2
    back = spool.read(files[0]) + spool.read(files[1])
    assert [e["request_id"] for e in back] == ["r1", "r2", "r3"]
    assert back[0]["id"] == first[0]["id"] and back[0]["created_at"] == first[0]["created_at"]
    assert back[0]["guardrail_results"][0]["latency_ms"] == 1.5
    spool.remove(files[0])
    assert spool.files() == [files[1]]
    assert not list(tmp_path.glob(".audit-*"))  # no temp files left behind


def test_bounded_size(tmp_path):
    spool = AuditSpool(tmp_path, max_bytes=600)
    assert spool.append([event(1)])
    assert not spool.append([event(n) for n in range(10)])  # would pass the limit: refused, caller counts a drop
    assert len(spool.files()) == 1 and spool.append([]) is True


def test_unwritable_directory_refuses(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    spool = AuditSpool(blocker / "sub")  # parent is a file: mkdir fails
    assert spool.append([event(1)]) is False


def test_size_is_tracked_and_bad_files_are_quarantined(tmp_path):
    spool = AuditSpool(tmp_path)
    assert spool.append([event(1)]) and spool.append([event(2)])
    first, second = spool.files()
    assert spool.size_bytes() == first.stat().st_size + second.stat().st_size
    second.write_text("not json\n")
    spool._size = spool._scan_size()
    spool.quarantine(second)
    assert spool.files() == [first] and (tmp_path / (second.stem + ".bad")).exists()
    spool.remove(first)
    assert spool.size_bytes() == 0
    assert AuditSpool(tmp_path).size_bytes() == 0  # a restart rescans (the .bad file is not counted)


def test_failed_write_leaves_no_temp_file(tmp_path, monkeypatch):
    import os

    spool = AuditSpool(tmp_path)

    def broken_fsync(fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", broken_fsync)
    assert spool.append([event(1)]) is False
    assert list(tmp_path.iterdir()) == [] and spool.size_bytes() == 0
