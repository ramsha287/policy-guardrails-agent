import json
from pathlib import Path

import httpx
import pytest

from app.config import APP_DIR
from app.engine.registry import PluginRegistry, SnapshotHolder
from app.engine.snapshot import Assignment, SnapshotDoc, expand_env, load_snapshot
from guardrail_sdk import EnvSecretReader, PluginContext, Stage

SNAP_DIR = Path(__file__).resolve().parents[1] / "config" / "snapshots"
PROJECT = "3fa85f64-5717-4562-b3fc-2c963f66afa6"


def test_env_expansion(monkeypatch):
    monkeypatch.setenv("X_ID", "42")
    assert expand_env({"a": "${X_ID}", "b": ["${MISSING_VAR:-dflt}"]}) == {"a": "42", "b": ["dflt"]}
    with pytest.raises(KeyError):
        expand_env("${DEFINITELY_NOT_SET_VAR}")


def test_assignment_scope_rules():
    with pytest.raises(ValueError):
        Assignment(
            id="a",
            guardrail_id="g",
            guardrail_version="1.0.0",
            scope_type="agent",
            scope_id="no-slash",
            stages=["input"],
        )
    with pytest.raises(ValueError):
        Assignment(
            id="a", guardrail_id="g", guardrail_version="1.0.0", scope_type="global", scope_id="x", stages=["input"]
        )


@pytest.mark.parametrize("env", ["dev", "staging", "production"])
def test_shipped_snapshots_parse(env, monkeypatch):
    monkeypatch.setenv("AI_GATEWAY_PROJECT_ID", PROJECT)
    doc = load_snapshot(SNAP_DIR / f"{env}.json")
    assert doc.environment == env


@pytest.fixture
def registry():
    r = PluginRegistry([APP_DIR / "plugins"], PluginContext(http=httpx.AsyncClient(), secrets=EnvSecretReader()))
    r.discover()
    return r


async def test_discovers_builtin_plugins(registry):
    assert {"ai-gateway-pii@1.0.0", "noop@1.0.0"} <= set(registry.manifests)


async def test_compile_dev_snapshot(registry, monkeypatch):
    monkeypatch.setenv("AI_GATEWAY_PROJECT_ID", PROJECT)
    compiled = await registry.compile_file(SNAP_DIR / "dev.json", "dev")
    ids = [b.manifest.id for b in compiled.resolve("demo", "research-agent", Stage.INPUT)]
    assert ids == ["ai-gateway-pii", "noop"]
    assert [b.manifest.id for b in compiled.resolve("demo", "a", Stage.RETRIEVAL)] == ["noop"]


async def test_compile_rejects_bad_snapshots(registry):
    base = {"version": "v", "environment": "dev"}
    bad_version = SnapshotDoc.model_validate(
        {
            **base,
            "assignments": [{"id": "a", "guardrail_id": "noop", "guardrail_version": "9.9.9", "stages": ["input"]}],
        }
    )
    with pytest.raises(LookupError):
        await registry.compile(bad_version, "dev")
    bad_stage = SnapshotDoc.model_validate(
        {
            **base,
            "assignments": [
                {
                    "id": "a",
                    "guardrail_id": "ai-gateway-pii",
                    "guardrail_version": "1.0.0",
                    "stages": ["retrieval"],
                    "config": {"project_id": PROJECT},
                }
            ],
        }
    )
    with pytest.raises(ValueError, match="does not support"):
        await registry.compile(bad_stage, "dev")
    bad_config = SnapshotDoc.model_validate(
        {
            **base,
            "assignments": [
                {
                    "id": "a",
                    "guardrail_id": "ai-gateway-pii",
                    "guardrail_version": "1.0.0",
                    "stages": ["input"],
                    "config": {"project_id": "nope"},
                }
            ],
        }
    )
    with pytest.raises(ValueError):
        await registry.compile(bad_config, "dev")
    with pytest.raises(ValueError, match="gateway runs in"):
        await registry.compile(SnapshotDoc.model_validate({**base, "assignments": []}), "production")


async def test_holder_keeps_last_good_snapshot(registry, tmp_path):
    path = tmp_path / "dev.json"
    good = {
        "version": "v1",
        "environment": "dev",
        "assignments": [
            {"id": "n", "guardrail_id": "noop", "guardrail_version": "1.0.0", "stages": ["input"], "mode": "enforce"}
        ],
    }
    path.write_text(json.dumps(good))
    holder = SnapshotHolder(registry, path, "dev")
    assert await holder.load() and holder.version == "v1"
    path.write_text(json.dumps({**good, "version": "v2", "assignments": [{"id": "broken"}]}))
    assert not await holder.load()
    assert holder.version == "v1" and holder.last_error
