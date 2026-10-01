"""Catalog documents stay readable by gateways that predate a field."""

from guardrail_sdk import GuardRequest
from guardrail_sdk.documents import CatalogApiKey, CatalogDoc, CatalogTenant, content_hash

HASH = "a" * 64


def test_unbound_key_serializes_without_agent_id():
    k = CatalogApiKey(id="k1", name="n", key_hash=HASH)
    assert "agent_id" not in k.model_dump(mode="json")
    bound = CatalogApiKey(id="k1", name="n", key_hash=HASH, agent_id="research-agent")
    assert bound.model_dump(mode="json")["agent_id"] == "research-agent"


def test_unbound_catalog_hash_is_unchanged_by_the_new_field():
    doc = CatalogDoc(
        version="v1",
        tenants=[CatalogTenant(id="t", name="T", api_keys=[CatalogApiKey(id="k", name="n", key_hash=HASH)])],
    )
    dumped = doc.model_dump(mode="json")
    assert "agent_id" not in dumped["tenants"][0]["api_keys"][0]
    assert CatalogDoc.model_validate(dumped) == doc
    assert content_hash(doc) == content_hash(CatalogDoc.model_validate(dumped))


def test_accepts_obligations_is_left_out_of_the_request_unless_set():
    body = GuardRequest(agent_id="a", action="llm.chat", payload={"text": "hi"})
    assert "accepts_obligations" not in body.model_dump(mode="json", exclude_none=True)
    body = GuardRequest(agent_id="a", action="llm.chat", payload={"text": "hi"}, accepts_obligations=True)
    assert body.model_dump(mode="json", exclude_none=True)["accepts_obligations"] is True
