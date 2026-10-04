"""Amazon Bedrock Agents and Bedrock AgentCore: managed agents, runtimes and gateways.

Bedrock Agents (bedrock-agent): ListAgents, GetAgent, ListAgentActionGroups,
ListAgentKnowledgeBases, ListAgentCollaborators, ListTagsForResource. Each agent becomes an agent
entity (keyed by its ARN) with its foundation model, service role, guardrail, action groups
(tools), knowledge bases (data stores) and collaborator agents (agent-to-agent edges).

AgentCore (bedrock-agentcore-control): ListAgentRuntimes, ListGateways, ListGatewayTargets.
Runtimes are agents; gateway targets are tools.

Credentials come from the standard AWS chain of the control plane (IRSA, instance profile, env),
optionally assuming `assume_role_arn` (with `external_id`). Use a role with only the read actions
above; docs/discovery.md has the policy. boto3 is imported only when this connector runs.

Tag `guardrails.io/agent-id` (or `guardrail:agent-id`) on a Bedrock agent links it to a registered
agent; `Owner`/`owner`/`team` tags give the owner guess.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from typing import Any, ClassVar

from pydantic import Field

from .. import signatures as sig
from ..model import CollectContext, ConnectorConfig, ConnectorError, EdgeFact, EntityFact, Observation


class AwsBedrockConfig(ConnectorConfig):
    regions: list[str] = Field(min_length=1, max_length=20)
    assume_role_arn: str | None = Field(default=None, pattern=r"^arn:aws[a-z-]*:iam::\d{12}:role/.+$")
    external_id: str | None = None
    bedrock_agents: bool = True
    agentcore: bool = True
    agent_version: str = "DRAFT"


ClientFactory = Callable[[str, str], Any]  # (service, region) -> boto3 client


class AwsBedrockConnector:
    kind: ClassVar[str] = "aws_bedrock"
    title: ClassVar[str] = "Amazon Bedrock and AgentCore"
    description: ClassVar[str] = (
        "Bedrock Agents (model, role, guardrail, action groups, knowledge bases, collaborators) and AgentCore "
        "runtimes and gateways, read with a read-only role."
    )
    full_snapshot: ClassVar[bool] = True
    Config: ClassVar[type[ConnectorConfig]] = AwsBedrockConfig

    async def collect(self, config: AwsBedrockConfig, ctx: CollectContext) -> AsyncIterator[Observation]:
        injected: ClientFactory | None = ctx.clients.get("aws")
        factory = injected if injected is not None else await asyncio.to_thread(_boto3_factory, config)
        for region in config.regions:
            if config.bedrock_agents:
                try:
                    client = factory("bedrock-agent", region)
                    for obs in await asyncio.to_thread(_bedrock_agents, client, region, config):
                        yield obs
                except ConnectorError:
                    raise
                except Exception as exc:  # noqa: BLE001 - one service failing leaves the rest of the run
                    ctx.warn(f"bedrock-agent {region}: {_aws_error(exc)}")
            if config.agentcore:
                try:
                    client = factory("bedrock-agentcore-control", region)
                    for obs in await asyncio.to_thread(_agentcore, client, region):
                        yield obs
                except ConnectorError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    ctx.warn(f"bedrock-agentcore-control {region}: {_aws_error(exc)}")


def _aws_error(exc: Exception) -> str:
    code = getattr(exc, "response", {}).get("Error", {}).get("Code") if hasattr(exc, "response") else None
    return f"{code or exc.__class__.__name__}"


def _boto3_factory(config: AwsBedrockConfig) -> ClientFactory:
    try:
        import boto3  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - installed in the image
        raise ConnectorError("boto3 is not installed on the control plane") from exc
    session = boto3.Session()
    if config.assume_role_arn:
        params: dict[str, Any] = {"RoleArn": config.assume_role_arn, "RoleSessionName": "guardrail-discovery"}
        if config.external_id:
            params["ExternalId"] = config.external_id
        creds = session.client("sts").assume_role(**params)["Credentials"]
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    return lambda service, region: session.client(service, region_name=region)


def _pages(call: Callable[..., dict[str, Any]], key: str, **kwargs: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    token: str | None = None
    for _ in range(200):
        resp = call(**kwargs, **({"nextToken": token} if token else {}))
        out.extend(resp.get(key) or [])
        token = resp.get("nextToken")
        if not token:
            break
    return out


def _agent_arn_from_alias(alias_arn: str) -> str | None:
    # arn:aws:bedrock:<region>:<account>:agent-alias/<agentId>/<aliasId> -> ...:agent/<agentId>
    head, _, rest = alias_arn.partition(":agent-alias/")
    agent_id = rest.split("/", 1)[0]
    return f"{head}:agent/{agent_id}" if head and agent_id else None


def _bedrock_agents(client: Any, region: str, config: AwsBedrockConfig) -> list[Observation]:
    out: list[Observation] = []
    for summary in _pages(client.list_agents, "agentSummaries"):
        agent_id = summary["agentId"]
        agent = client.get_agent(agentId=agent_id).get("agent", {})
        arn = agent.get("agentArn") or f"bedrock-agent:{region}/{agent_id}"
        tags: dict[str, str] = {}
        try:
            tags = client.list_tags_for_resource(resourceArn=arn).get("tags") or {}
        except Exception:  # noqa: BLE001 - tags are optional evidence
            tags = {}
        linked = next((tags[k] for k in sig.AGENT_ID_LABELS if tags.get(k)), None)
        owner = next((tags[k] for k in ("Owner", "owner", "team", "Team") if tags.get(k)), None)
        version = config.agent_version
        groups = _pages(client.list_agent_action_groups, "actionGroupSummaries", agentId=agent_id, agentVersion=version)
        kbs = _pages(
            client.list_agent_knowledge_bases, "agentKnowledgeBaseSummaries", agentId=agent_id, agentVersion=version
        )
        collabs = _pages(
            client.list_agent_collaborators, "agentCollaboratorSummaries", agentId=agent_id, agentVersion=version
        )
        guardrail = (agent.get("guardrailConfiguration") or {}).get("guardrailIdentifier")
        model = agent.get("foundationModel")
        role = agent.get("agentResourceRoleArn")

        strong = [arn] + ([f"agent:{linked}"] if linked else [])
        signals = {"agent_runtime", "calls_model"} | ({"uses_tools"} if groups or kbs else set())
        facts = [
            EntityFact(
                "self",
                "agent",
                summary.get("agentName") or agent_id,
                strong,
                signals=signals,
                owner=owner,
                attrs={
                    "runtime": "bedrock-agents",
                    "region": region,
                    "status": summary.get("agentStatus"),
                    "foundation_model": model,
                    "guardrail": guardrail,
                    "guardrail_attached": bool(guardrail),
                    "action_groups": len(groups),
                    "knowledge_bases": len(kbs),
                    "collaborators": len(collabs),
                },
            )
        ]
        edges: list[EdgeFact] = []
        if model:
            facts.append(EntityFact("model", "model_provider", f"bedrock/{model}", [f"bedrock-model:{model}"]))
            edges.append(EdgeFact("self", "model", "calls_model", {"via": "bedrock"}))
        if role:
            facts.append(EntityFact("role", "identity", role.rsplit("/", 1)[-1], [role], attrs={"type": "iam-role"}))
            edges.append(EdgeFact("self", "role", "runs_as"))
        for g in groups:
            ref = f"tool:{g.get('actionGroupId')}"
            facts.append(
                EntityFact(
                    ref,
                    "tool",
                    f"{summary.get('agentName') or agent_id}/{g.get('actionGroupName')}",
                    [f"bedrock-action-group:{region}/{agent_id}/{g.get('actionGroupId')}"],
                    attrs={"state": g.get("actionGroupState")},
                )
            )
            edges.append(EdgeFact("self", ref, "uses_tool"))
        for kb in kbs:
            kid = kb.get("knowledgeBaseId")
            ref = f"kb:{kid}"
            facts.append(
                EntityFact(
                    ref,
                    "datastore",
                    f"knowledge-base/{kid}",
                    [f"bedrock-kb:{region}/{kid}"],
                    attrs={"type": "knowledge_base"},
                )
            )
            edges.append(EdgeFact("self", ref, "reads_from"))
        for c in collabs:
            alias = ((c.get("agentDescriptor") or {}).get("aliasArn")) or ""
            target = _agent_arn_from_alias(alias)
            if target:
                ref = f"collab:{target}"
                facts.append(
                    EntityFact(ref, "agent", c.get("collaboratorName") or target, [target], signals={"agent_runtime"})
                )
                edges.append(EdgeFact("self", ref, "collaborates_with"))
        out.append(
            Observation(
                kind="aws.bedrock_agent",
                source_ref=arn,
                entities=facts,
                edges=edges,
                attrs={"agent": summary.get("agentName"), "region": region, "guardrail_attached": bool(guardrail)},
            )
        )
    return out


def _agentcore(client: Any, region: str) -> list[Observation]:
    out: list[Observation] = []
    for rt in _pages(client.list_agent_runtimes, "agentRuntimes"):
        arn = rt.get("agentRuntimeArn") or f"agentcore-runtime:{region}/{rt.get('agentRuntimeId')}"
        out.append(
            Observation(
                kind="aws.agentcore_runtime",
                source_ref=arn,
                entities=[
                    EntityFact(
                        "self",
                        "agent",
                        rt.get("agentRuntimeName") or rt.get("agentRuntimeId") or arn,
                        [arn],
                        signals={"agent_runtime", "calls_model"},
                        attrs={"runtime": "agentcore", "region": region, "status": rt.get("status")},
                    )
                ],
                attrs={"runtime": rt.get("agentRuntimeName"), "region": region},
            )
        )
    for gw in _pages(client.list_gateways, "items"):
        gid = gw.get("gatewayId")
        targets = _pages(client.list_gateway_targets, "items", gatewayIdentifier=gid)
        facts = [
            EntityFact(
                "self",
                "mcp_server",
                f"agentcore-gateway/{gw.get('name') or gid}",
                [f"agentcore-gateway:{region}/{gid}"],
                attrs={"region": region, "status": gw.get("status")},
            )
        ]
        edges = []
        for t in targets:
            ref = f"t:{t.get('targetId')}"
            facts.append(
                EntityFact(
                    ref,
                    "tool",
                    f"{gw.get('name') or gid}/{t.get('name')}",
                    [f"agentcore-target:{region}/{gid}/{t.get('targetId')}"],
                )
            )
            edges.append(EdgeFact("self", ref, "exposes_tool"))
        out.append(
            Observation(
                "aws.agentcore_gateway", f"agentcore-gateway:{region}/{gid}", facts, edges, {"targets": len(targets)}
            )
        )
    return out
