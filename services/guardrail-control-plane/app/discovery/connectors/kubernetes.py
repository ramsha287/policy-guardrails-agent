"""Kubernetes (k3s and others): what actually runs, with owners, identities and model access.

Reads pods through the Kubernetes API with a read-only service account (list/watch pods; the Helm
chart ships the ClusterRole when `discovery.kubernetes.enabled`), groups them by their top-level
workload (Deployment, StatefulSet, DaemonSet, Job/CronJob, bare Pod) and looks at:

- environment variable NAMES (model-provider keys, agent frameworks, MCP, data stores, our gateway)
  and plain `value`s that are URLs (provider and MCP hosts). `valueFrom` secrets are recorded as a
  reference (namespace/secret#key), never read;
- container images (agent frameworks; LLM servers such as vLLM, Ollama, TGI are model providers);
- labels: `guardrails.io/agent-id` links the workload to a registered agent, owner/team labels give
  the owner guess;
- the service account (the workload identity) and the pod IPs (weak keys for DNS evidence).

Optionally lists kagent `Agent` resources (agents.kagent.dev) when the CRD exists.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, ClassVar

import httpx
from pydantic import Field, field_validator

from .. import signatures as sig
from ..model import CollectContext, ConnectorConfig, ConnectorError, EdgeFact, EntityFact, Observation
from ..safety import validate_secret_name

IN_CLUSTER_URL = "https://kubernetes.default.svc"
SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
NAMESPACE = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")  # RFC 1123 label
TOP_LEVEL = {"Deployment", "StatefulSet", "DaemonSet", "CronJob"}


class KubernetesConfig(ConnectorConfig):
    cluster: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{0,62}$", description="name used in inventory keys")
    api_url: str = IN_CLUSTER_URL
    token_env: str | None = None  # default: the in-cluster service account token
    ca_file: str | None = None  # default: the in-cluster CA (when api_url is in-cluster)
    namespaces: list[str] = Field(default_factory=list, description="[] = all namespaces")
    label_selector: str | None = None
    include_kagent: bool = True
    gateway_hosts: list[str] = Field(
        default_factory=lambda: ["guardrail-gateway"], description="hosts of the guardrail gateway (proxy/SDK mode)"
    )

    @field_validator("token_env")
    @classmethod
    def _secret(cls, v: str | None) -> str | None:
        validate_secret_name(v)
        return v

    @field_validator("namespaces")
    @classmethod
    def _namespaces(cls, v: list[str]) -> list[str]:
        bad = [ns for ns in v if not NAMESPACE.fullmatch(ns)]
        if bad:
            raise ValueError(f"not a Kubernetes namespace name: {', '.join(bad[:3])}")
        return v


class KubernetesConnector:
    kind: ClassVar[str] = "kubernetes"
    title: ClassVar[str] = "Kubernetes workloads"
    description: ClassVar[str] = (
        "Workloads with model-provider keys, agent frameworks, MCP use and LLM servers, from pod specs "
        "(names only; secret values are never read)."
    )
    full_snapshot: ClassVar[bool] = True
    Config: ClassVar[type[ConnectorConfig]] = KubernetesConfig

    async def collect(self, config: KubernetesConfig, ctx: CollectContext) -> AsyncIterator[Observation]:
        base = config.api_url.rstrip("/")
        await ctx.check_url(base)
        headers = {"Accept": "application/json", "Authorization": f"Bearer {self._token(config, ctx)}"}
        injected = ctx.clients.get("kubernetes_http")
        # Its own client: the API server's CA is the cluster CA, not the platform's mTLS CA.
        http = injected or httpx.AsyncClient(verify=self._verify(config), timeout=30.0)
        try:
            async for obs in self._collect(config, ctx, http, base, headers):
                yield obs
        finally:
            if injected is None:
                await http.aclose()

    async def _collect(
        self, config: KubernetesConfig, ctx: CollectContext, http: httpx.AsyncClient, base: str, headers: dict[str, str]
    ) -> AsyncIterator[Observation]:
        pods: list[dict[str, Any]] = []
        paths = [f"/api/v1/namespaces/{ns}/pods" for ns in config.namespaces] or ["/api/v1/pods"]
        for path in paths:
            pods.extend(await _list(http, base + path, headers, config.label_selector))

        workloads: dict[str, dict[str, Any]] = {}
        for pod in pods:
            key, kind, name, ns = _workload_of(pod)
            w = workloads.setdefault(key, {"kind": kind, "name": name, "namespace": ns, "pods": []})
            w["pods"].append(pod)
        for key, w in sorted(workloads.items()):
            yield _workload_observation(config, key, w)

        if config.include_kagent:
            try:
                agents = await _list(http, base + "/apis/kagent.dev/v1alpha1/agents", headers, None)
            except ConnectorError as exc:
                if "404" not in str(exc):
                    ctx.warn(f"kagent agents: {exc}")
                agents = []
            for a in agents:
                yield _kagent_observation(config, a)

    @staticmethod
    def _token(config: KubernetesConfig, ctx: CollectContext) -> str:
        if config.token_env:
            return ctx.secrets(config.token_env)
        if config.api_url.rstrip("/") != IN_CLUSTER_URL:
            # The pod's own service-account token only ever goes to its own API server.
            raise ConnectorError("token_env is required when api_url is not the in-cluster API server")
        try:
            return (SA_DIR / "token").read_text().strip()
        except OSError as exc:
            raise ConnectorError("no token: run in-cluster or set token_env (a DISCOVERY_SECRET_* variable)") from exc

    @staticmethod
    def _verify(config: KubernetesConfig) -> str | bool:
        if config.ca_file:
            return config.ca_file
        if config.api_url.rstrip("/") == IN_CLUSTER_URL and (SA_DIR / "ca.crt").is_file():
            return str(SA_DIR / "ca.crt")
        return True


async def _list(
    http: httpx.AsyncClient, url: str, headers: dict[str, str], selector: str | None
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cont: str | None = None
    for _ in range(200):  # 200 pages x 500 = 100k objects
        params: dict[str, Any] = {"limit": 500}
        if selector:
            params["labelSelector"] = selector
        if cont:
            params["continue"] = cont
        try:
            resp = await http.get(url, headers=headers, params=params, follow_redirects=False)
        except httpx.HTTPError as exc:
            raise ConnectorError(f"kubernetes API unreachable: {exc.__class__.__name__}") from exc
        if resp.status_code != 200:
            raise ConnectorError(f"kubernetes API {url.split('/api', 1)[-1]} answered {resp.status_code}")
        body = resp.json()
        items.extend(body.get("items") or [])
        cont = (body.get("metadata") or {}).get("continue")
        if not cont:
            break
    return items


def _workload_of(pod: dict[str, Any]) -> tuple[str, str, str, str]:
    meta = pod.get("metadata") or {}
    ns = meta.get("namespace") or "default"
    labels = meta.get("labels") or {}
    kind, name = "Pod", meta.get("name") or "?"
    for ref in meta.get("ownerReferences") or []:
        if not ref.get("controller", True):
            continue
        kind, name = ref.get("kind") or kind, ref.get("name") or name
        if (
            kind == "ReplicaSet"
            and labels.get("pod-template-hash")
            and name.endswith("-" + labels["pod-template-hash"])
        ):
            kind, name = "Deployment", name[: -len(labels["pod-template-hash"]) - 1]
        elif kind == "Job" and name.rsplit("-", 1)[-1].isdigit():
            kind, name = "CronJob", name.rsplit("-", 1)[0]
        break
    return f"{ns}/{kind}/{name}", kind, name, ns


def _workload_observation(config: KubernetesConfig, key: str, w: dict[str, Any]) -> Observation:
    cluster, ns = config.cluster, w["namespace"]
    pod = w["pods"][0]
    meta, spec = pod.get("metadata") or {}, pod.get("spec") or {}
    labels = meta.get("labels") or {}
    gateway_hosts = {h.lower() for h in config.gateway_hosts}

    signals: set[str] = set()
    providers: dict[str, str] = {}  # provider -> evidence ("env OPENAI_API_KEY", "host api.openai.com")
    frameworks: set[str] = set()
    mcp_hosts: set[str] = set()
    data_env: set[str] = set()
    credentials: dict[str, dict[str, str]] = {}  # strong key -> {secret, key, provider, env}
    images: set[str] = set()
    uses_gateway = False

    for c in (spec.get("containers") or []) + (spec.get("initContainers") or []):
        image = str(c.get("image") or "")
        images.add(image)
        if sig.llm_server_image(image):
            signals.add("llm_server")
        fw = sig.framework_in_image(image)
        if fw:
            frameworks.add(fw)
        for env in c.get("env") or []:
            name = str(env.get("name") or "")
            value = env.get("value")
            ref = ((env.get("valueFrom") or {}).get("secretKeyRef")) or None
            provider = sig.provider_for_env(name)
            if provider:
                providers.setdefault(provider, f"env {name}")
                if ref and ref.get("name"):
                    skey = f"k8s-secret:{cluster}/{ns}/{ref['name']}#{ref.get('key', '')}"
                    credentials[skey] = {
                        "secret": ref["name"],
                        "key": str(ref.get("key", "")),
                        "env": name,
                        "provider": provider,
                    }
            if name.upper() in sig.GATEWAY_ENV:
                uses_gateway = True
            if sig.is_framework_env(name):
                frameworks.add(name.split("_", 1)[0].lower())
            if sig.is_mcp_env(name):
                signals.add("mcp_client")
            if sig.is_data_env(name):
                data_env.add(name)
            if isinstance(value, str):
                host = sig.host_of(value)
                if host:
                    if host in gateway_hosts or any(host.startswith(g + ".") for g in gateway_hosts):
                        uses_gateway = True
                    p = sig.provider_for_host(host)
                    if p:
                        providers.setdefault(p, f"host {host}")
                    if sig.MCP_PATH_RE.search(value) or sig.is_mcp_env(name):
                        mcp_hosts.add(host)
                        signals.add("mcp_client")
        for src in c.get("envFrom") or []:
            ref = (src.get("secretRef") or src.get("configMapRef") or {}).get("name")
            if ref and any(t in ref.lower() for t in ("openai", "anthropic", "llm", "gemini", "bedrock")):
                providers.setdefault("unknown", f"envFrom {ref}")

    if providers:
        signals.add("calls_model")
        if not uses_gateway:
            signals.add("direct_model_access")
    if uses_gateway:
        signals.add("gateway_client")
    if frameworks:
        signals.add("agent_framework")
    if data_env or mcp_hosts:
        signals.add("uses_tools")
    if "llm_server" in signals and not frameworks:
        signals.discard("calls_model")
        signals.discard("direct_model_access")

    agent_id = next((labels[k] for k in sig.AGENT_ID_LABELS if labels.get(k)), None)
    owner = next((labels[k] for k in sig.OWNER_LABELS if labels.get(k)), None)
    strong = [f"k8s:{cluster}/{key}"]
    if agent_id:
        strong.append(f"agent:{agent_id}")
    weak = sorted({f"ip:{p.get('status', {}).get('podIP')}" for p in w["pods"] if (p.get("status") or {}).get("podIP")})
    sa = spec.get("serviceAccountName") or "default"
    kind = "model_provider" if "llm_server" in signals and not frameworks else "workload"
    self_fact = EntityFact(
        ref="self",
        kind=kind,
        name=f"{ns}/{w['name']}",
        strong_keys=strong,
        weak_keys=weak,
        signals=signals,
        owner=owner,
        attrs={
            "cluster": cluster,
            "namespace": ns,
            "workload_kind": w["kind"],
            "replicas_seen": len(w["pods"]),
            "images": sorted(images)[:10],
            "service_account": sa,
            "model_providers": dict(sorted(providers.items())),
            "frameworks": sorted(frameworks),
            "mcp_hosts": sorted(mcp_hosts),
            "data_env": sorted(data_env)[:20],
            "uses_gateway": uses_gateway,
            "labels": {k: v for k, v in labels.items() if k != "pod-template-hash"},
        },
    )
    facts = [
        self_fact,
        EntityFact("sa", "identity", f"{ns}/{sa}", [f"k8s-sa:{cluster}/{ns}/{sa}"], attrs={"cluster": cluster}),
    ]
    edges = [EdgeFact("self", "sa", "runs_as")]
    for provider in sorted(p for p in providers if p != "unknown"):
        ref = f"provider:{provider}"
        facts.append(EntityFact(ref, "model_provider", provider, [f"provider:{provider}"]))
        edges.append(EdgeFact("self", ref, "calls_model", {"via": "gateway" if uses_gateway else "direct"}))
    for skey, cred in sorted(credentials.items()):
        ref = f"cred:{skey}"
        facts.append(EntityFact(ref, "credential", f"{ns}/{cred['secret']}#{cred['key']}", [skey], attrs=cred))
        edges.append(EdgeFact("self", ref, "holds_credential"))
    for host in sorted(mcp_hosts):
        ref = f"mcp:{host}"
        facts.append(EntityFact(ref, "mcp_server", host, [f"mcp-host:{host}"], weak_keys=[f"mcp-host:{host}"]))
        edges.append(EdgeFact("self", ref, "uses_tool"))
    return Observation(
        kind="k8s.workload",
        source_ref=f"{config.cluster}/{key}",
        entities=facts,
        edges=edges,
        attrs={
            k: self_fact.attrs[k]
            for k in ("namespace", "workload_kind", "model_providers", "frameworks", "uses_gateway")
        },
    )


def _kagent_observation(config: KubernetesConfig, a: dict[str, Any]) -> Observation:
    meta, spec = a.get("metadata") or {}, a.get("spec") or {}
    ns, name = meta.get("namespace") or "default", meta.get("name") or "?"
    labels = meta.get("labels") or {}
    agent_id = next((labels[k] for k in sig.AGENT_ID_LABELS if labels.get(k)), None)
    strong = [f"kagent:{config.cluster}/{ns}/{name}"] + ([f"agent:{agent_id}"] if agent_id else [])
    tools = [t for t in (spec.get("tools") or []) if isinstance(t, dict)]
    fact = EntityFact(
        "self",
        "agent",
        f"{ns}/{name}",
        strong,
        signals={"agent_runtime", "calls_model"} | ({"uses_tools"} if tools else set()),
        owner=next((labels[k] for k in sig.OWNER_LABELS if labels.get(k)), None),
        attrs={"cluster": config.cluster, "namespace": ns, "runtime": "kagent", "tools": len(tools)},
    )
    return Observation("k8s.kagent_agent", f"{config.cluster}/{ns}/agents.kagent.dev/{name}", [fact])
