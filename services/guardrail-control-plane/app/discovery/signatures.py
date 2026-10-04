"""What model providers, agent frameworks, MCP use and LLM servers look like from the outside.

Shared by the Kubernetes, DNS and gateway connectors. Matching is on names only (hosts, variable
names, image names, labels): values of secrets are never read.
"""

from __future__ import annotations

import re

# host suffix -> provider name
MODEL_PROVIDER_HOSTS: dict[str, str] = {
    "api.openai.com": "openai",
    "openai.azure.com": "azure-openai",
    "cognitiveservices.azure.com": "azure-ai",
    "services.ai.azure.com": "azure-ai-foundry",
    "api.anthropic.com": "anthropic",
    "generativelanguage.googleapis.com": "google-gemini",
    "aiplatform.googleapis.com": "google-vertex",
    "api.mistral.ai": "mistral",
    "api.cohere.ai": "cohere",
    "api.cohere.com": "cohere",
    "api.groq.com": "groq",
    "openrouter.ai": "openrouter",
    "api.together.xyz": "together",
    "api.together.ai": "together",
    "api.deepseek.com": "deepseek",
    "api.x.ai": "xai",
    "api.perplexity.ai": "perplexity",
    "api-inference.huggingface.co": "huggingface",
    "router.huggingface.co": "huggingface",
    "api.fireworks.ai": "fireworks",
    "integrate.api.nvidia.com": "nvidia",
}
# bedrock-runtime.<region>.amazonaws.com, bedrock-agent-runtime..., bedrock-agentcore...
BEDROCK_HOST_RE = re.compile(r"^bedrock(-agent)?(-runtime|core)(-fips)?\.[a-z0-9-]+\.amazonaws\.com$")

# Environment variable NAMES that hold model-provider credentials or endpoints.
PROVIDER_ENV: dict[str, str] = {
    "OPENAI_API_KEY": "openai",
    "OPENAI_ADMIN_KEY": "openai",
    "AZURE_OPENAI_API_KEY": "azure-openai",
    "AZURE_OPENAI_ENDPOINT": "azure-openai",
    "AZURE_AI_PROJECT_ENDPOINT": "azure-ai-foundry",
    "ANTHROPIC_API_KEY": "anthropic",
    "GOOGLE_API_KEY": "google-gemini",
    "GEMINI_API_KEY": "google-gemini",
    "MISTRAL_API_KEY": "mistral",
    "COHERE_API_KEY": "cohere",
    "CO_API_KEY": "cohere",
    "GROQ_API_KEY": "groq",
    "OPENROUTER_API_KEY": "openrouter",
    "TOGETHER_API_KEY": "together",
    "DEEPSEEK_API_KEY": "deepseek",
    "XAI_API_KEY": "xai",
    "PERPLEXITY_API_KEY": "perplexity",
    "FIREWORKS_API_KEY": "fireworks",
    "HUGGINGFACEHUB_API_TOKEN": "huggingface",
    "HF_TOKEN": "huggingface",
    "NVIDIA_API_KEY": "nvidia",
    "BEDROCK_MODEL_ID": "aws-bedrock",
    "AWS_BEDROCK_MODEL_ID": "aws-bedrock",
}

# Variables that say "this agent goes through the guardrail gateway" (SDK or proxy mode).
GATEWAY_ENV = frozenset(
    {"GUARDRAIL_GATEWAY_URL", "GUARDRAIL_E2E_URL", "GUARDRAIL_API_KEY", "GUARDRAIL_GATEWAY_API_KEY"}
)

# Agent framework fingerprints: variable names and image-name fragments.
FRAMEWORK_ENV_PREFIXES = (
    "LANGCHAIN_",
    "LANGSMITH_",
    "LANGGRAPH_",
    "CREWAI_",
    "AUTOGEN_",
    "AGENTOPS_",
    "LLAMA_INDEX_",
    "LLAMAINDEX_",
    "OPENAI_AGENTS_",
    "SEMANTIC_KERNEL_",
    "LETTA_",
    "PYDANTIC_AI_",
)
FRAMEWORK_IMAGES = ("langgraph", "langchain", "crewai", "autogen", "kagent", "letta", "flowise", "dify", "n8n")

MCP_ENV_RE = re.compile(r"(^|_)MCP(_|$)")
MCP_PATH_RE = re.compile(r"/mcp(/|$|\?)|/sse(/|$|\?)")

# Data / tool access (classification counts this as "uses tools or data").
DATA_ENV_PREFIXES = (
    "DATABASE_URL",
    "POSTGRES",
    "PGHOST",
    "PGDATABASE",
    "MYSQL",
    "MONGODB",
    "MONGO_",
    "REDIS_URL",
    "ELASTICSEARCH",
    "OPENSEARCH",
    "PINECONE",
    "WEAVIATE",
    "QDRANT",
    "CHROMA",
    "SNOWFLAKE",
    "BIGQUERY",
    "S3_BUCKET",
    "SLACK_",
    "JIRA_",
    "GITHUB_TOKEN",
    "SALESFORCE",
    "ZENDESK",
)

LLM_SERVER_IMAGES = (
    "vllm/vllm-openai",
    "vllm-openai",
    "ollama/ollama",
    "text-generation-inference",
    "huggingface/text-generation",
    "ghcr.io/ggerganov/llama.cpp",
    "ghcr.io/ggml-org/llama.cpp",
    "lmdeploy",
    "sglang",
    "localai/localai",
    "triton",
)

OWNER_LABELS = ("owner", "team", "app.kubernetes.io/owner", "contact", "maintainer", "app.kubernetes.io/part-of")
AGENT_ID_LABELS = ("guardrails.io/agent-id", "guardrail/agent-id", "guardrail:agent-id")


def provider_for_host(host: str) -> str | None:
    host = host.lower().rstrip(".")
    if BEDROCK_HOST_RE.match(host):
        return "aws-bedrock"
    for suffix, provider in MODEL_PROVIDER_HOSTS.items():
        if host == suffix or host.endswith("." + suffix):
            return provider
    return None


def provider_for_env(name: str) -> str | None:
    return PROVIDER_ENV.get(name.upper())


def is_framework_env(name: str) -> bool:
    return name.upper().startswith(FRAMEWORK_ENV_PREFIXES)


def is_data_env(name: str) -> bool:
    return name.upper().startswith(DATA_ENV_PREFIXES)


def is_mcp_env(name: str) -> bool:
    return bool(MCP_ENV_RE.search(name.upper()))


def framework_in_image(image: str) -> str | None:
    lowered = image.lower()
    return next((f for f in FRAMEWORK_IMAGES if f in lowered), None)


def llm_server_image(image: str) -> bool:
    lowered = image.lower()
    return any(s in lowered for s in LLM_SERVER_IMAGES)


def host_of(value: str) -> str | None:
    """Host of a URL-looking value (`https://api.openai.com/v1` -> api.openai.com)."""
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/:?#@]+@)?([^/:?#]+)", value.strip(), re.I)
    return m.group(2).lower() if m else None
