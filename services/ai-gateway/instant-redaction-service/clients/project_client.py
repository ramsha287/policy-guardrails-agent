import logging

import httpx
from fastapi import HTTPException

from config import get_settings

logger = logging.getLogger(__name__)


class ProjectClient:
    def __init__(self, client: httpx.AsyncClient, base_url: str):
        self._client = client
        self._base_url = base_url.rstrip("/")

    async def get_project(self, project_id: str) -> dict:
        url = f"{self._base_url}/ai-gateway/project/api/{project_id}"
        try:
            resp = await self._client.get(url)
        except httpx.RequestError as exc:
            logger.error("Project service unreachable: %s", exc)
            raise HTTPException(status_code=503, detail="Project service unavailable") from exc

        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 404:
            raise HTTPException(status_code=404, detail=f"Project {project_id} not found")
        logger.error("Project service error: status=%s body=%s", resp.status_code, resp.text)
        raise HTTPException(status_code=502, detail="Project service error")

    async def is_healthy(self) -> bool:
        url = f"{self._base_url}/ai-gateway/project/api/health"
        try:
            resp = await self._client.get(url)
            return resp.status_code == 200
        except httpx.RequestError as exc:
            logger.warning("Project service health probe failed: %s", exc)
            return False


_client_instance: ProjectClient | None = None


async def open_project_client() -> ProjectClient:
    global _client_instance
    settings = get_settings()
    transport = httpx.AsyncHTTPTransport(retries=2)
    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(settings.http_timeout_seconds),
        transport=transport,
    )
    _client_instance = ProjectClient(
        client=http_client,
        base_url=settings.project_service_url,
    )
    return _client_instance


async def close_project_client() -> None:
    global _client_instance
    if _client_instance is not None:
        await _client_instance._client.aclose()
        _client_instance = None


def get_project_client() -> ProjectClient:
    if _client_instance is None:
        raise RuntimeError("Project client not initialized")
    return _client_instance
