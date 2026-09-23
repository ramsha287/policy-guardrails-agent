"""Publishes project changes so instant-redaction-service can evict its project cache at once.

No-op unless REDIS_URL is set. Publishing never fails the API call: the cache TTL on the
redaction side is the fallback.
"""
import logging
import os

logger = logging.getLogger(__name__)

CHANNEL = "ai-gateway:project-changed"
_client = None


def _redis():
    global _client
    url = os.getenv("REDIS_URL")
    if not url:
        return None
    if _client is None:
        try:
            from redis.asyncio import Redis
        except ImportError:
            logger.warning("redis package not installed; project change events disabled")
            return None
        _client = Redis.from_url(url, decode_responses=True)
    return _client


async def publish_project_changed(project_id: str) -> None:
    client = _redis()
    if client is None:
        return
    try:
        await client.publish(CHANNEL, str(project_id))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not publish project change for %s: %s", project_id, exc.__class__.__name__)
