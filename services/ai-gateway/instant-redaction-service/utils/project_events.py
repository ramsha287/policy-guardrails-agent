"""Redis pub/sub listener: evicts cached project config when project-service changes a project.

project-service publishes the project id on channel `ai-gateway:project-changed` after every
update or delete. Without REDIS_URL this listener is not started and the cache TTL applies.
"""
import asyncio
import logging

logger = logging.getLogger(__name__)

CHANNEL = "ai-gateway:project-changed"


async def listen_for_project_changes(redis_url: str, on_change) -> None:
    try:
        from redis.asyncio import Redis
    except ImportError:
        logger.warning("redis package not installed; project cache relies on TTL only")
        return
    while True:
        client = Redis.from_url(redis_url, decode_responses=True)
        try:
            pubsub = client.pubsub()
            await pubsub.subscribe(CHANNEL)
            logger.info("Listening for project changes on %s", CHANNEL)
            async for message in pubsub.listen():
                if message.get("type") == "message":
                    on_change(str(message.get("data") or "") or None)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - reconnect on any Redis error
            logger.warning("Project change listener error (%s); clearing cache and retrying", exc.__class__.__name__)
            on_change(None)  # we may have missed events
            await asyncio.sleep(5)
        finally:
            await client.aclose()
