import asyncio
from contextlib import asynccontextmanager

_registry_lock = asyncio.Lock()

@asynccontextmanager
async def temp_custom_recognizers(analyzer, recognizers):
    await _registry_lock.acquire()
    try:
        for r in recognizers:
            analyzer.registry.add_recognizer(r)
        yield
    finally:
        for r in recognizers:
            analyzer.registry.remove_recognizer(r)
        _registry_lock.release()
