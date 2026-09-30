"""Async ownership helpers. Losing a lease interrupts in-flight network work."""
import asyncio
from contextlib import asynccontextmanager


async def db_call(function, *args, **kwargs):
    """Wait for an already submitted SQLite operation before cancellation cleanup.

    asyncio.to_thread cannot stop the thread. Without draining it, a cancelled
    claimant could acquire a lease *after* its cleanup had already run.
    """
    task = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        await task
        raise


@asynccontextmanager
async def renewable_lease(renew, release, *, interval=10):
    owner = asyncio.current_task()

    async def heartbeat():
        try:
            while True:
                await asyncio.sleep(interval)
                if not await renew():
                    owner.cancel()
                    return
        except Exception:
            owner.cancel()
            raise

    heartbeat_task = asyncio.create_task(heartbeat())
    try:
        yield
    finally:
        heartbeat_task.cancel()
        await asyncio.gather(heartbeat_task, return_exceptions=True)
        await release()
