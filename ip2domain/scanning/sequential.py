"""Durable bounded scan executor. Every worker handles one endpoint at a time."""
from __future__ import annotations

import asyncio
from collections import Counter

from .inventory import EndpointObservation
from .policies import ScanConfig
from .transports.network import NetworkBudget
from .stages import identify_endpoint


async def run_scan(repository, identifier, *, identify=identify_endpoint):
    """Can be restarted safely. Claims/results use fencing tokens, not an IP index."""
    scan = await asyncio.to_thread(repository.get, identifier)
    if scan is None:
        raise ValueError("scan not found")
    config = ScanConfig(**scan["config"])
    plan = config.plan()
    if scan["status"] not in ("running", "queued", "paused"):
        return
    executor_token = await asyncio.to_thread(repository.acquire_executor, identifier)
    if executor_token is None:
        raise ValueError("another executor owns this inventory database")
    await asyncio.to_thread(repository.transition, identifier, "running", ("queued", "paused"))
    if await asyncio.to_thread(repository.status, identifier) != "running":
        await asyncio.to_thread(repository.release_executor, identifier, executor_token)
        return
    budget = NetworkBudget(config, plan.scope)
    lease_seconds = 60.0

    async def worker():
        while True:
            claim = await asyncio.to_thread(repository.claim, identifier, lease_seconds, finalize=True)
            if claim is None:
                if await asyncio.to_thread(repository.status, identifier) != "running":
                    return
                # Other workers own all pending blocks; wait for completion or expiry.
                await asyncio.sleep(0.1)
                continue
            ordinal, token = claim
            block = plan.block(ordinal)
            lost = asyncio.Event()

            async def heartbeat():
                while True:
                    await asyncio.sleep(lease_seconds / 3)
                    if not await asyncio.to_thread(repository.renew, identifier, ordinal, token, lease_seconds):
                        lost.set()
                        return

            renewal = asyncio.create_task(heartbeat())
            try:
                start_port, saved_counters = await asyncio.to_thread(repository.progress, identifier, ordinal)
                counters = Counter(saved_counters)
                async def persist_partial(observation):
                    if observation.state == "open" or observation.services or config.retain_all_states:
                        if not await asyncio.to_thread(
                            repository.save_endpoint, identifier, ordinal, token, observation.to_dict(),
                        ):
                            raise asyncio.CancelledError

                for port_index, port in enumerate(block.ports[start_port:], start=start_port):
                    if lost.is_set() or await asyncio.to_thread(repository.status, identifier) != "running":
                        return
                    observation = EndpointObservation(
                        ip=block.ip, port=port, transport=block.transport,
                        network_id=config.network_id, hostname=config.hostname,
                    )
                    observation._checkpoint = persist_partial
                    await identify(observation, budget)
                    # Keep partial successes immediately. Silent/closed ports use
                    # compact per-block counters, not millions of endpoint rows.
                    await persist_partial(observation)
                    counters["processed"] += 1
                    if observation.state != "not_tested":
                        counters["tested"] += 1
                    counters[f"state:{observation.state}"] += 1
                    for attempt in observation.attempts:
                        counters[f"probe:{attempt['detector']}:{attempt['status']}"] += 1
                    if observation.services:
                        counters["identified"] += 1
                    if not await asyncio.to_thread(
                        repository.advance, identifier, ordinal, token, port_index + 1, dict(counters),
                    ):
                        return
                if not await asyncio.to_thread(repository.finish, identifier, ordinal, token, dict(counters)):
                    return
            finally:
                renewal.cancel()
                await asyncio.gather(renewal, return_exceptions=True)
                await asyncio.to_thread(repository.release, identifier, ordinal, token)

    tasks = [asyncio.create_task(worker()) for _ in range(config.workers)]

    async def executor_heartbeat():
        try:
            while True:
                await asyncio.sleep(10)
                owns = await asyncio.to_thread(repository.renew_executor, identifier, executor_token)
                status = await asyncio.to_thread(repository.status, identifier)
                if not owns or status not in ("running", "completed"):
                    for task in tasks:
                        task.cancel()
                    return
        except Exception:
            # Never keep issuing network requests after ownership becomes uncertain.
            for task in tasks:
                task.cancel()
            raise

    executor_renewal = asyncio.create_task(executor_heartbeat())
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        await asyncio.to_thread(repository.executor_transition, identifier, executor_token, "paused")
        raise
    except Exception as exc:
        await asyncio.to_thread(repository.executor_transition, identifier, executor_token, "error", type(exc).__name__)
        raise
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        executor_renewal.cancel()
        await asyncio.gather(executor_renewal, return_exceptions=True)
        await asyncio.to_thread(repository.release_executor, identifier, executor_token)
