"""Bounded async execution, deterministic result order and failure isolation."""
from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, Iterable, TypeVar

from .models import HostObservation, ProbeContext, ProbeData, ProbeOutcome
from .registry import ProbeRegistry, ProbeSpec

logger = logging.getLogger(__name__)
T = TypeVar("T")


async def run_bounded(
    items: Iterable[T],
    worker: Callable[[T], Awaitable[None]],
    concurrency: int,
    is_cancelled: Callable[[], bool] = lambda: False,
) -> None:
    """Consume lazily with O(concurrency) tasks, not one task per target.

    Worker failures propagate after sibling cleanup. Cooperative cancellation
    stops scheduling; external task cancellation also cancels in-flight workers.
    """
    if concurrency < 1:
        raise ValueError("concurrency must be positive")
    iterator = iter(items)
    iter_lock = asyncio.Lock()

    async def consume() -> None:
        while not is_cancelled():
            async with iter_lock:
                try:
                    item = next(iterator)
                except StopIteration:
                    return
            try:
                await worker(item)
            except Exception as exc:
                logger.warning("[run_bounded] Worker error on item: %s", exc)

    tasks = [asyncio.create_task(consume()) for _ in range(concurrency)]
    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class ProbeRunner:
    """Reuse within one event loop to share the probe limit across hosts."""

    def __init__(self, registry: ProbeRegistry, concurrency: int = 16) -> None:
        if concurrency < 1:
            raise ValueError("concurrency must be positive")
        self.registry = registry
        self._semaphore = asyncio.Semaphore(concurrency)

    async def _run(self, spec: ProbeSpec, context: ProbeContext) -> ProbeOutcome:
        async with self._semaphore:
            try:
                if spec.timeout is None:
                    data = await spec.run(context)
                else:
                    data = await asyncio.wait_for(spec.run(context), spec.timeout)
                if not isinstance(data, ProbeData):
                    raise TypeError("probe must return ProbeData")
                return ProbeOutcome(spec.probe_id, "completed", data)
            except asyncio.CancelledError:
                raise
            except asyncio.TimeoutError:
                return ProbeOutcome(spec.probe_id, "timeout", error_type="TimeoutError")
            except Exception as exc:
                # Exception messages / raw payloads can contain passwords or URLs.
                logger.debug("Probe %s failed (%s)", spec.probe_id, type(exc).__name__)
                return ProbeOutcome(spec.probe_id, "error", error_type=type(exc).__name__)

    async def probe(self, context: ProbeContext) -> HostObservation:
        specs = self.registry.select(context)
        tasks = [asyncio.create_task(self._run(spec, context)) for spec in specs]
        try:
            raw_outcomes = await asyncio.gather(*tasks, return_exceptions=True)
            outcomes = []
            for spec, res in zip(specs, raw_outcomes):
                if isinstance(res, ProbeOutcome):
                    outcomes.append(res)
                elif isinstance(res, Exception):
                    outcomes.append(ProbeOutcome(spec.probe_id, "error", error_type=type(res).__name__))
                else:
                    outcomes.append(ProbeOutcome(spec.probe_id, "error", error_type="Unknown"))
            return HostObservation(context.ip, context.endpoints, tuple(outcomes))
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
