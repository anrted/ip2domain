"""Asyncio TCP connect discovery backend powered by ScanPlan work blocks."""
from __future__ import annotations

import asyncio
from typing import AsyncIterator, Callable, Dict, List, Optional, Tuple

from .base import DiscoveryBackend, DiscoveryEvent
from ...scope import ScanPlan, TargetScope
from ...transports.network import close_writer


async def _probe_port(ip: str, port: int, timeout: float) -> Tuple[str, int, bool, bytes]:
    """Single TCP connect check with optional passive banner reading."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        banner = b""
        try:
            banner = await asyncio.wait_for(reader.read(512), timeout=min(0.3, timeout))
        except (asyncio.TimeoutError, OSError):
            pass
        finally:
            await close_writer(writer)
        return ip, port, True, banner
    except Exception:
        return ip, port, False, b""


class AsyncioDiscoveryBackend(DiscoveryBackend):
    """Safe, rate-limited TCP connect scanner for single hosts and <= /24 subnets."""

    name = "asyncio"

    def _build_plan(self, targets: List[str], ports: Tuple[int, ...], block_size: int = 32) -> ScanPlan:
        # Join targets for scope creation
        targets_str = "\n".join(targets)
        scope = TargetScope(targets_str)
        return ScanPlan(scope, ports, (), block_size=block_size)

    async def sweep(
        self,
        targets: List[str],
        ports: Tuple[int, ...],
        *,
        rate: float = 50.0,
        concurrency: int = 100,
        timeout: float = 1.5,
        on_progress: Optional[Callable[[int, int, str, int], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ) -> List[Tuple[str, List[int]]]:
        if not targets or not ports:
            return []

        plan = self._build_plan(targets, ports, block_size=min(len(ports), 32) or 1)
        semaphore = asyncio.Semaphore(concurrency)
        responsive: Dict[str, set] = {}
        completed_hosts = 0
        total_hosts = plan.scope.count
        lock = asyncio.Lock()

        # Group blocks by host ordinal for per-host tracking
        blocks_per_host = len(plan.blocks)

        async def execute_block(ordinal: int):
            if is_cancelled and is_cancelled():
                return
            block = plan.block(ordinal)
            async with semaphore:
                tasks = [_probe_port(block.ip, p, timeout) for p in block.ports]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, tuple) and len(r) == 4 and r[2]:
                        ip, port = r[0], r[1]
                        async with lock:
                            responsive.setdefault(ip, set()).add(port)

        # Execute host by host or in bounded batches
        batch_size = max(1, concurrency // max(1, len(ports)))
        for host_start in range(0, total_hosts, batch_size):
            if is_cancelled and is_cancelled():
                break
            batch_tasks = []
            host_end = min(total_hosts, host_start + batch_size)
            for h_idx in range(host_start, host_end):
                for b_idx in range(blocks_per_host):
                    ordinal = h_idx * blocks_per_host + b_idx
                    batch_tasks.append(execute_block(ordinal))

            await asyncio.gather(*batch_tasks, return_exceptions=True)
            completed_hosts = host_end
            if on_progress:
                last_ip = plan.scope.address(host_end - 1)
                on_progress(completed_hosts, total_hosts, last_ip, len(responsive))

        return [(ip, sorted(list(pts))) for ip, pts in responsive.items()]

    async def stream_events(
        self,
        targets: List[str],
        ports: Tuple[int, ...],
        *,
        rate: float = 50.0,
        concurrency: int = 100,
        timeout: float = 1.5,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ) -> AsyncIterator[DiscoveryEvent]:
        if not targets or not ports:
            return

        plan = self._build_plan(targets, ports, block_size=16)
        semaphore = asyncio.Semaphore(concurrency)
        queue: asyncio.Queue[Optional[DiscoveryEvent]] = asyncio.Queue(maxsize=1024)

        async def worker(ordinal_iter):
            for ordinal in ordinal_iter:
                if is_cancelled and is_cancelled():
                    break
                block = plan.block(ordinal)
                for port in block.ports:
                    if is_cancelled and is_cancelled():
                        break
                    async with semaphore:
                        ip, p, ok, banner = await _probe_port(block.ip, port, timeout)
                        if ok:
                            await queue.put(DiscoveryEvent(ip, p, "open", banner))

        ordinals = list(range(plan.total))
        num_workers = min(concurrency, max(1, plan.total))
        chunk_size = (len(ordinals) + num_workers - 1) // num_workers

        tasks = []
        for i in range(num_workers):
            sub = ordinals[i * chunk_size : (i + 1) * chunk_size]
            if sub:
                tasks.append(asyncio.create_task(worker(sub)))

        async def monitor():
            await asyncio.gather(*tasks, return_exceptions=True)
            await queue.put(None)

        monitor_task = asyncio.create_task(monitor())
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield item
        finally:
            if not monitor_task.done():
                monitor_task.cancel()
            for t in tasks:
                if not t.done():
                    t.cancel()
