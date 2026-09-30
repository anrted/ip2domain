"""External masscan discovery backend: generates (ip, port, open) events for large networks."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from typing import AsyncIterator, Callable, Dict, List, Optional, Tuple

from .base import DiscoveryBackend, DiscoveryEvent

logger = logging.getLogger(__name__)


class MasscanDiscoveryBackend(DiscoveryBackend):
    """Subprocess masscan runner streaming discovery events into pipeline queues."""

    name = "masscan"

    def __init__(self, binary_path: Optional[str] = None):
        self.binary = binary_path or shutil.which("masscan")

    async def sweep(
        self,
        targets: List[str],
        ports: Tuple[int, ...],
        *,
        rate: float = 25000.0,
        concurrency: int = 100,
        timeout: float = 1.5,
        on_progress: Optional[Callable[[int, int, str, int], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ) -> List[Tuple[str, List[int]]]:
        responsive: Dict[str, List[int]] = {}
        async for ev in self.stream_events(
            targets, ports, rate=rate, concurrency=concurrency, timeout=timeout, is_cancelled=is_cancelled
        ):
            if ev.state == "open":
                responsive.setdefault(ev.ip, []).append(ev.port)

        return [(ip, sorted(pts)) for ip, pts in responsive.items()]

    async def stream_events(
        self,
        targets: List[str],
        ports: Tuple[int, ...],
        *,
        rate: float = 25000.0,
        concurrency: int = 100,
        timeout: float = 1.5,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ) -> AsyncIterator[DiscoveryEvent]:
        resolved = shutil.which(self.binary) if self.binary else None
        if not resolved or not os.path.exists(resolved):
            raise RuntimeError(f"masscan executable '{self.binary}' not found on system PATH")
        if not targets or not ports:
            return

        port_str = ",".join(str(p) for p in ports)
        tmp_targets = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        tmp_out = tmp_targets.name + ".json"

        try:
            valid_targets = 0
            for t in targets:
                t = t.strip()
                if t and ":" not in t:  # masscan primary IPv4 CIDRs/IPs
                    tmp_targets.write(t + "\n")
                    valid_targets += 1
            tmp_targets.flush()
            tmp_targets.close()

            if valid_targets == 0:
                return

            cmd = [
                self.binary,
                "-iL", tmp_targets.name,
                "-p", port_str,
                "--rate", str(int(rate)),
                "--retries", "1",
                "--output-format", "json",
                "--output-filename", tmp_out,
                "--wait", "5",
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Read stderr for cancellation / progress
            async def _monitor_proc():
                try:
                    while proc.returncode is None:
                        if is_cancelled and is_cancelled():
                            try:
                                proc.kill()
                            except Exception:
                                pass
                            break
                        await asyncio.sleep(0.2)
                except asyncio.CancelledError:
                    try:
                        proc.kill()
                    except Exception:
                        pass

            monitor = asyncio.create_task(_monitor_proc())
            await proc.wait()
            monitor.cancel()

            if is_cancelled and is_cancelled():
                return

            # Parse results from output file
            if os.path.exists(tmp_out):
                try:
                    with open(tmp_out, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read().strip()
                    if content:
                        cleaned = re.sub(r",\s*\]", "]", content)
                        if cleaned.endswith(","):
                            cleaned = cleaned[:-1]
                        if not cleaned.startswith("["):
                            cleaned = "[" + cleaned + "]"
                        records = json.loads(cleaned)
                        for item in records:
                            ip = item.get("ip", "")
                            for p_info in item.get("ports", []):
                                if p_info.get("status") == "open":
                                    port_num = int(p_info.get("port", 0))
                                    if port_num > 0:
                                        yield DiscoveryEvent(ip, port_num, "open")
                except Exception as exc:
                    logger.warning("[MasscanBackend] Error reading JSON output: %s", exc)
        finally:
            for path in (tmp_targets.name, tmp_out):
                if os.path.exists(path):
                    try:
                        os.remove(path)
                    except Exception:
                        pass
