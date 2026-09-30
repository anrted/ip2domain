"""Base contract and data structures for port discovery backends."""
from __future__ import annotations

import shutil
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import AsyncIterator, Callable, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class DiscoveryEvent:
    ip: str
    port: int
    state: str = "open"  # "open" | "closed" | "filtered"
    banner: bytes = b""


class DiscoveryBackend(ABC):
    """Abstract interface for high-performance and safe port discovery backends."""

    name: str = "base"

    @abstractmethod
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
        """Execute discovery and return aggregated responsive hosts: [(ip, [open_ports])]."""
        raise NotImplementedError

    @abstractmethod
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
        """Stream open port discovery events as they appear."""
        raise NotImplementedError


def check_discovery_tools() -> Dict[str, bool]:
    """Return runtime capabilities for discovery backends."""
    return {
        "masscan": bool(shutil.which("masscan")),
        "nmap": bool(shutil.which("nmap")),
        "is_root": os.geteuid() == 0,
    }


def select_backend_name(
    target_count: int,
    requested_engine: str = "auto",
    tools: Optional[Dict[str, bool]] = None,
) -> str:
    """Select the best discovery engine name based on target size and tool availability."""
    if requested_engine not in ("auto", "", None):
        return requested_engine
    if tools is None:
        tools = check_discovery_tools()
    # Large networks (/16 or >= 4096 addresses) with root + masscan installed
    if target_count >= 4096 and tools.get("masscan") and tools.get("is_root"):
        return "masscan"
    return "asyncio"
