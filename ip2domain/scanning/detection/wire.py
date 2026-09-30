"""Wire-level probe descriptors: port hints affect priority, never applicability."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Tuple


@dataclass(frozen=True)
class WireRequest:
    payload: bytes
    parse: Callable[[bytes], Optional[dict]]
    # Framing is independent of socket read boundaries.
    framing: str = "headers"
    minimum: int = 0
    limit: int = 8192


@dataclass(frozen=True)
class WireProbe:
    name: str
    transport: str
    categories: Tuple[str, ...]
    build: Callable
    port_hints: Tuple[int, ...] = ()
    secure_name: str = ""
    version: str = "1"

    def to_dict(self):
        return {
            "id": self.name, "transport": self.transport, "categories": list(self.categories),
            "port_hints": list(self.port_hints), "version": self.version,
            "secure_name": self.secure_name,
        }


class WireRegistry:
    """Immutable composition of wire codecs, not a second job scheduler."""
    def __init__(self, probes=()):
        self.probes = tuple(probes)
        keys = [(p.transport, p.name) for p in self.probes]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate wire probe")

    def select(self, transport, port, enabled=None):
        probes = [p for p in self.probes if p.transport == transport and (enabled is None or p.name in enabled)]
        return tuple(sorted(probes, key=lambda p: port not in p.port_hints))

    def extend(self, *probes):
        return WireRegistry((*self.probes, *probes))
