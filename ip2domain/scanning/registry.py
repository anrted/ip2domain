"""Explicit, ordered plugin composition (no import-time global registration)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable, Iterable, Optional, Tuple

from .models import ProbeContext, ProbeData


def _always_applicable(context: ProbeContext) -> bool:
    return True


@dataclass(frozen=True)
class ProbeSpec:
    probe_id: str
    run: Callable[[ProbeContext], Awaitable[ProbeData]]
    applies: Callable[[ProbeContext], bool] = _always_applicable
    # None deliberately preserves legacy probes' own timeout policy.
    timeout: Optional[float] = None
    categories: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.probe_id:
            raise ValueError("probe_id must not be empty")
        if self.timeout is not None and self.timeout <= 0:
            raise ValueError("timeout must be positive")


class ProbeRegistry:
    def __init__(self, probes: Iterable[ProbeSpec] = ()) -> None:
        self._probes = tuple(probes)
        ids = [p.probe_id for p in self._probes]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate probe_id")

    def __iter__(self):
        return iter(self._probes)

    def select(self, context: ProbeContext) -> Tuple[ProbeSpec, ...]:
        return tuple(p for p in self._probes if p.applies(context))

    def extend(self, *probes: ProbeSpec) -> "ProbeRegistry":
        """Return a new registry without mutating running scans."""
        return ProbeRegistry((*self._probes, *probes))
