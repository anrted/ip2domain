"""Separate network endpoints, observed services and device classifications.

Protocol/category identifiers are open strings, not a closed camera enum.
One service may belong to several categories (e.g. RTP: video AND voice).
Device classifications are evidence, never inferred from an open port alone.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple


@dataclass(frozen=True)
class Endpoint:
    port: int
    transport: str = "tcp"

    def __post_init__(self) -> None:
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if self.transport not in ("tcp", "udp"):
            raise ValueError("transport must be tcp or udp")

    def to_dict(self) -> Dict[str, Any]:
        return {"port": self.port, "transport": self.transport}


@dataclass(frozen=True)
class ProbeContext:
    ip: str
    endpoints: Tuple[Endpoint, ...] = ()
    credentials: Tuple[Tuple[str, str], ...] = field(default=(), repr=False)
    # None = profile defaults; empty set = no explicitly selected probes.
    enabled_probes: Optional[frozenset[str]] = None

    def ports(self, transport: str = "tcp") -> Tuple[int, ...]:
        return tuple(sorted({e.port for e in self.endpoints if e.transport == transport}))


@dataclass(frozen=True)
class ServiceObservation:
    protocol: str
    endpoint: Endpoint
    categories: Tuple[str, ...] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol, "endpoint": self.endpoint.to_dict(),
            "categories": list(self.categories), "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class DeviceClassification:
    kind: str
    evidence: Tuple[str, ...] = ()
    confidence: float = 1.0

    def __post_init__(self) -> None:
        if not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind, "evidence": list(self.evidence),
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class ProbeData:
    detected: bool = False
    services: Tuple[ServiceObservation, ...] = ()
    classifications: Tuple[DeviceClassification, ...] = ()
    # Adapter-private payload; may contain credentials. Never exported by default.
    attributes: Mapping[str, Any] = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class ProbeOutcome:
    probe_id: str
    status: str  # completed | timeout | error
    data: ProbeData = field(default_factory=ProbeData)
    error_type: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "probe_id": self.probe_id, "status": self.status,
            "detected": self.data.detected, "error_type": self.error_type,
            "services": [s.to_dict() for s in self.data.services],
            "classifications": [c.to_dict() for c in self.data.classifications],
        }


@dataclass(frozen=True)
class HostObservation:
    ip: str
    endpoints: Tuple[Endpoint, ...] = ()
    outcomes: Tuple[ProbeOutcome, ...] = ()

    @property
    def detected(self) -> bool:
        return any(o.status == "completed" and o.data.detected for o in self.outcomes)

    def to_dict(self) -> Dict[str, Any]:
        # No requirement for video streams, camera brand or ffmpeg.
        return {
            "schema_version": 1, "ip": self.ip,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "detected": self.detected,
            "probes": [o.to_dict() for o in self.outcomes],
        }
