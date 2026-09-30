"""Public endpoint documents with bounded evidence, distinct from legacy cameras."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import re


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def public_text(value, limit=512):
    """Do not export arbitrary packets, credentials, cookies or URL query strings."""
    value = str(value)
    value = re.sub(r"(?i)(://)[^/\s@]+@", r"\1[redacted]@", value)
    value = re.sub(r"(?i)(password|token|secret|authorization|cookie)\s*[:=]\s*\S+", r"\1=[redacted]", value)
    return "".join(c for c in value if c.isprintable())[:limit]


@dataclass
class EndpointObservation:
    ip: str
    port: int
    transport: str
    state: str = "unknown"
    network_id: str = "local"
    hostname: str = ""
    services: list = field(default_factory=list)
    classifications: list = field(default_factory=list)
    device_info: dict = field(default_factory=dict)
    attempts: list = field(default_factory=list)
    observed_at: str = field(default_factory=utc_now)
    schema_version: int = 2
    evidence: list = field(default_factory=list)
    fingerprints: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    authentication: list = field(default_factory=list)
    streams: list = field(default_factory=list)
    channels: list = field(default_factory=list)
    devices: list = field(default_factory=list)
    stage_results: dict = field(default_factory=dict)

    def service(self, protocol, categories=(), **attributes):
        item = {
            "protocol": protocol, "categories": list(categories),
            "attributes": attributes,
        }
        if item not in self.services:
            self.services.append(item)

    def attempt(self, detector, status, **details):
        self.attempts.append({"detector": detector, "version": "1", "status": status, **details})

    async def checkpoint(self):
        """Optional execution-local persistence hook, excluded from serialization."""
        callback = getattr(self, "_checkpoint", None)
        if callback is not None:
            await callback(self)

    def to_dict(self):
        from .evidence import sanitize_document
        return sanitize_document(asdict(self))
