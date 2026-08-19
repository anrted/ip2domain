from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ProviderCapabilities(str, Enum):
    DISCOVERY = "discovery"
    SNAPSHOT = "snapshot"
    STREAM = "stream"
    EMBED = "embed"
    GEOCODING = "geocoding"


@dataclass(frozen=True)
class CameraEndpoint:
    kind: str
    url: str
    priority: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Camera:
    provider_id: str
    external_id: str
    title: str = ""
    address: str = ""
    camera_type: str = ""
    available: bool = True
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    endpoints: List[CameraEndpoint] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["endpoints"] = [endpoint.to_dict() for endpoint in self.endpoints]
        return result
