"""Data models for Camera Scanner v2 results."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class StreamInfo:
    """Represents a single discovered media stream."""
    url: str
    stream_type: str = "rtsp"        # rtsp | mjpeg | hls | rtmp | udp_rtp
    codec: str = ""                  # H264 | H265 | MJPEG | MPEG4
    resolution: str = ""             # e.g. "1920x1080"
    width: int = 0
    height: int = 0
    verified: bool = False           # frame captured successfully
    screenshot_path: str = ""        # local filesystem path
    channel: int = 1
    subtype: int = 0                 # 0=main, 1=sub

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "type": self.stream_type,
            "codec": self.codec,
            "resolution": self.resolution,
            "width": self.width,
            "height": self.height,
            "verified": self.verified,
            "screenshot": self.screenshot_path,
            "channel": self.channel,
            "subtype": self.subtype,
        }


@dataclass
class CameraResult:
    """Represents a discovered IP camera with all metadata."""
    ip: str
    brand: str = ""                  # Hikvision | Dahua | Axis | ONVIF | Generic
    model: str = ""
    serial: str = ""
    firmware: str = ""
    protocols: List[str] = field(default_factory=list)   # detected protocol names
    streams: List[StreamInfo] = field(default_factory=list)
    http_port: int = 0
    rtsp_port: int = 0
    onvif_port: int = 0
    rtmp_port: int = 0
    open_ports: List[int] = field(default_factory=list)
    credentials: Dict[str, str] = field(default_factory=dict)  # {"user": "admin", "password": ""}
    raw_probe: Dict[str, Any] = field(default_factory=dict)
    city: str = ""                   # Discovered city name (e.g. "Новокузнецк")
    region: str = ""                 # Region / Oblast
    country_code: str = ""           # "RU" | "BY"
    isp: str = ""                    # ISP / Autonomous System
    in_go2rtc: bool = False
    timestamp: str = ""

    @property
    def best_stream(self) -> Optional[StreamInfo]:
        """Return highest-quality verified stream."""
        verified = [s for s in self.streams if s.verified]
        if verified:
            return max(verified, key=lambda s: s.width * s.height if s.width else 0)
        return self.streams[0] if self.streams else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "brand": self.brand,
            "model": self.model,
            "serial": self.serial,
            "firmware": self.firmware,
            "protocols": self.protocols,
            "streams": [s.to_dict() for s in self.streams],
            "http_port": self.http_port,
            "rtsp_port": self.rtsp_port,
            "onvif_port": self.onvif_port,
            "rtmp_port": self.rtmp_port,
            "open_ports": self.open_ports,
            "credentials": self.credentials,
            "city": self.city,
            "region": self.region,
            "country_code": self.country_code,
            "isp": self.isp,
            "in_go2rtc": self.in_go2rtc,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanJob:
    """Runtime state for an active v2 scan job."""
    job_id: str
    status: str = "queued"           # queued | running | completed | cancelled | error
    total_targets: int = 0
    engine_used: str = "asyncio"     # asyncio | masscan | nmap_syn

    # Stage progress
    stage0_status: str = "pending"   # pending | running | done | skipped
    stage0_found: int = 0
    stage1_status: str = "pending"
    stage1_scanned: int = 0
    stage1_responsive: int = 0
    stage2_status: str = "pending"
    stage2_completed: int = 0
    stage2_total: int = 0
    stage3_status: str = "pending"
    stage3_completed: int = 0
    stage4_status: str = "pending"
    stage4_completed: int = 0

    progress_pct: int = 0
    current_ip: str = ""
    stage: str = ""
    results: List[CameraResult] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)
    cancelling: bool = False
    cancelled: bool = False
    error: str = ""

    def is_cancelled(self) -> bool:
        return self.cancelling or self.cancelled

    def add_log(self, msg: str) -> None:
        from datetime import datetime
        self.logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        if len(self.logs) > 200:
            self.logs = self.logs[-200:]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "total_targets": self.total_targets,
            "engine_used": self.engine_used,
            "stages": {
                "discovery": {"status": self.stage0_status, "found": self.stage0_found},
                "port_sweep": {
                    "status": self.stage1_status,
                    "scanned": self.stage1_scanned,
                    "responsive": self.stage1_responsive,
                },
                "fingerprint": {
                    "status": self.stage2_status,
                    "completed": self.stage2_completed,
                    "total": self.stage2_total,
                },
                "capture": {"status": self.stage3_status, "completed": self.stage3_completed},
                "geolocation": {"status": self.stage4_status, "completed": self.stage4_completed},
            },
            "progress_pct": self.progress_pct,
            "current_ip": self.current_ip,
            "stage": self.stage,
            "results_count": len(self.results),
            "results": [r.to_dict() for r in self.results],
            "logs": self.logs,
            "error": self.error,
        }


# Default credential pairs to try (user, password)
DEFAULT_CREDENTIALS = [
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "12345admin"),
    ("admin", "admin123"),
    ("admin", "admin12345"),
    ("admin", "password"),
    ("admin", "pass"),
    ("admin", "888888"),
    ("admin", "666666"),
    ("admin", "111111"),
    ("admin", "999999"),
    ("root", ""),
    ("root", "root"),
    ("root", "pass"),
    ("root", "password"),
    ("root", "123456"),
    ("root", "admin"),
    ("root", "12345"),
    ("service", "service"),
    ("user", "user"),
    ("guest", "guest"),
]

# Extended camera port list for v2
CAMERA_PORTS_V2 = (
    # RTSP / RTSPS
    554, 555, 8554, 10554, 5544, 6554, 7447, 322, 5555,
    # HTTP camera web interfaces / WebRTC / WHEP
    80, 81, 85, 88, 99, 1984,
    8000, 8001, 8002, 8005, 8008, 8080, 8081, 8082, 8083, 8085, 8086, 8087, 8088, 8089, 8090, 8099,
    2020, 7001, 8888, 8889, 9000, 9999,
    # HTTPS
    443, 8443,
    # DVR/NVR specific / VMS
    37777, 34567, 8899, 37810, 4550, 5550,
    # RTMP
    1935,
    # ONVIF / Frigate alternate
    5000,
    # Hikvision SDK
    49152, 49153, 49154,
    # Additional
    1026, 7070, 4747, 2600,
)

# Ports that indicate HTTP services
HTTP_PORTS = {80, 81, 85, 88, 99, 1984, 2020, 7001, 8000, 8001, 8002, 8005, 8008, 8080, 8081, 8082, 8083, 8085, 8086, 8087, 8088, 8089, 8090, 8099, 8888, 8889, 8899, 9000, 9999}
HTTPS_PORTS = {443, 8443}
RTSP_PORTS = {554, 555, 8554, 10554, 5544, 6554, 7447, 322, 5555}
RTMP_PORTS = {1935}
DVR_PORTS = {37777, 34567, 8899, 37810, 4550, 5550}
ONVIF_PORTS = {80, 8080, 8899, 5000, 8000}

