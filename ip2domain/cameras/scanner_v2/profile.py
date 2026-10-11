"""Camera compatibility profile for the domain-neutral probe runner.

The historical default/filter behaviour is intentional: SpRecord, Ingram and
generic HTTP always run; Sofia and DHIP also have port/alias activation rules.
Those rules belong here, not in the generic scheduler.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Mapping, Optional, Tuple

from ip2domain.scanning import Endpoint, ProbeContext, ProbeData, ProbeRegistry, ProbeSpec

from .models import HTTP_PORTS, HTTPS_PORTS, DVR_PORTS, RTSP_PORTS, RTMP_PORTS, ONVIF_PORTS, ROUTER_PORTS

DEFAULT_PROTOCOLS = frozenset({
    "onvif", "hikvision", "dahua", "axis", "rtsp", "hls", "rtmp", "webrtc", "vms", "router",
})
_PRIMARY_RTSP = {554, 555, 8554, 10554, 5544, 6554, 7447, 322, 5555}


def camera_context(
    ip: str,
    open_ports: List[int],
    credentials: List[Tuple[str, str]],
    protocols: Optional[List[str]] = None,
) -> ProbeContext:
    # Legacy API treats both None and [] as defaults.
    return ProbeContext(
        ip, tuple(Endpoint(p) for p in open_ports), tuple(credentials),
        frozenset(protocols) if protocols else DEFAULT_PROTOCOLS,
    )


def candidate_ports(context: ProbeContext) -> Dict[str, List[int]]:
    # Keep caller ordering for the legacy HTTP fallback (it probes only 4 ports).
    ports = [e.port for e in context.endpoints if e.transport == "tcp"]
    opened = set(ports)
    http = sorted(opened & (HTTP_PORTS | HTTPS_PORTS | DVR_PORTS | ROUTER_PORTS))
    if not http:
        http = [p for p in ports if p not in _PRIMARY_RTSP and p not in RTMP_PORTS]
    rtsp = sorted(opened & _PRIMARY_RTSP) or sorted(opened & RTSP_PORTS)
    return {
        "http": http,
        "rtsp": rtsp,
        "rtmp": sorted(opened & RTMP_PORTS),
        "onvif": sorted(opened & (ONVIF_PORTS | HTTP_PORTS)) or http,
    }


def build_camera_registry(probes: Mapping[str, Callable]) -> ProbeRegistry:
    """Bind existing protocol functions without changing their wire behaviour."""
    def enabled(context: ProbeContext) -> frozenset[str]:
        return DEFAULT_PROTOCOLS if context.enabled_probes is None else context.enabled_probes

    def adapt(key: str, group: str = "http", port: Optional[int] = None):
        async def run(context: ProbeContext) -> ProbeData:
            credentials = list(context.credentials)
            if port is not None:
                raw = await probes[key](context.ip, port, credentials)
            elif key == "rtmp":
                raw = await probes[key](context.ip, candidate_ports(context)[group])
            else:
                raw = await probes[key](context.ip, candidate_ports(context)[group], credentials)
            if not isinstance(raw, dict):
                raise TypeError("legacy probe must return dict")
            return ProbeData(detected=bool(raw.get("success")), attributes=raw)
        return run

    # External timeout caps applied by asyncio.wait_for() in runner.py.
    # None = probe manages its own timeouts internally.
    _PROBE_TIMEOUTS: Dict[str, Optional[float]] = {
        "onvif":      None,   # 2.5s x 8 creds x ports, already bounded
        "rtsp":       50.0,   # safety net; probe has internal 45s deadline
        "hikvision":  15.0,
        "dahua":      15.0,
        "axis":       12.0,
        "hls":        20.0,
        "rtmp":        8.0,
        "webrtc":     12.0,
        "vms":        12.0,
    }

    specs = []
    for key, group in (
        ("onvif", "onvif"), ("hikvision", "http"), ("dahua", "http"),
        ("axis", "http"), ("hls", "http"), ("rtsp", "rtsp"),
        ("rtmp", "rtmp"), ("webrtc", "http"), ("vms", "http"),
    ):
        def applies(context, key=key, group=group):
            return key in enabled(context) and (
                key not in ("rtsp", "rtmp") or bool(candidate_ports(context)[group])
            )
        specs.append(ProbeSpec(key, adapt(key, group), applies, categories=("video",),
                               timeout=_PROBE_TIMEOUTS.get(key)))

    specs.extend((
        ProbeSpec(
            "sofia", adapt("sofia", port=34567),
            lambda c: 34567 in c.ports() or bool(enabled(c) & {"sofia", "xiongmai"}),
            categories=("video",),
            timeout=8.0,
        ),
        ProbeSpec(
            "dahua_media", adapt("dahua_media", port=37777),
            lambda c: 37777 in c.ports() or bool(enabled(c) & {"dahua", "dhip"}),
            categories=("video",),
            timeout=8.0,
        ),
        ProbeSpec("sprecord", adapt("sprecord"), categories=("voice",), timeout=20.0),
        ProbeSpec("ingram", adapt("ingram"), categories=("video",), timeout=25.0),
        ProbeSpec("router", adapt("router", group="http"),
                  lambda c: "router" in enabled(c),
                  categories=("network", "router"), timeout=10.0),
        ProbeSpec("generic", adapt("generic"), categories=("web", "video"), timeout=10.0),
    ))
    return ProbeRegistry(specs)
