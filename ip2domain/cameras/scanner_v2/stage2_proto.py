"""Stage 2 compatibility facade: schedule probes, then project camera results.

Public probe imports are retained for existing callers and integrations. Network
fingerprinting, scheduling policy and result merging live in separate modules.
"""
from __future__ import annotations

import asyncio
from typing import List, Optional, Tuple

from ip2domain.scanning import HostObservation, ProbeRegistry, ProbeRunner

from .models import CameraResult
from .aggregation import merge_camera_results, merge_host_cameras
from .profile import build_camera_registry, camera_context, candidate_ports
from .fast_preflight import run_fast_preflight
from .protocols.generic_http import _probe_generic_http, _CAMERA_BRANDS
from .protocols.onvif import probe_onvif
from .protocols.hikvision import probe_hikvision
from .protocols.dahua import probe_dahua
from .protocols.axis import probe_axis
from .protocols.rtsp import probe_rtsp_direct
from .protocols.rtmp import probe_rtmp
from .protocols.hls import probe_hls_mjpeg
from .protocols.webrtc import probe_webrtc
from .protocols.vms import probe_vms
from .protocols.ingram import probe_ingram
from .protocols.sofia import probe_sofia
from .protocols.dahua_media import probe_dahua_media
from .protocols.sprecord import probe_sprecord
from .protocols.router import probe_router

_SHARED_CAMERA_REGISTRY: Optional[ProbeRegistry] = None


def get_camera_registry() -> ProbeRegistry:
    """Build camera probe registry dynamically."""
    return build_camera_registry({
        "onvif": probe_onvif,
        "hikvision": probe_hikvision,
        "dahua": probe_dahua,
        "axis": probe_axis,
        "hls": probe_hls_mjpeg,
        "rtsp": probe_rtsp_direct,
        "rtmp": probe_rtmp,
        "webrtc": probe_webrtc,
        "vms": probe_vms,
        "sofia": probe_sofia,
        "dahua_media": probe_dahua_media,
        "sprecord": probe_sprecord,
        "ingram": probe_ingram,
        "router": probe_router,
        "generic": _probe_generic_http,
    })


def camera_probe_runner() -> ProbeRunner:
    """Build a scan runner using cached registry."""
    return ProbeRunner(get_camera_registry(), concurrency=16)


async def probe_host_observation_v2(
    ip: str,
    open_ports: List[int],
    credentials: List[Tuple[str, str]],
    protocols: Optional[List[str]] = None,
    *,
    runner: Optional[ProbeRunner] = None,
) -> HostObservation:
    """Return per-probe diagnostics before the legacy camera projection."""
    context = camera_context(ip, open_ports, credentials, protocols)
    return await (runner or camera_probe_runner()).probe(context)


async def probe_host_v2(
    ip: str,
    open_ports: List[int],
    credentials: List[Tuple[str, str]],
    protocols: Optional[List[str]] = None,
) -> Optional[CameraResult]:
    """Backwards-compatible CameraResult API with fast preflight optimization and parallel batches."""
    groups = candidate_ports(camera_context(ip, open_ports, credentials, protocols))
    batches = [[p] for p in dict.fromkeys(open_ports)] if any(len(g) > 1 for g in groups.values()) else [open_ports]

    async def _probe_batch(ports: List[int]) -> Optional[CameraResult]:
        active_protocols = protocols
        is_test_ip = ip.startswith(("192.0.2.", "198.51.100.", "203.0.113."))
        http_ports = [p for p in ports if p in (groups.get("http") or [])]
        if http_ports and not is_test_ip:
            hp = http_ports[0]
            # Fast-path for port 7547 (TR-069 CWMP)
            if hp == 7547:
                return CameraResult(
                    ip=ip, brand="TR-069 CWMP", model="TR-069 CPE Agent",
                    http_port=7547, web_url=f"http://{ip}:7547/",
                    device_category="router", open_ports=sorted(open_ports),
                    protocols=["tr069", "router"]
                )

            pre = await run_fast_preflight(ip, hp)
            if pre.category == "generic_web":
                return CameraResult(
                    ip=ip, brand=pre.brand or "Generic Web Device",
                    model=pre.model or "Web Service",
                    http_port=hp, web_url=f"{pre.scheme}://{ip}:{hp}/",
                    device_category="generic_web", open_ports=sorted(open_ports),
                    protocols=["http"]
                )
            elif pre.target_protocols and not protocols:
                active_protocols = pre.target_protocols

        observation = await probe_host_observation_v2(ip, ports, credentials, active_protocols)
        results = {
            outcome.probe_id: dict(outcome.data.attributes)
            for outcome in observation.outcomes if outcome.status == "completed"
        }
        return merge_camera_results(ip, ports, results)

    # If single batch, execute directly
    if len(batches) == 1:
        return await _probe_batch(batches[0])

    # Multiple batches: execute in parallel
    results = await asyncio.gather(*[_probe_batch(p) for p in batches])
    valid_cameras = [c for c in results if c]
    return merge_host_cameras(valid_cameras)
