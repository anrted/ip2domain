"""Stage 2 compatibility facade: schedule probes, then project camera results.

Public probe imports are retained for existing callers and integrations. Network
fingerprinting, scheduling policy and result merging live in separate modules.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from ip2domain.scanning import HostObservation, ProbeRunner

from .models import CameraResult
from .aggregation import merge_camera_results, merge_host_cameras
from .profile import build_camera_registry, camera_context, candidate_ports
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


def camera_probe_runner() -> ProbeRunner:
    """Build a scan-local runner; importing modules does not register plugins."""
    return ProbeRunner(build_camera_registry({
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
        "generic": _probe_generic_http,
    }))


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
    """Backwards-compatible CameraResult API, including historical fallbacks."""
    groups = candidate_ports(camera_context(ip, open_ports, credentials, protocols))
    batches = [[p] for p in dict.fromkeys(open_ports)] if any(len(g) > 1 for g in groups.values()) else [open_ports]
    cameras = []
    for ports in batches:
        observation = await probe_host_observation_v2(ip, ports, credentials, protocols)
        results = {
            outcome.probe_id: dict(outcome.data.attributes)
            for outcome in observation.outcomes if outcome.status == "completed"
        }
        camera = merge_camera_results(ip, ports, results)
        if camera:
            cameras.append(camera)
    return merge_host_cameras(cameras)
