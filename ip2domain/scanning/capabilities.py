"""Honest capability manifest: catalog entries are not implemented detectors."""
import shutil

from .classification import DEVICE_TYPES
from .policies import PROFILES
from .detection.catalog import native_registry

PLANNED = [
    "rtp", "rtcp", "rtmp", "webrtc", "srt",
    "tr-069", "ethernet-ip", "dnp3", "bacnet-ip",
    "smb", "knx-ip", "dlms-cosem", "ipp", "lpd", "jetdirect",
    "rdp", "ica", "mavlink", "ocpp", "dicom", "hl7",
]


def capabilities():
    registry = native_registry()
    native = {"tcp": ["tls", "ssh", "ftp", "smtp", "imap", "pop3", "telnet"], "udp": []}
    for probe in registry.probes:
        native[probe.transport].append(probe.name)
        if probe.secure_name:
            native[probe.transport].append(probe.secure_name)
    return {
        "schema_version": 1,
        "profiles": PROFILES,
        "execution": {
            "default": "staged",
            "stages": ["discover", "identify", "enrich"],
            "durable_handoffs": True,
            "bounded_queue": True,
            "legacy_resume": "Sequential for jobs without execution_mode",
        },
        "native": native,
        "native_probes": [p.to_dict() for p in registry.probes],
        "opt_in_web_enrichment": {
            "protocols": ["websocket", "webdav", "hls", "mjpeg", "mpeg-ts", "http_snapshot"],
            "limits": "Explicit paths, up to 8192 body bytes; no redirects, media downloads or playback verification",
        },
        "optional_backends": {
            "nmap": {
                "available": bool(shutil.which("nmap")),
                "mode": "TCP service detection, installed signature database; no NSE",
                "coverage": "depends on installed nmap-service-probes; not guaranteed",
            },
        },
        "camera_legacy": {
            "available": True, "api": "/api/v2",
            "note": "Existing camera/media features retained separately; not yet universal enrichment",
        },
        "planned_native": PLANNED,
        "device_type_catalog": DEVICE_TYPES,
        "limitations": [
            "No claim to identify every protocol.",
            "UDP silence is open_or_filtered, not closed.",
            "Only explicit product signatures yield a device classification.",
            "Full TCP uses ports 1-65535; UDP full range is opt-in.",
            "Industrial/medical profiles still make TCP connections; not passive capture.",
            "One fenced executor per inventory database; distributed agents not yet implemented.",
            "Nmap subprocess rates are per process, not included in the native rate limiter.",
        ],
    }
