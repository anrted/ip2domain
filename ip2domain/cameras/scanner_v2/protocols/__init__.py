"""Protocol fingerprint modules for Camera Scanner v2."""
from importlib import import_module

_EXPORTS = {
    "probe_onvif": "onvif",
    "probe_hikvision": "hikvision",
    "probe_dahua": "dahua",
    "probe_axis": "axis",
    "probe_rtsp_direct": "rtsp",
    "probe_rtmp": "rtmp",
    "probe_hls_mjpeg": "hls",
    "probe_sprecord": "sprecord",
    "run_local_discovery": "discovery",
}
__all__ = list(_EXPORTS)


def __getattr__(name):
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    probe = getattr(import_module(f".{module_name}", __name__), name)
    globals()[name] = probe
    return probe
