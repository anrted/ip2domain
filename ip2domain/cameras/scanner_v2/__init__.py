"""Camera Scanner v2 — Multi-protocol IP camera discovery engine."""
from .models import CameraResult, StreamInfo, ScanJob

__all__ = ["run_v2_scan_pipeline", "CameraResult", "StreamInfo", "ScanJob"]


def __getattr__(name):
    # Importing a data model must not initialize the pipeline and all probes.
    if name == "run_v2_scan_pipeline":
        from .engine import run_v2_scan_pipeline
        globals()[name] = run_v2_scan_pipeline
        return run_v2_scan_pipeline
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
