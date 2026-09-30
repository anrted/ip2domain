"""Curated media path wordlists for automated HLS, MJPEG, and snapshot detection.

Consolidates all paths from Camera Scanner v2 (hls.py, cam_db_compiled.json).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# HLS Manifest paths
HLS_PATHS: Tuple[str, ...] = (
    "/live/index.m3u8",
    "/hls/live.m3u8",
    "/stream.m3u8",
    "/stream/live.m3u8",
    "/live.m3u8",
    "/api/streams/main.m3u8",
    "/hls/stream.m3u8",
    "/live/stream.m3u8",
)

# MJPEG Stream paths
MJPEG_PATHS: Tuple[str, ...] = (
    "/axis-cgi/mjpg/video.cgi",
    "/cgi-bin/mjpg/video.cgi",
    "/ISAPI/Streaming/channels/101/httpPreview",
    "/ISAPI/Streaming/channels/1/httpPreview",
    "/video.mjpg",
    "/videostream.cgi",
    "/cgi-bin/videostream.cgi",
    "/stream/video.mjpeg",
    "/mjpeg/video.mjpeg",
    "/video/mjpg.cgi",
    "/jpeg/stream=0",
    "/stw-cgi/video.cgi?msubmenu=stream&action=view&Profile=1&CodecType=MJPEG",
    "/api/camera/snapshot?width=640&height=480&fps=15",
)

# Snapshot paths
SNAPSHOT_PATHS: Tuple[str, ...] = (
    "/ISAPI/Streaming/channels/101/picture",
    "/ISAPI/Streaming/channels/1/picture",
    "/axis-cgi/jpg/image.cgi",
    "/axis-cgi/jpg/image.cgi?camera=1",
    "/cgi-bin/images_cgi?channel=0",
    "/cgi-bin/images_cgi?channel=1",
    "/api/camera/snapshot?width=640&height=480",
    "/api/camera/snapshot",
    "/snap.jpg",
    "/snapshot.jpg",
    "/snapshot.cgi",
    "/cgi-bin/snapshot.cgi",
    "/tmpfs/auto.jpg",
    "/tmpfs/snap.jpg",
    "/image.jpg",
    "/jpg/image.jpg",
    "/onvif-http/snapshot",
    "/jpeg/view.html",
    "/snapshot/view.jpg",
    "/stw-cgi/video.cgi?msubmenu=snapshot&action=view&Profile=1&Channel=0",
    "/stw-cgi/video.cgi?msubmenu=snapshot&action=view",
    "/cgi-bin/operator/snapshot.cgi?mainstream",
    "/cgi-bin/operator/snapshot.cgi?substream",
    "/LAPI/V1.0/Channels/0/Media/Video/Source/0/Snapshot",
    "/webcapture.jpg",
    "/action/snap",
    "/dms?nowprofileid=1",
)

_COMPILED_DB_PATH = Path(__file__).resolve().parent.parent.parent / "cameras" / "scanner_v2" / "cam_db_compiled.json"
_COMPILED_DB: Optional[dict] = None


def _get_compiled_db() -> dict:
    global _COMPILED_DB
    if _COMPILED_DB is None:
        if _COMPILED_DB_PATH.exists():
            try:
                with open(_COMPILED_DB_PATH, "r", encoding="utf-8") as f:
                    _COMPILED_DB = json.load(f)
            except Exception as exc:
                logger.warning("Failed to load compiled camera DB: %s", exc)
                _COMPILED_DB = {}
        else:
            _COMPILED_DB = {}
    return _COMPILED_DB or {}


def get_candidate_media_paths(brand: str = "", limit: int = 48) -> List[str]:
    """Return an ordered, deduplicated list of candidate media paths to probe.

    Priority:
    1. High-value HLS paths (for live web video)
    2. High-value MJPEG stream paths
    3. Vendor-specific paths if brand is known
    4. Top vendor-neutral snapshot paths
    5. Top HTTP paths from compiled DB
    """
    candidates: List[str] = []
    seen = set()

    def add(p: str):
        if not p or p in seen:
            return
        # Ensure starts with '/'
        clean = p.strip()
        if not clean.startswith("/"):
            clean = "/" + clean
        if clean not in seen:
            seen.add(clean)
            candidates.append(clean)

    # 1. HLS paths
    for p in HLS_PATHS:
        add(p)

    # 2. Key MJPEG paths
    for p in MJPEG_PATHS[:8]:
        add(p)

    # 3. Brand paths if known
    if brand:
        b_norm = brand.lower().strip()
        db = _get_compiled_db()
        brand_http = db.get("brand_http", {})
        if b_norm in brand_http:
            for p in brand_http[b_norm]:
                add(p)
        else:
            for k, paths in brand_http.items():
                if len(k) >= 3 and (k in b_norm or b_norm in k):
                    for p in paths:
                        add(p)
                    break

    # 4. Snapshot paths
    for p in SNAPSHOT_PATHS:
        add(p)

    # 5. Top compiled HTTP endpoints
    db = _get_compiled_db()
    for p in db.get("top_http", [])[:20]:
        add(p)

    return candidates[:limit]
