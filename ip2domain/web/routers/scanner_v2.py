"""Camera Scanner v2 — FastAPI router.

Endpoints:
  POST   /api/v2/scan                 Start new scan job
  GET    /api/v2/scan/{job_id}        Get job status + results
  POST   /api/v2/scan/{job_id}/cancel Cancel job
  GET    /api/v2/results              All stored results
  GET    /api/v2/results/{ip}         Single result by IP
  DELETE /api/v2/results              Clear all results
  GET    /api/v2/tools                Available tools status
  GET    /api/v2/stats                DB statistics
  POST   /api/v2/results/{ip}/go2rtc  Add camera to go2rtc
  GET    /api/v2/capture              Serve screenshot by path
"""
from __future__ import annotations

import asyncio
import os
import time
import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from .common import storage

router = APIRouter(prefix="/api/v2", tags=["scanner_v2"])

# Capture directory for v2 screenshots
_V2_CAPTURE_DIR = Path(__file__).resolve().parent.parent / "v2_captures"
_V2_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

# Lazy import engine (avoids importing at startup if not needed)
def _get_engine():
    from ip2domain.cameras.scanner_v2.engine import (
        create_job, cancel_job, get_job, run_v2_scan_pipeline,
    )
    from ip2domain.cameras.scanner_v2.stage1_sweep import check_tools
    return create_job, cancel_job, get_job, run_v2_scan_pipeline, check_tools


# ─────────────────────────────────────────────────────────────────────────────
# Request models
# ─────────────────────────────────────────────────────────────────────────────

class CredentialPair(BaseModel):
    user: str = "admin"
    password: str = ""


class ScanRequest(BaseModel):
    targets: str                                     # newline-separated IPs/CIDRs/ranges
    engine: str = "auto"                             # auto | asyncio | masscan | nmap_syn
    masscan_rate: int = 50000
    concurrency: int = 150
    port_timeout: float = 1.2
    stage2_concurrency: int = 20
    protocols: List[str] = []                        # empty = all
    credentials: List[CredentialPair] = []           # empty = defaults
    capture_frames: bool = True
    local_discovery: bool = True
    skip_existing: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/tools")
async def get_tools():
    """Return availability of scanning tools."""
    try:
        from ip2domain.cameras.scanner_v2.stage1_sweep import check_tools
        tools = check_tools()
    except Exception as exc:
        tools = {"error": str(exc)}
    return JSONResponse(content=tools)


@router.post("/scan")
async def start_scan(req: ScanRequest):
    """Start a new Camera Scanner v2 job."""
    active_job = storage.get_active_v2_job()
    if active_job:
        raise HTTPException(
            status_code=409,
            detail=f"Сканирование уже выполняется (ID: {active_job.get('job_id')}). Дождитесь завершения или нажмите «Отмена».",
        )

    create_job, _, _, run_v2_scan_pipeline, _ = _get_engine()

    job_id = f"v2_{int(time.time())}_{uuid.uuid4().hex[:6]}"
    job = create_job(job_id)


    credentials = (
        [(c.user, c.password) for c in req.credentials]
        if req.credentials
        else None
    )

    async def _run():
        await run_v2_scan_pipeline(
            job_id=job_id,
            targets_str=req.targets,
            engine=req.engine,
            masscan_rate=req.masscan_rate,
            concurrency=req.concurrency,
            port_timeout=req.port_timeout,
            stage2_concurrency=req.stage2_concurrency,
            credentials=credentials,
            protocols=req.protocols or None,
            capture_frames=req.capture_frames,
            local_discovery=req.local_discovery,
            capture_dir=_V2_CAPTURE_DIR,
            storage=storage,
        )

    asyncio.create_task(_run())
    return JSONResponse(content={"job_id": job_id, "status": "queued"}, status_code=202)


@router.get("/scan/{job_id}")
async def get_scan_status(job_id: str):
    """Return current job state including results."""
    _, _, get_job, _, _ = _get_engine()
    job = get_job(job_id)
    if not job:
        # Try from DB
        db_job = storage.get_v2_job(job_id)
        if db_job:
            db_job["results"] = storage.get_v2_results(limit=1000)
            return JSONResponse(content=db_job)
        raise HTTPException(status_code=404, detail="Job not found")
    return JSONResponse(content=job.to_dict())


@router.post("/scan/{job_id}/cancel")
async def cancel_scan(job_id: str):
    _, cancel_job, _, _, _ = _get_engine()
    ok = cancel_job(job_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Job not found or already finished")
    return {"cancelled": True, "job_id": job_id}


@router.get("/results")
async def get_results(
    limit: int = Query(default=500, le=2000),
    brand: str = Query(default=""),
    protocol: str = Query(default=""),
):
    """Return all stored v2 results from DB."""
    results = storage.get_v2_results(limit=limit, brand=brand, protocol=protocol)
    return JSONResponse(content={"results": results, "total": len(results)})


@router.get("/results/{ip}")
async def get_result(ip: str):
    result = storage.get_v2_result(ip)
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")
    return JSONResponse(content=result)


@router.delete("/results")
async def clear_results():
    storage.clear_v2_results()
    return {"cleared": True}


@router.get("/stats")
async def get_stats():
    stats = storage.get_v2_stats()
    return JSONResponse(content=stats)


@router.post("/results/{ip}/go2rtc")
async def add_to_go2rtc(
    ip: str,
    stream_url: str = Query(...),
    stream_name: str = Query(default=""),
):
    """Add a discovered camera stream to go2rtc."""
    import httpx
    from .common import GO2RTC_API_URL

    # Generate stream name: v2_{ip}_{channel_index}
    if not stream_name:
        # Count existing v2 streams with this IP prefix
        safe_ip = ip.replace(".", "_")
        stream_name = f"v2_{safe_ip}_1"

    go2rtc_url = f"{GO2RTC_API_URL}/api/streams"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.put(
                go2rtc_url,
                params={"name": stream_name},
                content=stream_url,
            )
            if resp.status_code in (200, 201, 204):
                storage.mark_v2_result_go2rtc(ip, True)
                return {"success": True, "stream_name": stream_name}
            return {"success": False, "status_code": resp.status_code}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@router.get("/capture")
async def serve_capture(path: str = Query(...)):
    """Serve a v2 screenshot by absolute path."""
    p = Path(path)
    # Security: only serve files within v2_captures dir
    try:
        p.resolve().relative_to(_V2_CAPTURE_DIR.resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="Access denied")
    if not p.exists():
        raise HTTPException(status_code=404, detail="Screenshot not found")
    return FileResponse(str(p), media_type="image/jpeg")


@router.api_route("/preview", methods=["GET", "POST", "HEAD"])
async def get_stream_preview(
    ip: str = Query(..., description="Camera IP"),
    stream_url: str = Query(..., description="RTSP / RTMP / HLS stream URL"),
    user: str = Query("", description="Optional username"),
    password: str = Query("", description="Optional password"),
):
    """Capture and return on-demand live snapshot for any camera stream."""
    from ip2domain.cameras.scanner_v2.stage3_stream import capture_stream_frame, _download_http_snapshot

    creds = {"user": user, "password": password} if user else None
    
    ok = False
    path = ""
    codec, w, h = "", 0, 0

    if (stream_url.startswith("http://") or stream_url.startswith("https://")) and ".m3u8" not in stream_url and "mjpg" not in stream_url.lower() and "video.cgi" not in stream_url.lower():
        # Try direct HTTP snapshot download first
        snap_path = await _download_http_snapshot(stream_url, _V2_CAPTURE_DIR, credentials=creds)
        if snap_path and Path(snap_path).exists():
            ok = True
            path = snap_path
            codec = "JPEG"

    if not ok:
        stream_type = "rtmp" if stream_url.startswith("rtmp://") else ("hls" if ".m3u8" in stream_url else ("mjpeg" if "mjpg" in stream_url.lower() else "rtsp"))
        ok, path, codec, w, h = await capture_stream_frame(
            stream_url=stream_url,
            stream_type=stream_type,
            capture_dir=_V2_CAPTURE_DIR,
            credentials=creds,
        )


    if ok and Path(path).exists():
        # Update stream metadata in database if result exists
        try:
            res = storage.get_v2_result(ip)
            if res:
                for s in res.get("streams", []):
                    if s.get("url") == stream_url:
                        s["verified"] = True
                        s["screenshot"] = path
                        s["codec"] = codec
                        s["resolution"] = f"{w}x{h}" if w and h else ""
                storage.save_v2_result(res)
        except Exception:
            pass

        return FileResponse(str(path), media_type="image/jpeg", headers={"Cache-Control": "private, max-age=5"})

    raise HTTPException(status_code=404, detail="Stream frame unavailable or authentication failed")

