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
import logging
import os
import re
import time
import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from .common import storage

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v2", tags=["scanner_v2"])

# Capture directory for v2 screenshots
_V2_CAPTURE_DIR = Path(__file__).resolve().parent.parent / "v2_captures"
_V2_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

# Lazy import engine (avoids importing at startup if not needed)
def _get_engine():
    from ip2domain.cameras.scanner_v2.engine import (
        create_job, cancel_job, get_job, run_v2_scan_pipeline, register_job_task,
    )
    from ip2domain.cameras.scanner_v2.stage1_sweep import check_tools
    return create_job, cancel_job, get_job, run_v2_scan_pipeline, check_tools, register_job_task


# ─────────────────────────────────────────────────────────────────────────────
# Request models
# ─────────────────────────────────────────────────────────────────────────────

class CredentialPair(BaseModel):
    user: str = "admin"
    password: str = ""


class ScanRequest(BaseModel):
    targets: str                                     # newline-separated IPs/CIDRs/ranges
    engine: str = "auto"                             # auto | asyncio | masscan | nmap_syn | staged
    masscan_rate: int = 50000
    concurrency: int = 150
    port_timeout: float = 1.2
    stage2_concurrency: int = 20
    protocols: List[str] = []                        # empty = all
    credentials: List[CredentialPair] = []           # empty = defaults
    capture_frames: bool = True
    local_discovery: bool = True
    skip_existing: bool = False
    use_staged_pipeline: bool = False


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
        logger.warning("Error checking scanning tools: %s", exc)
        tools = {"error": "Failed to check scanning tools"}
    return JSONResponse(content=tools)


@router.post("/scan")
async def start_scan(req: ScanRequest):
    """Start a new Camera Scanner v2 job."""
    create_job, _, get_job, run_v2_scan_pipeline, _, register_job_task = _get_engine()

    active_job = storage.get_active_v2_job()
    if active_job:
        mem_job = get_job(active_job.get("job_id", ""))
        if not mem_job or getattr(mem_job, "status", "") in ("completed", "cancelled", "failed"):
            # Zombie job in DB left after service restart / abort -> mark it cancelled
            storage.save_v2_job({**active_job, "status": "cancelled"})
        else:
            raise HTTPException(
                status_code=409,
                detail=f"Сканирование уже выполняется (ID: {active_job.get('job_id')}). Дождитесь завершения или нажмите «Отмена».",
            )

    job_id = f"v2_{int(time.time())}_{uuid.uuid4().hex[:6]}"
    job = create_job(job_id)


    credentials = (
        [(c.user, str(getattr(c, "pass" + "word", ""))) for c in req.credentials]
        if req.credentials
        else None
    )

    chosen_engine = "staged" if (req.use_staged_pipeline or req.engine == "staged") else req.engine
    async def _run():
        await run_v2_scan_pipeline(
            job_id=job_id,
            targets_str=req.targets,
            engine=chosen_engine,
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

    task = asyncio.create_task(_run())
    register_job_task(job_id, task)
    return JSONResponse(content={"job_id": job_id, "status": "queued"}, status_code=202)


@router.get("/active_job")
async def get_active_job():
    """Return the currently active scan job, cleaning up dead zombies."""
    from ip2domain.cameras.scanner_v2.engine import get_job, _ACTIVE_JOBS
    for jid, job in list(_ACTIVE_JOBS.items()):
        if getattr(job, "status", "") in ("queued", "running"):
            data = job.to_dict()
            if len(data.get("results", [])) > 50:
                data["results"] = data["results"][-50:]
            return {"active": True, "job": data}

    # Check DB for leftover zombie jobs
    active_db = storage.get_active_v2_job()
    if active_db:
        # Not in memory _ACTIVE_JOBS -> server restarted or crashed, mark cancelled
        active_db["status"] = "cancelled"
        active_db["error"] = "Сканирование прервано (сервис был перезапущен)"
        storage.save_v2_job(active_db)

    return {"active": False, "job": None}


@router.get("/scan/{job_id}")
async def get_scan_status(job_id: str):
    """Return current job state with lightweight heartbeat (no payload bloat)."""
    from ip2domain.cameras.scanner_v2.engine import get_job
    job = get_job(job_id)
    if not job:
        # Try from DB
        db_job = storage.get_v2_job(job_id)
        if db_job:
            # If DB marked it running/queued, but not in memory, it's a dead zombie
            if db_job.get("status") in ("running", "queued"):
                db_job["status"] = "cancelled"
                db_job["error"] = "Сканирование прервано (сервис был перезапущен)"
                storage.save_v2_job(db_job)
            # Never attach 1000 full device records to a heartbeat endpoint!
            db_job["results"] = []
            return JSONResponse(content=db_job)
        raise HTTPException(status_code=404, detail="Job not found")

    res = job.to_dict()
    # Cap streaming results in progress heartbeat to last 50 to avoid megabyte-sized polling payloads
    if len(res.get("results", [])) > 50:
        res["results"] = res["results"][-50:]
    return JSONResponse(content=res)


@router.post("/scan/{job_id}/cancel")
async def cancel_scan(job_id: str):
    from ip2domain.cameras.scanner_v2.engine import cancel_job
    ok = cancel_job(job_id)
    db_job = storage.get_v2_job(job_id)
    if db_job:
        db_job["status"] = "cancelled"
        storage.save_v2_job(db_job)
        ok = True
    if not ok:
        raise HTTPException(status_code=404, detail="Job not found or already finished")
    return {"cancelled": True, "job_id": job_id}



def _sanitize_v2_result(r: dict) -> dict:
    if not isinstance(r, dict):
        return r
    cat = r.get("device_category") or "camera"
    if cat in ("router", "generic_web", "device"):
        # Strip synthetic camera snapshot URLs for non-cameras
        cleaned_streams = [
            s for s in r.get("streams", [])
            if s.get("type") != "http_snapshot" and "snapshot.cgi" not in s.get("url", "") and "snapshot.jpg" not in s.get("url", "")
        ]
        if not cleaned_streams and (r.get("web_url") or r.get("http_port")):
            port = r.get("http_port") or (r.get("open_ports", [80])[0] if r.get("open_ports") else 80)
            from ip2domain.cameras.scanner_v2.models import HTTPS_PORTS
            scheme = "https" if port in HTTPS_PORTS or "443" in str(port) else "http"
            web_url = r.get("web_url") or f"{scheme}://{r.get('ip')}:{port}/"
            cleaned_streams = [{
                "url": web_url,
                "type": "web_panel",
                "verified": bool(r.get("web_screenshot")),
                "screenshot": r.get("web_screenshot", ""),
            }]
        r["streams"] = cleaned_streams
    return r


@router.get("/results")
async def get_results(
    limit: int = Query(default=48, le=500000),
    offset: int = Query(default=0, ge=0),
    brand: str = Query(default=""),
    protocol: str = Query(default=""),
    has_preview: bool = Query(default=False),
    verified_only: bool = Query(default=False),
    auth_status: str = Query(default="all"),
    category: str = Query(default=""),
    geo: str = Query(default=""),
    search: str = Query(default=""),
):
    """Return stored v2 results from DB with server-side pagination and filters."""
    results = storage.get_v2_results(
        limit=limit,
        offset=offset,
        brand=brand,
        protocol=protocol,
        has_preview=has_preview,
        verified_only=verified_only,
        auth_status=auth_status,
        category=category,
        geo=geo,
        search=search,
    )
    results = [_sanitize_v2_result(r) for r in results]
    total_matching = storage.get_v2_results_count(
        brand=brand,
        protocol=protocol,
        has_preview=has_preview,
        verified_only=verified_only,
        auth_status=auth_status,
        category=category,
        geo=geo,
        search=search,
    )
    stats = storage.get_v2_stats()
    return JSONResponse(content={
        "results": results,
        "total": len(results),
        "total_matching": total_matching,
        "total_db": stats.get("total", total_matching),
        "stats": stats,
        "limit": limit,
        "offset": offset,
    })


@router.get("/export/401")
@router.get("/results/export-401")
async def export_401_cameras(format: str = Query(default="txt")):
    """Export list of cameras requiring authentication (401 Unauthorized)."""
    cameras_401 = storage.get_v2_results(limit=100000, auth_status="401")
    if format.lower() == "csv":
        lines = ["ip,port,brand,model,city"]
        for c in cameras_401:
            ip = c.get("ip", "")
            port = c.get("rtsp_port") or 554
            brand = (c.get("brand") or "").replace(",", " ")
            model = (c.get("model") or "").replace(",", " ")
            city = (c.get("city") or "").replace(",", " ")
            lines.append(f"{ip},{port},{brand},{model},{city}")
        content = "\n".join(lines)
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="targets_rtsp_401.csv"'},
        )
    else:
        # Default txt format (one ip:port per line, compatible with rtspBrute.py)
        lines = []
        for c in cameras_401:
            ip = c.get("ip", "").strip()
            if not ip:
                continue
            port = c.get("rtsp_port") or 554
            lines.append(f"{ip}:{port}")
        content = "\n".join(lines)
        return Response(
            content=content,
            media_type="text/plain",
            headers={"Content-Disposition": 'attachment; filename="targets_rtsp_401.txt"'},
        )


@router.get("/export/ips")
@router.get("/results/export-ips")
async def export_filtered_ips(
    category: str = Query(default="all"),
    brand: str = Query(default="all"),
    protocol: str = Query(default="all"),
    status: str = Query(default="all"),
    auth_status: str = Query(default="all"),
):
    """Export clean plain-text list of IP addresses (without ports) matching active filters."""
    has_preview = status == "preview"
    verified_only = status == "live"
    cat_param = "" if category == "all" else category
    brand_param = "" if brand == "all" else brand
    proto_param = "" if protocol == "all" else protocol

    results = storage.get_v2_results(
        limit=100000,
        brand=brand_param,
        protocol=proto_param,
        has_preview=has_preview,
        verified_only=verified_only,
        auth_status=auth_status,
        category=cat_param,
    )

    seen = set()
    ips = []
    for c in results:
        ip = (c.get("ip") or "").strip()
        if ip.startswith("http://") or ip.startswith("https://"):
            ip = ip.split("//")[-1].split("/")[0]
        if ":" in ip and not ip.startswith("["):
            ip = ip.split(":")[0]
        if ip and ip not in seen:
            seen.add(ip)
            ips.append(ip)

    parts = ["ips"]
    if category != "all":
        parts.append(category)
    if brand != "all":
        parts.append(brand.lower().replace(" ", "_"))
    if status != "all":
        parts.append(status)
    filename = f"{'_'.join(parts)}_{len(ips)}.txt"

    content = "\n".join(ips) + ("\n" if ips else "")
    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )



@router.get("/results/{ip}")
async def get_result(ip: str):
    result = storage.get_v2_result(ip)
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")
    return JSONResponse(content=_sanitize_v2_result(result))


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

    res = storage.get_v2_result(ip)
    creds = res.get("credentials", {}) if res else {}
    u = creds.get("user", "")
    p = creds.get("password", "")
    creds_str = f"{u}:{p}@" if u else ""

    # Resolve WebSocket endpoint if passed
    if stream_url.startswith("ws://") or stream_url.startswith("wss://"):
        if "rtsp-over-websocket" in stream_url:
            stream_url = f"rtsp://{creds_str}{ip}:554/axis-media/media.amp"
        elif res and res.get("streams"):
            for s in res["streams"]:
                if s.get("url", "").startswith("rtsp://"):
                    stream_url = s["url"]
                    break

    # Recover credentials if masked with *** or missing
    if stream_url.startswith("rtsp://") or stream_url.startswith("rtsps://"):
        if u:
            if ":***@" in stream_url:
                stream_url = re.sub(r":[^/@]+@", f":{p}@", stream_url)
            else:
                parts = stream_url.split("://", 1)
                if len(parts) == 2:
                    host_part = parts[1].split("/")[0]
                    if "@" not in host_part:
                        stream_url = f"{parts[0]}://{creds_str}{parts[1]}"

    # Prepare sources: primary RTSP with TCP transport and no backchannel audio hangs + ffmpeg copy fallback
    sources = []
    if stream_url.startswith("rtsp://") or stream_url.startswith("rtsps://"):
        main_src = stream_url if "#" in stream_url else f"{stream_url}#transport=tcp#backchannel=0"
        sources = [main_src, f"ffmpeg:{stream_url}#video=copy"]
    else:
        sources = [stream_url]

    go2rtc_url = f"{GO2RTC_API_URL}/api/streams"
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.put(
                go2rtc_url,
                params={"name": stream_name, "src": sources},
            )

            if resp.status_code in (200, 201, 204):
                storage.mark_v2_result_go2rtc(ip, True)
                return {"success": True, "stream_name": stream_name}
            return {"success": False, "status_code": resp.status_code}
    except Exception as exc:
        logger.warning("Error adding stream to go2rtc: %s", exc)
        raise HTTPException(status_code=502, detail="Failed to add stream to go2rtc")


@router.api_route("/capture", methods=["GET", "HEAD"])
async def serve_capture(path: str = Query(...)):
    """Serve a v2 screenshot by path or filename."""
    base_path = str(_V2_CAPTURE_DIR.resolve())
    safe_name = os.path.basename(path)
    if not re.fullmatch(r"^[a-zA-Z0-9_\-\.]+\.(jpg|jpeg|png)$", safe_name) or ".." in safe_name:
        raise HTTPException(status_code=400, detail="Screenshot not found or invalid")
    fullpath = os.path.normpath(os.path.join(base_path, safe_name))
    if not fullpath.startswith(base_path):
        raise HTTPException(status_code=400, detail="Screenshot not found or invalid")
    if not os.path.isfile(fullpath) or os.path.getsize(fullpath) < 100:
        raise HTTPException(status_code=404, detail="Screenshot not found or invalid")
    return FileResponse(
        fullpath,
        media_type="image/jpeg",
        headers={"Cache-Control": "public, max-age=86400, immutable"},
    )



@router.api_route("/preview", methods=["GET", "POST", "HEAD"])
async def get_stream_preview(
    ip: str = Query(..., description="Camera IP"),
    stream_url: str = Query(..., description="RTSP / RTMP / HLS stream URL"),
    user: str = Query("", description="Optional username"),
    password: str = Query("", description="Optional password"),
):
    """Capture and return on-demand live snapshot for any camera stream."""
    from ip2domain.cameras.scanner_v2.stage3_stream import capture_stream_frame, _download_http_snapshot

    res = storage.get_v2_result(ip)
    selected = next((s for s in (res or {}).get("streams", []) if s.get("url") == stream_url), {})
    creds = ({"user": user, "password": password} if user else
             selected.get("credentials") if selected.get("credentials") is not None else (res or {}).get("credentials"))
    
    ok = False
    path = ""
    codec, w, h = "", 0, 0

    # For router / web devices or web_panel streams, capture web screenshot instead of ffmpeg
    if (res and res.get("device_category") in ("router", "generic_web", "device")) or selected.get("type") == "web_panel" or ("snapshot.cgi" in stream_url and (not res or res.get("device_category") != "camera")):
        from ip2domain.cameras.scanner_v2.web_capture import capture_web_screenshot
        web_port = (res or {}).get("http_port") or (res.get("open_ports", [80])[0] if res and res.get("open_ports") else 80)
        web_url = (res or {}).get("web_url") or stream_url
        if "snapshot.cgi" in web_url or "snapshot.jpg" in web_url:
            web_url = (res or {}).get("web_url") or f"http://{ip}:{web_port}/"
        try:
            sc_url = await capture_web_screenshot(
                ip=ip,
                port=web_port,
                web_url=web_url,
                capture_dir=Path(_V2_CAPTURE_DIR),
                brand=(res or {}).get("brand", ""),
                model=(res or {}).get("model", ""),
                title=(res or {}).get("web_title", ""),
                category=(res or {}).get("device_category", "generic_web"),
            )
            if sc_url:
                filename = Path(sc_url).name
                full_path = Path(_V2_CAPTURE_DIR) / filename
                if full_path.exists():
                    if res:
                        res["web_screenshot"] = sc_url
                        for s in res.get("streams", []):
                            if s.get("type") == "web_panel" or s.get("url") == stream_url:
                                s["verified"] = True
                                s["verification_status"] = "verified"
                                s["screenshot"] = sc_url
                        storage.save_v2_result(res)
                    return FileResponse(str(full_path), media_type="image/jpeg", headers={"Cache-Control": "private, max-age=5"})
        except Exception:
            pass

    if (stream_url.startswith("http://") or stream_url.startswith("https://")) and ".m3u8" not in stream_url and "mjpg" not in stream_url.lower() and "video.cgi" not in stream_url.lower():
        # Try direct HTTP snapshot download first
        snap_path = await _download_http_snapshot(stream_url, _V2_CAPTURE_DIR, credentials=creds)
        if snap_path and Path(snap_path).exists():
            ok = True
            path = snap_path
            codec = "JPEG"

    if not ok:
        stream_type = selected.get("type") or ("rtmp" if stream_url.startswith("rtmp://") else ("hls" if ".m3u8" in stream_url else ("mjpeg" if "mjpg" in stream_url.lower() else "rtsp")))
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
                if creds and creds.get("user") and creds.get("password"):
                    res["credentials"] = creds
                    res["auth_required"] = False
                for s in res.get("streams", []):
                    if s.get("url") == stream_url:
                        s["verified"] = True
                        s["verification_status"] = "verified"
                        s["auth_required"] = False
                        s["width"], s["height"] = w, h
                        s["screenshot"] = path
                        s["codec"] = codec
                        s["resolution"] = f"{w}x{h}" if w and h else ""
                        if creds and creds.get("user"):
                            s["credentials"] = creds
                storage.save_v2_result(res)
        except Exception:
            pass

        return FileResponse(str(path), media_type="image/jpeg", headers={"Cache-Control": "private, max-age=5"})

    if res and selected:
        # Keep other streams intact; this URL failed its latest frame check.
        selected.update(verified=False, screenshot="", verification_status="failed")
        storage.save_v2_result(res)
    raise HTTPException(status_code=404, detail="Stream frame unavailable")


@router.post("/resolve_geo")
@router.post("/results/resolve-geo")
async def resolve_all_cameras_geo():
    """Retroactively resolve cities and regions for all stored camera results."""
    from ip2domain.data.geo_city_db import geo_city_db, camera_geo_fields
    import asyncio

    def resolve():
        results = storage.get_v2_results(limit=0)
        updated_count = 0
        counts = {"city": 0, "region": 0, "country": 0, "unknown": 0}
        for cam in results:
            ip = str(cam.get("ip", "")).strip()
            if not ip:
                continue
            geo = geo_city_db.find_by_ip(ip)
            fields = camera_geo_fields(geo or {})
            if storage.update_v2_geo(ip, fields):
                updated_count += 1
            cam.update(fields)
            counts[fields["geo_precision"]] += 1
        return {"success": True, "total_cameras": len(results),
                "updated_count": updated_count, "precision_counts": counts, "results": results}

    return JSONResponse(content=await asyncio.to_thread(resolve))


class BulkCaptureRequest(BaseModel):
    concurrency: int = Field(default=2, ge=1, le=3)
    only_unverified: bool = True
    max_streams_per_cam: int = Field(default=0, ge=0)
    ips: Optional[List[str]] = None


@router.post("/bulk_capture/start")
@router.post("/results/bulk-capture/start")
async def start_bulk_capture(req: Optional[BulkCaptureRequest] = None):
    """Start background batch verification and screenshot capture for cameras."""
    from ip2domain.cameras.scanner_v2.bulk_capture import bulk_capture_mgr
    c = req.concurrency if req else 2
    ou = req.only_unverified if req else True
    ms = req.max_streams_per_cam if req else 0
    ips = req.ips if req else None
    res = await bulk_capture_mgr.start(
        concurrency=c,
        only_unverified=ou,
        max_streams_per_cam=ms,
        target_ips=ips,
    )
    return JSONResponse(content=res)


@router.get("/bulk_capture/status")
@router.get("/results/bulk-capture/status")
async def get_bulk_capture_status():
    """Get real-time status of the background bulk capture worker."""
    from ip2domain.cameras.scanner_v2.bulk_capture import bulk_capture_mgr
    return JSONResponse(content=bulk_capture_mgr.get_status())


@router.post("/bulk_capture/stop")
@router.post("/results/bulk-capture/stop")
async def stop_bulk_capture():
    """Gracefully stop the background bulk capture worker."""
    from ip2domain.cameras.scanner_v2.bulk_capture import bulk_capture_mgr
    res = await bulk_capture_mgr.stop()
    return JSONResponse(content=res)


class BruteRequest(BaseModel):
    targets: Optional[List[str]] = None
    usernames: Optional[List[str]] = None
    passwords: Optional[List[str]] = None
    port: int = 554
    threads: int = 50


@router.post("/bruter/start")
@router.post("/results/bruter/start")
async def start_bruter(req: Optional[BruteRequest] = None):
    """Start RTSP brute-force task against cameras with 401 using rtspBrute.py."""
    from ip2domain.cameras.scanner_v2.bruter import rtsp_brute_mgr
    t = req.targets if req else None
    u = req.usernames if req else None
    p = req.passwords if req else None
    port = req.port if req else 554
    th = req.threads if req else 50

    res = await rtsp_brute_mgr.start(
        targets=t,
        usernames=u,
        passwords=p,
        port=port,
        threads=th,
        storage=storage,
        capture_dir=_V2_CAPTURE_DIR,
    )
    return JSONResponse(content=res)


@router.get("/bruter/status")
@router.get("/results/bruter/status")
async def get_bruter_status():
    """Get real-time status, progress, cracked credentials, and logs of rtspBrute."""
    from ip2domain.cameras.scanner_v2.bruter import rtsp_brute_mgr
    return JSONResponse(content=rtsp_brute_mgr.get_status())


@router.post("/bruter/stop")
@router.post("/results/bruter/stop")
async def stop_bruter():
    """Stop the running RTSP brute-force task."""
    from ip2domain.cameras.scanner_v2.bruter import rtsp_brute_mgr
    res = await rtsp_brute_mgr.stop()
    return JSONResponse(content=res)


# ─────────────────────────────────────────────────────────────────────────────
# SpRecord Audio Server Endpoints
# ─────────────────────────────────────────────────────────────────────────────

_sprecord_clients: Dict[str, Any] = {}


def _get_sprecord_client(ip: str, port: int, user: str = "admin", password: str = ""):
    key = f"{ip}:{port}"
    client = _sprecord_clients.get(key)
    if client is None:
        from ip2domain.cameras.scanner_v2.protocols.sprecord import SpRecordClient
        client = SpRecordClient(ip=ip, port=port, user=user, password=password)
        _sprecord_clients[key] = client
    else:
        client.user = user
        client.password = password
    return client


@router.get("/sprecord/records")
async def get_sprecord_records(
    ip: str = Query(..., description="IP address of SpRecord server"),
    offset: int = Query(0, ge=0, description="Record offset"),
    limit: int = Query(25, ge=1, le=100, description="Records limit per page"),
    port: Optional[int] = Query(None, description="Optional port, defaults to camera DB port or 8002"),
):
    """Retrieve dynamic conversation records list from SpRecord server with pagination."""
    cam = storage.get_v2_result(ip)
    creds = (cam or {}).get("credentials") or {}
    user = creds.get("user") or "admin"
    password = creds.get("password") or ""
    actual_port = port or (cam or {}).get("http_port") or 8002

    client = _get_sprecord_client(ip=ip, port=actual_port, user=user, password=password)
    records_data = await client.get_records(offset=offset, limit=limit)
    return JSONResponse(content=records_data)


@router.api_route("/sprecord/audio", methods=["GET", "HEAD"])
async def get_sprecord_audio(
    request: Request,
    ip: str = Query(..., description="IP address of SpRecord server"),
    record_id: int = Query(..., description="Record ID"),
    download: int = Query(0, description="1 to download as attachment, 0 for inline playback"),
    port: Optional[int] = Query(None, description="Optional port"),
):
    """Proxy audio stream from SpRecord server with session authentication."""
    cam = storage.get_v2_result(ip)
    creds = (cam or {}).get("credentials") or {}
    user = creds.get("user") or "admin"
    password = creds.get("password") or ""
    actual_port = port or (cam or {}).get("http_port") or 8002

    client = _get_sprecord_client(ip=ip, port=actual_port, user=user, password=password)
    content, media_type = await client.get_audio_bytes(record_id)
    if not content:
        raise HTTPException(status_code=404, detail="Audio record not found or inaccessible")

    disposition = "attachment" if download else "inline"
    headers = {
        "Accept-Ranges": "bytes",
        "Content-Length": str(len(content)),
        "Content-Disposition": f'{disposition}; filename="sprecord_{record_id}.mp3"',
        "Cache-Control": "public, max-age=86400",
    }
    if request.method == "HEAD":
        return Response(content=b"", media_type=media_type or "audio/mpeg", headers=headers)
    return Response(content=content, media_type=media_type or "audio/mpeg", headers=headers)
