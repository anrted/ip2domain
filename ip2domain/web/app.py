import asyncio
import logging
import os
import re
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from ip2domain.web.routers.common import (
    _STATIC_DIR,
    _TEMPLATE_DIR,
    auth_manager,
    storage,
    strix_jobs,
)
from ip2domain.web.routers.strix import strix_scan_worker
from ip2domain.web.routers import (
    auth_router,
    recon_router,
    modules_router,
    remote_desktop_router,
    cameras_router,
    centra_router,
    go2rtc_router,
    strix_router,
    scanner_v2_router,
    city_ip_router,
)

logger = logging.getLogger(__name__)

_WEB_DIR = Path(__file__).resolve().parent

def _load_local_env() -> None:
    """Load repository .env defaults without overriding process environment."""
    env_path = _WEB_DIR.parent.parent / ".env"
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            os.environ.setdefault(key, value)

_load_local_env()

app = FastAPI(
    title="ip2domain Web UI",
    description="Interactive Domain & IP Mapping Dashboard with Nmap, Nikto & HTTP Tech Stack analysis",
    version="1.5.0",
)

@app.middleware("http")
async def require_authentication(request: Request, call_next):
    """Accept a browser session or the legacy API token."""
    public_paths = {"/login", "/api/auth/login"}
    if (
        request.url.path.startswith("/static/")
        or request.url.path.startswith("/api/go2rtc/player/")
        or request.url.path.startswith("/api/go2rtc/proxy/")
        or request.url.path.startswith("/api/go2rtc/frame/")
        or request.url.path.startswith("/api/strix/screenshot/")
        or request.url.path.startswith("/api/strix/preview")
        or request.url.path.startswith("/api/v2/capture")
        or request.url.path.startswith("/api/v2/preview")
        or request.url.path.startswith("/api/strix/asn-prefixes")
        or request.url.path.startswith("/api/asn/lookup")
        or request.url.path.startswith("/api/v2/tools")
        or request.url.path.startswith("/api/v2/resolve_geo")
        or request.url.path.startswith("/api/v2/results/resolve-geo")
        or request.url.path.startswith("/api/geo/")
        or request.url.path in public_paths
    ):
        return await call_next(request)

    expected = os.environ.get("IP2DOMAIN_API_TOKEN")
    if expected:
        supplied = request.headers.get("X-API-Key")
        auth = request.headers.get("Authorization", "")
        if not supplied and auth.startswith("Bearer "):
            supplied = auth[7:]
        import secrets
        if supplied and secrets.compare_digest(supplied, expected):
            request.state.user = {"id": None, "username": "api-token", "role": "admin"}
            return await call_next(request)

    user = auth_manager.get_session_user(request.cookies.get("ip2domain_session"))
    if user:
        request.state.user = user
        return await call_next(request)

    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})
    return RedirectResponse(url="/login", status_code=303)

# Mount static files
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# Include all modular routers
app.include_router(auth_router)
app.include_router(recon_router)
app.include_router(modules_router)
app.include_router(remote_desktop_router)
app.include_router(cameras_router)
app.include_router(centra_router)
app.include_router(go2rtc_router)
app.include_router(strix_router)
app.include_router(scanner_v2_router)
app.include_router(city_ip_router)

@app.get("/", response_class=HTMLResponse)
def serve_index():
    return (_TEMPLATE_DIR / "index.html").read_text(encoding="utf-8")

from ip2domain.web.routers.auth import login_page as serve_login
from ip2domain.web.routers.recon import get_providers

@app.on_event("startup")
async def _on_startup():
    """Purge stale jobs and auto-resume active background scanning tasks."""
    purged = storage.purge_stale_jobs()
    if purged:
        logger.warning(f"Marked {purged} stale job(s) as 'interrupted' from previous server run.")
    migrated = storage.migrate_legacy_centra_catalog()
    if migrated:
        logger.info("Migrated %s legacy Centra camera(s) to camera catalog", migrated)

    async def _delayed_resume():
        await asyncio.sleep(1.0)
        try:
            active_job = storage.get_active_strix_job()
            if active_job:
                job_id = active_job["job_id"]
                targets = active_job.get("targets", [])
                curr_idx = active_job.get("current_index", 0)
                params = active_job.get("params", {})
                if targets and curr_idx < len(targets):
                    logger.info("Auto-resuming interrupted Strix scan %s from IP #%d / %d", job_id, curr_idx + 1, len(targets))
                    strix_jobs[job_id] = {
                        "job_id": job_id,
                        "status": "running",
                        "total_targets": len(targets),
                        "current_index": curr_idx,
                        "current_ip": active_job.get("current_ip", ""),
                        "progress_pct": active_job.get("progress_pct", 0),
                        "stage": f"Возобновлено после перезапуска (с #{curr_idx+1})",
                        "results": [],
                        "logs": active_job.get("logs", []),
                        "active_session_id": None,
                        "cancelling": False,
                        "cancelled": False,
                    }
                    asyncio.create_task(strix_scan_worker(
                        job_id,
                        targets,
                        params.get("ids", "p:top-150"),
                        params.get("user", "admin"),
                        params.get("password", ""),
                        params.get("channel", ""),
                        params.get("ports", ""),
                        skip_existing=params.get("skip_existing", False),
                        concurrency=params.get("concurrency", 10),
                        start_index=curr_idx,
                        strict_video_only=params.get("strict_video_only", True),
                    ))
        except Exception as exc:
            logger.error("Failed to auto-resume active Strix scan on startup: %s", exc)

        # Auto-resume active Camera Scanner v2 job if interrupted
        try:
            active_v2 = storage.get_active_v2_job()
            if active_v2:
                v2_jid = active_v2["job_id"]
                v2_targets_str = active_v2.get("targets_str", "")
                v2_curr_idx = active_v2.get("current_index", 0)
                v2_params = active_v2.get("params", {})
                if v2_targets_str:
                    logger.info("Auto-resuming interrupted Camera Scanner v2 scan %s from IP #%d", v2_jid, v2_curr_idx + 1)
                    from ip2domain.cameras.scanner_v2.engine import create_job, run_v2_scan_pipeline
                    v2_job = create_job(v2_jid)
                    v2_job.status = "running"
                    v2_job.progress_pct = active_v2.get("progress_pct", 0)
                    v2_job.stage = f"Возобновлено после перезапуска (с #{v2_curr_idx + 1})"
                    v2_job.logs = active_v2.get("logs", [])
                    v2_job.add_log(f"[Возобновление] Сканирование продолжено после перезапуска сервера с IP #{v2_curr_idx + 1}")

                    from ip2domain.web.routers.scanner_v2 import _V2_CAPTURE_DIR
                    asyncio.create_task(run_v2_scan_pipeline(
                        job_id=v2_jid,
                        targets_str=v2_targets_str,
                        engine=v2_params.get("engine", "auto"),
                        masscan_rate=v2_params.get("masscan_rate", 50000),
                        concurrency=v2_params.get("concurrency", 150),
                        port_timeout=v2_params.get("port_timeout", 1.2),
                        stage2_concurrency=v2_params.get("stage2_concurrency", 20),
                        credentials=v2_params.get("credentials"),
                        protocols=v2_params.get("protocols"),
                        capture_frames=v2_params.get("capture_frames", True),
                        local_discovery=False,
                        capture_dir=_V2_CAPTURE_DIR,
                        storage=storage,
                        resume_from_index=v2_curr_idx,
                    ))
        except Exception as exc:
            logger.error("Failed to auto-resume active Scanner v2 job on startup: %s", exc)

    asyncio.create_task(_delayed_resume())
