import asyncio
import ipaddress
import json
import uuid
import logging
import os
import re
import time
import aiohttp
from pathlib import Path
from typing import Dict, List, Literal, Optional
from fastapi import FastAPI, BackgroundTasks, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ip2domain.core.ip_parser import IPParser
from ip2domain.core.engine import LookupEngine
from ip2domain.core.domain_recon import DomainReconEngine
from ip2domain.core.verifier import DomainVerifier
from ip2domain.core.graph_builder import GraphBuilder
from ip2domain.core.storage import StorageManager
from ip2domain.core.idn_utils import decode_punycode
from ip2domain.providers.manager import ProviderManager, AVAILABLE_PROVIDERS
from ip2domain.modules.nmap_scanner import NmapScanner, SCAN_PROFILES

from ip2domain.modules.vuln_scanner import VulnScanner
from ip2domain.modules.http_analyzer import HTTPTechAnalyzer
from ip2domain.modules.remote_desktop_scanner import RemoteDesktopScanner
from ip2domain.modules.camera_scanner import CameraScanner
from ip2domain.core.target_policy import validate_network_target, private_targets_allowed
from ip2domain.web.auth import AuthManager

logger = logging.getLogger(__name__)

_WEB_DIR      = Path(__file__).resolve().parent
_TEMPLATE_DIR = _WEB_DIR / "templates"
_STATIC_DIR   = _WEB_DIR / "static"


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
    version="1.4.0",
)


@app.middleware("http")
async def require_authentication(request: Request, call_next):
    """Accept a browser session or the legacy API token."""
    public_paths = {"/login", "/api/auth/login"}
    if request.url.path.startswith("/static/") or request.url.path in public_paths:
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

# Mount /static → web/static/ for CSS & JS files
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

storage = StorageManager()
auth_manager = AuthManager(storage.db_path)


# ─────────────────────────────────────────────────────────────
# JobStore: hybrid in-memory + SQLite job state manager
# Solves B-04: jobs survive server restarts via SQLite persistence
# ─────────────────────────────────────────────────────────────
class JobStore:
    """
    Hybrid job state manager.
    - Hot path: in-memory dict for O(1) reads during active execution.
    - Persistence: every state mutation is written to SQLite.
    - Recovery: on server start, stale queued/running jobs are marked 'interrupted'.
    - Fallback: GET by job_id checks SQLite if not in memory.
    """

    def __init__(self, storage_manager: StorageManager, job_type: str):
        self._mem: Dict[str, Dict[str, any]] = {}
        self._storage = storage_manager
        self._job_type = job_type

    def create(self, job_id: str, initial_state: dict) -> dict:
        """Register a new job in memory and SQLite."""
        self._mem[job_id] = initial_state.copy()
        self._storage.upsert_job(job_id, self._job_type, initial_state)
        return self._mem[job_id]

    def update(self, job_id: str, **kwargs) -> None:
        """Update fields in memory and persist to SQLite."""
        if job_id in self._mem:
            self._mem[job_id].update(kwargs)
            self._storage.upsert_job(job_id, self._job_type, self._mem[job_id])

    def get(self, job_id: str) -> Optional[Dict[str, any]]:
        """Get job: memory first, then SQLite fallback."""
        if job_id in self._mem:
            return self._mem[job_id]
        return self._storage.get_job(job_id)

    def __contains__(self, job_id: str) -> bool:
        return job_id in self._mem

    def __getitem__(self, job_id: str) -> Dict[str, any]:
        return self._mem[job_id]

    def __setitem__(self, job_id: str, value: dict) -> None:
        self._mem[job_id] = value
        self._storage.upsert_job(job_id, self._job_type, value)

    def __delitem__(self, job_id: str) -> None:
        self._mem.pop(job_id, None)

    def items(self):
        return self._mem.items()


JOBS      = JobStore(storage, job_type='scan')
VULN_JOBS = JobStore(storage, job_type='vuln')
REMOTE_DESKTOP_JOBS = JobStore(storage, job_type='remote_desktop')
CAMERA_JOBS = JobStore(storage, job_type='camera')
CENTRA_JOBS = JobStore(storage, job_type='centra_discovery')
HTTP_CACHE: Dict[str, Dict[str, any]] = {}
REMOTE_CAPTURE_DIR = _WEB_DIR / "captures"


@app.on_event("startup")
async def _on_startup():
    """Purge stale jobs left from previous server instances."""
    purged = storage.purge_stale_jobs()
    if purged:
        logger.warning(f"Marked {purged} stale job(s) as 'interrupted' from previous server run.")


class VulnKnownPort(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    service: str = Field(default="", max_length=100)
    version: str = Field(default="", max_length=300)
    tunnel: str = Field(default="", max_length=20)
    http_detected: bool = False
    service_confidence: int = Field(default=0, ge=0, le=10)
    cpe: str = Field(default="", max_length=300)


class VulnScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    target_type: str = "ip"  # "ip", "domain", "subdomain"
    tech_stack: Optional[List[str]] = None
    open_ports: Optional[List[VulnKnownPort]] = Field(default=None, max_items=100)


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=1024)
    providers: Optional[List[str]] = ["all"]
    verify: bool = True
    nmap: bool = False
    scan_mode: Optional[Literal["domains", "nmap", "combined"]] = None
    nmap_ports: Optional[str] = None
    nmap_profile: str = "fast"
    concurrency: int = Field(default=10, ge=1, le=50)


class RemoteDesktopScanRequest(BaseModel):
    targets: str = Field(min_length=1, max_length=200000)
    scan_rdp: bool = True
    scan_vnc: bool = True
    rdp_ports: List[int] = Field(default_factory=lambda: [3389], max_items=32)
    vnc_ports: List[int] = Field(default_factory=lambda: list(range(5900, 5911)), max_items=64)


class CameraScanRequest(BaseModel):
    targets: str = Field(min_length=1, max_length=200000)
    ports: List[int] = Field(default_factory=lambda: CameraScanner.DEFAULT_PORTS.copy(), max_items=128)


class CentraDiscoveryRequest(BaseModel):
    start_id: int = Field(default=1, ge=1, le=1000000)
    end_id: int = Field(default=40000, ge=1, le=1000000)
    entrances: int = Field(default=5, ge=1, le=20)
    concurrency: int = Field(default=20, ge=1, le=50)


DEFAULT_CENTRA_CAMERAS = [{
    "id": "I-374-1",
    "title": "Домофон Сибиряков-Гвардейцев 14",
    "address": "Новокузнецк, ул. Сибиряков-Гвардейцев, 14",
    "embed_url": "https://flus4.mycentra.ru/I-374-1/embed.html?proto=webrtc",
    "media_info_url": "https://flus4.mycentra.ru/I-374-1/media_info.json",
}]


def _centra_cameras() -> List[dict]:
    """Return public Centra cameras, optionally overridden from the environment."""
    raw = os.environ.get("IP2DOMAIN_CENTRA_CAMERAS")
    if not raw:
        return DEFAULT_CENTRA_CAMERAS
    try:
        cameras = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning("Ignoring invalid IP2DOMAIN_CENTRA_CAMERAS: %s", exc)
        return DEFAULT_CENTRA_CAMERAS
    if not isinstance(cameras, list):
        logger.warning("Ignoring IP2DOMAIN_CENTRA_CAMERAS: expected a JSON array")
        return DEFAULT_CENTRA_CAMERAS
    return cameras


def _centra_address(title: str) -> str:
    """Turn Centra titles into an unambiguous address for Yandex geocoding."""
    address = re.sub(r"^домофон\s+", "", str(title), flags=re.IGNORECASE).strip()
    configured_city = os.environ.get("IP2DOMAIN_CENTRA_CITY", "Новокузнецк").strip()
    configured_region = os.environ.get("IP2DOMAIN_CENTRA_REGION", "Кемеровская область").strip()
    city_match = re.search(r"\(([^()]*)\)\s*$", address)
    city = city_match.group(1).strip() if city_match else configured_city
    if city_match:
        address = address[:city_match.start()].strip()
    street_match = re.fullmatch(r"(.+?)\s+(\d+[А-Яа-яA-Za-z]?(?:/\d+)?)", address)
    if street_match:
        street, house = street_match.groups()
        address = f"ул. {street.strip()}, {house}"
    location = ", ".join(part for part in ("Россия", configured_region, city) if part)
    return f"{location}, {address}" if location and address else address

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=1024)
    role: str = "user"


class UserActiveRequest(BaseModel):
    is_active: bool


class PasswordChangeRequest(BaseModel):
    password: str = Field(min_length=12, max_length=1024)


class OwnPasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)


def _require_admin(request: Request) -> dict:
    user = request.state.user
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required")
    return user


@app.post("/api/auth/login")
async def login(req: LoginRequest, response: Response):
    user = auth_manager.authenticate(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = auth_manager.create_session(user["id"])
    response.set_cookie(
        key="ip2domain_session",
        value=token,
        max_age=7 * 24 * 60 * 60,
        httponly=True,
        secure=os.environ.get("IP2DOMAIN_SECURE_COOKIES", "0") == "1",
        samesite="lax",
        path="/",
    )
    return {"user": user}


@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    auth_manager.delete_session(request.cookies.get("ip2domain_session"))
    response.delete_cookie("ip2domain_session", path="/")
    return {"status": "logged_out"}


@app.get("/api/auth/me")
async def current_user(request: Request):
    return {"user": request.state.user}


@app.put("/api/auth/password")
async def change_own_password(req: OwnPasswordChangeRequest, request: Request, response: Response):
    user = request.state.user
    if user.get("id") is None:
        raise HTTPException(status_code=400, detail="Password changes require a user session")
    authenticated = auth_manager.authenticate(user["username"], req.current_password)
    if not authenticated:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    try:
        auth_manager.set_password(user["id"], req.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    token = auth_manager.create_session(user["id"])
    response.set_cookie(
        key="ip2domain_session",
        value=token,
        max_age=7 * 24 * 60 * 60,
        httponly=True,
        secure=os.environ.get("IP2DOMAIN_SECURE_COOKIES", "0") == "1",
        samesite="lax",
        path="/",
    )
    return {"status": "password_changed"}


@app.get("/api/users")
async def list_users(request: Request):
    _require_admin(request)
    return {"users": auth_manager.list_users()}


@app.post("/api/users", status_code=201)
async def create_user(req: UserCreateRequest, request: Request):
    _require_admin(request)
    try:
        return {"user": auth_manager.create_user(req.username, req.password, req.role)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.patch("/api/users/{user_id}/active")
async def set_user_active(user_id: int, req: UserActiveRequest, request: Request):
    actor = _require_admin(request)
    if actor.get("id") == user_id and not req.is_active:
        raise HTTPException(status_code=400, detail="You cannot disable your own account")
    user = auth_manager.set_active(user_id, req.is_active)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user": user}


@app.put("/api/users/{user_id}/password")
async def set_user_password(user_id: int, req: PasswordChangeRequest, request: Request):
    actor = _require_admin(request)
    if actor.get("id") != user_id and actor.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not allowed")
    try:
        user = auth_manager.set_password(user_id, req.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user": user}


async def _run_scan_job(job_id: str, req: ScanRequest):
    try:
        scan_mode = req.scan_mode or ("combined" if req.nmap else "domains")
        nmap_enabled = scan_mode in {"nmap", "combined"}
        domain_lookup_enabled = scan_mode in {"domains", "combined"}
        JOBS.update(job_id, status="parsing_targets", progress_pct=5, stage="Анализ целевого ввода...")

        if not domain_lookup_enabled:
            # Nmap-only mode: resolve an explicit domain if needed, but never run
            # passive providers, CT logs, AXFR or subdomain enrichment.
            if DomainReconEngine.is_domain_target(req.target):
                allowed, normalized = await validate_network_target(req.target)
                if not allowed:
                    raise ValueError(normalized)
                req.target = normalized
                resolved = await DomainVerifier.resolve_domain(req.target, timeout=5)
                ips = sorted(resolved)
                if not ips:
                    raise ValueError("Домен не удалось разрешить в IP-адрес")
                results = [{
                    "ip": ip, "domains": [req.target], "provider_details": {},
                    "candidate_domains": [req.target], "rejected_candidates": [],
                    "total_domains": 1, "verified_live": True,
                } for ip in ips]
            else:
                ips = list(IPParser.parse_target(req.target))
                if not ips:
                    raise ValueError("Не найден допустимый IP-адрес")
                results = [{
                    "ip": ip, "domains": [], "provider_details": {},
                    "candidate_domains": [], "rejected_candidates": [],
                    "total_domains": 0, "verified_live": False,
                } for ip in ips]
            if not private_targets_allowed() and any(not ipaddress.ip_address(ip).is_global for ip in ips):
                raise ValueError("Private, loopback, link-local and reserved targets are disabled")
            JOBS.update(job_id, total_ips=len(ips), progress_pct=60,
                        stage=f"Режим «Только Nmap» · подготовлено IP: {len(ips)}")

        # Branch 1: Domain-to-IP reconnaissance (e.g. grinronn.ru, example.com)
        elif DomainReconEngine.is_domain_target(req.target):
            allowed, normalized = await validate_network_target(req.target)
            if not allowed:
                raise ValueError(normalized)
            req.target = normalized
            JOBS.update(job_id, status="domain_recon", progress_pct=10,
                        stage=f"Доменный поиск: поиск поддоменов для {req.target}...")

            def _on_recon_progress(pct: int, stage_name: str):
                base_pct = 10 + int(pct * 0.5) if nmap_enabled else 10 + int(pct * 0.8)
                prefix = "Этап 1/2 · Поиск доменов и связей · " if nmap_enabled else ""
                JOBS.update(job_id, progress_pct=base_pct, stage=prefix + stage_name)

            recon_engine = DomainReconEngine(concurrency=req.concurrency)
            results = await recon_engine.run_domain_recon(req.target, progress_callback=_on_recon_progress)
            ips = [r["ip"] for r in results]
        else:
            # Branch 2: Reverse IP lookup (e.g. 194.33.15.13 or 194.33.15.0/28)
            ips = list(IPParser.parse_target(req.target))
            if not ips:
                JOBS.update(job_id, status="error", progress_pct=0,
                            error="No valid IP addresses or domain name found in target input.")
                return
            if not private_targets_allowed() and any(not ipaddress.ip_address(ip).is_global for ip in ips):
                raise ValueError("Private, loopback, link-local and reserved targets are disabled")

            total_ips = len(ips)
            JOBS.update(job_id, total_ips=total_ips, status="running_lookups",
                        stage=f"Поиск доменов для {total_ips} IP...")

            def _on_lookup_progress(completed: int, total: int, stage_name: str, calculated_pct: int = None):
                if calculated_pct is not None:
                    pct = max(5, min(92, calculated_pct))
                else:
                    base_scale = 60 if nmap_enabled else 90
                    pct = 5 + int((completed / total) * base_scale)
                prefix = "Этап 1/2 · Поиск доменов и связей · " if nmap_enabled else ""
                JOBS.update(job_id, progress_pct=pct, stage=prefix + stage_name)

            # Setup providers & engine
            provider_manager = ProviderManager(selected_providers=req.providers)
            engine = LookupEngine(
                provider_manager=provider_manager,
                concurrency=req.concurrency,
                verify_live=req.verify,
            )

            results = await engine.run(ips, progress_callback=_on_lookup_progress)

        # Optional Nmap Port Scan
        if nmap_enabled:
            nmap_stage_prefix = "Этап 2/2 · Nmap" if domain_lookup_enabled else "Nmap"
            profile_hints = {
                "fast": "проверка 50 популярных портов",
                "normal": "проверка 200 популярных портов",
                "full": "проверка всех 65 535 TCP-портов; это может занять до 15 минут на IP",
                "stealth": "медленное SYN-сканирование 100 портов",
                "udp": "проверка 30 популярных UDP-портов",
            }
            nmap_hint = "проверка указанных портов" if req.nmap_ports else profile_hints.get(req.nmap_profile, "сканирование портов")
            JOBS.update(job_id, status="scanning_ports", progress_pct=65,
                        stage=f"{nmap_stage_prefix} ({req.nmap_profile}) · {nmap_hint} · запуск процесса...")
            scanner = NmapScanner(ports=req.nmap_ports, profile=req.nmap_profile)
            nmap_completed = 0
            nmap_activity = ""

            def _on_nmap_progress(completed: int, total: int, stage_name: str):
                nonlocal nmap_completed, nmap_activity
                nmap_completed = completed
                nmap_activity = stage_name
                pct = 65 + int((completed / total) * 30)
                JOBS.update(job_id, progress_pct=pct,
                            stage=f"{nmap_stage_prefix} · готово {completed}/{total} IP · {stage_name}")

            if scanner.is_available():
                nmap_ips = [ip for ip in ips if private_targets_allowed() or ipaddress.ip_address(ip).is_global]
                skipped_ips = set(ips) - set(nmap_ips)
                nmap_started = time.monotonic()
                scan_task = asyncio.create_task(scanner.scan_ips_concurrently(
                    nmap_ips, max_concurrency=min(req.concurrency, 4), progress_callback=_on_nmap_progress,
                    use_cache=False, return_details=True,
                ))
                while not scan_task.done():
                    done, _ = await asyncio.wait({scan_task}, timeout=2)
                    if done:
                        break
                    elapsed = int(time.monotonic() - nmap_started)
                    pct = 65 + int((nmap_completed / max(1, len(nmap_ips))) * 30)
                    JOBS.update(
                        job_id, progress_pct=pct,
                        stage=(f"{nmap_stage_prefix} ({req.nmap_profile}) работает · "
                               f"готово {nmap_completed}/{len(nmap_ips)} IP · прошло {elapsed} сек. · "
                               f"{nmap_activity or nmap_hint}"),
                    )
                port_map = await scan_task
                for item in results:
                    ip = item["ip"]
                    detail = port_map.get(ip, {})
                    item["open_ports"] = detail.get("open_ports", [])
                    item["nmap_status"] = "skipped" if ip in skipped_ips else ("error" if detail.get("error") else "completed")
                    item["nmap_error"] = "Приватный или служебный IP пропущен" if ip in skipped_ips else detail.get("error", "")
                    item["nmap_hostname"] = detail.get("hostname", "")
                    item["nmap_os"] = detail.get("os", "")
                    item["nmap_tech_stack"] = detail.get("tech_stack", [])
            else:
                for item in results:
                    item["nmap_status"] = "unavailable"
                    item["nmap_error"] = "Nmap не установлен на сервере"
                    item["nmap_tech_stack"] = []

        # Build Graph Data
        JOBS.update(job_id, status="building_graph", stage="Построение графа связей...", progress_pct=95)
        graph_data = GraphBuilder.build_graph(results, hide_empty_ips=scan_mode != "nmap")

        total_domains = sum(len(item.get("domains", [])) for item in results)

        JOBS.update(job_id,
            results=results,
            graph=graph_data,
            status="completed",
            progress_pct=100,
            stage="Сканирование завершено! (100%)",
        )

        # Save to SQLite Database
        storage.save_scan(
            job_id=job_id,
            target=req.target,
            verify=req.verify,
            nmap=nmap_enabled,
            total_ips=len(ips),
            total_domains=total_domains,
            results=results,
            graph=graph_data,
            status="completed",
        )
    except Exception as e:
        logger.error(f"Scan job {job_id} failed: {e}", exc_info=True)
        JOBS.update(job_id, status="error", error=str(e))


@app.get("/api/providers")
def get_providers():
    return {
        name: {"name": name, "description": cls.description}
        for name, cls in AVAILABLE_PROVIDERS.items()
    }


@app.get("/api/history")
def get_history():
    return storage.list_history()


@app.post("/api/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_mode = req.scan_mode or ("combined" if req.nmap else "domains")
    nmap_enabled = scan_mode in {"nmap", "combined"}
    if nmap_enabled:
        try:
            NmapScanner.validate_ports(req.nmap_ports)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if req.nmap_profile not in SCAN_PROFILES:
            raise HTTPException(status_code=400, detail="Неизвестный профиль Nmap")
    terminal_statuses = {"completed", "error", "interrupted"}
    active_jobs = [(job_id, job) for job_id, job in JOBS.items()
                   if job.get("status") not in terminal_statuses]
    target_key = req.target.strip().lower().rstrip(".")
    for existing_id, existing in active_jobs:
        if str(existing.get("target", "")).strip().lower().rstrip(".") == target_key:
            return {
                "job_id": existing_id,
                "status": "already_running",
                "message": "Сканирование этой цели уже выполняется",
            }
    active_count = len(active_jobs)
    if active_count >= 4:
        raise HTTPException(status_code=429, detail="Too many active scan jobs")
    job_id = str(uuid.uuid4())[:8]
    JOBS.create(job_id, {
        "job_id": job_id,
        "status": "queued",
        "target": req.target,
        "verify": req.verify,
        "nmap": nmap_enabled,
        "scan_mode": scan_mode,
        "nmap_ports": req.nmap_ports,
        "nmap_profile": req.nmap_profile,
        "concurrency": req.concurrency,
        "total_ips": 0,
        "results": [],
        "graph": {"nodes": [], "edges": [], "stats": {}},
        "error": None,
    })
    background_tasks.add_task(_run_scan_job, job_id, req)
    return {"job_id": job_id, "status": "queued"}


@app.get("/api/scan/active")
def get_active_scans():
    terminal_statuses = {"completed", "error", "interrupted"}
    public_fields = (
        "job_id", "target", "status", "progress_pct", "stage", "verify", "nmap",
        "scan_mode", "nmap_ports", "nmap_profile", "concurrency", "total_ips", "error",
    )
    return {
        "jobs": [{field: job.get(field) for field in public_fields} for _, job in JOBS.items()
                 if job.get("status") not in terminal_statuses]
    }


class NodePositionsRequest(BaseModel):
    positions: Dict[str, Dict[str, float]]


class NodeHideRequest(BaseModel):
    node_ids: List[str]


@app.get("/api/graph/global")
def get_global_graph():
    global_results = storage.get_global_scan_results()
    graph_data = GraphBuilder.build_graph(global_results, hide_empty_ips=True)

    # Attach saved coordinates from SQLite to graph nodes
    saved_positions = storage.get_all_node_positions()
    for node in graph_data.get("nodes", []):
        n_id = node["id"]
        if n_id in saved_positions:
            node["x"] = saved_positions[n_id]["x"]
            node["y"] = saved_positions[n_id]["y"]

    hidden_nodes = storage.get_hidden_nodes()

    return {
        "results": global_results,
        "graph": graph_data,
        "saved_positions": saved_positions,
        "hidden_node_ids": hidden_nodes,
    }


@app.post("/api/graph/positions")
def save_graph_node_positions(req: NodePositionsRequest):
    storage.save_node_positions(req.positions)
    return {"status": "saved", "count": len(req.positions)}


@app.get("/api/graph/nodes/hidden")
def get_hidden_nodes_api():
    return {"hidden_nodes": storage.get_hidden_nodes()}


@app.post("/api/graph/nodes/hide")
def hide_nodes_api(req: NodeHideRequest):
    storage.hide_nodes(req.node_ids)
    return {"status": "hidden", "count": len(req.node_ids)}


@app.post("/api/graph/nodes/unhide")
def unhide_nodes_api(req: NodeHideRequest):
    expanded_ids = set(req.node_ids)
    try:
        global_results = storage.get_global_scan_results()

        for nid in list(expanded_ids):
            if nid.startswith("ip:"):
                target_ip = nid.replace("ip:", "")
                for rec in global_results:
                    if rec.get("ip") == target_ip:
                        for d in rec.get("domains", []):
                            d_clean = decode_punycode(d.strip().lower())
                            if d_clean.startswith("www."):
                                d_clean = d_clean[4:]
                            apex = GraphBuilder.extract_apex_domain(d_clean)
                            expanded_ids.add(f"domain:{apex}")
                            if d_clean != apex:
                                expanded_ids.add(f"subdomain:{d_clean}")
    except Exception as e:
        logger.error(f"Failed expanding unhide node IDs: {e}")

    storage.unhide_nodes(list(expanded_ids))
    return {"status": "unhidden", "count": len(expanded_ids)}


@app.post("/api/graph/nodes/unhide-all")
def unhide_all_nodes_api():
    storage.clear_hidden_nodes()
    return {"status": "cleared"}


@app.get("/api/scan/{job_id}")
def get_scan_status(job_id: str):
    hidden_nodes = storage.get_hidden_nodes()
    # Check in-memory JobStore first (includes SQLite fallback)
    job = JOBS.get(job_id) if job_id in JOBS else None
    if job:
        res = dict(job)
        res["hidden_node_ids"] = hidden_nodes
        return res

    # Fallback: completed scans stored in scan_history
    saved_scan = storage.get_scan(job_id)
    if saved_scan:
        res = dict(saved_scan)
        res["hidden_node_ids"] = hidden_nodes
        return res

    persisted_job = JOBS.get(job_id)
    if persisted_job:
        return persisted_job

    raise HTTPException(status_code=404, detail="Job not found")


@app.get("/api/graph/{job_id}")
def get_scan_graph(job_id: str):
    job = JOBS.get(job_id) if job_id in JOBS else None
    if job:
        return job.get("graph", {"nodes": [], "edges": [], "stats": {}})

    saved_scan = storage.get_scan(job_id)
    if saved_scan:
        return saved_scan.get("graph", {"nodes": [], "edges": [], "stats": {}})

    raise HTTPException(status_code=404, detail="Job not found")


@app.delete("/api/history/{job_id}")
def delete_scan_history(job_id: str):
    storage.delete_scan(job_id)
    if job_id in JOBS:
        del JOBS[job_id]
    return {"status": "deleted", "job_id": job_id}


async def _run_remote_desktop_job(job_id: str, req: RemoteDesktopScanRequest, targets: List[str]):
    try:
        started = time.monotonic()
        latest_progress = {"pct": 1, "stage": f"Подготовка {len(targets)} IP"}
        REMOTE_DESKTOP_JOBS.update(job_id, status="running", progress_pct=1,
                                   stage=latest_progress["stage"])

        def progress(pct: int, stage: str):
            latest_progress["pct"] = pct
            latest_progress["stage"] = stage
            REMOTE_DESKTOP_JOBS.update(job_id, progress_pct=pct,
                                       stage=f"{stage} · прошло {int(time.monotonic() - started)} сек.")

        scanner = RemoteDesktopScanner(REMOTE_CAPTURE_DIR)
        scan_task = asyncio.create_task(scanner.scan(
            targets, req.scan_rdp, req.scan_vnc, req.rdp_ports, req.vnc_ports, progress
        ))
        while not scan_task.done():
            done, _ = await asyncio.wait({scan_task}, timeout=2)
            if done:
                break
            REMOTE_DESKTOP_JOBS.update(
                job_id,
                progress_pct=latest_progress["pct"],
                stage=(f"{latest_progress['stage']} · "
                       f"прошло {int(time.monotonic() - started)} сек."),
            )
        result = await scan_task
        storage.save_remote_desktop_services(result.get("services", []))
        result["services"] = storage.get_remote_desktop_services()
        REMOTE_DESKTOP_JOBS.update(job_id, status="completed", progress_pct=100,
                                   stage="Проверка завершена", results=result)
    except Exception as exc:
        logger.error("Remote desktop scan %s failed: %s", job_id, exc, exc_info=True)
        REMOTE_DESKTOP_JOBS.update(job_id, status="error", error=str(exc), stage="Ошибка")


@app.post("/api/remote-desktop/scan")
async def start_remote_desktop_scan(req: RemoteDesktopScanRequest, background_tasks: BackgroundTasks):
    try:
        specs = [item for item in re.split(r"[\s,;]+", req.targets.strip()) if item]
        targets = []
        seen = set()
        max_targets = 65536
        for spec in specs:
            for target in IPParser.parse_target(spec, max_ips=max_targets - len(targets)):
                if target not in seen:
                    seen.add(target)
                    targets.append(target)
                    if len(targets) > max_targets:
                        raise ValueError(f"Одно задание может содержать не более {max_targets} IP")
        if not targets:
            raise ValueError("Список IP-адресов пуст")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not private_targets_allowed():
        blocked = next((target for target in targets if not ipaddress.ip_address(target).is_global), None)
        if blocked:
            raise HTTPException(status_code=400, detail=f"Приватный или служебный IP запрещён: {blocked}")
    for port in req.rdp_ports + req.vnc_ports:
        if port < 1 or port > 65535:
            raise HTTPException(status_code=400, detail="Порты должны находиться в диапазоне 1–65535")
    if not req.scan_rdp and not req.scan_vnc:
        raise HTTPException(status_code=400, detail="Выберите RDP или VNC")
    job_id = uuid.uuid4().hex[:12]
    target_label = targets[0] if len(targets) == 1 else f"{len(targets)} IP"
    REMOTE_DESKTOP_JOBS.create(job_id, {"job_id": job_id, "target": target_label,
        "total_targets": len(targets),
        "status": "queued", "progress_pct": 0, "stage": "В очереди", "error": ""})
    background_tasks.add_task(_run_remote_desktop_job, job_id, req, targets)
    return {"status": "queued", "job_id": job_id, "total_targets": len(targets)}


@app.get("/api/remote-desktop/scan/{job_id}")
def get_remote_desktop_scan(job_id: str):
    job = REMOTE_DESKTOP_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Задание не найдено")
    return job


@app.get("/api/remote-desktop/results")
def get_remote_desktop_results():
    services = storage.get_remote_desktop_services()
    return {"services": services, "service_count": len(services)}


@app.delete("/api/remote-desktop/results")
def clear_remote_desktop_results():
    return {"status": "cleared", "deleted": storage.clear_remote_desktop_services()}


async def _run_camera_job(job_id: str, req: CameraScanRequest, targets: List[str]):
    try:
        started = time.monotonic()
        latest_progress = {"pct": 1, "stage": f"Подготовка {len(targets)} IP"}
        CAMERA_JOBS.update(job_id, status="running", progress_pct=1,
                           stage=f"Подготовка {len(targets)} IP")

        def progress(pct: int, stage: str):
            latest_progress.update(pct=pct, stage=stage)
            CAMERA_JOBS.update(job_id, progress_pct=pct,
                               stage=f"{stage} · прошло {int(time.monotonic() - started)} сек.")

        scan_task = asyncio.create_task(CameraScanner().scan(targets, req.ports, progress))
        while not scan_task.done():
            done, _ = await asyncio.wait({scan_task}, timeout=2)
            if done:
                break
            CAMERA_JOBS.update(
                job_id, progress_pct=latest_progress["pct"],
                stage=f'{latest_progress["stage"]} · прошло {int(time.monotonic() - started)} сек.',
            )
        result = await scan_task
        storage.save_camera_devices(result.get("devices", []))
        result["devices"] = storage.get_camera_devices()
        result["camera_count"] = len(result["devices"])
        CAMERA_JOBS.update(job_id, status="completed", progress_pct=100,
                           stage="Проверка завершена", results=result)
    except Exception as exc:
        logger.error("Camera scan %s failed: %s", job_id, exc, exc_info=True)
        CAMERA_JOBS.update(job_id, status="error", error=str(exc), stage="Ошибка")


@app.post("/api/cameras/scan")
async def start_camera_scan(req: CameraScanRequest, background_tasks: BackgroundTasks):
    try:
        specs = [item for item in re.split(r"[\s,;]+", req.targets.strip()) if item]
        targets, seen = [], set()
        max_targets = 65536
        for spec in specs:
            for target in IPParser.parse_target(spec, max_ips=max_targets - len(targets)):
                if target not in seen:
                    seen.add(target)
                    targets.append(target)
                    if len(targets) > max_targets:
                        raise ValueError(f"Одно задание может содержать не более {max_targets} IP")
        if not targets:
            raise ValueError("Список IP-адресов пуст")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not private_targets_allowed():
        blocked = next((target for target in targets if not ipaddress.ip_address(target).is_global), None)
        if blocked:
            raise HTTPException(status_code=400, detail=f"Приватный или служебный IP запрещён: {blocked}")
    if not req.ports or any(port < 1 or port > 65535 for port in req.ports):
        raise HTTPException(status_code=400, detail="Порты должны находиться в диапазоне 1–65535")
    job_id = uuid.uuid4().hex[:12]
    target_label = targets[0] if len(targets) == 1 else f"{len(targets)} IP"
    CAMERA_JOBS.create(job_id, {"job_id": job_id, "target": target_label,
        "total_targets": len(targets), "status": "queued", "progress_pct": 0,
        "stage": "В очереди", "error": ""})
    background_tasks.add_task(_run_camera_job, job_id, req, targets)
    return {"status": "queued", "job_id": job_id, "total_targets": len(targets)}


@app.get("/api/cameras/scan/{job_id}")
def get_camera_scan(job_id: str):
    job = CAMERA_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Задание не найдено")
    return job


@app.get("/api/cameras/results")
def get_camera_results():
    devices = storage.get_camera_devices()
    return {"devices": devices, "camera_count": len(devices)}


@app.delete("/api/cameras/results")
def clear_camera_results():
    return {"status": "cleared", "deleted": storage.clear_camera_devices()}


@app.get("/api/cameras/centra")
def get_centra_cameras():
    stored = storage.get_centra_cameras()
    cameras = ([camera for camera in stored if camera.get("available", True)]
               if stored else _centra_cameras())
    for camera in cameras:
        camera["address"] = _centra_address(camera.get("title") or camera.get("address", ""))
    def camera_order(camera):
        match = re.fullmatch(r"I-(\d+)-(\d+)", str(camera.get("id", "")), re.IGNORECASE)
        return (int(match.group(1)), int(match.group(2))) if match else (10**9, 10**9)
    cameras.sort(key=camera_order)
    return {
        "cameras": cameras,
        "yandex_maps_api_key": os.environ.get("YANDEX_MAPS_API_KEY", ""),
    }


async def _run_centra_discovery(job_id: str, req: CentraDiscoveryRequest):
    total = (req.end_id - req.start_id + 1) * req.entrances
    checked = found = 0
    current_building = req.start_id
    semaphore = asyncio.Semaphore(req.concurrency)
    timeout = aiohttp.ClientTimeout(total=8, connect=4, sock_read=5)
    headers = {"User-Agent": "ip2domain-centra-discovery/1.0"}
    known = {camera["id"]: camera for camera in storage.get_centra_cameras()}

    async def probe(session: aiohttp.ClientSession, building: int, entrance: int):
        nonlocal checked, found, current_building
        camera_id = f"I-{building}-{entrance}"
        media_url = f"https://flus4.mycentra.ru/{camera_id}/media_info.json"
        available = False
        try:
            async with semaphore:
                async with session.get(media_url, allow_redirects=False) as response:
                    if response.status != 200:
                        return
                    data = await response.json(content_type=None)
            if not isinstance(data, dict) or not data.get("tracks"):
                return
            video = next((track for track in data["tracks"] if track.get("content") == "video"), {})
            title = str(data.get("title") or camera_id).strip()
            address = _centra_address(title)
            camera = {
                "id": camera_id,
                "building_id": building,
                "entrance": entrance,
                "title": title,
                "address": address,
                "embed_url": f"https://flus4.mycentra.ru/{camera_id}/embed.html?proto=webrtc",
                "media_info_url": media_url,
                "available": True,
                "video": {key: video.get(key) for key in ("codec", "width", "height", "fps", "avg_fps") if video.get(key) is not None},
            }
            storage.save_centra_cameras([camera])
            available = True
            found += 1
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, TypeError):
            pass
        finally:
            if not available and camera_id in known:
                storage.save_centra_cameras([{**known[camera_id], "available": False}])
            checked += 1
            current_building = max(current_building, building)
            if checked == total or checked % max(25, req.concurrency) == 0:
                pct = min(99, int(checked * 100 / total))
                CENTRA_JOBS.update(job_id, status="running", progress_pct=pct,
                    stage=(f"Дом {current_building:,} из {req.end_id:,} · "
                           f"проверено камер {checked:,} из {total:,} · найдено {found}"),
                    checked=checked, found=found, current_building=current_building)

    try:
        CENTRA_JOBS.update(job_id, status="running", progress_pct=0,
                           stage=f"Подготовка {total:,} адресов")
        connector = aiohttp.TCPConnector(limit=req.concurrency, ttl_dns_cache=300)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector, headers=headers) as session:
            pending = set()
            for building in range(req.start_id, req.end_id + 1):
                for entrance in range(1, req.entrances + 1):
                    pending.add(asyncio.create_task(probe(session, building, entrance)))
                    if len(pending) >= req.concurrency * 4:
                        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                        for task in done:
                            await task
            if pending:
                await asyncio.gather(*pending)
        CENTRA_JOBS.update(job_id, status="completed", progress_pct=100,
                           stage=(f"Готово · дома {req.start_id:,}–{req.end_id:,} · "
                                  f"проверено камер {checked:,} · найдено {found}"),
                           checked=checked, found=found, current_building=req.end_id)
    except Exception as exc:
        logger.error("Centra discovery %s failed: %s", job_id, exc, exc_info=True)
        CENTRA_JOBS.update(job_id, status="error", error=str(exc), stage="Ошибка")


@app.post("/api/cameras/centra/discover")
async def start_centra_discovery(req: CentraDiscoveryRequest, background_tasks: BackgroundTasks):
    if req.end_id < req.start_id:
        raise HTTPException(status_code=400, detail="Конечный ID должен быть не меньше начального")
    total = (req.end_id - req.start_id + 1) * req.entrances
    if total > 200000:
        raise HTTPException(status_code=400, detail="За один запуск можно проверить не более 200 000 камер")
    job_id = uuid.uuid4().hex[:12]
    CENTRA_JOBS.create(job_id, {"job_id": job_id, "target": f"{req.start_id}-{req.end_id}",
        "status": "queued", "progress_pct": 0, "stage": "В очереди", "error": "",
        "total": total, "checked": 0, "found": 0})
    background_tasks.add_task(_run_centra_discovery, job_id, req)
    return {"status": "queued", "job_id": job_id, "total": total}


@app.get("/api/cameras/centra/discover/{job_id}")
def get_centra_discovery(job_id: str):
    job = CENTRA_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Задание не найдено")
    return job


@app.delete("/api/cameras/centra")
def clear_centra_cameras():
    return {"status": "cleared", "deleted": storage.clear_centra_cameras()}


@app.get("/api/remote-desktop/capture/{capture_id}")
def get_remote_desktop_capture(capture_id: str):
    if not re.fullmatch(r"[a-f0-9]{32}", capture_id):
        raise HTTPException(status_code=404, detail="Снимок не найден")
    path = REMOTE_CAPTURE_DIR / f"{capture_id}.png"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Снимок не найден")
    return FileResponse(path, media_type="image/png", headers={"Cache-Control": "private, no-store"})


async def _run_vuln_scan_job(vuln_job_id: str, target: str, tech_stack: Optional[List[str]] = None,
                             open_ports: Optional[List[dict]] = None):
    try:
        stage_text = "Выполнение сканирования Nmap NSE и Nikto..."
        if tech_stack:
            stage_text = f"Сканирование Nmap NSE & Nikto (стек: {', '.join(tech_stack[:3])})..."

        VULN_JOBS.update(vuln_job_id,
            status="running",
            progress_pct=15,
            stage=stage_text,
        )

        scanner = VulnScanner()
        scan_started = time.monotonic()
        latest_progress = {"pct": 5, "stage": stage_text}

        def _on_progress(pct: int, msg: str):
            latest_progress.update(pct=pct, stage=msg)
            elapsed = int(time.monotonic() - scan_started)
            VULN_JOBS.update(vuln_job_id, progress_pct=pct, stage=f"{msg} · прошло {elapsed} сек.")

        scan_task = asyncio.create_task(scanner.scan_target_combined(
            target=target,
            tech_stack=tech_stack,
            known_ports=open_ports,
            progress_callback=_on_progress,
            use_cache=False,
        ))
        while not scan_task.done():
            done, _ = await asyncio.wait({scan_task}, timeout=2)
            if done:
                break
            elapsed = int(time.monotonic() - scan_started)
            VULN_JOBS.update(
                vuln_job_id,
                progress_pct=latest_progress["pct"],
                stage=f"{latest_progress['stage']} · прошло {elapsed} сек.",
            )
        res = await scan_task

        VULN_JOBS.update(vuln_job_id,
            results=res,
            status="completed",
            progress_pct=100,
            stage="Поиск уязвимостей завершен!",
        )

        # Save to SQLite Database
        storage.save_vuln_analysis(target, res)
    except Exception as e:
        logger.error(f"Vuln scan job {vuln_job_id} failed for target {target}: {e}", exc_info=True)
        VULN_JOBS.update(vuln_job_id, status="error", error=str(e))


@app.post("/api/vuln/scan")
async def start_vuln_scan(req: VulnScanRequest, background_tasks: BackgroundTasks):
    target_clean = req.target.strip()
    allowed, normalized = await validate_network_target(target_clean)
    if not allowed:
        raise HTTPException(status_code=400, detail=normalized)
    target_clean = normalized
    active_count = sum(1 for _, job in VULN_JOBS.items()
                       if job.get("status") in ("queued", "running"))
    if active_count >= 2:
        raise HTTPException(status_code=429, detail="Too many active vulnerability scan jobs")

    # Check if a scan is already running for this target
    for j_id, job in VULN_JOBS.items():
        if job["target"] == target_clean and job["status"] in ("queued", "running"):
            return {
                "status": "already_running",
                "job_id": j_id,
                "message": f"Сканирование уязвимостей для {target_clean} уже выполняется!"
            }

    # Auto-detect tech stack if not explicitly provided in request
    tech_stack = req.tech_stack
    if not tech_stack:
        # Check HTTP cache
        if target_clean in HTTP_CACHE and HTTP_CACHE[target_clean].get("tech_stack"):
            tech_stack = HTTP_CACHE[target_clean]["tech_stack"]
        else:
            # Check SQLite DB
            db_http = storage.get_http_analysis(target_clean)
            if db_http and db_http.get("tech_stack"):
                tech_stack = db_http["tech_stack"]

    merged_analysis = _merge_nmap_stack(target_clean, {"tech_stack": tech_stack or []})
    tech_stack = merged_analysis["tech_stack"]

    open_ports = [port.dict() for port in (req.open_ports or [])]

    vuln_job_id = str(uuid.uuid4())[:8]
    VULN_JOBS.create(vuln_job_id, {
        "job_id": vuln_job_id,
        "target": target_clean,
        "target_type": req.target_type,
        "tech_stack": tech_stack,
        "open_ports": open_ports,
        "status": "queued",
        "progress_pct": 5,
        "stage": "Инициализация сканера уязвимостей...",
        "results": None,
        "error": None,
    })

    background_tasks.add_task(_run_vuln_scan_job, vuln_job_id, target_clean, tech_stack, open_ports)
    return {"status": "queued", "job_id": vuln_job_id, "tech_stack": tech_stack, "open_ports": open_ports}


@app.get("/api/vuln/scan/{job_id}")
def get_vuln_scan_status(job_id: str):
    job = VULN_JOBS.get(job_id)
    if job:
        if job.get("status") == "completed" and not job.get("results") and job.get("target"):
            saved = storage.get_vuln_analysis(job["target"])
            if saved:
                job = dict(job)
                job["results"] = saved
        return job
    raise HTTPException(status_code=404, detail="Vulnerability scan job not found")


@app.get("/api/vuln/check/{target}")
async def check_vuln_scan_target(target: str):
    """
    Checks if there is an active running job or saved SQLite vulnerability scan for a target.
    """
    allowed, target_clean = await validate_network_target(target)
    if not allowed:
        raise HTTPException(status_code=400, detail=target_clean)

    # 1. Check in-memory running / queued jobs
    for j_id, job in VULN_JOBS.items():
        if job["target"] == target_clean and job["status"] in ("queued", "running"):
            return job

    # 2. Check SQLite active_jobs for interrupted jobs with this target
    db_job = storage.get_job(target_clean)  # by job_id — skip

    # 3. Check SQLite Database for completed vuln scans
    db_saved = storage.get_vuln_analysis(target_clean)
    if db_saved:
        return {
            "status": "completed",
            "target": target_clean,
            "results": db_saved,
        }

    return {"status": "idle", "target": target_clean}


@app.get("/api/http/analyze/{target}")
async def analyze_http_tech(target: str, force: bool = Query(False)):
    """
    Analyzes target's HTTP security headers & detected technology stack.
    Checks SQLite database first unless force=True is specified.
    """
    allowed, target_clean = await validate_network_target(target)
    if not allowed:
        raise HTTPException(status_code=400, detail=target_clean)

    if not force:
        # Check in-memory cache first
        if target_clean in HTTP_CACHE:
            return _merge_nmap_stack(target_clean, HTTP_CACHE[target_clean])

        # Check SQLite Database next
        db_saved = storage.get_http_analysis(target_clean)
        if db_saved:
            HTTP_CACHE[target_clean] = db_saved
            return _merge_nmap_stack(target_clean, db_saved)

    analyzer = HTTPTechAnalyzer(timeout=7)
    res = await analyzer.analyze_target(target_clean)

    # Save to SQLite and in-memory cache
    HTTP_CACHE[target_clean] = res
    storage.save_http_analysis(target_clean, res)
    return _merge_nmap_stack(target_clean, res)


def _merge_nmap_stack(target: str, analysis: Dict[str, any]) -> Dict[str, any]:
    """Merge persisted Nmap -sV fingerprints into an HTTP technology report."""
    nmap_stack = set()
    try:
        target_ip = str(ipaddress.ip_address(target))
    except ValueError:
        target_ip = None

    for item in storage.get_global_scan_results():
        applies = item.get("ip") == target_ip if target_ip else any(
            domain == target or domain.endswith("." + target)
            for domain in item.get("domains", [])
        )
        if applies:
            nmap_stack.update(item.get("nmap_tech_stack", []))

    merged = dict(analysis)
    http_stack = list(analysis.get("tech_stack", []))
    merged["tech_sources"] = {"http": http_stack, "nmap": sorted(nmap_stack, key=str.casefold)}
    merged["tech_stack"] = NmapScanner.normalize_tech_stack(set(http_stack) | nmap_stack)
    return merged


@app.get("/", response_class=HTMLResponse)
def serve_index():
    return (_TEMPLATE_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/login", response_class=HTMLResponse)
def serve_login():
    return (_TEMPLATE_DIR / "login.html").read_text(encoding="utf-8")
