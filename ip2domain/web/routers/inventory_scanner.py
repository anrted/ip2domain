"""Universal inventory API, isolated from the existing /api/v2 camera contract."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse

from ip2domain.scanning.capabilities import capabilities
from ip2domain.scanning.persistence import InventoryRepository
from ip2domain.scanning.pipeline import run_scan
from ip2domain.scanning.policies import ScanConfig
from .common import storage

router = APIRouter()
_tasks = {}
_start_lock = asyncio.Lock()


def _admin(request: Request):
    if getattr(request.state, "user", {}).get("role") != "admin":
        raise HTTPException(403, "Administrator access required")


def _repo():
    # Derive at request time so existing storage/test isolation remains effective.
    path = os.environ.get("IP2DOMAIN_INVENTORY_DB_PATH", storage.db_path + ".inventory")
    return InventoryRepository(path)


def _enabled():
    if os.environ.get("IP2DOMAIN_SCANNER_V2_ENABLED", "0") != "1":
        raise HTTPException(403, "Set IP2DOMAIN_SCANNER_V2_ENABLED=1 to enable network scans")


def _launch(repository, identifier, credentials=None):
    key = (repository.path, identifier)
    if key in _tasks and not _tasks[key].done():
        raise HTTPException(409, "Scan is already running")
    task = asyncio.create_task(run_scan(repository, identifier, credentials=credentials))
    _tasks[key] = task
    def done(finished):
        if credentials is not None: credentials.clear()
        if _tasks.get(key) is finished:
            _tasks.pop(key, None)
        if not finished.cancelled():
            finished.exception()  # run_scan persists error state; consume exception.
    task.add_done_callback(done)


@router.get("/scanner-v2", response_class=HTMLResponse, dependencies=[Depends(_admin)])
def page():
    return (Path(__file__).resolve().parent.parent / "templates" / "inventory_scanner.html").read_text(encoding="utf-8")


@router.get("/api/scanner/v2/capabilities", dependencies=[Depends(_admin)])
def get_capabilities():
    return capabilities()


@router.post("/api/scanner/v2/scans", dependencies=[Depends(_admin)])
async def create_scan(payload: dict):
    _enabled()
    bool_fields = (
        "authorized", "active_consent", "nmap", "nmap_all_ports",
        "retain_all_states", "industrial_consent", "web_enrichment",
        "prioritize_base_ports", "media_catalog",
    )
    for field in bool_fields:
        if field in payload and isinstance(payload[field], str):
            payload[field] = payload[field].lower() in ("true", "1", "yes", "on")

    if payload.get("authorized") is not True:
        raise HTTPException(422, "Explicit authorization confirmation is required")
    try:
        from ip2domain.scanning.authentication import CredentialVault
        vault = CredentialVault(payload.get("credentials", []))
        config = ScanConfig(**{key: value for key, value in payload.items() if key not in ("authorized", "credentials")})
        if vault.entries and not config.allow_credentials: raise ValueError("credentials require allow_credentials")
        if any(not config.plan().scope.contains(c.host) for c in vault.entries): raise ValueError("credential host outside target scope")
        plan = config.plan()
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(422, str(exc))
    async with _start_lock:
        repository = _repo()
        if any(not task.done() for task in _tasks.values()):
            raise HTTPException(409, "Only one scan may run per API process")
        # Also check persisted active jobs: restart does not silently start another.
        if repository.active_scan():
            raise HTTPException(409, "Resume or cancel the existing unfinished scan first")
        try:
            identifier = await asyncio.to_thread(repository.create, config, plan, exclusive=True)
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        if vault.entries: _launch(repository, identifier, vault)
        else: _launch(repository, identifier)
    return {"id": identifier, "total_endpoints": plan.endpoint_count, "total_blocks": plan.total}


@router.get("/api/scanner/v2/scans", dependencies=[Depends(_admin)])
def list_scans():
    return _repo().list()


@router.get("/api/scanner/v2/scans/{identifier}", dependencies=[Depends(_admin)])
def get_scan(identifier: str):
    result = _repo().get(identifier)
    if result is None:
        raise HTTPException(404, "Scan not found")
    return result


@router.post("/api/scanner/v2/scans/{identifier}/{action}", dependencies=[Depends(_admin)])
async def control(identifier: str, action: str, payload: dict):
    if action not in ("pause", "cancel", "resume"):
        raise HTTPException(404, "Unknown action")
    repository = _repo()
    if repository.get(identifier) is None:
        raise HTTPException(404, "Scan not found")
    if action == "resume":
        _enabled()
        if payload.get("authorized") is not True:
            raise HTTPException(422, "Explicit authorization confirmation is required")
        async with _start_lock:
            if any(not task.done() for task in _tasks.values()):
                raise HTTPException(409, "Another executor is running")
            from ip2domain.scanning.authentication import CredentialVault
            try:
                vault=CredentialVault(payload.get("credentials",[]))
                config=ScanConfig(**repository.get(identifier)['config'])
                if vault.entries and not config.allow_credentials:raise ValueError('scan does not allow credentials')
                if any(not config.plan().scope.contains(c.host) for c in vault.entries):raise ValueError('credential outside scope')
            except (TypeError,ValueError) as exc: raise HTTPException(422,str(exc))
            if not repository.resume(identifier):
                raise HTTPException(409, "Scan cannot be resumed")
            if vault.entries: _launch(repository,identifier,vault)
            else: _launch(repository, identifier)
    else:
        status = "paused" if action == "pause" else "cancelled"
        repository.transition(identifier, status, ("queued", "running", "finalizing", "paused", "error"))
        task = _tasks.get((repository.path, identifier))
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    return {"id": identifier, "status": repository.status(identifier)}


@router.get("/api/scanner/v2/scans/{identifier}/endpoints", dependencies=[Depends(_admin)])
def endpoints(
    identifier: str, limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0), state: str = "", protocol: str = "", category: str = "",
):
    return _repo().endpoints(identifier, limit, offset, state or None, protocol or None, category or None)


@router.get("/api/scanner/v2/scans/{identifier}/export", dependencies=[Depends(_admin)])
def export(identifier: str, format: str = "ndjson", view: str = "inventory"):
    if format not in ("ndjson","json","csv","pdf"): raise HTTPException(422,"unsupported export format")
    repository = _repo()
    if repository.get(identifier) is None:
        raise HTTPException(404, "Scan not found")
    if format == "pdf":
        from ip2domain.scanning.reports import pdf_report
        from fastapi.responses import Response
        return Response(pdf_report(repository,identifier),media_type="application/pdf",headers={"Content-Disposition":'attachment; filename="inventory.pdf"'})
    def documents():
        offset = 0
        if format == "json": yield "["
        first=True
        if format == "csv": yield "host,device_type,vendor,model,firmware,ports,services,streams,confidence\n"
        while True:
            rows = repository.endpoints(identifier, 500, offset) if view == "ports" else repository.hosts(identifier, 100, offset)
            if not rows:
                break
            for row in rows:
                if format == "csv":
                    import csv,io
                    buffer=io.StringIO();writer=csv.writer(buffer);device=row.get('device',{})
                    writer.writerow([row.get('ip'),device.get('type'),device.get('vendor'),device.get('model'),device.get('firmware'),';'.join(str(p['port']) for p in row.get('ports',[])),';'.join(s['protocol'] for s in row.get('services',[])),len(row.get('streams',[])),device.get('confidence',0)])
                    yield buffer.getvalue()
                else:
                    yield ("," if format=="json" and not first else "")+json.dumps(row, ensure_ascii=False)+"\n"
                first=False
            offset += len(rows)
        if format == "json":yield "]"
    return StreamingResponse(
        documents(), media_type={"ndjson":"application/x-ndjson","json":"application/json","csv":"text/csv"}[format],
        headers={"Content-Disposition": 'attachment; filename="scanner-v2-export"'},
    )


async def shutdown_scans():
    tasks = list(_tasks.values())
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

@router.get('/api/scanner/v2/hosts', dependencies=[Depends(_admin)])
def hosts(scan_id: str, limit: int=Query(100,ge=1,le=500), offset: int=Query(0,ge=0)):
    return _repo().hosts(scan_id,limit,offset)

@router.get('/api/scanner/v2/hosts/{host}', dependencies=[Depends(_admin)])
def host_detail(host: str, scan_id: str):
    repo=_repo(); result=repo.host(scan_id,host)
    if result is None:
        with repo.connect() as db:
            row=db.execute('SELECT host FROM inventory_v2_hosts WHERE scan_id=? AND id=?',(scan_id,host)).fetchone()
        result=repo.host(scan_id,row[0]) if row else None
    if result is None:raise HTTPException(404,'Host not found')
    return result

@router.get('/api/scanner/v2/scans/{identifier}/events', dependencies=[Depends(_admin)])
async def events(identifier: str, request: Request, after: int=Query(0,ge=0)):
    repository=_repo()
    if repository.get(identifier) is None:raise HTTPException(404,'Scan not found')
    last=request.headers.get('last-event-id','')
    if last.isdigit():after=max(after,int(last))
    async def stream():
        cursor=after
        while not await request.is_disconnected():
            rows=await asyncio.to_thread(repository.events,identifier,cursor)
            for row in rows:
                cursor=row['id']
                yield f'id: {cursor}\nevent: {row["type"]}\ndata: {json.dumps(row)}\n\n'
            status=await asyncio.to_thread(repository.status,identifier)
            if not rows and status in ('completed','cancelled','error','paused'):break
            if not rows:
                yield ': heartbeat\n\n'
                await asyncio.sleep(1)
    return StreamingResponse(stream(),media_type='text/event-stream',headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

@router.post('/api/scanner/v2/fingerprints', dependencies=[Depends(_admin)])
def classify_unknown(payload: dict):
    try:return _repo().save_signature(payload)
    except (ValueError,TypeError) as exc:raise HTTPException(422,str(exc))

@router.get('/api/scanner/v2/{kind}', dependencies=[Depends(_admin)])
def entities(kind: str, scan_id: str, limit: int=Query(100,ge=1,le=500), offset: int=Query(0,ge=0), q: str=''):
    from ip2domain.scanning.graph_store import KINDS
    if kind not in KINDS:raise HTTPException(404,'Unknown resource')
    return _repo().entities(scan_id,kind,limit,offset,q)

@router.get('/api/scanner/v2/port-presets/{count}', dependencies=[Depends(_admin)])
def port_preset(count: int):
    if count not in (10,100,1000):raise HTTPException(422,'invalid port preset')
    from ip2domain.scanning.scan_modes import top_ports
    return top_ports(count)
