"""go2rtc WebRTC and WebSocket streaming proxy endpoints."""
import asyncio
import hashlib
import re
import shutil
from pathlib import Path
from fastapi import APIRouter, HTTPException, Query, Request, Response, WebSocket
from fastapi.responses import HTMLResponse
import httpx
import websockets

from ip2domain.web.routers.common import GO2RTC_API_URL, GO2RTC_WS_URL, STRIX_CAPTURE_DIR, STRIX_FFMPEG_SEMAPHORE

router = APIRouter(tags=["go2rtc"])

async def _extract_frame_fallback(stream_url: str, output_file: Path) -> bool:
    """Capture a single frame from an RTSP/HTTP camera stream using ffmpeg."""
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg or not stream_url:
        return False
    temp_file = output_file.with_suffix(".tmp.jpg")
    try:
        temp_file.unlink(missing_ok=True)
        async with STRIX_FFMPEG_SEMAPHORE:
            cmd = [
                ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
                "-rtsp_transport", "tcp",
                "-timeout", "5000000",
                "-i", stream_url,
                "-vframes", "1",
                "-q:v", "3",
                "-f", "image2",
                str(temp_file)
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            try:
                await asyncio.wait_for(proc.wait(), timeout=6.0)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return False

        if temp_file.exists() and temp_file.stat().st_size > 0:
            temp_file.replace(output_file)
            return True
        return False
    except Exception:
        return False
    finally:
        temp_file.unlink(missing_ok=True)

from pydantic import BaseModel, Field
from typing import List, Optional
from ip2domain.web.routers.common import storage

class CameraMetaRequest(BaseModel):
    custom_title: Optional[str] = None
    group_ip: Optional[str] = None
    group_name: Optional[str] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None
    is_favorite: Optional[bool] = None

class GroupMetaRequest(BaseModel):
    custom_name: Optional[str] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None
    is_favorite: Optional[bool] = None

@router.get("/api/go2rtc/meta")
def get_go2rtc_meta():
    """Retrieve all stored metadata for go2rtc cameras and groups."""
    return storage.get_all_go2rtc_meta()

@router.post("/api/go2rtc/meta/camera/{stream_name}")
def save_camera_meta(stream_name: str, req: CameraMetaRequest):
    """Update metadata for an individual camera stream."""
    return storage.save_go2rtc_camera_meta(
        stream_name=stream_name,
        custom_title=req.custom_title,
        group_ip=req.group_ip,
        group_name=req.group_name,
        tags=req.tags,
        notes=req.notes,
        is_favorite=req.is_favorite,
    )

@router.post("/api/go2rtc/meta/group/{group_ip}")
def save_group_meta(group_ip: str, req: GroupMetaRequest):
    """Update metadata for an IP / location group."""
    return storage.save_go2rtc_group_meta(
        group_ip=group_ip,
        custom_name=req.custom_name,
        tags=req.tags,
        notes=req.notes,
        is_favorite=req.is_favorite,
    )

@router.get("/api/go2rtc/status")
async def get_go2rtc_status():
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{GO2RTC_API_URL}/api/streams")
            return {"online": resp.status_code == 200, "url": GO2RTC_API_URL}
    except Exception as exc:
        return {"online": False, "url": GO2RTC_API_URL, "error": str(exc)}

@router.get("/api/go2rtc/streams")
async def get_go2rtc_streams():
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{GO2RTC_API_URL}/api/streams")
            if resp.status_code == 200:
                streams = resp.json()
                meta = storage.get_all_go2rtc_meta()
                return {
                    "streams": streams,
                    "meta": meta,
                }
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@router.post("/api/go2rtc/streams")
async def add_go2rtc_stream(req: Request):
    data = await req.json()
    name = data.get("name", "").strip()
    raw_url = data.get("url")
    tags = data.get("tags")
    group_name = data.get("group_name")
    custom_title = data.get("custom_title")
    if isinstance(raw_url, list):
        url_list = [str(u).strip() for u in raw_url if str(u).strip()]
    elif isinstance(raw_url, str):
        url_list = [raw_url.strip()]
    else:
        url_list = []

    # Smart Multi-Source Candidate Generator for robust streaming:
    # 1. Original URL (e.g. rtsp://admin:pass@IP/path)
    # 2. Anonymous URL (without credentials, if camera is public/anonymous)
    # 3. Default credentials (admin:admin, admin:123456)
    # 4. If path is "/" or empty on Hipcam/generic devices, fallback to "/11", "/12", "/1/stream1"
    expanded_urls = []
    for u in url_list:
        candidates = [u]
        
        # Strip empty/broken creds: admin:@, :@
        no_empty_creds = re.sub(r'rtsp://[a-zA-Z0-9_-]+:@', 'rtsp://', u)
        no_empty_creds = re.sub(r'rtsp://:@', 'rtsp://', no_empty_creds)
        if no_empty_creds not in candidates:
            candidates.append(no_empty_creds)
            
        # Completely anonymous candidate (without any user/password)
        no_creds = re.sub(r'rtsp://[^@]+@', 'rtsp://', u)
        if no_creds not in candidates:
            candidates.append(no_creds)
            
        # If credentials were admin: or empty, test admin:admin
        if 'admin:@' in u or 'rtsp://' in no_creds:
            admin_admin = re.sub(r'rtsp://([^@]+@)?', 'rtsp://admin:admin@', no_creds)
            if admin_admin not in candidates:
                candidates.append(admin_admin)

        # Path fallbacks for root '/'
        for cand in list(candidates):
            if cand.endswith('/'):
                cand_11 = cand[:-1] + '/11'
                cand_stream = cand[:-1] + '/1/stream1'
                if cand_11 not in candidates:
                    candidates.append(cand_11)
                if cand_stream not in candidates:
                    candidates.append(cand_stream)

        # Also register ffmpeg: source as ultimate fallback
        # for cameras with quirky RTSP SETUP behavior
        for cand in list(candidates)[:2]:
            ff_cand = f"ffmpeg:{cand}#video=copy"
            if ff_cand not in candidates:
                candidates.append(ff_cand)

        for c in candidates:
            if c not in expanded_urls:
                expanded_urls.append(c)

    url_list = expanded_urls

    if not name or not url_list:
        raise HTTPException(status_code=400, detail="Укажите имя и RTSP URL камеры")
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.put(f"{GO2RTC_API_URL}/api/streams", params={"name": name, "src": url_list})
            if resp.status_code not in (200, 201):
                raise HTTPException(status_code=502, detail=f"Ошибка go2rtc: {resp.text}")
            
            # Save metadata if provided
            if tags or group_name or custom_title:
                storage.save_go2rtc_camera_meta(
                    stream_name=name,
                    custom_title=custom_title,
                    group_name=group_name,
                    tags=tags,
                )
            return {"success": True, "name": name}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@router.delete("/api/go2rtc/streams/{name}")
async def delete_go2rtc_stream(name: str):
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.delete(f"{GO2RTC_API_URL}/api/streams", params={"src": name})
            return {"success": True}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@router.get("/api/go2rtc/player/{filename:path}")
async def proxy_go2rtc_player_asset(filename: str, src: str = Query(default="")):
    try:
        url = f"{GO2RTC_API_URL}/{filename}"
        params = {"src": src} if src else None
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(url, params=params)
            media_type = resp.headers.get("content-type", "text/plain")
            content = resp.content
            if "text/html" in media_type:
                html = resp.text
                html = html.replace("api/ws?src=", "/api/go2rtc/proxy/api/ws?src=")
                html = html.replace("api/ws'", "/api/go2rtc/proxy/api/ws'")
                html = html.replace('api/ws"', '/api/go2rtc/proxy/api/ws"')
                html = html.replace("api/webrtc", "/api/go2rtc/proxy/api/webrtc")
                return HTMLResponse(html, status_code=resp.status_code)
            return Response(content=content, status_code=resp.status_code, media_type=media_type)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"go2rtc недоступен: {exc}")

@router.post("/api/go2rtc/proxy/api/webrtc")
async def proxy_go2rtc_webrtc(req: Request):
    try:
        body = await req.body()
        query = req.url.query
        target_url = f"{GO2RTC_API_URL}/api/webrtc" + (f"?{query}" if query else "")
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(target_url, content=body, headers={"Content-Type": req.headers.get("content-type", "application/x-www-form-urlencoded")})
            return Response(content=resp.content, status_code=resp.status_code, media_type=resp.headers.get("content-type"))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))

@router.get("/api/go2rtc/frame/{name:path}")
async def proxy_go2rtc_frame(name: str):
    """Proxy live JPEG snapshot frame from go2rtc, with fallback to direct frame extraction."""
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(f"{GO2RTC_API_URL}/api/frame.jpeg", params={"src": name})
            if resp.status_code == 200 and len(resp.content) > 500:
                return Response(
                    content=resp.content,
                    media_type="image/jpeg",
                    headers={"Cache-Control": "public, max-age=21600, stale-while-revalidate=86400"}
                )

            # Fallback
            streams_resp = await client.get(f"{GO2RTC_API_URL}/api/streams", params={"src": name})
            if streams_resp.status_code == 200:
                sdata = streams_resp.json()
                stream_info = sdata.get("streams", {}).get(name) or sdata.get(name) or {}
                producers = stream_info.get("producers", [])
                src_url = producers[0].get("url") if producers else None
                if src_url and not src_url.startswith("ffmpeg:"):
                    url_hash = hashlib.md5(src_url.encode('utf-8')).hexdigest()
                    cache_file = STRIX_CAPTURE_DIR / f"{url_hash}.jpg"
                    if cache_file.exists() and cache_file.stat().st_size > 0:
                        return Response(
                            content=cache_file.read_bytes(),
                            media_type="image/jpeg",
                            headers={"Cache-Control": "public, max-age=21600, stale-while-revalidate=86400"}
                        )
                    success = await _extract_frame_fallback(src_url, cache_file)
                    if success and cache_file.exists():
                        return Response(
                            content=cache_file.read_bytes(),
                            media_type="image/jpeg",
                            headers={"Cache-Control": "public, max-age=21600, stale-while-revalidate=86400"}
                        )

            return Response(status_code=resp.status_code if resp.status_code != 200 else 503, content=b"")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))

@router.websocket("/api/go2rtc/proxy/api/ws")
async def proxy_go2rtc_ws(websocket: WebSocket):
    await websocket.accept()
    query = websocket.scope.get("query_string", b"").decode("utf-8")
    target_ws = f"{GO2RTC_WS_URL}/api/ws" + (f"?{query}" if query else "")
    try:
        async with websockets.connect(target_ws) as go2rtc_ws:
            async def client_to_go2rtc():
                try:
                    while True:
                        msg = await websocket.receive_text()
                        await go2rtc_ws.send(msg)
                except Exception:
                    pass

            async def go2rtc_to_client():
                try:
                    async for msg in go2rtc_ws:
                        if isinstance(msg, bytes):
                            await websocket.send_bytes(msg)
                        else:
                            await websocket.send_text(msg)
                except Exception:
                    pass

            await asyncio.gather(client_to_go2rtc(), go2rtc_to_client())
    except Exception:
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass

from ip2domain.cameras.ptz import PTZController

class PTZControlRequest(BaseModel):
    ip: str
    command: str
    port: Optional[int] = 80
    username: Optional[str] = "admin"
    password: Optional[str] = ""
    speed: Optional[float] = 0.5
    preset_token: Optional[str] = "1"

@router.get("/api/go2rtc/ptz/probe")
async def probe_ptz_endpoint(ip: str = Query(...), port: int = Query(default=80), user: str = Query(default="admin"), pwd: str = Query(default="")):
    """Probe whether camera supports ONVIF / CGI PTZ control."""
    res = await PTZController.probe_ptz_service(ip, port=port, username=user, password=pwd)
    return res

@router.post("/api/go2rtc/ptz/control")
async def control_ptz_endpoint(req: PTZControlRequest):
    """Send Move, Stop, Preset or Patrol command to camera."""
    res = await PTZController.send_ptz_command(
        ip=req.ip,
        command=req.command,
        port=req.port or 80,
        username=req.username or "admin",
        password=req.password or "",
        speed=req.speed or 0.5,
        preset_token=req.preset_token or "1"
    )
    return res

