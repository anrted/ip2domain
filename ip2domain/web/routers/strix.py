"""Strix Video Stream Discovery, ASN Lookup, Checkpoints & Frame Captures."""
import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import httpx
from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel

from ip2domain.core.ip_parser import IPParser
from ip2domain.web.routers.common import (
    storage,
    GO2RTC_API_URL,
    STRIX_API_URL,
    STRIX_FFMPEG_SEMAPHORE,
    STRIX_CAPTURE_LOCKS,
    STRIX_CAPTURE_DIR,
    strix_jobs,
    strix_results_cache,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["strix"])

@router.get("/api/strix/status")
async def get_strix_status():
    """Check connectivity to the Strix service."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{STRIX_API_URL}/")
            return {"online": resp.status_code == 200, "url": STRIX_API_URL}
    except Exception as exc:
        return {"online": False, "url": STRIX_API_URL, "error": str(exc)}

@router.get("/api/strix/presets")
async def get_strix_presets():
    """Retrieve preset list and camera brands from Strix."""
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(f"{STRIX_API_URL}/api/search?q=")
            if resp.status_code == 200:
                data = resp.json()
                return {"results": data.get("results", [])}
            return {"results": []}
    except Exception as exc:
        return {"results": [], "error": str(exc)}

@router.get("/api/asn/lookup")
@router.get("/api/strix/asn-prefixes")
async def lookup_asn_prefixes(asn: str = Query(..., description="ASN number or AS prefix e.g. 12958 or AS12958")):
    """Lookup announced IP ranges/prefixes by ASN number from RIPE Stat and 2ip.io."""
    raw_asn = str(asn or "").strip().upper()
    asn_num = re.sub(r'[^0-9]', '', raw_asn)
    if not asn_num:
        raise HTTPException(status_code=400, detail="Укажите корректный номер ASN (например: 12958 или AS12958)")

    prefixes_v4: List[str] = []
    prefixes_v6: List[str] = []
    asn_info: Dict[str, Any] = {"asn": f"AS{asn_num}", "source": ""}

    # 1. Primary fast source: RIPE Stat API
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.get(
                f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_num}",
                headers={"User-Agent": "ip2domain/1.0"}
            )
            if r.status_code == 200:
                data = r.json()
                asn_info["source"] = "RIPE Stat"
                for item in data.get("data", {}).get("prefixes", []):
                    pref = str(item.get("prefix") or "").strip()
                    if pref:
                        if ":" in pref:
                            prefixes_v6.append(pref)
                        else:
                            prefixes_v4.append(pref)
    except Exception:
        pass

    # 2. Fallback source: 2ip.io
    if not prefixes_v4 and not prefixes_v6:
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/json",
            }
            async with httpx.AsyncClient(timeout=3.0, headers=headers) as client:
                r = await client.get(f"https://2ip.io/as/{asn_num}.json")
                if r.status_code == 200:
                    data = r.json()
                    asn_info["source"] = "2ip.io"
                    if isinstance(data, dict):
                        prefixes = data.get("prefixes") or data.get("routes") or data.get("ip_ranges") or []
                        if isinstance(prefixes, list):
                            for p in prefixes:
                                pref = str(p.get("prefix") if isinstance(p, dict) else p).strip()
                                if pref:
                                    if ":" in pref:
                                        prefixes_v6.append(pref)
                                    else:
                                        prefixes_v4.append(pref)
        except Exception:
            pass

    if not prefixes_v4 and not prefixes_v6:
        raise HTTPException(status_code=404, detail=f"Не удалось найти анонсированные префиксы для AS{asn_num}")

    prefixes_v4 = list(dict.fromkeys(prefixes_v4))
    prefixes_v6 = list(dict.fromkeys(prefixes_v6))

    return {
        "asn": f"AS{asn_num}",
        "source": asn_info.get("source", ""),
        "total_v4_prefixes": len(prefixes_v4),
        "total_v6_prefixes": len(prefixes_v6),
        "prefixes_v4": prefixes_v4,
        "prefixes_v6": prefixes_v6,
        "prefixes": prefixes_v4,
    }

from ip2domain.cameras.strix_engine import (
    check_single_port as check_ip_camera_port,
    probe_ip_ports as fast_ip_camera_probe,
    extract_stream_frame as extract_strix_stream_frame,
    run_strix_scan_pipeline as strix_scan_worker,
)

@router.get("/api/strix/targets/db_ips")
async def get_strix_db_targets():
    """Retrieve saved camera IPs from SQLite classified by presence in go2rtc."""
    try:
        results = storage.get_strix_results()
        active_results = [r for r in results if not r.get("is_garbage")]
        all_saved_ips = [r["ip"] for r in active_results if r.get("ip")]
        all_saved_ips = list(dict.fromkeys(all_saved_ips))
    except Exception as err:
        logger.error("Failed to query strix_results for target presets: %s", err)
        all_saved_ips = []

    go2rtc_ips = set()
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{GO2RTC_API_URL}/api/streams")
            if resp.status_code == 200:
                for s_name, s_data in resp.json().items():
                    if isinstance(s_data, dict):
                        producers = s_data.get("producers") or []
                        for p in producers:
                            if isinstance(p, dict):
                                p_url = p.get("url") or ""
                                m = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", p_url)
                                go2rtc_ips.update(m)
                    m_name = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", str(s_name))
                    go2rtc_ips.update(m_name)
    except Exception:
        pass

    not_in_go2rtc = [ip for ip in all_saved_ips if ip not in go2rtc_ips]
    in_go2rtc = [ip for ip in all_saved_ips if ip in go2rtc_ips]

    return {
        "all_ips": all_saved_ips,
        "not_in_go2rtc": not_in_go2rtc,
        "in_go2rtc": in_go2rtc,
        "counts": {
            "total_saved": len(all_saved_ips),
            "not_in_go2rtc": len(not_in_go2rtc),
            "in_go2rtc": len(in_go2rtc),
        }
    }


@router.post("/api/strix/scan")
async def start_strix_scan(req: Request):
    """Start high-speed concurrent batch scan of multiple IPs via Strix."""
    data = await req.json()
    raw_targets = str(data.get("targets") or "").strip()
    if not raw_targets:
        raise HTTPException(status_code=400, detail="Укажите один или несколько IP-адресов / CIDR / диапазонов")

    ids = str(data.get("ids") or "p:top-150").strip()
    user = str(data.get("user") if "user" in data else "admin").strip()
    if user == "":
        user = "admin"
    password = str(data.get("password") or "").strip()
    channel = str(data.get("channel") or "").strip()
    ports = str(data.get("ports") or "").strip()
    skip_existing = bool(data.get("skip_existing", False))
    skip_cidrs = bool(data.get("skip_cidrs", False))
    strict_video_only = bool(data.get("strict_video_only", True))
    concurrency = int(data.get("concurrency") or 10)

    lines = [line.strip() for line in raw_targets.splitlines() if line.strip() and not line.strip().startswith("#")]
    
    # Check for previously scanned CIDRs if skip_cidrs is enabled
    scanned_cidrs_set = storage.get_strix_scanned_cidr_set() if skip_cidrs else set()
    active_lines = []
    skipped_cidr_lines = []
    
    for l in lines:
        if skip_cidrs and l in scanned_cidrs_set:
            skipped_cidr_lines.append(l)
        else:
            active_lines.append(l)

    try:
        parsed_ips = list(IPParser.parse_targets(active_lines))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
        
    if not parsed_ips:
        if skipped_cidr_lines:
            raise HTTPException(status_code=400, detail=f"Все указанные диапазоны ({len(skipped_cidr_lines)} CIDR) уже были полностью отсканированы ранее")
        raise HTTPException(status_code=400, detail="Не удалось распознать ни одного корректного IP-адреса")

    job_id = f"strix_{uuid.uuid4().hex[:10]}"
    params = {
        "ids": ids,
        "user": user,
        "password": password,
        "channel": channel,
        "ports": ports,
        "skip_existing": skip_existing,
        "skip_cidrs": skip_cidrs,
        "strict_video_only": strict_video_only,
        "input_cidrs": [l for l in lines if "/" in l or "-" in l],
        "concurrency": concurrency,
    }

    try:
        storage.create_strix_job(job_id, parsed_ips, params)
    except Exception as err:
        logger.error("Failed to create strix job in SQLite: %s", err)

    initial_logs = []
    if skipped_cidr_lines:
        initial_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Пропущено ранее отсканированных подсетей: {len(skipped_cidr_lines)} ({', '.join(skipped_cidr_lines[:5])}{'...' if len(skipped_cidr_lines) > 5 else ''})")

    job_info = {
        "job_id": job_id,
        "status": "queued",
        "created_at": datetime.now().isoformat(),
        "total_targets": len(parsed_ips),
        "current_index": 0,
        "current_ip": "",
        "progress_pct": 0,
        "stage": f"В очереди: {len(parsed_ips)} IP-адресов",
        "results": [],
        "logs": initial_logs,
        "active_session_id": None,
        "cancelling": False,
        "cancelled": False,
    }
    strix_jobs[job_id] = job_info

    asyncio.create_task(strix_scan_worker(
        job_id,
        parsed_ips,
        ids,
        user,
        password,
        channel,
        ports,
        skip_existing=skip_existing,
        concurrency=concurrency,
        start_index=0,
        strict_video_only=strict_video_only,
    ))
    return {
        "job_id": job_id,
        "total_targets": len(parsed_ips),
        "skipped_cidrs": len(skipped_cidr_lines)
    }

@router.get("/api/strix/scan/{job_id}")
async def get_strix_scan_status(job_id: str):
    job = strix_jobs.get(job_id)
    if not job:
        db_job = storage.get_strix_job(job_id)
        if not db_job:
            raise HTTPException(status_code=404, detail="Задание не найдено")
        return db_job
    return job

@router.post("/api/strix/scan/{job_id}/cancel")
async def cancel_strix_scan(job_id: str):
    job = strix_jobs.get(job_id)
    if job:
        job["cancelling"] = True
        job["cancelled"] = True
    try:
        storage.update_strix_job_progress(job_id, 0, "", 0, "Остановлено пользователем", status="cancelled")
    except Exception:
        pass
    return {"success": True}

@router.get("/api/strix/results")
async def get_strix_results():
    try:
        db_results = storage.get_strix_results()
        if db_results:
            return {"results": db_results}
    except Exception as err:
        logger.error("Failed to read strix results from SQLite: %s", err)
    return {"results": strix_results_cache}

class StrixGarbageRequest(BaseModel):
    is_garbage: bool = True


@router.post("/api/strix/results/{ip}/garbage")
async def set_strix_result_garbage(ip: str, req: StrixGarbageRequest):
    clean_ip = str(ip or "").strip()
    if not clean_ip:
        raise HTTPException(status_code=400, detail="IP адрес не указан")
    
    # Update in memory cache
    for item in strix_results_cache:
        if item.get("ip") == clean_ip:
            item["is_garbage"] = bool(req.is_garbage)
            
    # Update in SQLite
    try:
        storage.set_strix_garbage_status(clean_ip, bool(req.is_garbage))
    except Exception as err:
        logger.error("Failed to update strix garbage status in SQLite: %s", err)
        raise HTTPException(status_code=500, detail="Ошибка сохранения статуса в базе данных")
        
    return {"success": True, "ip": clean_ip, "is_garbage": bool(req.is_garbage)}


@router.delete("/api/strix/results")
async def clear_strix_results():
    strix_results_cache.clear()
    try:
        storage.clear_strix_results()
    except Exception as err:
        logger.error("Failed to clear strix results in SQLite: %s", err)
    return {"success": True}

@router.get("/api/strix/preview")
async def get_strix_stream_preview(url: str = Query(..., description="RTSP / HTTP stream URL")):
    """Get or generate thumbnail preview for any discovered Strix stream URL."""
    stream_url = str(url or "").strip()
    if not stream_url:
        raise HTTPException(status_code=400, detail="URL потока не указан")

    url_hash = hashlib.md5(stream_url.encode('utf-8')).hexdigest()
    cache_file = STRIX_CAPTURE_DIR / f"{url_hash}.jpg"
    fail_file = STRIX_CAPTURE_DIR / f"{url_hash}.failed"

    if cache_file.exists() and cache_file.stat().st_size > 0:
        return Response(
            content=cache_file.read_bytes(),
            media_type="image/jpeg",
            headers={"Cache-Control": "public, max-age=86400, stale-while-revalidate=604800"}
        )

    # Check negative cache: if failed within the last 10 minutes, return 404 immediately
    if fail_file.exists():
        try:
            mtime = fail_file.stat().st_mtime
            if (datetime.now().timestamp() - mtime) < 600:
                raise HTTPException(status_code=404, detail="Снимок недоступен (камера не отдает видеопоток)")
        except HTTPException:
            raise
        except Exception:
            pass

    lock = STRIX_CAPTURE_LOCKS.setdefault(url_hash, asyncio.Lock())
    async with lock:
        if cache_file.exists() and cache_file.stat().st_size > 0:
            return Response(
                content=cache_file.read_bytes(),
                media_type="image/jpeg",
                headers={"Cache-Control": "public, max-age=86400, stale-while-revalidate=604800"}
            )

        success = await extract_strix_stream_frame(stream_url, cache_file)
        if success and cache_file.exists() and cache_file.stat().st_size > 0:
            fail_file.unlink(missing_ok=True)
            return Response(
                content=cache_file.read_bytes(),
                media_type="image/jpeg",
                headers={"Cache-Control": "public, max-age=86400, stale-while-revalidate=604800"}
            )
        else:
            try:
                fail_file.write_text(datetime.now().isoformat())
            except Exception:
                pass

    raise HTTPException(status_code=404, detail="Не удалось захватить кадр потока")

@router.get("/api/strix/screenshot/{session_id}/{index}")
async def proxy_strix_screenshot(session_id: str, index: int):
    """Proxy screenshot from Strix test session or fallback to saved stream capture."""
    safe_session = re.sub(r'[^a-zA-Z0-9_-]', '_', session_id)
    cache_file = STRIX_CAPTURE_DIR / f"{safe_session}_{index}.jpg"

    if cache_file.exists() and cache_file.stat().st_size > 0:
        return Response(
            content=cache_file.read_bytes(),
            media_type="image/jpeg",
            headers={"Cache-Control": "public, max-age=86400, stale-while-revalidate=604800"}
        )

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(f"{STRIX_API_URL}/api/test/screenshot", params={"id": session_id, "i": index})
            if resp.status_code == 200 and len(resp.content) > 0:
                try:
                    cache_file.write_bytes(resp.content)
                except Exception:
                    pass
                return Response(
                    content=resp.content,
                    media_type="image/jpeg",
                    headers={"Cache-Control": "public, max-age=86400, stale-while-revalidate=604800"}
                )
    except Exception:
        pass

    stream_url = None
    try:
        db_results = storage.get_strix_results()
        for item in db_results:
            if item.get("session_id") == session_id:
                streams = item.get("streams") or []
                if 0 <= index < len(streams):
                    stream_url = streams[index].get("source")
                    break
    except Exception:
        pass

    if stream_url:
        url_hash = hashlib.md5(stream_url.encode('utf-8')).hexdigest()
        hash_file = STRIX_CAPTURE_DIR / f"{url_hash}.jpg"
        if hash_file.exists() and hash_file.stat().st_size > 0:
            try:
                cache_file.write_bytes(hash_file.read_bytes())
            except Exception:
                pass
            return Response(
                content=hash_file.read_bytes(),
                media_type="image/jpeg",
                headers={"Cache-Control": "public, max-age=86400, stale-while-revalidate=604800"}
            )
        success = await extract_strix_stream_frame(stream_url, hash_file)
        if success and hash_file.exists() and hash_file.stat().st_size > 0:
            try:
                cache_file.write_bytes(hash_file.read_bytes())
            except Exception:
                pass
            return Response(
                content=hash_file.read_bytes(),
                media_type="image/jpeg",
                headers={"Cache-Control": "public, max-age=86400, stale-while-revalidate=604800"}
            )

    raise HTTPException(status_code=404, detail="Снимок недоступен")
