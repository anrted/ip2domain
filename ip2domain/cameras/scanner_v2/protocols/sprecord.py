"""SpRecord (OOO 'Сарапульские системы') Audio Recorder protocol probe.

Detects multi-channel telephone and audio conversation recording systems:
- SpRecord Web interface & Synapse backend
- Software info extraction (firmware version, web version)
- Challenge-response SHA256 authentication (default admin without password)
- Conversation records catalog & MP3 audio stream playback endpoints
"""
from __future__ import annotations

import base64
import hashlib
import logging
from typing import Dict, List, Optional, Tuple
import httpx

logger = logging.getLogger(__name__)
_TIMEOUT = 4.0


def compute_password_hash(password: str, salt: str) -> str:
    """Compute SpRecord challenge-response password hash: base64(sha256(password + salt))."""
    h = hashlib.sha256((password + salt).encode("utf-8")).digest()
    return base64.b64encode(h).decode("utf-8")


class SpRecordClient:
    """Async client for communicating with SpRecord server."""

    def __init__(self, ip: str, port: int = 8002, user: str = "admin", password: str = ""):
        self.ip = ip
        self.port = port
        self.user = user
        self.password = password
        self.base = f"http://{ip}:{port}"
        self._client: Optional[httpx.AsyncClient] = None
        self.authenticated = False

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(verify=False, timeout=12.0)
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def login(self, user: Optional[str] = None, password: Optional[str] = None) -> bool:
        u = user if user is not None else self.user
        p = password if password is not None else self.password
        client = await self._get_client()
        try:
            r1 = await client.post(f"{self.base}/", json={
                "cmd": "ui_event",
                "data": {
                    "type": "dialog_box_callback",
                    "button_id": "login_btn_ok_id",
                    "callback_data": "login_dialog_box_cbd",
                    "controls": [
                        {"id": "login_edit_username_id", "value": u},
                        {"id": "login_edit_pswd_id", "value": p}
                    ]
                }
            })
            d1 = r1.json()
            if "get_password_hash" not in d1:
                return False
            salt = d1["get_password_hash"].get("salt", "")
            cb = d1["get_password_hash"].get("callback_data", "")
            h_b64 = compute_password_hash(p, salt)
            r2 = await client.post(f"{self.base}/", json={
                "cmd": "password_hash",
                "hash": h_b64,
                "callback_data": cb
            })
            res = r2.json()
            self.authenticated = res.get("login_ok") is True
            if self.authenticated:
                self.user = u
                self.password = p
            return self.authenticated
        except Exception as exc:
            logger.debug("SpRecord login failed for %s on %s: %s", u, self.ip, exc)
            return False

    async def get_records(self, offset: int = 0, limit: int = 25) -> Dict:
        client = await self._get_client()
        if not self.authenticated:
            ok = await self.login()
            if not ok:
                return {"code": 401, "error": "Authentication required", "total": 0, "records": []}
        try:
            r = await client.post(f"{self.base}/", json={
                "cmd": "get_records",
                "row_offset": offset,
                "rows_per_page": limit
            })
            data = r.json()
            if data.get("code") == 200:
                return self._parse_records_response(data, offset, limit)
            # Session expired? Try re-login once
            if await self.login():
                r = await client.post(f"{self.base}/", json={
                    "cmd": "get_records",
                    "row_offset": offset,
                    "rows_per_page": limit
                })
                data = r.json()
                if data.get("code") == 200:
                    return self._parse_records_response(data, offset, limit)
        except Exception as exc:
            logger.debug("Failed getting SpRecord records for %s: %s", self.ip, exc)
        return {"code": 500, "error": "Failed fetching records", "total": 0, "records": []}

    def _parse_records_response(self, data: Dict, offset: int, limit: int) -> Dict:
        raw_records = data.get("data", [])
        records = []
        for item in raw_records:
            rec_id = item.get("id")
            row = item.get("row", [])
            channel = row[0] if len(row) > 0 else ""
            time_str = row[1] if len(row) > 1 else ""
            dur_str = row[2] if len(row) > 2 else ""
            rec_type = row[3].get("caption", "") if len(row) > 3 and isinstance(row[3], dict) else (row[3] if len(row) > 3 else "")
            caller = row[4] if len(row) > 4 else ""
            filename = item.get("filename", f"{rec_id}.wav")
            records.append({
                "id": rec_id,
                "channel": channel,
                "time": time_str,
                "duration": dur_str,
                "type": rec_type,
                "caller": caller,
                "filename": filename,
                "audio_url": f"/api/v2/sprecord/audio?ip={self.ip}&record_id={rec_id}",
                "download_url": f"/api/v2/sprecord/audio?ip={self.ip}&record_id={rec_id}&download=1",
            })
        return {
            "code": 200,
            "total": data.get("total", 0),
            "offset": offset,
            "limit": limit,
            "records": records,
        }

    async def get_audio_bytes(self, record_id: int) -> Tuple[Optional[bytes], str]:
        client = await self._get_client()
        if not self.authenticated:
            await self.login()
        try:
            r = await client.get(f"{self.base}/records/audio/{record_id}")
            if r.status_code == 200 and "json" in r.headers.get("content-type", ""):
                # Session expired, re-login
                if await self.login():
                    r = await client.get(f"{self.base}/records/audio/{record_id}")
            if r.status_code == 200 and "audio" in r.headers.get("content-type", ""):
                return r.content, r.headers.get("content-type", "audio/mpeg")
            if r.status_code == 200 and len(r.content) > 64:
                return r.content, "audio/mpeg"
        except Exception as exc:
            logger.debug("Failed getting SpRecord audio %s for %s: %s", record_id, self.ip, exc)
        return None, ""


async def probe_sprecord(
    ip: str,
    candidate_ports: List[int],
    credentials: List[Tuple[str, str]],
) -> Dict:
    """Probe HTTP ports for SpRecord Audio Recording Server.

    Returns dict with success, brand, model, firmware, streams, http_port, credentials, etc.
    """
    result = {
        "success": False,
        "brand": "SpRecord",
        "model": "Audio Recorder",
        "firmware": "",
        "http_port": 0,
        "auth_required": False,
        "credentials": {},
        "streams": [],
        "protocols": ["sprecord_audio"],
        "total_records": 0,
        "recent_records": [],
    }
    if not candidate_ports:
        return result

    # Standard SpRecord web ports are typically 8002, 8080, 8000, 80
    ports = sorted(candidate_ports, key=lambda p: (0 if p == 8002 else (1 if p in {80, 8080, 8000} else 2)))

    async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT, follow_redirects=True) as client:
        for port in ports:
            base = f"http://{ip}:{port}"
            detected = False
            server_header = ""

            # 1. Quick check for SpRecord banner/signature
            try:
                r_root = await client.get(f"{base}/", timeout=_TIMEOUT)
                server_header = r_root.headers.get("server", "")
                text_root = r_root.text
                if (
                    "sprecord" in server_header.lower()
                    or "sprecord" in text_root.lower()
                    or "система многоканальной записи" in text_root.lower()
                ):
                    detected = True
            except Exception:
                continue

            if not detected:
                # Try JSON command probe directly
                try:
                    r_cmd = await client.post(
                        f"{base}/",
                        json={"cmd": "login", "web_version": "1.07"},
                        timeout=_TIMEOUT,
                    )
                    if r_cmd.status_code == 200 and "sprecord" in r_cmd.text.lower():
                        detected = True
                except Exception:
                    pass

            if not detected:
                continue

            result["success"] = True
            result["http_port"] = port

            # Extract software info
            try:
                r_info = await client.post(
                    f"{base}/",
                    json={"cmd": "login", "web_version": "1.07"},
                    timeout=_TIMEOUT,
                )
                if r_info.status_code == 200:
                    data = r_info.json()
                    sw_info = data.get("software_info", {})
                    table = sw_info.get("table_data", [])
                    versions = [item.get("value") for item in table if isinstance(item, dict) and item.get("value")]
                    if versions:
                        result["firmware"] = ", ".join(versions)
                    else:
                        result["firmware"] = "1.2.0"
                    result["model"] = "Система записи разговоров SpRecord"
            except Exception as exc:
                logger.debug("Failed fetching SpRecord sw_info on %s:%d: %s", ip, port, exc)

            # 2. Authentication testing
            test_creds = [("admin", "")]
            for u, p in credentials:
                if (u, p) not in test_creds:
                    test_creds.append((u, p))
            if ("admin", "admin") not in test_creds:
                test_creds.append(("admin", "admin"))
            if ("admin", "12345") not in test_creds:
                test_creds.append(("admin", "12345"))

            auth_ok = False
            sp_client = SpRecordClient(ip, port)

            for user, password in test_creds:
                if await sp_client.login(user, password):
                    auth_ok = True
                    result["auth_required"] = False
                    result["credentials"] = {"user": user, "password": password}
                    break

            if not auth_ok:
                result["auth_required"] = True
                result["streams"].append({
                    "type": "http_web",
                    "url": f"{base}/",
                    "title": "SpRecord Web (требуется пароль)",
                    "auth_required": True,
                })
                await sp_client.close()
                return result

            # 3. Retrieve conversation records list and audio stream URLs
            try:
                rec_data = await sp_client.get_records(0, 5)
                total = rec_data.get("total", 0)
                result["total_records"] = total
                if total > 0:
                    fmt_total = f"{total:,}".replace(",", " ")
                    result["model"] = f"Система записи разговоров SpRecord ({fmt_total} записей)"
                else:
                    result["model"] = "Система записи разговоров SpRecord"

                # Primary stream: Web portal / login page
                result["streams"].append({
                    "type": "http_web",
                    "url": f"{base}/",
                    "title": f"SpRecord Web ({total} записей)",
                    "verified": True,
                })

                # Sample audio stream proxy
                records = rec_data.get("records", [])
                if records:
                    top = records[0]
                    result["streams"].append({
                        "type": "sprecord_audio",
                        "url": top["audio_url"],
                        "filename": top.get("filename", ""),
                        "title": f"Последняя запись: {top.get('channel')} ({top.get('time')}, {top.get('duration')})",
                        "verified": True,
                    })

            except Exception as exc:
                logger.debug("Failed retrieving SpRecord records on %s: %s", ip, exc)

            await sp_client.close()
            return result

    return result
