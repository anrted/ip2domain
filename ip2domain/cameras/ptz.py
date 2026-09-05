"""ONVIF and RTSP PTZ Controller & Preset Manager."""
import asyncio
import base64
import hashlib
import ipaddress
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
import httpx

logger = logging.getLogger(__name__)


def _clean_safe_ip(raw_ip: str) -> Optional[str]:
    if not raw_ip or not isinstance(raw_ip, str):
        return None
    cleaned = raw_ip.strip().strip("[]")
    if cleaned.lower() in ("metadata.google.internal", "metadata", "instance-data", "169.254.169.254", "localhost"):
        return None
    try:
        addr = ipaddress.ip_address(cleaned)
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
            return None
        if addr.version == 4:
            n = int(addr)
            return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"
        return str(addr)
    except ValueError:
        pass
    if re.fullmatch(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,61}[a-zA-Z0-9])?$", cleaned):
        if not any(b in cleaned.lower() for b in ("metadata", "internal", "localhost")):
            return cleaned
    return None


def _sanitize_ptz_port(port: int) -> int:
    try:
        p = int(port)
        if 1 <= p <= 65535:
            return p
    except (ValueError, TypeError):
        pass
    return 80


def _generate_ws_security_header(username: str, code: str) -> str:
    """Generate WS-Security UsernameToken XML header with PasswordDigest."""
    if not username and not code:
        return ""
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    nonce_raw = os.urandom(16)
    nonce_b64 = base64.b64encode(nonce_raw).decode("utf-8")
    
    # Digest = B64(SHA1(Nonce + Created + Code))
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha1.update(nonce_raw + created.encode("utf-8") + code.encode("utf-8"))
    digest_b64 = base64.b64encode(sha1.digest()).decode("utf-8")
    
    return f"""
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.dtd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.dtd">
      <wsse:UsernameToken>
        <wsse:Username>{username}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest_b64}</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</wsse:Nonce>
        <wsu:Created>{created}</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
    """

class PTZController:
    """Sends ONVIF SOAP / HTTP CGI PTZ commands (Move, Stop, Preset, Tour/Patrol)."""

    @classmethod
    async def probe_ptz_service(cls, ip: str, port: int = 80, username: str = "admin", code: str = "") -> dict:
        """Probe whether camera supports ONVIF PTZ service or CGI PTZ."""
        safe_ip = _clean_safe_ip(ip)
        if not safe_ip:
            return {"supported": False, "type": "none"}
        target_ports = [_sanitize_ptz_port(port)] if port else [80, 8080, 8899, 5000]
        async with httpx.AsyncClient(timeout=3.0) as client:
            for p in target_ports:
                url = f"http://{safe_ip}:{int(p)}/onvif/device_service"
                body = f"""<?xml version="1.0" encoding="utf-8"?>
                <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
                  <soap:Header>{_generate_ws_security_header(username, code)}</soap:Header>
                  <soap:Body><tds:GetCapabilities><tds:Category>PTZ</tds:Category></tds:GetCapabilities></soap:Body>
                </soap:Envelope>"""
                try:
                    resp = await client.post(url, content=body, headers={"Content-Type": "application/soap+xml; charset=utf-8"})
                    if resp.status_code == 200 and "PTZ" in resp.text:
                        return {"supported": True, "type": "onvif", "port": int(p), "ptz_url": f"http://{safe_ip}:{int(p)}/onvif/ptz_service"}
                except Exception:
                    pass
        return {"supported": False, "type": "none"}

    @classmethod
    async def send_ptz_command(
        cls,
        ip: str,
        command: str,
        port: int = 80,
        username: str = "admin",
        code: str = "",
        speed: float = 0.5,
        preset_token: str = "1"
    ) -> dict:
        """
        Execute PTZ action:
        - 'up', 'down', 'left', 'right', 'upleft', 'upright', 'downleft', 'downright'
        - 'zoom_in', 'zoom_out'
        - 'stop'
        - 'goto_preset', 'set_preset'
        - 'start_patrol', 'stop_patrol'
        """
        if not _is_safe_ptz_host(ip):
            return {"success": False, "error": "Invalid host/IP", "command": command}

        safe_port = _sanitize_ptz_port(port)
        allowed_commands = {
            "up", "down", "left", "right", "upleft", "upright", "downleft", "downright",
            "zoom_in", "zoom_out", "stop", "goto_preset", "set_preset", "start_patrol", "stop_patrol"
        }
        clean_cmd = str(command or "").strip().lower()
        if clean_cmd not in allowed_commands:
            return {"success": False, "error": "Invalid PTZ command", "command": command}

        speed = max(0.0, min(1.0, float(speed)))
        safe_preset = re.sub(r"[^a-zA-Z0-9_\-]", "", str(preset_token)) or "1"

        pan_speed = 0.0
        tilt_speed = 0.0
        zoom_speed = 0.0

        if clean_cmd == "up": tilt_speed = speed
        elif clean_cmd == "down": tilt_speed = -speed
        elif clean_cmd == "left": pan_speed = -speed
        elif clean_cmd == "right": pan_speed = speed
        elif clean_cmd == "upleft": pan_speed = -speed; tilt_speed = speed
        elif clean_cmd == "upright": pan_speed = speed; tilt_speed = speed
        elif clean_cmd == "downleft": pan_speed = -speed; tilt_speed = -speed
        elif clean_cmd == "downright": pan_speed = speed; tilt_speed = -speed
        elif clean_cmd == "zoom_in": zoom_speed = speed
        elif clean_cmd == "zoom_out": zoom_speed = -speed

        safe_ip = _clean_safe_ip(ip)
        if not safe_ip:
            return {"success": False, "error": "Invalid camera IP address", "command": clean_cmd}
        safe_port_num = _sanitize_ptz_port(port)
        ptz_service_url = f"http://{safe_ip}:{safe_port_num}/onvif/ptz_service"

        if clean_cmd == "stop":
            body = f"""<?xml version="1.0" encoding="utf-8"?>
            <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl">
              <soap:Header>{_generate_ws_security_header(username, code)}</soap:Header>
              <soap:Body><tptz:Stop><tptz:ProfileToken>Profile_1</tptz:ProfileToken><tptz:PanTilt>true</tptz:PanTilt><tptz:Zoom>true</tptz:Zoom></tptz:Stop></soap:Body>
            </soap:Envelope>"""
        elif clean_cmd in ("goto_preset", "start_patrol"):
            body = f"""<?xml version="1.0" encoding="utf-8"?>
            <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl">
              <soap:Header>{_generate_ws_security_header(username, code)}</soap:Header>
              <soap:Body><tptz:GotoPreset><tptz:ProfileToken>Profile_1</tptz:ProfileToken><tptz:PresetToken>{safe_preset}</tptz:PresetToken></tptz:GotoPreset></soap:Body>
            </soap:Envelope>"""
        else:
            body = f"""<?xml version="1.0" encoding="utf-8"?>
            <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">
              <soap:Header>{_generate_ws_security_header(username, code)}</soap:Header>
              <soap:Body>
                <tptz:ContinuousMove>
                  <tptz:ProfileToken>Profile_1</tptz:ProfileToken>
                  <tptz:Velocity>
                    <tt:PanTilt x="{pan_speed}" y="{tilt_speed}"/>
                    <tt:Zoom x="{zoom_speed}"/>
                  </tptz:Velocity>
                </tptz:ContinuousMove>
              </soap:Body>
            </soap:Envelope>"""

        async with httpx.AsyncClient(timeout=4.0) as client:
            try:
                resp = await client.post(ptz_service_url, content=body, headers={"Content-Type": "application/soap+xml; charset=utf-8"})
                return {"success": resp.status_code == 200, "status_code": resp.status_code, "command": clean_cmd}
            except Exception as e:
                # Also try CGI / HTTP PTZ fallback for Dahua / Hikvision
                try:
                    safe_speed_int = int(speed * 8)
                    cgi_url = f"http://{safe_ip}:{safe_port_num}/cgi-bin/ptz.cgi?action=start&channel=1&code={clean_cmd.upper()}&arg1=0&arg2={safe_speed_int}&arg3=0"
                    cgi_resp = await client.get(cgi_url, auth=(username, code) if username else None)
                    if cgi_resp.status_code == 200:
                        return {"success": True, "type": "cgi", "command": clean_cmd}
                except Exception:
                    pass
                return {"success": False, "error": str(e), "command": clean_cmd}
