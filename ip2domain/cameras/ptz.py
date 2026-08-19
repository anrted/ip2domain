"""ONVIF and RTSP PTZ Controller & Preset Manager."""
import asyncio
import base64
import hashlib
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
import httpx

logger = logging.getLogger(__name__)

def _generate_ws_security_header(username: str, password: str) -> str:
    """Generate WS-Security UsernameToken XML header with PasswordDigest."""
    if not username and not password:
        return ""
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    nonce_raw = os.urandom(16)
    nonce_b64 = base64.b64encode(nonce_raw).decode("utf-8")
    
    # Digest = B64(SHA1(Nonce + Created + Password))
    sha1 = hashlib.sha1()
    sha1.update(nonce_raw + created.encode("utf-8") + password.encode("utf-8"))
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
    async def probe_ptz_service(cls, ip: str, port: int = 80, username: str = "admin", password: str = "") -> dict:
        """Probe whether camera supports ONVIF PTZ service or CGI PTZ."""
        target_ports = [port] if port else [80, 8080, 8899, 5000]
        async with httpx.AsyncClient(timeout=3.0) as client:
            for p in target_ports:
                url = f"http://{ip}:{p}/onvif/device_service"
                body = f"""<?xml version="1.0" encoding="utf-8"?>
                <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
                  <soap:Header>{_generate_ws_security_header(username, password)}</soap:Header>
                  <soap:Body><tds:GetCapabilities><tds:Category>PTZ</tds:Category></tds:GetCapabilities></soap:Body>
                </soap:Envelope>"""
                try:
                    resp = await client.post(url, content=body, headers={"Content-Type": "application/soap+xml; charset=utf-8"})
                    if resp.status_code == 200 and "PTZ" in resp.text:
                        return {"supported": True, "type": "onvif", "port": p, "ptz_url": f"http://{ip}:{p}/onvif/ptz_service"}
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
        password: str = "",
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
        pan_speed = 0.0
        tilt_speed = 0.0
        zoom_speed = 0.0

        if command == "up": tilt_speed = speed
        elif command == "down": tilt_speed = -speed
        elif command == "left": pan_speed = -speed
        elif command == "right": pan_speed = speed
        elif command == "upleft": pan_speed = -speed; tilt_speed = speed
        elif command == "upright": pan_speed = speed; tilt_speed = speed
        elif command == "downleft": pan_speed = -speed; tilt_speed = -speed
        elif command == "downright": pan_speed = speed; tilt_speed = -speed
        elif command == "zoom_in": zoom_speed = speed
        elif command == "zoom_out": zoom_speed = -speed

        ptz_service_url = f"http://{ip}:{port}/onvif/ptz_service"

        if command == "stop":
            body = f"""<?xml version="1.0" encoding="utf-8"?>
            <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl">
              <soap:Header>{_generate_ws_security_header(username, password)}</soap:Header>
              <soap:Body><tptz:Stop><tptz:ProfileToken>Profile_1</tptz:ProfileToken><tptz:PanTilt>true</tptz:PanTilt><tptz:Zoom>true</tptz:Zoom></tptz:Stop></soap:Body>
            </soap:Envelope>"""
        elif command in ("goto_preset", "start_patrol"):
            body = f"""<?xml version="1.0" encoding="utf-8"?>
            <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl">
              <soap:Header>{_generate_ws_security_header(username, password)}</soap:Header>
              <soap:Body><tptz:GotoPreset><tptz:ProfileToken>Profile_1</tptz:ProfileToken><tptz:PresetToken>{preset_token}</tptz:PresetToken></tptz:GotoPreset></soap:Body>
            </soap:Envelope>"""
        else:
            body = f"""<?xml version="1.0" encoding="utf-8"?>
            <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">
              <soap:Header>{_generate_ws_security_header(username, password)}</soap:Header>
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
                return {"success": resp.status_code == 200, "status_code": resp.status_code, "command": command}
            except Exception as e:
                # Also try CGI / HTTP PTZ fallback for Dahua / Hikvision
                try:
                    cgi_url = f"http://{ip}:{port}/cgi-bin/ptz.cgi?action=start&channel=1&code={command.upper()}&arg1=0&arg2={int(speed*8)}&arg3=0"
                    cgi_resp = await client.get(cgi_url, auth=(username, password) if username else None)
                    if cgi_resp.status_code == 200:
                        return {"success": True, "type": "cgi", "command": command}
                except Exception:
                    pass
                return {"success": False, "error": str(e), "command": command}
