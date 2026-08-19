"""ONVIF WS protocol probe for Camera Scanner v2.

Sends SOAP GetDeviceInformation and GetCapabilities to ONVIF device_service.
Returns brand, model, serial, RTSP stream URIs.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import httpx

logger = logging.getLogger(__name__)

_TIMEOUT = 4.0
_ONVIF_PATH = "/onvif/device_service"


def _ws_security_header(user: str, password: str) -> str:
    if not user and not password:
        return ""
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    nonce_raw = os.urandom(16)
    nonce_b64 = base64.b64encode(nonce_raw).decode()
    sha1 = hashlib.sha1()
    sha1.update(nonce_raw + created.encode() + password.encode())
    digest_b64 = base64.b64encode(sha1.digest()).decode()
    return f"""<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.dtd"
 xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.dtd">
  <wsse:UsernameToken><wsse:Username>{user}</wsse:Username>
  <wsse:Password Type="...#PasswordDigest">{digest_b64}</wsse:Password>
  <wsse:Nonce EncodingType="...#Base64Binary">{nonce_b64}</wsse:Nonce>
  <wsu:Created>{created}</wsu:Created></wsse:UsernameToken></wsse:Security>"""


def _soap(body: str, user: str = "", password: str = "") -> str:
    sec = _ws_security_header(user, password)
    return f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Header>{sec}</s:Header>
  <s:Body>{body}</s:Body>
</s:Envelope>"""


async def _soap_post(client: httpx.AsyncClient, url: str, body: str,
                     user: str, password: str) -> Optional[str]:
    try:
        resp = await client.post(
            url,
            content=_soap(body, user, password).encode(),
            headers={"Content-Type": "application/soap+xml; charset=utf-8"},
            timeout=_TIMEOUT,
        )
        if resp.status_code in (200, 400):   # some cameras return 400 but still have body
            return resp.text
    except Exception:
        pass
    return None


def _extract_xml_value(xml: str, tag: str) -> str:
    """Quick non-namespace-aware tag value extraction."""
    import re
    pattern = rf"<[^>]*{re.escape(tag)}[^>]*>([^<]+)<"
    m = re.search(pattern, xml, re.IGNORECASE)
    return m.group(1).strip() if m else ""


async def probe_onvif(
    ip: str,
    candidate_ports: List[int],
    credentials: List[Tuple[str, str]],
) -> Dict:
    """Probe ONVIF device_service on all candidate HTTP ports.

    Returns dict with keys: brand, model, serial, firmware, rtsp_urls, onvif_port, success
    """
    result = {
        "success": False, "brand": "", "model": "", "serial": "",
        "firmware": "", "rtsp_urls": [], "onvif_port": 0,
        "credentials": {},
    }
    if not candidate_ports:
        return result

    async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT) as client:
        for port in candidate_ports:
            url = f"http://{ip}:{port}{_ONVIF_PATH}"

            # Try GetDeviceInformation with each credential pair
            for user, password in credentials:
                xml = await _soap_post(
                    client, url,
                    "<tds:GetDeviceInformation/>",
                    user, password,
                )
                if not xml or "Envelope" not in xml:
                    continue

                # Parse device info
                brand = (
                    _extract_xml_value(xml, "Manufacturer")
                    or _extract_xml_value(xml, "Brand")
                )
                model = _extract_xml_value(xml, "Model")
                serial = _extract_xml_value(xml, "SerialNumber")
                firmware = _extract_xml_value(xml, "FirmwareVersion")

                if not brand and not model:
                    continue  # Not an ONVIF device info response

                result.update({
                    "success": True, "brand": brand, "model": model,
                    "serial": serial, "firmware": firmware,
                    "onvif_port": port,
                    "credentials": {"user": user, "password": password},
                })

                # GetStreamUri for RTSP URLs via GetProfiles
                profiles_xml = await _soap_post(
                    client, url,
                    "<tds:GetProfiles/>",
                    user, password,
                )
                rtsp_urls = []
                if profiles_xml:
                    import re
                    tokens = re.findall(r'token="([^"]+)"', profiles_xml)
                    for token in tokens[:4]:
                        stream_xml = await _soap_post(
                            client, url,
                            f"""<tds:GetStreamUri>
                              <tds:StreamSetup>
                                <tt:Stream>RTP-Unicast</tt:Stream>
                                <tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>
                              </tds:StreamSetup>
                              <tds:ProfileToken>{token}</tds:ProfileToken>
                            </tds:GetStreamUri>""",
                            user, password,
                        )
                        if stream_xml:
                            uri = _extract_xml_value(stream_xml, "Uri")
                            if uri and uri.startswith("rtsp://"):
                                rtsp_urls.append(uri)

                result["rtsp_urls"] = list(dict.fromkeys(rtsp_urls))  # dedup
                return result

    return result
