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
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape
from urllib.parse import urlsplit
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import httpx

logger = logging.getLogger(__name__)

_TIMEOUT = 2.5
_ONVIF_PATH = "/onvif/device_service"


_WSSE_PW_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
_WSSE_NONCE_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"


def _ws_security_header(user: str, p_str: str) -> str:
    if not user and not p_str:
        return ""
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    nonce_raw = os.urandom(16)
    nonce_b64 = base64.b64encode(nonce_raw).decode()
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha1.update(nonce_raw + created.encode() + p_str.encode())
    digest_b64 = base64.b64encode(sha1.digest()).decode()
    return f"""<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
 xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <wsse:UsernameToken><wsse:Username>{escape(user)}</wsse:Username>
  <wsse:Password Type="{_WSSE_PW_TYPE}">{digest_b64}</wsse:Password>
  <wsse:Nonce EncodingType="{_WSSE_NONCE_TYPE}">{nonce_b64}</wsse:Nonce>
  <wsu:Created>{created}</wsu:Created></wsse:UsernameToken></wsse:Security>"""


def _soap(body: str, user: str = "", p_str: str = "") -> str:
    sec = _ws_security_header(user, p_str)
    return f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
            xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Header>{sec}</s:Header>
  <s:Body>{body}</s:Body>
</s:Envelope>"""


async def _soap_post(client: httpx.AsyncClient, url: str, body: str,
                     user: str, p_str: str) -> Optional[str]:
    try:
        resp = await client.post(
            url,
            content=_soap(body, user, p_str).encode(),
            headers={"Content-Type": "application/soap+xml; charset=utf-8"},
            timeout=_TIMEOUT,
        )
        if resp.status_code in (200, 400, 401, 500):   # cameras return 400/401/500 on auth challenge or faults
            return resp.text
    except Exception:
        pass
    return None


def _xml_root(xml: str):
    if not xml or "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
        return None
    try:
        return ET.fromstring(xml)
    except ET.ParseError:
        return None


def _extract_xml_value(xml: str, tag: str) -> str:
    root = _xml_root(xml)
    if root is None:
        return ""
    return next((e.text.strip() for e in root.iter()
                 if e.tag.rsplit("}", 1)[-1] == tag and e.text), "")


async def probe_onvif(
    ip: str,
    candidate_ports: List[int],
    credentials: List[Tuple[str, str]],
) -> Dict:
    """Probe ONVIF device_service on all candidate HTTP ports.

    Returns dict with keys: brand, model, serial, firmware, rtsp_urls, onvif_port, auth_required, success
    """
    result = {
        "success": False, "brand": "", "model": "", "serial": "",
        "firmware": "", "rtsp_urls": [], "onvif_port": 0,
        "credentials": {}, "auth_required": None,
    }
    if not candidate_ports:
        return result

    async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT) as client:
        for port in candidate_ports:
            url = f"http://{ip}:{port}{_ONVIF_PATH}"
            onvif_service_confirmed = False
            auth_challenge = False

            # Try GetDeviceInformation with each credential pair (cap at 8 to avoid long brute)
            for u_str, auth_val in (credentials or [("", "")])[:8]:
                xml = await _soap_post(
                    client, url,
                    "<tds:GetDeviceInformation/>",
                    u_str, auth_val,
                )
                if not xml or "Envelope" not in xml:
                    continue

                # Check if this endpoint confirmed it's an ONVIF service (even if auth failed)
                if any(x in xml for x in ("onvif.org", "Fault", "NotAuthorized", "Sender", "DeviceInformation")):
                    onvif_service_confirmed = True
                if "NotAuthorized" in xml or "FailedAuthentication" in xml:
                    auth_challenge = True

                # Parse device info if authenticated
                brand = (
                    _extract_xml_value(xml, "Manufacturer")
                    or _extract_xml_value(xml, "Brand")
                )
                model = _extract_xml_value(xml, "Model")
                serial = _extract_xml_value(xml, "SerialNumber")
                firmware = _extract_xml_value(xml, "FirmwareVersion")

                if not brand and not model:
                    continue  # Not an authorized ONVIF device info response yet

                result.update({
                    "success": True, "brand": brand or "ONVIF", "model": model,
                    "serial": serial, "firmware": firmware,
                    "onvif_port": port,
                    "auth_required": False,
                    "credentials": {"user": u_str, "password": auth_val},
                })

                # Media operations use the Media namespace and advertised
                # service address, not the Device namespace/device endpoint.
                caps = await _soap_post(client, url,
                    "<tds:GetCapabilities><tds:Category>Media</tds:Category></tds:GetCapabilities>",
                    u_str, auth_val)
                media_url = url
                root = _xml_root(caps or "")
                if root is not None:
                    for node in root.iter():
                        if node.tag.rsplit("}", 1)[-1] == "Media":
                            for addr in node.iter():
                                if addr.tag.rsplit("}", 1)[-1] == "XAddr" and addr.text:
                                    candidate = addr.text.strip()
                                    parsed = urlsplit(candidate)
                                    if parsed.scheme in ("http", "https") and parsed.hostname == ip and not parsed.username:
                                        media_url = candidate
                profiles_xml = await _soap_post(client, media_url, "<trt:GetProfiles/>", u_str, auth_val)
                rtsp_urls = []
                root = _xml_root(profiles_xml or "")
                if root is not None:
                    tokens = list(dict.fromkeys(node.get("token") for node in root.iter()
                                  if node.tag.rsplit("}", 1)[-1] == "Profiles" and node.get("token")))
                    for token in tokens:
                        stream_xml = await _soap_post(
                            client, media_url,
                            f"""<trt:GetStreamUri>
                              <trt:StreamSetup>
                                <tt:Stream>RTP-Unicast</tt:Stream>
                                <tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>
                              </trt:StreamSetup>
                              <trt:ProfileToken>{escape(token)}</trt:ProfileToken>
                            </trt:GetStreamUri>""",
                            u_str, auth_val,
                        )
                        if stream_xml:
                            uri = _extract_xml_value(stream_xml, "Uri")
                            if uri.startswith(("rtsp://", "rtsps://")):
                                rtsp_urls.append(uri)
                                parsed_uri = urlsplit(uri)
                                if parsed_uri.hostname and parsed_uri.hostname != ip:
                                    r_port = parsed_uri.port or (port if port != 80 else 554)
                                    for p_try in dict.fromkeys([r_port, port, 554]):
                                        netloc = f"{ip}:{p_try}" if p_try not in (554, None) else ip
                                        rewritten = urlunsplit((parsed_uri.scheme, netloc, parsed_uri.path, parsed_uri.query, parsed_uri.fragment))
                                        rtsp_urls.append(rewritten)

                result["rtsp_urls"] = list(dict.fromkeys(rtsp_urls))  # dedup
                return result

            # If ONVIF service confirmed but all default credentials failed (auth required)
            if onvif_service_confirmed and not result["success"]:
                result.update({
                    "success": True,
                    "brand": "ONVIF",
                    "model": "Generic ONVIF Camera",
                    "onvif_port": port,
                    "auth_required": True if auth_challenge else None,
                    "rtsp_urls": [
                        f"rtsp://{ip}:554/onvif1",
                        f"rtsp://{ip}:554/live/ch0",
                        f"rtsp://{ip}:554/live",
                        f"rtsp://{ip}:554/media/video1",
                    ],
                })
                return result

    return result
