"""Passive local network discovery for Camera Scanner v2.

Implements:
  - ONVIF WS-Discovery (UDP multicast 239.255.255.250:3702)
  - SSDP/UPnP discovery (UDP multicast 239.255.255.250:1900)
  - mDNS probe for _rtsp._tcp.local. (UDP multicast 224.0.0.251:5353)

Only useful on local network segments — skipped for Internet addresses.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import struct
import uuid
from typing import Dict, List, Set

logger = logging.getLogger(__name__)

_WSD_PROBE = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <s:Header>
    <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
    <a:MessageID>uuid:{msg_id}</a:MessageID>
    <a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
  </s:Header>
  <s:Body>
    <d:Probe>
      <d:Types xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
        dn:NetworkVideoTransmitter
      </d:Types>
    </d:Probe>
  </s:Body>
</s:Envelope>"""

_SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 3\r\n"
    "ST: ssdp:all\r\n\r\n"
)

_CAMERA_KEYWORDS = re.compile(
    r"(camera|ipcam|nvr|dvr|video|cctv|onvif|hikvision|dahua|axis|foscam|reolink)",
    re.IGNORECASE,
)


def _is_private_ip(ip: str) -> bool:
    """Check if IP is in RFC1918 private range."""
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


async def _udp_multicast_probe(
    mcast_ip: str,
    mcast_port: int,
    message: str,
    listen_timeout: float = 3.0,
) -> List[str]:
    """Send UDP multicast probe and collect responses."""
    responses = []
    loop = asyncio.get_event_loop()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
    sock.setblocking(False)

    try:
        data = message.encode()
        await loop.sock_sendto(sock, data, (mcast_ip, mcast_port))
        deadline = loop.time() + listen_timeout
        while loop.time() < deadline:
            remaining = max(0.1, deadline - loop.time())
            try:
                fut = loop.sock_recvfrom(sock, 4096)
                data_recv, addr = await asyncio.wait_for(fut, timeout=remaining)
                responses.append((addr[0], data_recv.decode(errors="ignore")))
            except asyncio.TimeoutError:
                break
            except Exception:
                break
    except Exception as exc:
        logger.debug("[v2 Discovery] UDP probe error: %s", exc)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return responses


def _extract_ip_from_wsd(xml: str) -> List[str]:
    """Extract XAddrs IPs from WS-Discovery response."""
    ips = []
    matches = re.findall(r"XAddrs[^>]*>([^<]+)<", xml, re.IGNORECASE)
    for m in matches:
        ip_m = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", m)
        ips.extend(ip_m)
    return ips


def _extract_ip_from_ssdp(response: str) -> List[str]:
    """Extract IPs from SSDP Location header."""
    ips = []
    if not _CAMERA_KEYWORDS.search(response):
        return ips
    loc = re.search(r"Location:\s*(http[s]?://[^\r\n]+)", response, re.IGNORECASE)
    if loc:
        ip_m = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", loc.group(1))
        ips.extend(ip_m)
    return ips


async def run_local_discovery() -> List[str]:
    """Run WS-Discovery and SSDP multicast probes.

    Returns list of discovered camera IP addresses.
    """
    discovered: Set[str] = set()

    # WS-Discovery
    try:
        wsd_msg = _WSD_PROBE.format(msg_id=str(uuid.uuid4()))
        responses = await _udp_multicast_probe("239.255.255.250", 3702, wsd_msg, listen_timeout=3.0)
        for src_ip, body in responses:
            ips = _extract_ip_from_wsd(body)
            for ip in ips:
                if _is_private_ip(ip):
                    discovered.add(ip)
            if _is_private_ip(src_ip):
                discovered.add(src_ip)
        logger.info("[v2 Discovery] WS-Discovery found: %d", len(discovered))
    except Exception as exc:
        logger.debug("[v2 Discovery] WS-Discovery error: %s", exc)

    # SSDP
    before = len(discovered)
    try:
        responses = await _udp_multicast_probe("239.255.255.250", 1900, _SSDP_MSEARCH, listen_timeout=3.0)
        for src_ip, body in responses:
            ips = _extract_ip_from_ssdp(body)
            for ip in ips:
                if _is_private_ip(ip):
                    discovered.add(ip)
            if _CAMERA_KEYWORDS.search(body) and _is_private_ip(src_ip):
                discovered.add(src_ip)
        logger.info("[v2 Discovery] SSDP found: %d new", len(discovered) - before)
    except Exception as exc:
        logger.debug("[v2 Discovery] SSDP error: %s", exc)

    return sorted(discovered)
