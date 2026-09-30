import asyncio
import pytest

from ip2domain.scanning.detection.catalog import native_registry
from ip2domain.scanning.enrichment.device_endpoints import synthesize_device_endpoints
from ip2domain.scanning.enrichment.web import enrich_web
from ip2domain.scanning.inventory import EndpointObservation
from ip2domain.scanning.policies import ScanConfig
from ip2domain.scanning.protocols.binary import (
    s7_request, s7_response,
    enip_request, enip_response,
    bacnet_request, bacnet_response,
)
from ip2domain.scanning.transports.network import NetworkBudget, frame_complete


def test_s7comm_wire_handshake_and_framing():
    req = s7_request()
    assert req.startswith(b"\x03\x00\x00\x16")
    assert frame_complete(b"\x03\x00\x00\x16" + b"\x00" * 18, "s7")
    assert not frame_complete(b"\x03\x00\x00\x16\x11", "s7")

    # Valid COTP Connection Confirm
    resp_packet = b"\x03\x00\x00\x16\x11\xd0\x00\x01\x00\x02\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02"
    parsed = s7_response(resp_packet)
    assert parsed is not None
    assert parsed["protocol"] == "s7comm"
    assert parsed["vendor"] == "Siemens"


def test_enip_wire_handshake_and_framing():
    req = enip_request()
    assert len(req) == 24
    assert req[:2] == b"\x63\x00"

    # Enip encapsulation header (24 bytes) + 10 bytes product
    payload = b"\x63\x00\x0a\x00" + b"\x00" * 20 + b"1756-L83E ControlLogix"
    assert frame_complete(payload, "enip")
    assert not frame_complete(payload[:15], "enip")

    parsed = enip_response(payload)
    assert parsed is not None
    assert parsed["protocol"] == "enip"
    assert "ControlLogix" in parsed.get("product", "")


def test_bacnet_wire_handshake():
    req = bacnet_request()
    assert req.startswith(b"\x81\x0a")

    resp_packet = b"\x81\x0a\x00\x10\x01\x20\x00\x01\x10\x08"
    parsed = bacnet_response(resp_packet)
    assert parsed is not None
    assert parsed["protocol"] == "bacnet"


def test_native_registry_contains_new_industrial_probes():
    registry = native_registry()
    names = {p.name for p in registry.probes}
    assert "s7comm" in names
    assert "enip" in names
    assert "bacnet" in names

    s7_probe = next(p for p in registry.probes if p.name == "s7comm")
    assert 102 in s7_probe.port_hints
    assert "industrial" in s7_probe.categories

    bacnet_probe = next(p for p in registry.probes if p.name == "bacnet")
    assert 47808 in bacnet_probe.port_hints
    assert bacnet_probe.transport == "udp"


def test_web_title_and_fingerprint_enrichment():
    async def scenario():
        html_page = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"Server: nginx/1.18.0\r\n"
            b"Connection: close\r\n\r\n"
            b"<!DOCTYPE html><html><head>"
            b"<title>FreePBX Administration - Sangoma</title>"
            b"<meta name=\"generator\" content=\"FreePBX 16.0\">"
            b"</head><body><h1>Login to FreePBX</h1></body></html>"
        )

        async def handler(reader, writer):
            try:
                await reader.readuntil(b"\r\n\r\n")
                writer.write(html_page)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        config = ScanConfig(
            targets="127.0.0.1", tcp_ports=str(port), profile="deep_identification",
            active_consent=True, web_enrichment=True, timeout=1, rate=10000,
        )
        observation = EndpointObservation("127.0.0.1", port, "tcp", state="open")
        observation.service("http", ("web",))

        async with server:
            await enrich_web(observation, NetworkBudget(config, config.plan().scope))

        http_svc = next(s for s in observation.services if s["protocol"] == "http")
        assert http_svc["attributes"]["title"] == "FreePBX Administration - Sangoma"
        assert http_svc["attributes"]["generator"] == "FreePBX 16.0"
        assert "freepbx" in http_svc["attributes"]["body_clues"]

        dev_info = synthesize_device_endpoints(observation)
        assert dev_info["category"] == "voice"
        assert dev_info["vendor"] == "FreePBX / Asterisk"
        assert dev_info["web_url"].endswith("/admin/")
        assert any(a["id"] == "web" for a in dev_info["actions"])

    asyncio.run(scenario())


def test_s7_plc_classification_with_wire_and_endpoints():
    obs = EndpointObservation("192.168.1.100", 102, "tcp", state="open")
    obs.service("s7comm", ("industrial",), vendor="Siemens", server="Siemens SIMATIC S7 PLC")

    dev_info = synthesize_device_endpoints(obs)
    assert dev_info["category"] == "industrial"
    assert dev_info["vendor"] == "Siemens"
    assert dev_info["type"] == "plc"
    assert any(a["id"] == "api" for a in dev_info["actions"])
    assert "s7://" in dev_info["api_url"]
