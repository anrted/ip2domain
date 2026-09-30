import asyncio
import json

import pytest

from ip2domain.scanning.classification import classify
from ip2domain.scanning.detection.nmap import parse_xml
from ip2domain.scanning.discovery.tcp import identify_tcp
from ip2domain.scanning.discovery.udp import identify_udp
from ip2domain.scanning.inventory import EndpointObservation
from ip2domain.scanning.policies import ScanConfig
from ip2domain.scanning.protocols.binary import coap_request, dns_request, mqtt_response, sip_request
from ip2domain.scanning.protocols.text import banner_service, parse_response
from ip2domain.scanning.transports.network import NetworkBudget


def test_strict_response_parsing_and_secret_exclusion():
    assert parse_response(b"HTTP/1.1 200 OK\r\nServer: test\r\nSet-Cookie: secret\r\n\r\n", "rtsp") is None
    assert parse_response(b"RTSP/1.0 200 OK\r\nCSeq: 99\r\n\r\n", "rtsp") is None
    result = parse_response(
        b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm=\"private\"\r\n\r\n", "rtsp",
    )
    assert result["auth_required"]
    assert "private" not in json.dumps(result)
    assert banner_service(b"220 Ready\r\n") is None
    assert banner_service(b"SSH-2.0-OpenSSH_9.0\r\n")[0] == "ssh"


def test_binary_response_correlation():
    payload, match = coap_request()
    assert match(b"\x70\x00" + payload[2:4])
    assert not match(b"\x70\x00\xff\xff") or payload[2:4] == b"\xff\xff"
    payload, match = dns_request()
    assert match(payload[:2] + b"\x80\x00" + payload[4:])
    assert not match(b"\x00")
    assert mqtt_response(b"\x20\x02\x00\x05")["auth_required"]
    assert mqtt_response(b"HTTP/1.1") is None


def test_nmap_port_table_guess_is_not_a_confirmed_protocol():
    observation = EndpointObservation("192.0.2.1", 554, "tcp", state="open")
    xml = b"""<nmaprun><host><address addr="192.0.2.1"/><ports>
    <port protocol="tcp" portid="554"><state state="open"/>
    <service name="rtsp" method="table" conf="3"/></port></ports></host></nmaprun>"""
    parse_xml(xml, observation)
    assert not observation.services
    xml = xml.replace(b'method="table" conf="3"', b'method="probed" conf="10" product="test"')
    parse_xml(xml, observation)
    assert observation.services[0]["protocol"] == "rtsp"
    with pytest.raises(ValueError):
        parse_xml(b"<!DOCTYPE x><nmaprun/>", observation)


def test_general_protocols_do_not_imply_device_kind():
    observation = EndpointObservation("192.0.2.1", 80, "tcp")
    observation.service("http", ("web",), server="nginx")
    observation.service("mqtt", ("iot",))
    classify(observation)
    assert observation.classifications == []
    observation.service("http", ("web",), server="SpRecord")
    classify(observation)
    assert observation.classifications[0]["kind"] == "audio_recorder"


@pytest.mark.parametrize("protocol", ["http", "rtsp"])
def test_real_server_on_random_port(protocol):
    async def scenario():
        async def handler(reader, writer):
            try:
                data = await asyncio.wait_for(reader.read(4096), 0.5)
                if protocol == "http" and data.startswith(b"HEAD"):
                    writer.write(b"HTTP/1.1 200 OK\r\nServer: fixture\r\n\r\n")
                    await writer.drain()
                elif protocol == "rtsp" and data.startswith(b"OPTIONS"):
                    # Fragment the response to ensure identification is not tied
                    # to TCP packet boundaries.
                    writer.write(b"RTSP/1.0 401 ")
                    await writer.drain()
                    await asyncio.sleep(0.005)
                    writer.write(b"Unauthorized\r\nCSeq: 1\r\n\r\n")
                    await writer.drain()
            except (OSError, asyncio.TimeoutError):
                pass
            finally:
                writer.close()
                await writer.wait_closed()
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        config = ScanConfig(
            targets="127.0.0.1", tcp_ports=str(port),
            profile="deep_identification", active_consent=True,
            timeout=0.2, banner_timeout=0.02, retries=0, rate=10000,
        )
        budget = NetworkBudget(config, config.plan().scope)
        observation = EndpointObservation("127.0.0.1", port, "tcp")
        async with server:
            await identify_tcp(observation, budget)
        assert observation.state == "open"
        assert protocol in [s["protocol"] for s in observation.services]
        if protocol == "rtsp":
            assert observation.services[0]["attributes"]["auth_required"]
    asyncio.run(scenario())


def test_udp_silence_is_not_closed(monkeypatch):
    async def silence(*args, **kwargs):
        raise asyncio.TimeoutError
    monkeypatch.setattr("ip2domain.scanning.detection.scheduler.datagram", silence)
    config = ScanConfig(
        targets="192.0.2.1", profile="deep_identification", active_consent=True,
        udp_ports="5683", retries=0,
    )
    observation = EndpointObservation("192.0.2.1", 5683, "udp")
    asyncio.run(identify_udp(observation, NetworkBudget(config, config.plan().scope)))
    assert observation.state == "open_or_filtered"
    assert not observation.services


def test_banner_connection_reset_does_not_abort_discovery(monkeypatch):
    from ip2domain.scanning.discovery.tcp import discover_tcp
    from unittest.mock import AsyncMock, Mock
    async def scenario():
        reader = Mock()
        reader.read = AsyncMock(side_effect=ConnectionResetError)
        writer = Mock()
        writer.wait_closed = AsyncMock()
        config = ScanConfig(targets="192.0.2.1", retries=0)
        budget = NetworkBudget(config, config.plan().scope)
        monkeypatch.setattr(budget, "connect", AsyncMock(return_value=(reader, writer)))
        observation = EndpointObservation("192.0.2.1", 80, "tcp")
        await discover_tcp(observation, budget)
        assert observation.state == "open"
        assert observation.attempts[-1]["status"] == "error"
        writer.close.assert_called_once()
    asyncio.run(scenario())
