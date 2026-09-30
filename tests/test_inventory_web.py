import asyncio
import base64
import secrets

import pytest

from ip2domain.scanning.enrichment.web import media_signature, websocket_accept, websocket_confirmed, enrich_web
from ip2domain.scanning.inventory import EndpointObservation
from ip2domain.scanning.policies import ScanConfig
from ip2domain.scanning.transports.http import HttpSample, parse_headers, http_sample
from ip2domain.scanning.transports.network import NetworkBudget


def test_websocket_accept_matches_standard_example():
    assert websocket_accept("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    headers = {"upgrade": "websocket", "connection": "Upgrade", "sec-websocket-accept": websocket_accept(key)}
    assert websocket_confirmed(HttpSample(101, headers, b""), key)
    assert not websocket_confirmed(HttpSample(200, headers, b""), key)
    assert not websocket_confirmed(HttpSample(101, headers, b""), "different")


def test_media_requires_content_evidence_not_extension_or_type():
    assert media_signature(HttpSample(200, {"content-type": "application/vnd.apple.mpegurl"}, b"error")) is None
    assert media_signature(HttpSample(200, {}, b"#EXTM3U\n#EXT-X-TARGETDURATION:5\n")) == "hls"
    packet = b"\x47" + b"\0" * 187
    assert media_signature(HttpSample(200, {}, packet * 3)) == "mpeg-ts"
    assert media_signature(HttpSample(403, {}, packet * 3)) is None
    assert media_signature(HttpSample(200, {"content-type": "multipart/x-mixed-replace;boundary=test"},
                                      b"--test\r\nContent-Type: image/jpeg\r\n\r\n\xff\xd8\xff")) == "mjpeg"


@pytest.mark.parametrize("path", ["//evil.invalid/a", "/%2fexample.com", "/a?token=secret", "/%0d%0aHEAD", "/a b", "/a\\b", "https://example.com"])
def test_resource_paths_are_origin_relative_without_credentials(path):
    with pytest.raises(ValueError):
        ScanConfig(targets="192.0.2.1", resource_paths=[path])


def test_duplicate_http_headers_are_rejected():
    with pytest.raises(ValueError):
        parse_headers(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 100\r\n\r\n")


def test_local_websocket_webdav_and_hls_on_random_port():
    async def scenario():
        paths = []
        async def handler(reader, writer):
            try:
                raw = await reader.readuntil(b"\r\n\r\n")
                method, path, _ = raw.split(b"\r\n")[0].split()
                paths.append(path)
                headers = {}
                for line in raw.split(b"\r\n")[1:]:
                    if b":" in line:
                        k, v = line.split(b":", 1)
                        headers[k.lower()] = v.strip()
                if method == b"OPTIONS":
                    reply = b"HTTP/1.1 204 No Content\r\nDAV: 1,2\r\n\r\n"
                elif b"sec-websocket-key" in headers:
                    accepted = websocket_accept(headers[b"sec-websocket-key"].decode())
                    reply = f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accepted}\r\n\r\n".encode()
                else:
                    body = b"#EXTM3U\n#EXT-X-TARGETDURATION:5\n"
                    reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
                writer.write(reply)
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
        assert {s["protocol"] for s in observation.services} == {"http", "webdav", "websocket", "hls"}
        assert paths == [b"/"] * 3
    asyncio.run(scenario())


def test_redirect_is_not_followed():
    async def scenario():
        calls = []
        async def handler(reader, writer):
            calls.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b"HTTP/1.1 302 Found\r\nLocation: http://203.0.113.1/private\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        config = ScanConfig(targets="127.0.0.1", tcp_ports=str(port), rate=10000)
        async with server:
            result = await http_sample(NetworkBudget(config, config.plan().scope),
                                       EndpointObservation("127.0.0.1", port, "tcp"), "/")
        assert result.status == 302 and len(calls) == 1
    asyncio.run(scenario())
