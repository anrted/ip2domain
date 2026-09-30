"""Bounded HTTP/1 reads on a numeric scoped destination; never follows redirects."""
import asyncio
import re
from dataclasses import dataclass

from .network import close_writer
from ..protocols.text import authority


@dataclass(frozen=True)
class HttpSample:
    status: int
    headers: dict
    body: bytes


def parse_headers(raw):
    if len(raw) > 16384 or not raw.endswith(b"\r\n\r\n"):
        raise ValueError("invalid or oversized HTTP headers")
    lines = raw.decode("iso-8859-1").split("\r\n")
    match = re.fullmatch(r"HTTP/1\.[01] ([1-5]\d\d)(?: .*)?", lines[0])
    if not match:
        raise ValueError("not HTTP/1")
    headers = {}
    for line in lines[1:-2]:
        if ":" not in line:
            raise ValueError("invalid HTTP header")
        key, value = line.split(":", 1)
        key = key.lower()
        if key in headers:
            if key in ("content-length","transfer-encoding","host"):raise ValueError("ambiguous duplicate HTTP header")
            if key=="www-authenticate":continue
            headers[key]+=", "+value.strip()
            continue
        headers[key] = value.strip()
    return int(match.group(1)), headers


async def _body(reader, headers, limit):
    if headers.get("content-encoding", "identity").lower() != "identity":
        return b""  # No decompression bombs or implicit decoder dependencies.
    transfer = headers.get("transfer-encoding", "").lower()
    if transfer and "content-length" in headers:
        raise ValueError("ambiguous HTTP framing")
    data = bytearray()
    if transfer:
        if transfer != "chunked":
            raise ValueError("unsupported transfer encoding")
        while len(data) < limit:
            line = await reader.readuntil(b"\r\n")
            if len(line) > 128:
                raise ValueError("oversized chunk header")
            size = int(line.split(b";", 1)[0].strip(), 16)
            if not 0 <= size <= 2 ** 32:
                raise ValueError("invalid chunk size")
            if size == 0:
                break
            wanted = min(size, limit - len(data))
            data.extend(await reader.readexactly(wanted))
            if wanted < size:
                break
            if await reader.readexactly(2) != b"\r\n":
                raise ValueError("invalid chunk terminator")
        return bytes(data)
    length = headers.get("content-length")
    if length is not None:
        if not length.isdigit():
            raise ValueError("invalid content length")
        wanted = min(int(length), limit)
        try:
            return await reader.readexactly(wanted)
        except asyncio.IncompleteReadError as exc:
            return exc.partial
    while len(data) < limit:
        chunk = await reader.read(min(4096, limit - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


async def http_sample(budget, observation, path, *, method="GET", headers=None, body_limit=8192, tls=False):
    host = authority(observation.ip, observation.port, budget.config.hostname)
    values = {
        "Host": host, "User-Agent": "Scanner-v2", "Connection": "close",
        "Accept-Encoding": "identity", **(headers or {}),
    }
    payload = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in values.items()) + "\r\n"
    reader, writer = await budget.connect(observation.ip, observation.port, tls=tls)
    async def read_response():
        writer.write(payload.encode("ascii"))
        await writer.drain()
        raw = await reader.readuntil(b"\r\n\r\n")
        status, response_headers = parse_headers(raw)
        body = b""
        if method != "HEAD" and status in (200, 206) and body_limit:
            body = await _body(reader, response_headers, body_limit)
        return HttpSample(status, response_headers, body)
    try:
        return await asyncio.wait_for(read_response(), budget.config.timeout)
    finally:
        await close_writer(writer)
