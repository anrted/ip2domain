"""Strict text handshakes; evidence excludes response bodies and credentials."""
from __future__ import annotations

import re
from ..inventory import public_text


def banner_service(data):
    line = data.split(b"\n", 1)[0].strip()
    if re.match(rb"SSH-[12]\.\d+-[^\r\n]+", line):
        return "ssh", ("management",), {"banner": public_text(line.decode("ascii", "replace"))}
    if re.match(rb"220[ -]", line):
        lower = line.lower()
        if b"ftp" in lower:
            return "ftp", ("storage",), {"banner": public_text(line.decode("ascii", "replace"))}
        if b"smtp" in lower or b"esmtp" in lower:
            return "smtp", ("mail",), {"banner": public_text(line.decode("ascii", "replace"))}
    if re.match(rb"\* OK\b", line, re.I):
        return "imap", ("mail",), {}
    if re.match(rb"\+OK\b", line) and b"pop" in line.lower():
        return "pop3", ("mail",), {}
    if re.search(rb"\xff[\xfb-\xfe][\x00-\xff]", data):
        return "telnet", ("management",), {}
    return None


def authority(ip, port, hostname=""):
    host = hostname or (f"[{ip}]" if ":" in ip else ip)
    return f"{host}:{port}"


def request(protocol, ip, port, hostname=""):
    host = authority(ip, port, hostname)
    if protocol == "http":
        return f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Scanner-v2\r\nConnection: close\r\n\r\n".encode()
    return f"OPTIONS rtsp://{host}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Scanner-v2\r\n\r\n".encode()


def parse_response(data, protocol):
    header = data.split(b"\r\n\r\n", 1)[0]
    lines = header.decode("iso-8859-1", "replace").split("\r\n")
    pattern = r"HTTP/1\.[01] ([1-5]\d\d)(?:\s|$)" if protocol == "http" else r"RTSP/[12]\.0 ([1-5]\d\d)(?:\s|$)"
    match = re.match(pattern, lines[0])
    if not match:
        return None
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.lower().strip()] = value.strip()
    if protocol == "rtsp" and headers.get("cseq") != "1":
        return None
    code = int(match.group(1))
    result = {"status_code": code, "auth_required": code in (401, 403, 407)}
    if headers.get("server"):
        result["server"] = public_text(headers["server"])
    if headers.get("content-type"):
        result["content_type"] = public_text(headers["content-type"])
    if headers.get("public"):
        result["methods"] = public_text(headers["public"])
    # Do not follow redirects (even when they point outside the authorized scope).
    if "location" in headers:
        result["redirect_present"] = True
    if "www-authenticate" in headers:
        result["auth_scheme"] = public_text(headers["www-authenticate"].split(" ", 1)[0], 32)
    return result
