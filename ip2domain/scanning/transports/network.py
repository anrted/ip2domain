"""Small network primitives. No redirects, DNS expansion or implicit credentials."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import ipaddress
import socket
import ssl


class NetworkBudget:
    def __init__(self, config, scope):
        self.config, self.scope = config, scope
        self._protocol_next = {}
        self._protocol_lock = asyncio.Lock()
        self._host_requests = {}
        self._hosts = {}
        self._subnets = {}
        self._rate_lock = asyncio.Lock()
        self._next = 0.0
        # Shared by discovery, identification and enrichment pools.
        self._global = asyncio.Semaphore(config.max_connections)

    @asynccontextmanager
    async def endpoint(self, ip):
        if not self.scope.contains(ip):
            raise ValueError("destination outside scope")
        address = ipaddress.ip_address(ip)
        subnet = str(ipaddress.ip_network(f"{ip}/{24 if address.version == 4 else 64}", strict=False))
        keys = ((self._hosts, ip, self.config.per_host), (self._subnets, subnet, self.config.per_subnet))
        entries = []
        for mapping, key, limit in keys:
            entry = mapping.setdefault(key, [asyncio.Semaphore(limit), 0])
            entry[1] += 1
            entries.append((mapping, key, entry))
        try:
            async with entries[0][2][0], entries[1][2][0], self._global:
                yield
        finally:
            for mapping, key, entry in entries:
                entry[1] -= 1
                if not entry[1]:
                    mapping.pop(key, None)

    async def protocol_tick(self, ip, protocol):
        from ..plugins.base import BudgetExhausted
        count=self._host_requests.get(ip,0)
        if count>=self.config.max_requests_per_host:raise BudgetExhausted()
        self._host_requests[ip]=count+1
        async with self._protocol_lock:
            now=asyncio.get_running_loop().time()
            scheduled=max(now,self._protocol_next.get(('host',ip),0),self._protocol_next.get(('protocol',protocol),0))
            self._protocol_next[('host',ip)]=scheduled+1/self.config.per_host_rate
            self._protocol_next[('protocol',protocol)]=scheduled+1/self.config.per_protocol_rate
        if scheduled>now:await asyncio.sleep(scheduled-now)

    async def tick(self):
        async with self._rate_lock:
            loop = asyncio.get_running_loop()
            delay = self._next - loop.time()
            if delay > 0:
                await asyncio.sleep(delay)
            self._next = loop.time() + 1 / self.config.rate

    async def connect(self, ip, port, *, tls=False):
        if not self.scope.contains(ip):
            raise ValueError("destination outside scope")
        await self.tick()
        context = None
        kwargs = {}
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.set_alpn_protocols(["http/1.1"])
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            kwargs["server_hostname"] = self.config.hostname or ip
            kwargs["ssl_handshake_timeout"] = self.config.timeout
        return await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context, **kwargs), self.config.timeout,
        )


async def close_writer(writer):
    if writer is not None:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 0.25)
        except (OSError, asyncio.TimeoutError, ssl.SSLError):
            pass


def frame_complete(data, framing, minimum=0):
    if framing == "dicom":
        return len(data)>=6 and len(data)>=6+int.from_bytes(data[2:6],"big")
    if framing == "http_body":
        import re
        head,sep,body=bytes(data).partition(b"\r\n\r\n")
        match=re.search(rb"(?im)^Content-Length:\s*(\d+)",head)
        return bool(sep and match and len(body)>=int(match[1]))
    if framing == "headers":
        return b"\r\n\r\n" in data
    if framing == "fixed":
        return len(data) >= minimum
    if framing == "dns":
        return len(data) >= 2 and len(data) >= 2 + int.from_bytes(data[:2], "big")
    if framing == "rpc":
        return len(data) >= 4 and len(data) >= 4 + (int.from_bytes(data[:4], "big") & 0x7fffffff)
    if framing == "opcua":
        return len(data) >= 8 and len(data) >= int.from_bytes(data[4:8], "little")
    if framing == "modbus":
        return len(data) >= 6 and len(data) >= 6 + int.from_bytes(data[4:6], "big")
    if framing == "smb":
        return len(data) >= 4 and len(data) >= 4 + int.from_bytes(data[1:4], "big")
    if framing == "rdp":
        return len(data) >= 4 and len(data) >= int.from_bytes(data[2:4], "big")
    if framing == "s7":
        return len(data) >= 4 and len(data) >= int.from_bytes(data[2:4], "big")
    if framing == "enip":
        return len(data) >= 24 and len(data) >= 24 + int.from_bytes(data[2:4], "little")
    return False


async def exchange(budget, ip, port, payload, *, tls=False, limit=8192, framing="headers", minimum=0):
    reader, writer = await budget.connect(ip, port, tls=tls)
    try:
        writer.write(payload)
        await asyncio.wait_for(writer.drain(), budget.config.timeout)
        # Read enough for framed headers even when TCP splits the response.
        data = bytearray()
        while len(data) < limit:
            try:
                chunk = await asyncio.wait_for(reader.read(min(4096, limit - len(data))), budget.config.timeout)
            except asyncio.TimeoutError:
                if data:
                    break
                raise
            if not chunk:
                break
            data.extend(chunk)
            if frame_complete(data, framing, minimum):
                break
        return bytes(data)
    finally:
        await close_writer(writer)


async def datagram(budget, ip, port, payload, limit=8192):
    if not budget.scope.contains(ip):
        raise ValueError("destination outside scope")
    await budget.tick()
    family = socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    loop = asyncio.get_running_loop()
    try:
        await loop.sock_connect(sock, (ip, port))
        await loop.sock_sendall(sock, payload)
        return await asyncio.wait_for(loop.sock_recv(sock, limit), budget.config.timeout)
    finally:
        sock.close()
