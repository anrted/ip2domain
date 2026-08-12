import asyncio
import ipaddress
import re
import shutil
import struct
import uuid
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path
from typing import Dict, List, Optional


class RemoteDesktopScanner:
    """Detect RDP/VNC services and capture unauthenticated VNC framebuffers."""

    DEFAULT_RDP_PORTS = [3389]
    DEFAULT_VNC_PORTS = list(range(5900, 5911))
    NMAP_BATCH_SIZE = 32
    NMAP_BATCH_CONCURRENCY = 4

    def __init__(self, capture_dir: Path, timeout: int = 120):
        self.capture_dir = capture_dir
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.nmap_bin = shutil.which("nmap")

    async def scan(self, targets: List[str], scan_rdp: bool = True, scan_vnc: bool = True,
                   rdp_ports: Optional[List[int]] = None,
                   vnc_ports: Optional[List[int]] = None, progress_callback=None) -> Dict:
        targets = list(dict.fromkeys(str(ipaddress.ip_address(target)) for target in targets))
        if not targets:
            raise ValueError("Список IP-адресов пуст")
        rdp_ports = rdp_ports or self.DEFAULT_RDP_PORTS
        vnc_ports = vnc_ports or self.DEFAULT_VNC_PORTS
        requested = sorted(set((rdp_ports if scan_rdp else []) + (vnc_ports if scan_vnc else [])))
        if not requested:
            raise ValueError("Выберите хотя бы один протокол")
        if progress_callback:
            progress_callback(5, f"Nmap: 0/{len(targets)} IP · {len(requested)} портов")
        services = await self._nmap(targets, requested, progress_callback)
        if progress_callback:
            progress_callback(55, f"Найдено сервисов: {len(services)}")

        captures = []
        vnc_services = [item for item in services if item["protocol_type"] == "vnc"]
        completed = 0
        semaphore = asyncio.Semaphore(4)

        async def capture_service(service):
            nonlocal completed
            async with semaphore:
                capture = await self._capture_vnc(service["target"], service["port"])
                service["capture_status"] = capture["status"]
                service["capture_message"] = capture["message"]
                if capture.get("capture_id"):
                    service["capture_id"] = capture["capture_id"]
                    captures.append({**capture, "port": service["port"], "target": service["target"]})
                completed += 1
                if progress_callback:
                    progress_callback(55 + int(completed / max(1, len(vnc_services)) * 40),
                                      f"Снимки VNC: {completed}/{len(vnc_services)}")

        await asyncio.gather(*(capture_service(service) for service in vnc_services))
        return {"target_count": len(targets), "services": services, "captures": captures}

    async def _nmap(self, targets: List[str], ports: List[int], progress_callback=None) -> List[Dict]:
        if not self.nmap_bin:
            raise RuntimeError("Nmap не установлен")
        batches = [targets[index:index + self.NMAP_BATCH_SIZE]
                   for index in range(0, len(targets), self.NMAP_BATCH_SIZE)]
        semaphore = asyncio.Semaphore(self.NMAP_BATCH_CONCURRENCY)
        completed = 0
        completed_lock = asyncio.Lock()

        async def scan_batch(batch: List[str]) -> List[Dict]:
            nonlocal completed
            async with semaphore:
                services = await self._nmap_batch(batch, ports)
            async with completed_lock:
                completed += len(batch)
                if progress_callback:
                    pct = completed / len(targets) * 100
                    progress_callback(
                        5 + int(pct * .5),
                        f"Nmap: {completed}/{len(targets)} IP ({pct:.1f}%)",
                    )
            return services

        results = await asyncio.gather(*(scan_batch(batch) for batch in batches))
        return [service for batch_services in results for service in batch_services]

    async def _nmap_batch(self, targets: List[str], ports: List[int]) -> List[Dict]:
        scripts = "rdp-enum-encryption,rdp-ntlm-info,vnc-info"
        cmd = [self.nmap_bin, "-Pn", "-sV", "-T4", "--max-retries", "1",
               "--host-timeout", "120s", "--script", scripts, "-p",
               ",".join(map(str, ports)), "--stats-every", "3s", "-oX", "-"] + targets
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.PIPE)
        stderr_chunks = []

        async def read_stderr():
            while True:
                line = await proc.stderr.readline()
                if not line:
                    break
                stderr_chunks.append(line)
                text = line.decode(errors="ignore")
        stdout_task = asyncio.create_task(proc.stdout.read())
        stderr_task = asyncio.create_task(read_stderr())
        try:
            batch_timeout = max(self.timeout + 10, min(7200, len(targets) * 2))
            await asyncio.wait_for(proc.wait(), timeout=batch_timeout)
            stdout = await stdout_task
            await stderr_task
            stderr = b"".join(stderr_chunks)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            stdout_task.cancel()
            stderr_task.cancel()
            raise RuntimeError("Nmap превысил лимит времени")
        if proc.returncode != 0 and not stdout:
            raise RuntimeError(stderr.decode(errors="ignore").strip()[:400] or "Ошибка Nmap")
        return self._parse_nmap(stdout.decode(errors="ignore"))

    @staticmethod
    def _parse_nmap(xml_text: str) -> List[Dict]:
        if not xml_text.strip():
            return []
        root = ET.fromstring(xml_text)
        services = []
        for host in root.findall("host"):
            address = host.find("address")
            target = address.get("addr", "") if address is not None else ""
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                number = int(port.get("portid", 0))
                service = port.find("service")
                name = service.get("name", "") if service is not None else ""
                product = service.get("product", "") if service is not None else ""
                version = service.get("version", "") if service is not None else ""
                scripts = [{"id": script.get("id", ""), "output": script.get("output", "").strip()}
                           for script in port.findall("script") if script.get("output")]
                script_blob = " ".join(item["id"] + " " + item["output"] for item in scripts).lower()
                if "vnc" in name.lower() or "vnc-info" in script_blob or 5900 <= number <= 5999:
                    protocol_type = "vnc"
                elif "rdp" in name.lower() or "ms-wbt" in name.lower() or "rdp-" in script_blob or number == 3389:
                    protocol_type = "rdp"
                else:
                    continue
                services.append({"target": target, "port": number, "transport": port.get("protocol", "tcp"),
                                 "protocol_type": protocol_type, "service": name,
                                 "product": " ".join(x for x in (product, version) if x).strip(),
                                 "scripts": scripts})
        return services

    async def _capture_vnc(self, host: str, port: int) -> Dict:
        try:
            return await asyncio.wait_for(self._capture_vnc_inner(host, port), timeout=15)
        except asyncio.TimeoutError:
            return {"status": "error", "message": "VNC не ответил за 15 секунд"}
        except Exception as exc:
            return {"status": "error", "message": str(exc)[:240]}

    async def _capture_vnc_inner(self, host: str, port: int) -> Dict:
        reader, writer = await asyncio.open_connection(host, port)
        try:
            banner = await reader.readexactly(12)
            if not re.fullmatch(rb"RFB \d{3}\.\d{3}\n", banner):
                raise RuntimeError("Сервис не подтвердил протокол VNC/RFB")
            legacy = banner[4:11] < b"003.007"
            writer.write(b"RFB 003.003\n" if legacy else b"RFB 003.008\n")
            await writer.drain()
            if legacy:
                security_type = struct.unpack(">I", await reader.readexactly(4))[0]
                if security_type != 1:
                    return {"status": "auth_required", "message": "VNC найден, требуется аутентификация"}
            else:
                count = (await reader.readexactly(1))[0]
                if count == 0:
                    length = struct.unpack(">I", await reader.readexactly(4))[0]
                    reason = (await reader.readexactly(min(length, 500))).decode(errors="ignore")
                    raise RuntimeError(reason or "VNC отклонил соединение")
                security = await reader.readexactly(count)
                if 1 not in security:
                    return {"status": "auth_required", "message": "VNC найден, требуется аутентификация"}
                writer.write(b"\x01")
                await writer.drain()
                result = struct.unpack(">I", await reader.readexactly(4))[0]
                if result != 0:
                    return {"status": "auth_required", "message": "VNC не разрешил подключение без пароля"}
            writer.write(b"\x01")  # shared session
            await writer.drain()
            width, height = struct.unpack(">HH", await reader.readexactly(4))
            await reader.readexactly(16)
            name_len = struct.unpack(">I", await reader.readexactly(4))[0]
            await reader.readexactly(name_len)
            if width < 1 or height < 1 or width * height > 16_777_216:
                raise RuntimeError("Некорректный размер экрана VNC")
            # 32bpp, depth 24, little endian, true colour, RGB shifts 16/8/0.
            pixel_format = struct.pack(">BBBBHHHBBBxxx", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
            writer.write(b"\x00\x00\x00\x00" + pixel_format)
            writer.write(struct.pack(">BBHi", 2, 0, 1, 0))  # raw encoding only
            writer.write(struct.pack(">BBHHHH", 3, 0, 0, 0, width, height))
            await writer.drain()
            while True:
                msg_type = (await reader.readexactly(1))[0]
                if msg_type != 0:
                    if msg_type == 2:
                        await reader.readexactly(1)
                    elif msg_type == 3:
                        await reader.readexactly(3)
                        length = struct.unpack(">I", await reader.readexactly(4))[0]
                        await reader.readexactly(length)
                    continue
                await reader.readexactly(1)
                rectangles = struct.unpack(">H", await reader.readexactly(2))[0]
                canvas = bytearray(width * height * 3)
                for _ in range(rectangles):
                    x, y, rw, rh, encoding = struct.unpack(">HHHHi", await reader.readexactly(12))
                    if encoding != 0:
                        raise RuntimeError(f"VNC использует неподдерживаемое кодирование {encoding}")
                    raw = await reader.readexactly(rw * rh * 4)
                    for row in range(rh):
                        for col in range(rw):
                            src = (row * rw + col) * 4
                            dst = ((y + row) * width + x + col) * 3
                            canvas[dst:dst + 3] = bytes((raw[src + 2], raw[src + 1], raw[src]))
                capture_id = uuid.uuid4().hex
                path = self.capture_dir / f"{capture_id}.png"
                path.write_bytes(_encode_png(width, height, bytes(canvas)))
                return {"status": "captured", "message": f"Снимок {width}×{height}",
                        "capture_id": capture_id, "width": width, "height": height}
        finally:
            writer.close()
            await writer.wait_closed()


def _encode_png(width: int, height: int, rgb: bytes) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
    rows = b"".join(b"\x00" + rgb[y * width * 3:(y + 1) * width * 3] for y in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 6)) + chunk(b"IEND", b""))
