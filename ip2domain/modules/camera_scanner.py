import asyncio
import aiohttp
import ipaddress
import re
import shutil
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlsplit


class CameraScanner:
    """Identify IP cameras/NVRs from remotely observable service fingerprints."""

    DEFAULT_PORTS = [80, 443, 554, 8000, 8080, 8081, 8443, 8554, 8899, 37777]
    NMAP_BATCH_SIZE = 32
    NMAP_BATCH_CONCURRENCY = 4
    KEYWORDS = {
        "hikvision": "Hikvision", "dahua": "Dahua", "axis": "Axis",
        "ipcamera": "IP Camera", "ip camera": "IP Camera",
        "network camera": "Network Camera", "cctv": "CCTV",
        "onvif": "ONVIF", "nvr": "NVR", "dvr": "DVR",
        "boa": "Boa web server",
        "vivotek": "Vivotek", "mobotix": "Mobotix", "uniview": "Uniview",
        "amcrest": "Amcrest", "foscam": "Foscam", "hanwha": "Hanwha",
        "dvr remote management system": "DVR Remote Management System",
        "web_preview.js": "DVR preview interface",
        "activexsetup": "DVR ActiveX client",
    }
    PTR_RE = re.compile(r"(?:^|[.\-_])(cam(?:era)?\d*|cctv|ipc|nvr|dvr)(?:[.\-_]|$)", re.I)

    def __init__(self, timeout: int = 120):
        self.timeout = timeout
        self.nmap_bin = shutil.which("nmap")

    async def scan(self, targets: List[str], ports: Optional[List[int]] = None,
                   progress_callback=None) -> Dict:
        targets = list(dict.fromkeys(str(ipaddress.ip_address(item)) for item in targets))
        if not targets:
            raise ValueError("Список IP-адресов пуст")
        ports = sorted(set(ports or self.DEFAULT_PORTS))
        if not ports or any(port < 1 or port > 65535 for port in ports):
            raise ValueError("Порты должны находиться в диапазоне 1–65535")
        if not self.nmap_bin:
            raise RuntimeError("Nmap не установлен")
        if progress_callback:
            progress_callback(5, f"Nmap: 0/{len(targets)} IP · {len(ports)} портов")
        batches = [targets[i:i + self.NMAP_BATCH_SIZE]
                   for i in range(0, len(targets), self.NMAP_BATCH_SIZE)]
        semaphore = asyncio.Semaphore(self.NMAP_BATCH_CONCURRENCY)
        completed = 0
        lock = asyncio.Lock()

        async def run(batch):
            nonlocal completed
            async with semaphore:
                result = await self._nmap_batch(batch, ports)
            async with lock:
                completed += len(batch)
                if progress_callback:
                    progress_callback(5 + int(completed / len(targets) * 90),
                                      f"Проверено: {completed}/{len(targets)} IP")
            return result

        results = await asyncio.gather(*(run(batch) for batch in batches))
        candidates = [device for part in results for device in part]
        await self._probe_http_candidates(candidates, progress_callback)
        devices = []
        for device in candidates:
            self._update_confidence(device)
            if device["score"] >= 20:
                devices.append(device)
        return {"target_count": len(targets), "devices": devices,
                "camera_count": len(devices)}

    async def _nmap_batch(self, targets: List[str], ports: List[int]) -> List[Dict]:
        # Discovery must stay quick. Deeper enumeration/auth checks belong to the
        # explicit vulnerability scan launched from a camera result card.
        scripts = ("banner,http-favicon,http-headers,http-server-header,http-title,"
                   "ssl-cert,rtsp-methods,upnp-info")
        cmd = [self.nmap_bin, "-Pn", "-R", "-sV", "-T4", "--max-retries", "1",
               "--host-timeout", "75s", "--script-timeout", "20s",
               "--stats-every", "2s", "--script", scripts, "-p",
               ",".join(map(str, ports)), "-oX", "-"] + targets
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=max(self.timeout + 10, min(7200, len(targets) * 2)))
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise RuntimeError("Nmap превысил лимит времени")
        if proc.returncode != 0 and not stdout:
            raise RuntimeError(stderr.decode(errors="ignore").strip()[:400] or "Ошибка Nmap")
        return self._parse_nmap(stdout.decode(errors="ignore"), include_unmatched=True)

    async def _probe_http_candidates(self, devices: List[Dict], progress_callback=None) -> None:
        semaphore = asyncio.Semaphore(20)
        timeout = aiohttp.ClientTimeout(total=10, connect=5, sock_read=7)
        connector = aiohttp.TCPConnector(ssl=False, limit=20)
        probes = []
        async with aiohttp.ClientSession(timeout=timeout, connector=connector,
                                         headers={"User-Agent": "ip2domain-camera-discovery/1.0"}) as session:
            async def probe(device, service):
                async with semaphore:
                    findings = await self._probe_http_service(session, device["target"], service)
                    device["findings"].extend(findings)

            for device in devices:
                for service in device.get("services", []):
                    name = str(service.get("service", "")).lower()
                    if "http" in name or service.get("port") in {80, 443, 8000, 8080, 8081, 8443, 8899}:
                        probes.append(probe(device, service))
            if probes:
                if progress_callback:
                    progress_callback(95, f"HTTP fingerprint: {len(probes)} сервисов")
                await asyncio.gather(*probes)

    async def _probe_http_service(self, session: aiohttp.ClientSession,
                                  target: str, service: Dict) -> List[Dict]:
        port = int(service["port"])
        name = str(service.get("service", "")).lower()
        scheme = "https" if service.get("tunnel") == "ssl" or "https" in name or port in {443, 8443} else "http"
        url_host = f"[{target}]" if ":" in target else target
        url = f"{scheme}://{url_host}:{port}/"
        try:
            for _ in range(4):
                async with session.get(url, allow_redirects=False) as response:
                    body = (await response.content.read(262144)).decode(errors="ignore")
                    headers = "\n".join(f"{key}: {value}" for key, value in response.headers.items())
                    location = response.headers.get("Location")
                    if response.status in {301, 302, 303, 307, 308} and location:
                        next_url = urljoin(url, location)
                        parsed = urlsplit(next_url)
                        # Never follow a camera-controlled redirect to another host.
                        if parsed.scheme not in {"http", "https"} or parsed.hostname != target:
                            break
                        url = next_url
                        continue
                    return self._http_findings(target, port, url, headers, body)
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return []
        return []

    @classmethod
    def _http_findings(cls, target: str, port: int, url: str,
                       headers: str, body: str) -> List[Dict]:
        blob = f"{headers}\n{body}".lower()
        matches = sorted({label for key, label in cls.KEYWORDS.items() if key in blob})
        findings = []
        if matches:
            findings.append({"criterion": "HTTP HTML/JS fingerprint",
                             "value": f'{target}:{port} · {", ".join(matches)} · {url}',
                             "reliability": "высокая", "weight": 40})
        if "goahead" in blob:
            findings.append({"criterion": "Embedded HTTP server",
                             "value": f"{target}:{port} · GoAhead · {url}",
                             "reliability": "низкая", "weight": 10})
        return findings

    @classmethod
    def _parse_nmap(cls, xml_text: str, include_unmatched: bool = False) -> List[Dict]:
        if not xml_text.strip():
            return []
        root = ET.fromstring(xml_text)
        devices = []
        for host in root.findall("host"):
            address = host.find("address")
            target = address.get("addr", "") if address is not None else ""
            hostname_node = host.find("./hostnames/hostname")
            hostname = hostname_node.get("name", "") if hostname_node is not None else ""
            findings, services = [], []
            if hostname and cls.PTR_RE.search(hostname):
                findings.append({"criterion": "Reverse DNS / PTR", "value": hostname,
                                 "reliability": "средняя", "weight": 20})
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                name = service.get("name", "") if service is not None else ""
                product = service.get("product", "") if service is not None else ""
                version = service.get("version", "") if service is not None else ""
                tunnel = service.get("tunnel", "") if service is not None else ""
                port_number = int(port.get("portid", 0))
                scripts = [{"id": node.get("id", ""), "output": node.get("output", "").strip()}
                           for node in port.findall("script") if node.get("output")]
                blob = " ".join([name, product, version] +
                                [f'{item["id"]} {item["output"]}' for item in scripts])
                services.append({"port": port_number,
                                 "transport": port.get("protocol", "tcp"), "service": name,
                                 "tunnel": tunnel,
                                 "product": " ".join(x for x in (product, version) if x).strip(),
                                 "scripts": scripts})
                lower = blob.lower()
                if name.lower() == "rtsp" or "rtsp-methods" in lower:
                    findings.append({"criterion": "RTSP", "value": f'{target}:{port_number} · {product or name}',
                                     "reliability": "очень высокая", "weight": 55})
                if "onvif" in lower:
                    findings.append({"criterion": "ONVIF", "value": "ONVIF fingerprint в ответе сервиса",
                                     "reliability": "очень высокая", "weight": 60})
                if "upnp-info" in lower:
                    findings.append({"criterion": "SSDP / UPnP", "value": cls._short(blob),
                                     "reliability": "высокая", "weight": 35})
                matches = sorted({label for key, label in cls.KEYWORDS.items() if key in lower})
                if matches:
                    findings.append({"criterion": "HTTP / TLS / баннер сервиса",
                                     "value": f'{target}:{port_number} · {", ".join(matches)}',
                                     "reliability": "высокая", "weight": 40})
                # GoAhead is common in embedded hardware, not just cameras. Keep it
                # as supporting evidence, but never classify a host from it alone.
                if "goahead" in lower:
                    findings.append({"criterion": "Embedded HTTP server",
                                     "value": f"{target}:{port_number} · GoAhead",
                                     "reliability": "низкая", "weight": 10})
            unique = {(f["criterion"], f["value"]): f for f in findings}
            findings = list(unique.values())
            score = min(100, sum(item["weight"] for item in findings))
            if score < 20 and not include_unmatched:
                continue
            confidence = "очень высокая" if score >= 75 else "высокая" if score >= 40 else "средняя" if score >= 20 else "низкая"
            devices.append({"target": target, "hostname": hostname, "score": score,
                            "confidence": confidence, "findings": findings, "services": services})
        return devices

    @staticmethod
    def _update_confidence(device: Dict) -> None:
        unique = {}
        for item in device.get("findings", []):
            criterion = item["criterion"]
            previous = unique.get(criterion)
            if (not previous or item.get("weight", 0) > previous.get("weight", 0) or
                    (item.get("weight", 0) == previous.get("weight", 0) and
                     len(item.get("value", "")) > len(previous.get("value", "")))):
                unique[criterion] = item
        device["findings"] = list(unique.values())
        score = min(100, sum(item.get("weight", 0) for item in device["findings"]))
        device["score"] = score
        device["confidence"] = ("очень высокая" if score >= 75 else "высокая" if score >= 40
                                else "средняя" if score >= 20 else "низкая")

    @staticmethod
    def _short(value: str, limit: int = 240) -> str:
        value = " ".join(value.split())
        return value[:limit] + ("…" if len(value) > limit else "")
