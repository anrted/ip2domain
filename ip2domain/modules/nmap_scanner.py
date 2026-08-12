import asyncio
import logging
import re
import shutil
import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Default scan arguments by profile name
SCAN_PROFILES: Dict[str, str] = {
    "fast":    "-sV -T4 -Pn --top-ports 50 --max-retries 1 --host-timeout 60s",
    "normal":  "-sV -T4 -Pn --top-ports 200 --max-retries 2 --host-timeout 120s",
    "full":    "-sV -T3 -Pn -p- --max-retries 1 --host-timeout 15m",
    "stealth": "-sS -T2 -Pn --top-ports 100 --max-retries 1 --host-timeout 180s",
    "udp":     "-sU -T4 -Pn --top-ports 30 --max-retries 1 --host-timeout 180s",
}

# In-process result cache: {(ip, configuration): (timestamp, result)}
_RESULT_CACHE: Dict[str, Tuple[float, List[Dict]]] = {}
_CACHE_TTL_SECONDS = 300  # 5 minutes


class NmapScanner:
    """
    Asynchronous Nmap scanner.

    Improvements over v1:
    - Named scan profiles (fast / normal / full / stealth / udp)
    - Custom port specification: e.g. "80,443,8080" or "1-1024"
    - In-process result cache (TTL 300s) — avoids redundant rescans
    - OS detection support (-O flag, requires root)
    - Host status, hostname and OS name included in result
    - Graceful SIGKILL on timeout (prevents zombie processes)
    - Structured per-port CPE extraction from Nmap XML
    """

    def __init__(
        self,
        ports: Optional[str] = None,
        arguments: Optional[str] = None,
        profile: str = "fast",
        os_detect: bool = False,
        timeout: Optional[int] = None,
    ):
        if profile not in SCAN_PROFILES:
            raise ValueError(f"Unknown Nmap profile: {profile}")
        self.ports    = self.validate_ports(ports)
        self.profile  = profile
        profile_timeouts = {"fast": 75, "normal": 150, "full": 960, "stealth": 210, "udp": 210}
        self.timeout  = timeout if timeout is not None else profile_timeouts[profile]
        self.os_detect = os_detect
        self.nmap_bin  = shutil.which("nmap")

        if arguments:
            self.arguments = arguments
        elif self.ports:
            # Custom ports override profile
            scan_type = "-sU" if profile == "udp" else ("-sS" if profile == "stealth" else "-sV")
            self.arguments = f"{scan_type} -T4 -Pn --max-retries 2 --host-timeout 120s"
        else:
            self.arguments = SCAN_PROFILES.get(profile, SCAN_PROFILES["fast"])

        if os_detect and "-O" not in self.arguments:
            self.arguments += " -O --osscan-guess"

    def is_available(self) -> bool:
        return self.nmap_bin is not None

    @staticmethod
    def validate_ports(ports: Optional[str]) -> Optional[str]:
        """Normalize a safe Nmap TCP/UDP port list such as 22,80,443 or 1-1024."""
        if ports is None or not ports.strip():
            return None
        compact = re.sub(r"\s+", "", ports)
        if len(compact) > 512 or not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", compact):
            raise ValueError("Порты должны быть указаны как 22,80,443 или 1-1024")
        for part in compact.split(","):
            bounds = [int(value) for value in part.split("-")]
            if any(value < 1 or value > 65535 for value in bounds):
                raise ValueError("Номер порта должен находиться в диапазоне 1–65535")
            if len(bounds) == 2 and bounds[0] > bounds[1]:
                raise ValueError(f"Начало диапазона портов больше конца: {part}")
        return compact

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan_ip(self, ip: str, use_cache: bool = True, progress_callback=None) -> Dict[str, any]:
        """
        Scans a single IP address. Returns structured result:
        {
            "ip":        "1.2.3.4",
            "hostname":  "example.com",
            "os":        "Linux 4.15",
            "open_ports": [{"port": 80, "protocol": "tcp", "state": "open",
                            "service": "http", "version": "nginx 1.18", "cpe": "cpe:/a:nginx:nginx"}]
        }
        """
        if not self.is_available():
            logger.warning("Nmap executable not found in system PATH.")
            return self._empty_result(ip, error="nmap not installed")

        # Cache check
        cache_key = f"{ip}|{self.ports}|{self.arguments}|{self.profile}|{self.os_detect}"
        if use_cache and cache_key in _RESULT_CACHE:
            ts, cached = _RESULT_CACHE[cache_key]
            if time.monotonic() - ts < _CACHE_TTL_SECONDS:
                logger.debug(f"[NmapScanner] Cache hit for {ip}")
                return cached

        cmd = self._build_cmd(ip)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stderr_chunks = []

            async def _read_stderr():
                while True:
                    line = await proc.stderr.readline()
                    if not line:
                        break
                    stderr_chunks.append(line)
                    message = line.decode("utf-8", errors="ignore").strip()
                    match = re.search(r"About\s+([0-9]+(?:\.[0-9]+)?)%\s+done", message, re.IGNORECASE)
                    if match and progress_callback:
                        percent = min(100.0, max(0.0, float(match.group(1))))
                        total_ports = self.port_count()
                        checked = min(total_ports, round(total_ports * percent / 100))
                        progress_callback(percent, checked, total_ports)

            stdout_task = asyncio.create_task(proc.stdout.read())
            stderr_task = asyncio.create_task(_read_stderr())
            try:
                await asyncio.wait_for(proc.wait(), timeout=self.timeout)
                stdout = await stdout_task
                await stderr_task
                stderr = b"".join(stderr_chunks)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
                stdout_task.cancel()
                stderr_task.cancel()
                logger.warning(f"[NmapScanner] Timeout ({self.timeout}s) for {ip}")
                return self._empty_result(ip, error=f"timeout after {self.timeout}s")

            err_msg = ""
            if proc.returncode != 0:
                err_msg = stderr.decode("utf-8", errors="ignore").strip()[:300]
                logger.warning(f"[NmapScanner] Nmap returned {proc.returncode} for {ip}: {err_msg}")

            result = self._parse_xml(ip, stdout.decode("utf-8", errors="ignore"))
            if proc.returncode != 0:
                result["error"] = err_msg or f"nmap exited with code {proc.returncode}"

        except Exception as e:
            logger.error(f"[NmapScanner] Error scanning {ip}: {e}")
            return self._empty_result(ip, error=str(e))

        # Cache store
        _RESULT_CACHE[cache_key] = (time.monotonic(), result)
        return result

    async def scan_ips_concurrently(
        self,
        ips: List[str],
        max_concurrency: int = 5,
        progress_callback=None,
        use_cache: bool = True,
        return_details: bool = False,
    ) -> Dict[str, List[Dict[str, any]]]:
        """
        Scans multiple IPs concurrently via semaphore.
        Returns: { ip: [port_info, ...] }  — backward-compatible with previous API.
        """
        semaphore  = asyncio.Semaphore(max_concurrency)
        total      = len(ips)
        completed  = 0

        async def _scan(target_ip: str):
            nonlocal completed
            async with semaphore:
                if progress_callback:
                    progress_callback(completed, total, f"Nmap начал проверку {target_ip}")
                def _port_progress(percent: float, checked: int, total_ports: int):
                    if progress_callback:
                        progress_callback(
                            completed,
                            total,
                            f"{target_ip} · проверено ≈ {checked:,}/{total_ports:,} портов ({percent:.1f}%)".replace(",", " "),
                        )

                res = await self.scan_ip(
                    target_ip, use_cache=use_cache, progress_callback=_port_progress
                )
                completed += 1
                if progress_callback:
                    progress_callback(completed, total, "Nmap port scanning")
                return target_ip, res

        tasks   = [_scan(ip) for ip in ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        scan_map: Dict[str, List[Dict]] = {}
        for item in results:
            if isinstance(item, tuple):
                target_ip, res = item
                # Flatten: backward-compatible — callers expect {ip: [ports]}
                scan_map[target_ip] = res if return_details else res.get("open_ports", [])
            elif isinstance(item, Exception):
                logger.error(f"[NmapScanner] Batch error: {item}")

        return scan_map

    def invalidate_cache(self, ip: Optional[str] = None) -> None:
        """Remove cached result for one IP, or clear all if ip=None."""
        if ip:
            for key in [k for k in _RESULT_CACHE if k.startswith(f"{ip}|")]:
                _RESULT_CACHE.pop(key, None)
        else:
            _RESULT_CACHE.clear()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_cmd(self, ip: str) -> List[str]:
        cmd = [self.nmap_bin, "-oX", "-"]
        if self.ports:
            cmd += ["-p", self.ports]
        cmd += self.arguments.split()
        if "--stats-every" not in cmd:
            cmd += ["--stats-every", "2s"]
        cmd.append(ip)
        return cmd

    def port_count(self) -> int:
        """Return the number of ports requested by the current scan configuration."""
        if self.ports:
            ports = set()
            for part in self.ports.split(","):
                bounds = [int(value) for value in part.split("-")]
                if len(bounds) == 1:
                    ports.add(bounds[0])
                else:
                    ports.update(range(bounds[0], bounds[1] + 1))
            return len(ports)
        return {"fast": 50, "normal": 200, "full": 65535, "stealth": 100, "udp": 30}[self.profile]

    def _parse_xml(self, ip: str, xml_content: str) -> Dict[str, any]:
        """Parse Nmap XML output into structured dict."""
        result = self._empty_result(ip)
        if not xml_content.strip():
            return result

        try:
            root = ET.fromstring(xml_content)
            for host in root.findall("host"):
                # Host status
                status = host.find("status")
                if status is not None and status.get("state") != "up":
                    continue

                # Hostname
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    hn = hostnames.find("hostname")
                    if hn is not None:
                        result["hostname"] = hn.get("name", "")

                # OS detection
                os_elem = host.find("os")
                if os_elem is not None:
                    best_match = os_elem.find("osmatch")
                    if best_match is not None:
                        result["os"] = best_match.get("name", "")
                        result["os_accuracy"] = int(best_match.get("accuracy", 0))

                # Ports
                ports_node = host.find("ports")
                if ports_node is None:
                    continue

                for port in ports_node.findall("port"):
                    state_node = port.find("state")
                    if state_node is None or state_node.get("state") != "open":
                        continue

                    port_id   = int(port.get("portid", 0))
                    protocol  = port.get("protocol", "tcp")

                    service_name = ""
                    version      = ""
                    cpe          = ""

                    svc = port.find("service")
                    service_method = ""
                    service_confidence = 0
                    tunnel = ""
                    http_detected = False
                    if svc is not None:
                        service_name = svc.get("name", "")
                        product      = svc.get("product", "")
                        ver          = svc.get("version", "")
                        extrainfo    = svc.get("extrainfo", "")
                        version      = " ".join(filter(None, [product, ver, extrainfo]))
                        service_method = svc.get("method", "")
                        service_confidence = int(svc.get("conf", 0) or 0)
                        tunnel = svc.get("tunnel", "")
                        service_fp = svc.get("servicefp", "")
                        http_detected = (
                            service_name in {"http", "https", "http-proxy"}
                            or "http" in service_name.lower()
                            or "HTTP/1." in service_fp
                        )

                        cpe_elem = svc.find("cpe")
                        if cpe_elem is not None and cpe_elem.text:
                            cpe = cpe_elem.text

                    # Risk hint from port number
                    risk = _port_risk(port_id, service_name)

                    result["open_ports"].append({
                        "port":     port_id,
                        "protocol": protocol,
                        "state":    "open",
                        "service":  service_name,
                        "version":  version,
                        "cpe":      cpe,
                        "risk":     risk,
                        "service_method": service_method,
                        "service_confidence": service_confidence,
                        "tunnel": tunnel,
                        "http_detected": http_detected,
                    })

        except ET.ParseError as e:
            logger.warning(f"[NmapScanner] XML parse error for {ip}: {e}")
        except Exception as e:
            logger.error(f"[NmapScanner] Unexpected parse error for {ip}: {e}")

        result["tech_stack"] = self.extract_tech_stack(result["open_ports"])
        return result

    @staticmethod
    def extract_tech_stack(open_ports: List[Dict[str, any]]) -> List[str]:
        """Build a normalized technology list from Nmap service/version fingerprints."""
        stack: Dict[str, str] = {}
        for port in open_ports or []:
            version = str(port.get("version", "")).strip()
            # Table-based names without a product/version are guesses based only on
            # port number and must not be presented as detected technologies.
            if version:
                stack.setdefault(version.casefold(), version)
        return NmapScanner.normalize_tech_stack(stack.values())

    @staticmethod
    def normalize_tech_stack(values) -> List[str]:
        """Deduplicate stack labels and prefer a versioned fingerprint over its generic name."""
        unique: Dict[str, str] = {}
        for raw in values or []:
            value = str(raw).strip()
            if value:
                unique.setdefault(value.casefold(), value)
        versioned_products = {
            value.split(None, 1)[0].casefold()
            for value in unique.values()
            if re.search(r"\d+(?:\.\d+)+", value)
        }
        normalized = [
            value for value in unique.values()
            if not (" " not in value and value.casefold() in versioned_products)
        ]
        return sorted(normalized, key=str.casefold)

    @staticmethod
    def _empty_result(ip: str, error: str = "") -> Dict[str, any]:
        return {
            "ip":         ip,
            "hostname":   "",
            "os":         "",
            "os_accuracy": 0,
            "open_ports": [],
            "tech_stack": [],
            "error":      error,
        }


def _port_risk(port: int, service: str) -> str:
    """
    Heuristic risk level based on port number and service name.
    Returns: 'critical' | 'high' | 'medium' | 'low' | 'info'
    """
    CRITICAL = {21, 22, 23, 3389, 5900}          # FTP, SSH, Telnet, RDP, VNC
    HIGH     = {25, 110, 143, 3306, 5432, 6379,  # Mail, DB, Redis
                27017, 9200, 11211}               # MongoDB, ES, Memcache
    MEDIUM   = {80, 443, 8080, 8443, 8000}        # HTTP/HTTPS

    svc_lower = service.lower()
    if port in CRITICAL or any(k in svc_lower for k in ("telnet", "vnc", "rdp")):
        return "critical"
    if port in HIGH or any(k in svc_lower for k in ("mysql", "postgres", "redis", "mongo")):
        return "high"
    if port in MEDIUM:
        return "medium"
    return "info"
