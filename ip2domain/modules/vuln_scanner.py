import asyncio
import logging
import re
import shutil
from pathlib import Path
import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# CVE/OSVDB severity keywords for Nikto output
_HIGH_KEYWORDS    = frozenset(["osvdb", "cve", "vulnerability", "sql injection",
                                "xss", "rce", "rfi", "lfi", "authentication bypass",
                                "arbitrary", "remote code", "buffer overflow"])
_MEDIUM_KEYWORDS  = frozenset(["directory listing", "outdated", "deprecated",
                                "insecure", "sensitive", "information disclosure",
                                "admin", "login", "phpmyadmin"])
_ALLOWED_NIKTO_TUNING = frozenset("123456789abc")

# In-process dedup cache: {target: (ts, result)}
_VULN_CACHE: Dict[str, Tuple[float, Dict]] = {}
_CACHE_TTL = 600  # 10 min


# Technology stack to specific Nmap NSE scripts mapping
TECH_NSE_SCRIPTS: Dict[str, List[str]] = {
    "wordpress":      ["http-wordpress-enum", "http-wordpress-users"],
    "joomla":         ["http-joomla-enum"],
    "drupal":         ["http-drupal-enum"],
    "php":            ["http-php-version", "http-vuln-cve2012-1823"],
    "asp.net":        ["http-iis-short-name-brute", "http-vuln-cve2015-1635"],
    "iis":            ["http-iis-short-name-brute", "http-vuln-cve2015-1635", "http-iis-webdav-vuln"],
    "microsoft-iis":  ["http-iis-short-name-brute", "http-vuln-cve2015-1635"],
    "apache":         ["http-apache-negotiation", "http-apache-server-status"],
    "nginx":          ["http-enum", "http-methods", "http-security-headers"],
    "openssh":        ["ssh-auth-methods", "ssh-hostkey"],
    "samba":          ["smb-os-discovery", "smb-protocols", "smb-security-mode",
                       "smb2-security-mode", "smb-vuln-ms17-010", "smb-vuln-cve-2017-7494"],
    "vsftpd":         ["ftp-anon", "ftp-syst", "ftp-vsftpd-backdoor"],
    "bitrix":         ["http-enum", "http-headers", "http-methods"],
    "laravel":        ["http-enum"],
    "django":         ["http-enum"],
    "goahead":        ["http-auth", "http-auth-finder", "http-default-accounts",
                        "http-enum", "http-methods", "http-robots.txt",
                        "http-security-headers", "http-server-header"],
    "telnetd":        ["banner", "telnet-encryption", "telnet-ntlm-info"],
    "dvr":            ["http-auth", "http-auth-finder", "http-default-accounts",
                        "http-enum", "http-methods", "http-security-headers",
                        "http-server-header", "rtsp-methods", "rtsp-url-brute"],
    "nvr":            ["http-auth", "http-auth-finder", "http-default-accounts",
                        "http-enum", "http-methods", "http-security-headers",
                        "http-server-header", "rtsp-methods", "rtsp-url-brute"],
    "ip camera":      ["http-auth", "http-auth-finder", "http-default-accounts",
                        "http-enum", "http-methods", "http-security-headers",
                        "http-server-header", "rtsp-methods", "rtsp-url-brute"],
    "ipcamera":       ["http-auth", "http-auth-finder", "http-default-accounts",
                        "http-enum", "http-methods", "http-security-headers",
                        "http-server-header", "rtsp-methods", "rtsp-url-brute"],
    "cctv":           ["http-auth", "http-auth-finder", "http-default-accounts",
                        "http-enum", "http-methods", "http-security-headers",
                        "http-server-header", "rtsp-methods", "rtsp-url-brute"],
    "network camera": ["http-auth", "http-auth-finder", "http-default-accounts",
                        "http-enum", "http-methods", "http-security-headers",
                        "http-server-header", "rtsp-methods", "rtsp-url-brute"],
}

# Service-driven checks also work when Nmap could not identify a product version.
SERVICE_NSE_SCRIPTS: Dict[str, List[str]] = {
    "telnet": ["banner", "telnet-encryption", "telnet-ntlm-info"],
    "iso-tsap": ["s7-info"],
    "s7": ["s7-info"],
    "hostname": ["banner"],
    "tcpwrapped": ["banner"],
    "rtsp": ["banner", "rtsp-methods", "rtsp-url-brute"],
    "http": ["http-auth", "http-auth-finder", "http-default-accounts", "http-enum",
             "http-methods", "http-robots.txt", "http-security-headers", "http-server-header"],
}

# Technology stack to Nikto tuning mapping
TECH_NIKTO_TUNING: Dict[str, str] = {
    "wordpress": "14589c",
    "php":       "14589c",
    "asp.net":   "123489b",
    "iis":       "123489b",
    "microsoft-iis": "123489b",
    "bitrix":    "123489b",
    "joomla":    "14589c",
    "drupal":    "14589c",
}

# Known Version CVE Database for precise version-based vulnerability matching
# Solves user's issue: generic Nmap/Nikto banner scans miss version-specific CVEs
VERSION_CVE_DATABASE: List[Dict[str, any]] = [
    # Nginx
    {
        "product": "nginx",
        "min_ver": "1.18.0", "max_ver": "1.20.0",
        "cve": "CVE-2021-23017",
        "title": "Nginx DNS Resolver 1-Byte Heap Memory Corruption",
        "severity": "high",
        "cvss": 7.7,
        "details": "1-byte memory overwrite in ngx_resolver.c via crafted DNS response. Can lead to DoS or remote code execution.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"
    },
    {
        "product": "nginx",
        "min_ver": "1.0.0", "max_ver": "1.23.1",
        "cve": "CVE-2022-41741",
        "title": "Nginx MP4 Module Memory Corruption",
        "severity": "high",
        "cvss": 7.8,
        "details": "Memory corruption vulnerability in ngx_http_mp4_module allowing remote worker process crash or code execution.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-41741"
    },
    {
        "product": "nginx",
        "min_ver": "1.0.0", "max_ver": "1.23.1",
        "cve": "CVE-2022-41742",
        "title": "Nginx MP4 Module Information Disclosure",
        "severity": "medium",
        "cvss": 7.1,
        "details": "Memory disclosure vulnerability in ngx_http_mp4_module allowing worker process memory leakage.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-41742"
    },

    # Microsoft IIS
    {
        "product": "iis",
        "min_ver": "7.5", "max_ver": "8.5",
        "cve": "CVE-2015-1635",
        "title": "Microsoft IIS HTTP.sys Remote Code Execution (MS15-034)",
        "severity": "critical",
        "cvss": 10.0,
        "details": "Integer overflow vulnerability in HTTP.sys kernel driver when processing HTTP Range headers. Allows unauthenticated RCE.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2015-1635"
    },
    {
        "product": "iis",
        "min_ver": "6.0", "max_ver": "10.0",
        "cve": "CVE-2021-31166",
        "title": "HTTP Protocol Stack Remote Code Execution",
        "severity": "critical",
        "cvss": 9.8,
        "details": "Wormable remote code execution vulnerability in HTTP Protocol Stack (HTTP.sys) parsing malicious packets.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-31166"
    },

    # PHP
    {
        "product": "php",
        "min_ver": "7.0.0", "max_ver": "7.3.10",
        "cve": "CVE-2019-11043",
        "title": "PHP-FPM Remote Code Execution (Nginx / php-fpm)",
        "severity": "critical",
        "cvss": 9.8,
        "details": "Underflow in env_path_info in php-fpm with Nginx fastcgi_split_path_info leading to RCE.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2019-11043"
    },
    {
        "product": "php",
        "min_ver": "7.4.0", "max_ver": "7.4.25",
        "cve": "CVE-2021-21703",
        "title": "PHP-FPM Local Privilege Escalation & Memory Corruption",
        "severity": "high",
        "cvss": 7.5,
        "details": "Numeric overflow in PHP-FPM master process memory management leading to crash or privilege escalation.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-21703"
    },

    # Apache
    {
        "product": "apache",
        "min_ver": "2.4.49", "max_ver": "2.4.50",
        "cve": "CVE-2021-41773",
        "title": "Apache HTTP Server Path Traversal & Remote Code Execution",
        "severity": "critical",
        "cvss": 9.8,
        "details": "Path traversal flaw in URL normalization allowing unauthenticated remote command execution when mod_cgi is enabled.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
    },
]


class VulnScanner:
    """
    Asynchronous vulnerability scanner: Nmap NSE + Nikto.
    Supports dynamic technology stack adaptation for targeted scanning.
    """

    def __init__(
        self,
        nmap_args:     Optional[str] = None,
        nikto_args:    Optional[str] = None,
        nmap_timeout:  int = 210,
        nikto_timeout: int = 120,
    ):
        self.nmap_bin    = shutil.which("nmap")
        self.nikto_bin   = shutil.which("nikto")
        self.nmap_timeout  = nmap_timeout
        self.nikto_timeout = nikto_timeout
        self.adapted_stack: List[str] = []
        scripts_dir = Path("/usr/share/nmap/scripts")
        self.available_nse_scripts = {
            path.stem for path in scripts_dir.glob("*.nse")
        } if scripts_dir.is_dir() else set()

        # Sane safe defaults — include vulners (Vulners.com CVE database lookup) & top-ports 100
        self.nmap_args = (
            nmap_args
            or "-sV -T4 --host-timeout 180s --max-retries 1 "
               "--script=vuln,vulners,http-title,http-headers,ssl-cert,ssl-enum-ciphers "
               "--top-ports 100"
        )
        # Nikto tuning: 1=interesting, 2=misc, 3=auth, 4=default, 8=inject, 9=SQL
        self.nikto_args = nikto_args or "-Tuning 12489 -timeout 10 -maxtime 90"

    def configure_for_stack(self, tech_stack: Optional[List[str]]) -> List[str]:
        """
        Dynamically adjusts Nmap NSE scripts and Nikto tuning based on detected technology stack.
        Returns list of matched/adapted technologies.
        """
        if not tech_stack:
            return []

        matched_techs = []
        custom_scripts = set()
        nikto_tuning_flags = set("12489")

        for tech in tech_stack:
            tech_low = tech.strip().lower()
            # Partial or exact match
            for known_tech, scripts in TECH_NSE_SCRIPTS.items():
                if known_tech in tech_low or tech_low in known_tech:
                    custom_scripts.update(
                        script for script in scripts
                        if not self.available_nse_scripts or script in self.available_nse_scripts
                    )
                    matched_techs.append(tech)

            for known_tech, tuning in TECH_NIKTO_TUNING.items():
                if known_tech in tech_low or tech_low in known_tech:
                    nikto_tuning_flags.update(tuning)

        base_scripts = "vuln,vulners,http-title,http-headers,ssl-cert,ssl-enum-ciphers"
        if custom_scripts:
            all_scripts = base_scripts + "," + ",".join(sorted(custom_scripts))
        else:
            all_scripts = base_scripts

        self.nmap_args = (
            f"-sV -T4 --host-timeout 180s --max-retries 1 --script={all_scripts} --top-ports 100"
        )

        if nikto_tuning_flags:
            tuning_str = "".join(sorted(nikto_tuning_flags))
            self.nikto_args = f"-Tuning {tuning_str} -timeout 10 -maxtime 90"

        self.adapted_stack = sorted(list(set(matched_techs)))
        logger.info(f"[VulnScanner] Adapted scan for tech stack: {self.adapted_stack}")
        return self.adapted_stack

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_nmap_available(self) -> bool:
        return self.nmap_bin is not None

    def is_nikto_available(self) -> bool:
        return self.nikto_bin is not None

    async def scan_target_combined(
        self,
        target: str,
        tech_stack: Optional[List[str]] = None,
        progress_callback=None,
        use_cache: bool = True,
        known_ports: Optional[List[Dict[str, any]]] = None,
    ) -> Dict[str, any]:
        """
        Run Nmap NSE + Nikto concurrently with optional technology stack adaptation.
        Returns structured result dict with nmap_findings, nikto_findings,
        severity_counts, adapted_stack, and scan_duration_sec.
        """
        if tech_stack:
            self.configure_for_stack(tech_stack)

        port_key = ",".join(sorted(f"{p.get('protocol', 'tcp')}:{p.get('port')}" for p in (known_ports or [])))
        key = f"{target.strip().lower()}:{','.join(sorted(tech_stack)) if tech_stack else ''}:{port_key}"

        if use_cache and key in _VULN_CACHE:
            ts, cached = _VULN_CACHE[key]
            if time.monotonic() - ts < _CACHE_TTL:
                logger.debug(f"[VulnScanner] Cache hit for {key}")
                return cached

        t0 = time.monotonic()

        stage_msg = "Запуск сканирования Nmap & Nikto..."
        if self.adapted_stack:
            stage_msg = f"Запуск Nmap & Nikto (стек: {', '.join(self.adapted_stack[:4])})..."

        tool_progress = {"Nmap NSE": 0.0, "Nikto": 0.0}
        tool_stage = {"Nmap NSE": "подготовка", "Nikto": "подготовка"}

        def _tool_progress(tool: str, percent: float, message: str):
            tool_progress[tool] = max(tool_progress[tool], min(100.0, percent))
            tool_stage[tool] = message
            if progress_callback:
                combined = 5 + int(tool_progress["Nmap NSE"] * 0.60 + tool_progress["Nikto"] * 0.30)
                progress_callback(
                    min(95, combined),
                    f"Nmap NSE: {tool_stage['Nmap NSE']} · Nikto: {tool_stage['Nikto']}",
                )

        if progress_callback:
            progress_callback(5, stage_msg)

        nmap_task = asyncio.create_task(
            self._run_nmap(target, lambda pct, msg: _tool_progress("Nmap NSE", pct, msg), known_ports)
        )
        nikto_task = asyncio.create_task(
            self._run_nikto(target, lambda pct, msg: _tool_progress("Nikto", pct, msg), known_ports)
        )

        nmap_res, nikto_res = await asyncio.gather(nmap_task, nikto_task)

        detected_stack = self._fingerprint_findings(nikto_res)

        duration = round(time.monotonic() - t0, 1)

        if progress_callback:
            progress_callback(100, "Сканирование уязвимостей завершено")

        # Version-based CVE Database matching
        version_cves = self.check_version_cves(target, self.adapted_stack)
        severity_counts = _count_severities(nmap_res + nikto_res + version_cves)
        actionable_findings = sum(severity_counts.get(level, 0) for level in ("critical", "high", "medium", "low"))

        result = {
            "target":           target,
            "adapted_stack":    self.adapted_stack,
            "detected_stack":   detected_stack,
            "nmap_findings":    nmap_res,
            "nikto_findings":   nikto_res,
            "version_cves":     version_cves,
            "total_findings":   len(nmap_res) + len(nikto_res) + len(version_cves),
            "actionable_findings": actionable_findings,
            "severity_counts":  severity_counts,
            "scan_duration_sec": duration,
            "scanned_ports": known_ports or [],
            "service_coverage": self._build_service_coverage(known_ports),
        }

        _VULN_CACHE[key] = (time.monotonic(), result)
        return result

    @staticmethod
    def _fingerprint_findings(findings: List[Dict[str, any]]) -> List[str]:
        """Recognize products from strong scanner evidence and annotate their endpoint."""
        by_endpoint: Dict[str, List[Dict[str, any]]] = {}
        for finding in findings:
            by_endpoint.setdefault(str(finding.get("endpoint", "")), []).append(finding)

        detected = set()
        for endpoint_findings in by_endpoint.values():
            evidence = "\n".join(str(item.get("details", "")) for item in endpoint_findings).lower()
            # Cockpit sets a cookie literally named "cockpit". Paths and daemon names
            # are additional strong indicators; port 9090 alone is deliberately ignored.
            if (re.search(r"\bcookie\s+cockpit\b", evidence) or
                    re.search(r"set-cookie[^\n]*\bcockpit=", evidence) or
                    any(marker in evidence for marker in ("cockpit-ws", "/cockpit/", "cockpit.socket"))):
                detected.add("Cockpit")
                for item in endpoint_findings:
                    item["technology"] = "Cockpit"
                    item["service"] = "Cockpit Web Console"
        return sorted(detected)

    def _build_service_coverage(self, known_ports: Optional[List[Dict[str, any]]]) -> List[Dict[str, any]]:
        """Describe CVE/NSE coverage for every versioned service sent to the scanner."""
        coverage = []
        for port in known_ports or []:
            version = str(port.get("version", "")).strip()
            cpe = str(port.get("cpe", "")).strip()
            product_text = f"{port.get('service', '')} {version}".lower()
            targeted = sorted({
                script
                for technology, scripts in TECH_NSE_SCRIPTS.items()
                if technology in product_text
                for script in scripts
                if not self.available_nse_scripts or script in self.available_nse_scripts
            })
            targeted.extend(self._service_scripts(port))
            targeted = sorted(set(targeted))
            checks = ["Nmap service detection", "Nmap vuln category"]
            if cpe:
                checks.append("Vulners CVE by CPE")
            if targeted:
                checks.append("Targeted NSE")
            if version or cpe or targeted:
                coverage.append({
                "port": port.get("port"), "protocol": port.get("protocol", "tcp"),
                "service": port.get("service", ""), "version": version, "cpe": cpe,
                "checks": checks, "targeted_scripts": targeted,
                })
        return coverage

    def check_version_cves(self, target: str, tech_stack: List[str]) -> List[Dict[str, any]]:
        """
        Performs direct version-based CVE matching from VERSION_CVE_DATABASE.
        Extracts product version from HTTP headers/stack (e.g. nginx/1.18.0, IIS/8.5, PHP/7.4.3).
        """
        cve_findings = []
        if not tech_stack:
            return cve_findings

        # Parse products & versions from tech_stack strings
        for item in tech_stack:
            item_low = item.lower()
            ver_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", item_low)
            version_str = ver_match.group(1) if ver_match else None

            for entry in VERSION_CVE_DATABASE:
                prod = entry["product"]
                if prod in item_low:
                    if version_str:
                        if _is_version_in_range(version_str, entry["min_ver"], entry["max_ver"]):
                            cve_findings.append({
                                "tool": "CVE DB",
                                "title": f"[{entry['cve']}] {entry['title']}",
                                "severity": entry["severity"],
                                "cvss": entry["cvss"],
                                "details": f"Обнаружена версия: {item}\nCVSS {entry['cvss']}\n{entry['details']}\nСсылка: {entry['link']}",
                                "cves": [entry["cve"]],
                            })
                    else:
                        # Version unknown, add as potential vulnerability advisory
                        cve_findings.append({
                            "tool": "CVE DB",
                            "title": f"[{entry['cve']}] Рекомендация CVE для {prod.title()}",
                            "severity": "info",
                            "cvss": entry["cvss"],
                            "details": f"Проверьте версию {item}.\n{entry['title']}: {entry['details']}\nСсылка: {entry['link']}",
                            "cves": [entry["cve"]],
                        })
        return cve_findings

    async def scan_target_nmap_vuln(self, target: str) -> List[Dict[str, any]]:
        """Run only the Nmap NSE scan. Convenience method."""
        return await self._run_nmap(target)

    async def scan_target_nikto(self, target: str) -> List[Dict[str, any]]:
        """Run only the Nikto scan. Convenience method."""
        return await self._run_nikto(target)

    def invalidate_cache(self, target: Optional[str] = None) -> None:
        if target:
            prefix = target.strip().lower() + ":"
            for key in [key for key in _VULN_CACHE if key.startswith(prefix)]:
                _VULN_CACHE.pop(key, None)
        else:
            _VULN_CACHE.clear()

    # ------------------------------------------------------------------
    # Internal runners
    # ------------------------------------------------------------------

    async def _run_nmap(self, target: str, progress_callback=None,
                        known_ports: Optional[List[Dict[str, any]]] = None) -> List[Dict[str, any]]:
        if not self.is_nmap_available():
            return [_finding("Nmap NSE", "Nmap не установлен", "error",
                             "Nmap binary not found in PATH.")]

        cmd = self._build_nmap_command(target, known_ports)
        findings = []

        if progress_callback:
            progress_callback(1, "запуск процесса")
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
                message = line.decode("utf-8", errors="ignore")
                match = re.search(r"About\s+([0-9]+(?:\.[0-9]+)?)%\s+done", message, re.IGNORECASE)
                if match and progress_callback:
                    percent = min(99.0, float(match.group(1)))
                    progress_callback(percent, f"работает, {percent:.1f}%")

        stdout_task = asyncio.create_task(proc.stdout.read())
        stderr_task = asyncio.create_task(_read_stderr())
        try:
            await asyncio.wait_for(proc.wait(), timeout=self.nmap_timeout)
            stdout = await stdout_task
            await stderr_task
            stderr = b"".join(stderr_chunks)
        except asyncio.TimeoutError:
            await _kill_proc(proc)
            stdout_task.cancel()
            stderr_task.cancel()
            if progress_callback:
                progress_callback(100, "таймаут")
            return [_finding("Nmap NSE", "Nmap Timeout",
                             "warning",
                             f"Nmap превысил лимит {self.nmap_timeout}s. Результаты могут быть неполными.")]

        if progress_callback:
            progress_callback(100, "завершён")

        if stdout:
            findings = self._parse_nmap_xml(stdout.decode("utf-8", errors="ignore"))

        if proc.returncode != 0:
            message = stderr.decode("utf-8", errors="ignore").strip()[:500]
            findings.append(_finding("Nmap NSE", "Ошибка выполнения Nmap", "error",
                                     message or f"Nmap завершился с кодом {proc.returncode}."))

        if not findings:
            findings.append(_finding(
                "Nmap NSE", "Сканирование Nmap завершено", "info",
                "Известных уязвимостей скриптами Nmap NSE не обнаружено."
            ))

        return findings

    def _build_nmap_command(self, target: str,
                            known_ports: Optional[List[Dict[str, any]]] = None) -> List[str]:
        args = self.nmap_args.split()
        if "-Pn" not in args:
            args.append("-Pn")
        if known_ports:
            service_scripts = sorted({script for port in known_ports for script in self._service_scripts(port)})
            if service_scripts:
                for index, arg in enumerate(args):
                    if arg.startswith("--script="):
                        existing = arg.split("=", 1)[1].split(",")
                        args[index] = "--script=" + ",".join(dict.fromkeys(existing + service_scripts))
                        break
            # Replace broad top-port discovery with the ports already confirmed open.
            if "--top-ports" in args:
                index = args.index("--top-ports")
                del args[index:index + 2]
            tcp_ports = sorted({int(p["port"]) for p in known_ports if p.get("protocol", "tcp") == "tcp"})
            udp_ports = sorted({int(p["port"]) for p in known_ports if p.get("protocol") == "udp"})
            specs = []
            if tcp_ports: specs.append("T:" + ",".join(map(str, tcp_ports)))
            if udp_ports:
                specs.append("U:" + ",".join(map(str, udp_ports)))
                if "-sU" not in args: args.append("-sU")
            if specs: args += ["-p", ",".join(specs)]
        if "--stats-every" not in args:
            args += ["--stats-every", "2s"]
        return [self.nmap_bin, "-oX", "-"] + args + [target]

    def _service_scripts(self, port: Dict[str, any]) -> List[str]:
        service = str(port.get("service", "")).lower()
        version = str(port.get("version", "")).lower()
        matches = set()
        for marker, scripts in SERVICE_NSE_SCRIPTS.items():
            if marker in service or marker in version:
                matches.update(scripts)
        if port.get("http_detected"):
            matches.update(SERVICE_NSE_SCRIPTS["http"])
        return sorted(script for script in matches
                      if not self.available_nse_scripts or script in self.available_nse_scripts)

    async def _run_nikto(self, target: str, progress_callback=None,
                         known_ports: Optional[List[Dict[str, any]]] = None) -> List[Dict[str, any]]:
        if not self.is_nikto_available():
            return [_finding("Nikto", "Nikto не установлен", "info",
                             "Nikto не найден в PATH. Установите: apt install nikto")]

        web_ports = self._select_nikto_ports(known_ports)
        targets = web_ports or [None]
        nikto_semaphore = asyncio.Semaphore(3)
        completed = 0

        if progress_callback:
            labels = [str(port["port"]) for port in targets if port]
            scope = f"веб-порты {', '.join(labels)}" if labels else "автоопределение веб-порта"
            progress_callback(1, f"запуск · {scope}")

        async def _scan_port(port_info):
            nonlocal completed
            async with nikto_semaphore:
                if progress_callback:
                    label = f"порт {port_info['port']}" if port_info else "веб-порт"
                    progress_callback(completed / len(targets[:16]) * 100,
                                      f"проверяется {label}, готово {completed}/{len(targets[:16])}")
                cmd = [self.nikto_bin, "-h", target] + self.nikto_args.split()
                if port_info:
                    cmd += ["-p", str(port_info["port"])]
                    service = str(port_info.get("service", "")).lower()
                    if (int(port_info["port"]) in {443, 8443} or "https" in service or
                            "ssl" in service or port_info.get("tunnel") == "ssl"):
                        cmd.append("-ssl")
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.nikto_timeout)
                except asyncio.TimeoutError:
                    await _kill_proc(proc)
                    completed += 1
                    if progress_callback:
                        progress_callback(completed / len(targets[:16]) * 100,
                                          f"готово {completed}/{len(targets[:16])} целей")
                    label = f" на порту {port_info['port']}" if port_info else ""
                    return [_finding("Nikto", "Nikto Timeout", "warning",
                                     f"Nikto превысил лимит {self.nikto_timeout}s{label}.")]
                completed += 1
                if progress_callback:
                    progress_callback(completed / len(targets[:16]) * 100,
                                      f"готово {completed}/{len(targets[:16])} целей")
                return self._parse_nikto_text(
                    stdout.decode("utf-8", errors="ignore"),
                    port_info=port_info,
                    target=target,
                )

        gathered = await asyncio.gather(*[_scan_port(port) for port in targets[:16]])
        findings = [finding for group in gathered for finding in group]

        if progress_callback:
            progress_callback(100, "завершён")

        if not findings:
            findings.append(_finding(
                "Nikto", "Nikto Scan Completed", "info",
                "Nikto завершён без существенных находок."
            ))

        return findings

    @staticmethod
    def _select_nikto_ports(known_ports: Optional[List[Dict[str, any]]]) -> List[Dict[str, any]]:
        web_names = ("http", "https", "ssl", "web", "http-proxy")
        return [
            port for port in (known_ports or [])
            if port.get("protocol", "tcp") == "tcp" and (
                int(port.get("port", 0)) in {80, 443, 8000, 8080, 8443, 8888}
                or port.get("http_detected")
                or port.get("tunnel") == "ssl"
                or any(name in str(port.get("service", "")).lower() for name in web_names)
            )
        ]

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------

    def _parse_nmap_xml(self, xml_content: str) -> List[Dict[str, any]]:
        findings = []
        if not xml_content.strip():
            return findings
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            logger.warning(f"[VulnScanner] Nmap XML parse error: {e}")
            return findings

        for host in root.findall("host"):
            # Host-level scripts (e.g. broadcast-* or smb-vuln-*)
            host_script_elem = host.find("hostscript")
            if host_script_elem is not None:
                for script in host_script_elem.findall("script"):
                    findings.extend(self._extract_script_finding(
                        script, port_label="host-level"
                    ))

            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                port_id  = port_elem.get("portid", "?")
                protocol = port_elem.get("protocol", "tcp")

                svc = port_elem.find("service")
                svc_name = svc.get("name", "unknown") if svc is not None else "unknown"
                port_label = f"{port_id}/{protocol} ({svc_name})"

                for script in port_elem.findall("script"):
                    findings.extend(self._extract_script_finding(script, port_label))

        return findings

    def _extract_script_finding(
        self, script: ET.Element, port_label: str
    ) -> List[Dict[str, any]]:
        """Parse a single <script> element into zero or more finding dicts."""
        results = []
        script_id  = script.get("id", "script")
        raw_output = script.get("output", "").strip()

        if not raw_output:
            return results

        # Dedicated parser for vulners.nse XML structured tables
        if script_id == "vulners":
            for cpe_table in script.findall("table"):
                cpe_name = cpe_table.get("key", "CPE")
                for item_table in cpe_table.findall("table"):
                    cve_id = item_table.get("key", "")
                    cvss_str = ""
                    is_exploit = False
                    for elem in item_table.findall("elem"):
                        k = elem.get("key")
                        if k == "cvss":
                            cvss_str = elem.text or ""
                        elif k == "is_exploit":
                            is_exploit = (elem.text or "").lower() == "true"

                    try:
                        cvss_score = float(cvss_str) if cvss_str else 0.0
                    except ValueError:
                        cvss_score = 0.0

                    if cvss_score >= 9.0:
                        severity = "critical"
                    elif cvss_score >= 7.0:
                        severity = "high"
                    elif cvss_score >= 4.0:
                        severity = "medium"
                    else:
                        severity = "low"

                    exploit_badge = " 🔥 EXPLOIT AVAILABLE" if is_exploit else ""
                    results.append({
                        "tool":     "Nmap Vulners",
                        "port":     port_label,
                        "title":    f"CVE: {cve_id} (CVSS {cvss_score}){exploit_badge}",
                        "severity": severity,
                        "details":  f"CPE: {cpe_name}\nCVSS Score: {cvss_score}\nCVE: https://vulners.com/cve/{cve_id}",
                        "cves":     [cve_id] if cve_id.startswith("CVE-") else [],
                    })
            if results:
                return results

        # Severity heuristics for standard NSE scripts
        output_up = raw_output.upper()
        if "VULNERABLE" in output_up or "CVE-" in output_up:
            severity = "high"
        elif "WARNING" in output_up or "WEAK" in output_up:
            severity = "medium"
        elif script_id in ("ssl-cert", "http-title", "http-headers"):
            severity = "info"
        else:
            severity = "low"

        # Extract CVE IDs if present
        cves = re.findall(r"CVE-\d{4}-\d+", raw_output, re.IGNORECASE)

        results.append({
            "tool":     "Nmap NSE",
            "port":     port_label,
            "title":    f"NSE: {script_id}" + (f" [{', '.join(cves)}]" if cves else ""),
            "severity": severity,
            "details":  raw_output[:800],
            "cves":     cves,
        })
        return results

    def _parse_nikto_text(self, output: str, port_info: Optional[Dict[str, any]] = None,
                          target: str = "") -> List[Dict[str, any]]:
        """
        Parse Nikto plaintext output into structured findings.
        Uses word boundaries for severity matching to prevent false positives (e.g. 'rce' matching 'force').
        Filters out non-finding status lines.
        """
        findings = []
        skip_phrases = (
            "target ip:", "target hostname:", "target port:", "start time:",
            "end time:", "requests:", "error(s):", "item(s) reported",
            "host(s) tested", "no cgi directories found", "see osvdb"
        )

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not (line.startswith("+ ") and len(line) > 4):
                continue
            text = line[2:]
            low = text.lower()

            if any(skip in low for skip in skip_phrases):
                continue

            # Determine severity using word boundaries to avoid false positives like 'rce' in 'force'
            severity = "info"
            # Reporting a defensive header is informational, not an XSS finding.
            if "uncommon header" in low:
                severity = "info"
            elif any(re.search(rf"\b{re.escape(kw)}\b", low) for kw in _HIGH_KEYWORDS):
                severity = "high"
            elif any(re.search(rf"\b{re.escape(kw)}\b", low) for kw in _MEDIUM_KEYWORDS):
                severity = "medium"

            title = _extract_nikto_title(text)
            cves = re.findall(r"CVE-\d{4}-\d+", text, re.IGNORECASE)

            protocol = str((port_info or {}).get("protocol", "tcp"))
            port = (port_info or {}).get("port")
            service = str((port_info or {}).get("service", ""))
            endpoint = f"{target}:{port}" if target and port else target
            findings.append({
                "tool":     "Nikto",
                "target":   target,
                "endpoint": endpoint,
                "port":     f"{port}/{protocol}" if port else "автоопределение",
                "port_number": port,
                "protocol": protocol,
                "service":  service,
                "title":    title,
                "severity": severity,
                "details":  text,
                "cves":     cves,
            })

        return findings


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _finding(tool: str, title: str, severity: str, details: str) -> Dict[str, any]:
    return {"tool": tool, "title": title, "severity": severity, "details": details, "cves": []}


def _count_severities(findings: List[Dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "error": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev == "warning":
            sev = "medium"
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _extract_nikto_title(text: str) -> str:
    """Return a short title: path fragment or first 80 chars."""
    low = text.lower()
    if low.startswith("ssl info:"):
        return "Сведения TLS-сертификата"
    if low.startswith("server:"):
        return "Баннер веб-сервера"
    if "root page" in low and "redirect" in low:
        return "Перенаправление главной страницы"
    if "hostname" in low and "certificate" in low:
        return "Несоответствие имени TLS-сертификата"
    # Check for path-like fragments e.g. /admin/login.php
    path_match = re.search(r"(?:^|\s)(/[\w/.\-?=&%]{3,60})", text)
    if path_match:
        path = path_match.group(1)[:50]
        return f"Web Path: {path}"
    # OSVDB / CVE reference
    ref_match = re.search(r"(OSVDB-\d+|CVE-\d{4}-\d+)", text, re.IGNORECASE)
    if ref_match:
        return f"Finding: {ref_match.group(1)}"
    # Fall back to first 80 chars
    return text[:80].rstrip(". ")


async def _kill_proc(proc: asyncio.subprocess.Process) -> None:
    """Gracefully terminate then SIGKILL a subprocess."""
    try:
        proc.terminate()
        await asyncio.sleep(1)
        if proc.returncode is None:
            proc.kill()
        await proc.wait()
    except Exception:
        pass


def _is_version_in_range(ver: str, min_ver: str, max_ver: str) -> bool:
    """Helper to check if semantic version string lies within [min_ver, max_ver]."""
    def _parse_v(v_str: str):
        parts = []
        for p in v_str.split("."):
            try:
                parts.append(int(p))
            except ValueError:
                parts.append(0)
        while len(parts) < 3:
            parts.append(0)
        return parts[:3]

    v = _parse_v(ver)
    v_min = _parse_v(min_ver)
    v_max = _parse_v(max_ver)
    return v_min <= v <= v_max
