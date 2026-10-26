import asyncio
import ipaddress
import logging
import os
import re
import shutil
import tempfile
from pathlib import Path
import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

import aiohttp

logger = logging.getLogger(__name__)

# CVE/OSVDB severity keywords for Nikto output
_HIGH_KEYWORDS = frozenset([
    "osvdb", "cve", "vulnerability", "sql injection",
    "xss", "rce", "rfi", "lfi", "authentication bypass",
    "arbitrary", "remote code", "buffer overflow",
])
_MEDIUM_KEYWORDS = frozenset([
    "directory listing", "outdated", "deprecated",
    "insecure", "sensitive", "information disclosure",
    "admin", "login", "phpmyadmin",
])
_ALLOWED_NIKTO_TUNING = frozenset("123456789abc")

# In-process dedup cache: {target: (ts, result)}
_VULN_CACHE: Dict[str, Tuple[float, Dict]] = {}
_CACHE_TTL = 600  # 10 min

# In-process cache for OSV.dev CVE queries: {cache_key: (ts, findings)}
_OSV_CACHE: Dict[str, Tuple[float, List[Dict]]] = {}
_OSV_CACHE_TTL = 3600  # 1 hour

# Technology stack to specific Nmap NSE scripts mapping
TECH_NSE_SCRIPTS: Dict[str, List[str]] = {
    "wordpress":      ["http-wordpress-enum", "http-wordpress-users"],
    "joomla":         ["http-joomla-enum"],
    "drupal":         ["http-drupal-enum"],
    "php":            ["http-php-version", "http-vuln-cve2012-1823"],
    "asp.net":        ["http-iis-short-name-brute", "http-vuln-cve2015-1635"],
    "iis":            ["http-iis-short-name-brute", "http-vuln-cve2015-1635", "http-iis-webdav-vuln"],
    "microsoft-iis":  ["http-iis-short-name-brute", "http-vuln-cve2015-1635"],
    "apache":         ["http-apache-negotiation", "http-apache-server-status", "http-vuln-cve2017-5638", "http-vuln-cve2021-41773"],
    "nginx":          ["http-enum", "http-methods", "http-security-headers"],
    "openssh":        ["ssh-auth-methods", "ssh2-enum-algos", "ssh-hostkey"],
    "ssh":            ["ssh-auth-methods", "ssh2-enum-algos", "ssh-hostkey"],
    "samba":          ["smb-os-discovery", "smb-protocols", "smb-security-mode",
                       "smb2-security-mode", "smb-vuln-ms17-010", "smb-vuln-cve-2017-7494"],
    "smb":            ["smb-os-discovery", "smb-protocols", "smb-security-mode",
                       "smb2-security-mode", "smb-vuln-ms17-010", "smb-vuln-cve-2017-7494"],
    "vsftpd":         ["ftp-anon", "ftp-syst", "ftp-vsftpd-backdoor"],
    "proftpd":        ["ftp-anon", "ftp-syst", "ftp-proftpd-backdoor"],
    "bitrix":         ["http-enum", "http-headers", "http-methods"],
    "laravel":        ["http-enum"],
    "django":         ["http-enum"],
    "tomcat":         ["http-tomcat-enum", "ajp-methods", "ajp-headers"],
    "mysql":          ["mysql-info", "mysql-enum", "mysql-empty-password", "mysql-vuln-cve2012-2122"],
    "postgresql":     ["pgsql-databases"],
    "postgres":       ["pgsql-databases"],
    "redis":          ["redis-info"],
    "mongodb":        ["mongodb-info", "mongodb-databases"],
    "rdp":            ["rdp-enum-encryption", "rdp-vuln-ms12-020"],
    "ms-wbt-server":  ["rdp-enum-encryption", "rdp-vuln-ms12-020"],
    "goahead":        ["http-auth", "http-auth-finder", "http-default-accounts",
                        "http-enum", "http-methods", "http-robots.txt",
                        "http-security-headers", "http-server-header"],
    "telnetd":        ["banner", "telnet-encryption", "telnet-ntlm-info"],
    "telnet":         ["banner", "telnet-encryption", "telnet-ntlm-info"],
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
    "rtsp":           ["banner", "rtsp-methods", "rtsp-url-brute"],
    "hikvision":      ["http-auth", "http-auth-finder", "http-default-accounts", "rtsp-methods"],
    "dahua":          ["http-auth", "http-auth-finder", "http-default-accounts", "rtsp-methods"],
}

# Broad base NSE set: comprehensive vuln audit + full TLS posture + SMB/SSH/HTTP service checks.
BASE_NSE_SCRIPTS: List[str] = [
    "vuln", "vulners",
    "http-title", "http-headers", "http-enum", "http-methods", "http-security-headers", "http-robots.txt",
    "ssl-cert", "ssl-enum-ciphers", "ssl-poodle", "ssl-heartbleed",
    "ssl-dh-params", "ssl-known-key", "sslv2", "sslv2-drown", "ssl-ccs-injection",
    "tls-alpn", "tls-ticketbleed", "ssl-date",
    "smb-protocols", "smb-security-mode", "smb-vuln-ms17-010", "smb-os-discovery",
    "ssh-auth-methods",
]
BASE_NSE_SCRIPTS_STR = ",".join(BASE_NSE_SCRIPTS)

# Brute-force NSE scripts keyed by service marker (used when brute_force=True).
BRUTE_SERVICE_SCRIPTS: Dict[str, List[str]] = {
    "smb":         ["smb-brute"],
    "netbios":     ["smb-brute"],
    "netbios-ssn": ["smb-brute"],
    "ssh":         ["ssh-brute"],
    "telnet":      ["telnet-brute"],
    "ftp":         ["ftp-brute"],
    "postgresql":  ["pgsql-brute"],
    "postgres":    ["pgsql-brute"],
    "mysql":       ["mysql-brute"],
    "redis":       ["redis-brute"],
    "mongodb":     ["mongodb-brute"],
    "oracle":      ["oracle-brute"],
    "http":        ["http-brute"],
    "http-proxy":  ["http-proxy-brute"],
}

# Built-in weak-credential wordlists (safe minimal audit without requiring external files).
_DEFAULT_USERS: List[str] = [
    "admin", "administrator", "root", "test", "guest", "user", "support", "operator", "nobody", "oracle",
]
_DEFAULT_PASSES: List[str] = [
    "admin", "password", "root", "test", "123456", "1234", "letmein", "guest", "admin123", "toor",
]

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
# Covers popular web servers, runtime environments, databases, and network daemons
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
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
    },
    {
        "product": "nginx",
        "min_ver": "1.0.0", "max_ver": "1.23.1",
        "cve": "CVE-2022-41741",
        "title": "Nginx MP4 Module Memory Corruption",
        "severity": "high",
        "cvss": 7.8,
        "details": "Memory corruption vulnerability in ngx_http_mp4_module allowing remote worker process crash or code execution.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-41741",
    },
    {
        "product": "nginx",
        "min_ver": "1.0.0", "max_ver": "1.23.1",
        "cve": "CVE-2022-41742",
        "title": "Nginx MP4 Module Information Disclosure",
        "severity": "medium",
        "cvss": 7.1,
        "details": "Memory disclosure vulnerability in ngx_http_mp4_module allowing worker process memory leakage.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-41742",
    },
    {
        "product": "nginx",
        "min_ver": "1.25.0", "max_ver": "1.25.2",
        "cve": "CVE-2023-44487",
        "title": "HTTP/2 Rapid Reset Denial of Service",
        "severity": "high",
        "cvss": 7.5,
        "details": "HTTP/2 protocol flaw allowing rapid stream resets causing resource exhaustion and DoS.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
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
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2015-1635",
    },
    {
        "product": "iis",
        "min_ver": "6.0", "max_ver": "10.0",
        "cve": "CVE-2021-31166",
        "title": "HTTP Protocol Stack Remote Code Execution",
        "severity": "critical",
        "cvss": 9.8,
        "details": "Wormable remote code execution vulnerability in HTTP Protocol Stack (HTTP.sys) parsing malicious packets.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-31166",
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
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2019-11043",
    },
    {
        "product": "php",
        "min_ver": "7.4.0", "max_ver": "7.4.25",
        "cve": "CVE-2021-21703",
        "title": "PHP-FPM Local Privilege Escalation & Memory Corruption",
        "severity": "high",
        "cvss": 7.5,
        "details": "Numeric overflow in PHP-FPM master process memory management leading to crash or privilege escalation.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-21703",
    },
    {
        "product": "php",
        "min_ver": "8.1.0", "max_ver": "8.1.28",
        "cve": "CVE-2024-4577",
        "title": "PHP CGI Argument Injection Remote Code Execution",
        "severity": "critical",
        "cvss": 9.8,
        "details": "Best-fit character encoding flaw in Windows PHP CGI wrapper allowing unauthenticated remote code execution.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-4577",
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
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
    },
    {
        "product": "apache",
        "min_ver": "2.4.51", "max_ver": "2.4.51",
        "cve": "CVE-2021-42013",
        "title": "Apache HTTP Server Incomplete Fix for Path Traversal",
        "severity": "critical",
        "cvss": 9.8,
        "details": "Incomplete fix for CVE-2021-41773 allowing remote path traversal and code execution.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
    },
    {
        "product": "apache",
        "min_ver": "2.4.0", "max_ver": "2.4.53",
        "cve": "CVE-2022-22720",
        "title": "Apache HTTP Server HTTP Request Smuggling",
        "severity": "high",
        "cvss": 7.5,
        "details": "Request smuggling flaw via body length limit bypass leading to cache poisoning or request hijacking.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-22720",
    },

    # OpenSSL
    {
        "product": "openssl",
        "min_ver": "1.0.1", "max_ver": "1.0.1f",
        "cve": "CVE-2014-0160",
        "title": "OpenSSL Heartbleed TLS Heartbeat Information Disclosure",
        "severity": "critical",
        "cvss": 7.5,
        "details": "Buffer over-read in TLS heartbeat handling leaking up to 64KB of server memory including private keys.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
    },
    {
        "product": "openssl",
        "min_ver": "3.0.0", "max_ver": "3.0.6",
        "cve": "CVE-2022-3602",
        "title": "OpenSSL X.509 Email Address 4-byte Buffer Overflow",
        "severity": "high",
        "cvss": 7.5,
        "details": "Buffer overflow in punycode decoding during X.509 certificate verification.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-3602",
    },

    # OpenSSH
    {
        "product": "openssh",
        "min_ver": "8.5p1", "max_ver": "9.7p1",
        "cve": "CVE-2024-6387",
        "title": "OpenSSH RegreSSHion Unauthenticated Remote Code Execution",
        "severity": "critical",
        "cvss": 8.1,
        "details": "Signal handler race condition in sshd on glibc-based Linux systems allows unauthenticated remote root RCE.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
    },

    # Samba
    {
        "product": "samba",
        "min_ver": "3.5.0", "max_ver": "4.6.4",
        "cve": "CVE-2017-7494",
        "title": "Samba EternalRed Remote Code Execution",
        "severity": "critical",
        "cvss": 9.8,
        "details": "Remote code execution from writable share via shared library loading vulnerability in smbd.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2017-7494",
    },

    # vsftpd
    {
        "product": "vsftpd",
        "min_ver": "2.3.4", "max_ver": "2.3.4",
        "cve": "CVE-2011-2523",
        "title": "vsftpd 2.3.4 Backdoor Execution",
        "severity": "critical",
        "cvss": 9.8,
        "details": "Malicious backdoor embedded into source download of vsftpd 2.3.4 opening root shell on port 6200.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
    },

    # ProFTPD
    {
        "product": "proftpd",
        "min_ver": "1.3.5", "max_ver": "1.3.5",
        "cve": "CVE-2015-3306",
        "title": "ProFTPD mod_copy Arbitrary File Copy & RCE",
        "severity": "critical",
        "cvss": 9.8,
        "details": "Unauthenticated file copy command CPFR/CPTO in mod_copy allowing arbitrary PHP backdoor deployment.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2015-3306",
    },

    # Redis
    {
        "product": "redis",
        "min_ver": "5.0.0", "max_ver": "6.2.6",
        "cve": "CVE-2022-0543",
        "title": "Redis Lua Sandbox Escape Remote Code Execution",
        "severity": "critical",
        "cvss": 10.0,
        "details": "Packaging issue in Debian/Ubuntu Redis packages allowing Lua sandbox escape and host command execution.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-0543",
    },

    # Tomcat
    {
        "product": "tomcat",
        "min_ver": "9.0.0", "max_ver": "9.0.30",
        "cve": "CVE-2020-1938",
        "title": "Apache Tomcat AJP Connector Ghostcat File Read / Inclusion",
        "severity": "critical",
        "cvss": 9.8,
        "details": "Vulnerability in Tomcat AJP connector (port 8009) allowing unauthorized arbitrary file read and JSP execution.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2020-1938",
    },
]


def _normalize_product_name(product: str) -> str:
    """Normalize server banner tokens and product aliases to standard OSV / CVE package names."""
    p = product.lower().strip()
    if "nginx" in p:
        return "nginx"
    if "apache" in p or p == "httpd":
        return "apache"
    if "php" in p:
        return "php"
    if "wordpress" in p:
        return "wordpress"
    if "mysql" in p:
        return "mysql"
    if "postgres" in p or "pgsql" in p:
        return "postgresql"
    if "redis" in p:
        return "redis"
    if "proftpd" in p:
        return "proftpd"
    if "vsftpd" in p:
        return "vsftpd"
    if "openssh" in p or p == "ssh":
        return "openssh"
    return p


class VulnScanner:
    """
    Asynchronous vulnerability scanner: Nmap NSE + Nikto + OSV.dev CVE + Version CVE DB.
    Supports dynamic technology stack adaptation, brute-force auditing, and passive intel correlation.
    """

    def __init__(
        self,
        nmap_args:     Optional[str] = None,
        nikto_args:    Optional[str] = None,
        nmap_timeout:  int = 210,
        nikto_timeout: int = 120,
        brute_force:   bool = False,
        passive_intel: bool = False,
        osv_base_url:  str = "https://api.osv.dev",
    ):
        self.nmap_bin    = shutil.which("nmap")
        self.nikto_bin   = shutil.which("nikto")
        self.nmap_timeout  = nmap_timeout
        self.nikto_timeout = nikto_timeout
        self.adapted_stack: List[str] = []
        self.brute_force = brute_force
        self.passive_intel = passive_intel
        self.osv_base_url = osv_base_url.rstrip("/")
        self.brute_users = _DEFAULT_USERS
        self.brute_passes = _DEFAULT_PASSES

        scripts_dir = Path("/usr/share/nmap/scripts")
        self.available_nse_scripts = {
            path.stem for path in scripts_dir.glob("*.nse")
        } if scripts_dir.is_dir() else set()

        # Build initial nmap args
        self.nmap_args = (
            nmap_args
            or f"-sV -T4 --host-timeout 180s --max-retries 1 --script={BASE_NSE_SCRIPTS_STR} --top-ports 100"
        )
        if self.brute_force:
            brute_scripts = sorted({s for scripts in BRUTE_SERVICE_SCRIPTS.values() for s in scripts})
            existing_scripts = self._get_script_arg_list(self.nmap_args)
            combined = existing_scripts + [s for s in brute_scripts if s not in existing_scripts]
            self.nmap_args = re.sub(r"--script=\S+", f"--script={','.join(combined)}", self.nmap_args)

        # Nikto tuning: 1=interesting, 2=misc, 3=auth, 4=default, 8=inject, 9=SQL
        self.nikto_args = nikto_args or "-Tuning 12489 -timeout 10 -maxtime 90"

        # Weak-credential files generated in a temp dir if brute_force=True
        self._brute_tmp: Optional[str] = None
        self._brute_user_db: Optional[str] = None
        self._brute_pass_db: Optional[str] = None
        if self.brute_force:
            try:
                self._brute_tmp = tempfile.mkdtemp(prefix="ip2domain-brute-")
                self._brute_user_db = os.path.join(self._brute_tmp, "users.txt")
                self._brute_pass_db = os.path.join(self._brute_tmp, "passwords.txt")
                Path(self._brute_user_db).write_text("\n".join(self.brute_users) + "\n", encoding="utf-8")
                Path(self._brute_pass_db).write_text("\n".join(self.brute_passes) + "\n", encoding="utf-8")
            except Exception as exc:
                logger.warning("[VulnScanner] Failed to setup brute wordlists: %s", exc)

    def __del__(self):
        if self._brute_tmp and os.path.exists(self._brute_tmp):
            try:
                shutil.rmtree(self._brute_tmp, ignore_errors=True)
            except Exception:
                pass

    @staticmethod
    def _get_script_arg_list(nmap_args_str: str) -> List[str]:
        m = re.search(r"--script=(\S+)", nmap_args_str)
        if m:
            return m.group(1).split(",")
        return []

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

        all_scripts = list(BASE_NSE_SCRIPTS)
        for s in sorted(custom_scripts):
            if s not in all_scripts:
                all_scripts.append(s)

        if self.brute_force:
            brute_scripts = sorted({s for scripts in BRUTE_SERVICE_SCRIPTS.values() for s in scripts})
            for s in brute_scripts:
                if s not in all_scripts:
                    all_scripts.append(s)

        scripts_str = ",".join(all_scripts)
        self.nmap_args = (
            f"-sV -T4 --host-timeout 180s --max-retries 1 --script={scripts_str} --top-ports 100"
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
        version_cves, osv_cves, passive_intel, severity_counts, adapted_stack, and scan_duration_sec.
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

        # Version-based CVE Database matching (offline curated high-impact database)
        merged_stack = list(set((self.adapted_stack or []) + (tech_stack or []) + detected_stack))
        version_cves = self.check_version_cves(target, merged_stack)

        # Dynamic CVE lookup via OSV.dev (free public JSON API, zero key required)
        osv_cves = await self.fetch_osv_for_stack(merged_stack)

        # Passive threat-intel (Shodan / Censys) when enabled
        passive_domains: Dict[str, List[str]] = {}
        if self.passive_intel:
            passive_domains = await self.fetch_passive_intel(target)

        # Device inventory correlation
        device_context = self._correlate_device_inventory(target)

        duration = round(time.monotonic() - t0, 1)

        if progress_callback:
            progress_callback(100, "Сканирование уязвимостей завершено")

        all_findings = nmap_res + nikto_res + version_cves + osv_cves
        severity_counts = _count_severities(all_findings)
        actionable_findings = sum(severity_counts.get(level, 0) for level in ("critical", "high", "medium", "low"))

        result = {
            "target":              target,
            "adapted_stack":       self.adapted_stack,
            "detected_stack":      detected_stack,
            "nmap_findings":       nmap_res,
            "nikto_findings":      nikto_res,
            "version_cves":        version_cves,
            "osv_cves":            osv_cves,
            "passive_intel":       passive_domains,
            "device_context":      device_context,
            "total_findings":      len(nmap_res) + len(nikto_res) + len(version_cves) + len(osv_cves),
            "actionable_findings": actionable_findings,
            "severity_counts":     severity_counts,
            "scan_duration_sec":   duration,
            "scanned_ports":       known_ports or [],
            "service_coverage":    self._build_service_coverage(known_ports),
            "options":             {"brute_force": self.brute_force, "passive_intel": self.passive_intel},
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
            evidence = "\n".join(str(item.get("details", "")) for item in endpoint_findings)
            evidence_low = evidence.lower()

            if (re.search(r"\bcookie\s+cockpit\b", evidence_low) or
                    re.search(r"set-cookie[^\n]*\bcockpit=", evidence_low) or
                    any(marker in evidence_low for marker in ("cockpit-ws", "/cockpit/", "cockpit.socket"))):
                detected.add("Cockpit")
                for item in endpoint_findings:
                    item["technology"] = "Cockpit"
                    item["service"] = "Cockpit Web Console"

            # Extract Server header: e.g. "Server: nginx-reuseport/1.21.1" or "Server: Apache/2.4.49"
            server_m = re.search(r"server:\s*([a-zA-Z0-9_\-\.]+)(?:/([0-9\.]+))?", evidence, re.IGNORECASE)
            if server_m:
                prod = server_m.group(1).strip()
                ver = server_m.group(2)
                if ver:
                    detected.add(f"{prod} {ver}")
                    if "nginx" in prod.lower():
                        detected.add(f"nginx {ver}")
                    elif "apache" in prod.lower():
                        detected.add(f"apache {ver}")
                else:
                    detected.add(prod)

            # Extract X-Powered-By: e.g. "x-powered-by header: PHP/8.2.35"
            pby_m = re.search(r"x-powered-by[^\n:]*:\s*([a-zA-Z0-9_\-\.]+)(?:/([0-9\.]+))?", evidence, re.IGNORECASE)
            if pby_m:
                prod = pby_m.group(1).strip()
                ver = pby_m.group(2)
                if ver:
                    detected.add(f"{prod} {ver}")
                else:
                    detected.add(prod)

            if "wordpress" in evidence_low:
                detected.add("WordPress")

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

    async def fetch_osv_cves(self, product: str, version: str) -> List[Dict[str, any]]:
        """
        Query OSV.dev for vulnerabilities in a specific product version.
        OSV is a free JSON API, zero API key required.
        """
        if not product or not version:
            return []

        cache_key = f"{product.lower().strip()}:{version.strip()}"
        if cache_key in _OSV_CACHE:
            ts, cached = _OSV_CACHE[cache_key]
            if time.monotonic() - ts < _OSV_CACHE_TTL:
                return cached

        payload = {"package": {"name": product.lower()}, "version": version}
        findings: List[Dict[str, any]] = []
        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.osv_base_url}/v1/query",
                    json=payload,
                    timeout=timeout,
                ) as resp:
                    if resp.status != 200:
                        logger.warning("[OSV] query for %s %s -> HTTP %s", product, version, resp.status)
                        return []
                    data = await resp.json(content_type=None)
        except Exception as exc:
            logger.warning("[OSV] query for %s %s failed: %s", product, version, exc)
            return []

        seen_cves = set()
        for vuln in (data.get("vulns", []) if isinstance(data, dict) else []):
            vuln_id = str(vuln.get("id", "OSV"))
            aliases = vuln.get("aliases", []) or []
            cve_id = next((a for a in aliases if a.upper().startswith("CVE-")), None)
            if not cve_id:
                if "CVE-" in vuln_id.upper():
                    cve_match = re.search(r"CVE-\d+-\d+", vuln_id.upper())
                    cve_id = cve_match.group(0) if cve_match else vuln_id
                else:
                    cve_id = vuln_id

            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)

            severity = _osv_severity(vuln)
            summary = vuln.get("summary") or vuln.get("details", "")[:120]
            link = f"https://osv.dev/vulnerability/{vuln_id}"

            findings.append({
                "tool":     "OSV",
                "title":    f"[{cve_id}] {product} {version}: {summary[:80]}",
                "severity": severity,
                "details":  f"ID: {vuln_id}\n{summary}\nСсылка: {link}",
                "cves":     [cve_id] + [a for a in aliases if a != cve_id],
                "link":     link,
            })

        _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda x: _sev_order.get(x.get("severity", "medium"), 2))
        findings = findings[:30]

        _OSV_CACHE[cache_key] = (time.monotonic(), findings)
        return findings

    async def fetch_osv_for_stack(self, tech_stack: Optional[List[str]]) -> List[Dict[str, any]]:
        """Run OSV queries for every product+version found in the tech stack."""
        if not tech_stack:
            return []

        tasks = []
        seen_queries = set()
        for item in tech_stack:
            item_low = item.lower()
            ver_match = re.search(r"(\d+(?:\.\d+)+)", item_low)
            if not ver_match:
                continue
            version_str = ver_match.group(1)
            # Extract product identifier
            product_raw = item_low.split()[0] if " " in item_low else item_low.split("-")[0]
            product_raw = product_raw.split("/")[0]  # handles "nginx/1.18.0"
            product = _normalize_product_name(product_raw)
            q_key = (product, version_str)
            if q_key in seen_queries:
                continue
            seen_queries.add(q_key)
            tasks.append(self.fetch_osv_cves(product, version_str))

        if not tasks:
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings: List[Dict[str, any]] = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
        return findings

    async def fetch_passive_intel(self, target: str) -> Dict[str, List[str]]:
        """
        Query passive threat-intel providers (Shodan, Censys) for domains and host tags.
        """
        try:
            from ip2domain.providers.manager import ProviderManager
            provider_manager = ProviderManager(
                selected_providers=["shodan", "censys"],
                api_keys={},
            )
            if not provider_manager.providers:
                return {}
            timeout = aiohttp.ClientTimeout(total=20)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                return await provider_manager.lookup_ip(target, session)
        except Exception as exc:
            logger.warning("[PassiveIntel] lookup failed for %s: %s", target, exc)
            return {}

    def _correlate_device_inventory(self, target: str) -> Dict[str, any]:
        """Correlate target IP with local storage/inventory if available."""
        try:
            from ip2domain.web.routers.common import storage
            if hasattr(storage, "get_global_scan_results"):
                for item in storage.get_global_scan_results():
                    if item.get("ip") == target:
                        return {
                            "hostname": item.get("hostname", ""),
                            "device_type": item.get("device_type", ""),
                            "vendor": item.get("vendor", ""),
                            "model": item.get("model", ""),
                        }
        except Exception:
            pass
        return {}

    def check_version_cves(self, target: str, tech_stack: List[str]) -> List[Dict[str, any]]:
        """
        Performs direct version-based CVE matching from VERSION_CVE_DATABASE.
        Extracts product version from HTTP headers/stack (e.g. nginx/1.18.0, IIS/8.5, PHP/7.4.3).
        """
        cve_findings = []
        if not tech_stack:
            return cve_findings

        # Sort so versioned items come first
        sorted_stack = sorted(
            tech_stack,
            key=lambda x: (bool(re.search(r"\d+\.\d+", str(x))), len(str(x))),
            reverse=True,
        )

        seen_cves = set()
        matched_products_with_ver = set()

        # Pass 1: Confirmed version matches with real CVE severity
        for item in sorted_stack:
            item_low = str(item).lower()
            ver_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", item_low)
            if not ver_match:
                continue
            version_str = ver_match.group(1)

            for entry in VERSION_CVE_DATABASE:
                prod = entry["product"]
                if prod in item_low or (prod == "nginx" and "nginx" in item_low):
                    if _is_version_in_range(version_str, entry["min_ver"], entry["max_ver"]):
                        if entry["cve"] not in seen_cves:
                            seen_cves.add(entry["cve"])
                            matched_products_with_ver.add(prod)
                            cve_findings.append({
                                "tool": "CVE DB",
                                "title": f"[{entry['cve']}] {entry['title']}",
                                "severity": entry["severity"],
                                "cvss": entry["cvss"],
                                "details": f"Обнаружена уязвимая версия: {item}\nCVSS {entry['cvss']}\n{entry['details']}\nСсылка: {entry['link']}",
                                "cves": [entry["cve"]],
                            })

        # Pass 2: Recommendations for products where no version could be confirmed
        for item in sorted_stack:
            item_low = str(item).lower()
            ver_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", item_low)
            if ver_match:
                continue

            for entry in VERSION_CVE_DATABASE:
                prod = entry["product"]
                if (prod in item_low or (prod == "nginx" and "nginx" in item_low)) and prod not in matched_products_with_ver:
                    if entry["cve"] not in seen_cves:
                        seen_cves.add(entry["cve"])
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
            for key in [k for k in _VULN_CACHE if k.startswith(prefix)]:
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

            # Brute-force: add service-matched brute scripts and pass temporary wordlist paths
            if self.brute_force and self._brute_user_db:
                matched_brute = set()
                for port in known_ports:
                    text = f"{port.get('service', '')} {port.get('version', '')}".lower()
                    for marker, scripts in BRUTE_SERVICE_SCRIPTS.items():
                        if marker in text:
                            matched_brute.update(scripts)
                    if port.get("http_detected"):
                        matched_brute.update(BRUTE_SERVICE_SCRIPTS["http"])
                for script in sorted(matched_brute):
                    for index, arg in enumerate(args):
                        if arg.startswith("--script="):
                            existing = arg.split("=", 1)[1].split(",")
                            if script not in existing:
                                args[index] = "--script=" + ",".join(dict.fromkeys(existing + [script]))
                            break
                args += ["--script-args",
                         f"smb-brute.userdb={self._brute_user_db} smb-brute.passwd={self._brute_pass_db} "
                         f"ssh-brute.userdb={self._brute_user_db} ssh-brute.passwd={self._brute_pass_db} "
                         f"ftp-brute.userdb={self._brute_user_db} ftp-brute.passwd={self._brute_pass_db} "
                         f"http-brute.userdb={self._brute_user_db} http-brute.passwd={self._brute_pass_db} "
                         f"pgsql-brute.userdb={self._brute_user_db} pgsql-brute.passwd={self._brute_pass_db}"]

            # Replace broad top-port discovery with the confirmed ports
            if "--top-ports" in args:
                index = args.index("--top-ports")
                del args[index:index + 2]
            tcp_ports = sorted({int(p["port"]) for p in known_ports if p.get("protocol", "tcp") == "tcp"})
            udp_ports = sorted({int(p["port"]) for p in known_ports if p.get("protocol") == "udp"})
            specs = []
            if tcp_ports:
                specs.append("T:" + ",".join(map(str, tcp_ports)))
            if udp_ports:
                specs.append("U:" + ",".join(map(str, udp_ports)))
                if "-sU" not in args:
                    args.append("-sU")
            if specs:
                args += ["-p", ",".join(specs)]
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
        # Scan up to 64 discovered web ports
        targets = web_ports[:64] if web_ports else [None]
        nikto_semaphore = asyncio.Semaphore(3)
        completed = 0
        total_targets = len(targets)

        if progress_callback:
            labels = [str(port["port"]) for port in targets if port]
            scope = f"веб-порты {', '.join(labels)}" if labels else "автоопределение веб-порта"
            progress_callback(1, f"запуск · {scope}")

        async def _scan_port(port_info):
            nonlocal completed
            async with nikto_semaphore:
                if progress_callback:
                    label = f"порт {port_info['port']}" if port_info else "веб-порт"
                    progress_callback(completed / total_targets * 100,
                                      f"проверяется {label}, готово {completed}/{total_targets}")
                cmd = [self.nikto_bin, "-h", target] + self.nikto_args.split()
                if port_info:
                    cmd += ["-p", str(port_info["port"])]
                    service = str(port_info.get("service", "")).lower()
                    if (int(port_info["port"]) in {443, 8443, 9443, 4433, 10443} or
                            "https" in service or "ssl" in service or port_info.get("tunnel") == "ssl"):
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
                        progress_callback(completed / total_targets * 100,
                                          f"готово {completed}/{total_targets} целей")
                    label = f" на порту {port_info['port']}" if port_info else ""
                    return [_finding("Nikto", "Nikto Timeout", "warning",
                                     f"Nikto превысил лимит {self.nikto_timeout}s{label}.")]
                completed += 1
                if progress_callback:
                    progress_callback(completed / total_targets * 100,
                                      f"готово {completed}/{total_targets} целей")
                return self._parse_nikto_text(
                    stdout.decode("utf-8", errors="ignore"),
                    port_info=port_info,
                    target=target,
                )

        gathered = await asyncio.gather(*[_scan_port(port) for port in targets])
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
        web_names = ("http", "https", "ssl", "web", "http-proxy", "alt-http")
        if not known_ports:
            return [
                {"port": 80, "service": "http", "protocol": "tcp"},
                {"port": 443, "service": "https", "protocol": "tcp", "tunnel": "ssl"},
            ]
        selected = [
            port for port in known_ports
            if port.get("protocol", "tcp") == "tcp" and (
                int(port.get("port", 0)) in {80, 443, 8000, 8080, 8443, 8888, 9090, 9443, 8081, 8088, 3000, 5000, 5005}
                or port.get("http_detected")
                or port.get("tunnel") == "ssl"
                or any(name in str(port.get("service", "")).lower() for name in web_names)
            )
        ]
        if not selected:
            return [
                {"port": 80, "service": "http", "protocol": "tcp"},
                {"port": 443, "service": "https", "protocol": "tcp", "tunnel": "ssl"},
            ]
        ports_set = {int(p.get("port", 0)) for p in selected}
        if 80 in ports_set and 443 not in ports_set:
            selected.append({"port": 443, "service": "https", "protocol": "tcp", "tunnel": "ssl"})
        return selected

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
            # Host-level scripts
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
        elif script_id in ("ssl-cert", "http-title", "http-headers", "ssl-date"):
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
        Uses word boundaries for severity matching to prevent false positives.
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

            # Determine severity using word boundaries to avoid false positives
            severity = "info"
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
                "tool":        "Nikto",
                "target":      target,
                "endpoint":    endpoint,
                "port":        f"{port}/{protocol}" if port else "автоопределение",
                "port_number": port,
                "protocol":    protocol,
                "service":     service,
                "title":       title,
                "severity":    severity,
                "details":     text,
                "cves":        cves,
            })

        return findings


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _finding(tool: str, title: str, severity: str, details: str) -> Dict[str, any]:
    return {"tool": tool, "title": title, "severity": severity, "details": details, "cves": []}


def _osv_severity(vuln: Dict) -> str:
    """Map an OSV vulnerability entry to a normalized severity level."""
    # Check database_specific.severity e.g. "HIGH", "CRITICAL"
    db_spec = vuln.get("database_specific") or {}
    if isinstance(db_spec, dict):
        db_sev = str(db_spec.get("severity", "")).lower()
        if db_sev in ("critical", "high", "medium", "low"):
            return db_sev
        if db_sev in ("negligible", "none"):
            return "info"

    sev_field = vuln.get("severity")
    if isinstance(sev_field, str):
        sev_low = sev_field.lower()
        if sev_low in ("critical", "high", "medium", "low", "info"):
            return sev_low
        if sev_low in ("negligible", "none", "unknown"):
            return "info"
    elif isinstance(sev_field, list):
        for s_item in sev_field:
            if isinstance(s_item, dict):
                score_val = s_item.get("score")
                if isinstance(score_val, (int, float)):
                    if score_val >= 9.0: return "critical"
                    if score_val >= 7.0: return "high"
                    if score_val >= 4.0: return "medium"
                    if score_val > 0.0: return "low"
                elif isinstance(score_val, str):
                    try:
                        f_score = float(score_val)
                        if f_score >= 9.0: return "critical"
                        if f_score >= 7.0: return "high"
                        if f_score >= 4.0: return "medium"
                        if f_score > 0.0: return "low"
                    except ValueError:
                        vec = score_val.upper()
                        if "AV:N" in vec and ("C:H/I:H" in vec or "C:H/I:H/A:H" in vec or "S:C" in vec or "VC:H" in vec):
                            return "critical"
                        if "C:H" in vec or "I:H" in vec or "A:H" in vec or "VC:H" in vec or "VI:H" in vec or "VA:H" in vec:
                            return "high"
                        if "C:L" in vec or "I:L" in vec or "A:L" in vec or "VC:L" in vec:
                            return "medium"

    cvss = vuln.get("cvss", {}).get("score") if isinstance(vuln.get("cvss"), dict) else None
    if cvss is None:
        cvss_obj = vuln.get("cvss")
        if isinstance(cvss_obj, dict):
            cvss = cvss_obj.get("score")
    try:
        score = float(cvss) if cvss is not None else 0.0
    except (TypeError, ValueError):
        score = 0.0

    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "medium"


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
    path_match = re.search(r"(?:^|\s)(/[\w/.\-?=&%]{3,60})", text)
    if path_match:
        path = path_match.group(1)[:50]
        return f"Web Path: {path}"
    ref_match = re.search(r"(OSVDB-\d+|CVE-\d{4}-\d+)", text, re.IGNORECASE)
    if ref_match:
        return f"Finding: {ref_match.group(1)}"
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
