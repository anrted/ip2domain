"""
High-Speed WordPress Hunter Engine.
Asynchronous mass discovery, version fingerprinting, plugin/theme extraction,
and security posture auditing for hundreds of websites or CIDR ranges.
"""

import asyncio
import ipaddress
import logging
import re
import ssl
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import aiohttp
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID

logger = logging.getLogger(__name__)

# Common WordPress Asset regexes for version discovery
_GENERATOR_REGEX = re.compile(
    r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']WordPress\s+([0-9\.]+)["\']',
    re.IGNORECASE,
)
_FEED_GENERATOR_REGEX = re.compile(
    r'<generator>https?://wordpress\.org/\?v=([0-9\.]+)</generator>',
    re.IGNORECASE,
)
_README_VERSION_REGEX = re.compile(
    r'(?:Version|WordPress\s+(?:&#8250;|&rsaquo;)?\s*Version)\s+([0-9\.]+)',
    re.IGNORECASE,
)
_CORE_ASSET_VER_REGEX = re.compile(
    r'(?:wp-includes|wp-admin)/[^\s"\']*?\.(?:js|css)\?ver=([0-9\.]+)',
    re.IGNORECASE,
)
_THEME_REGEX = re.compile(
    r'/wp-content/themes/([a-zA-Z0-9_\-]+)/',
    re.IGNORECASE,
)
_PLUGIN_REGEX = re.compile(
    r'/wp-content/plugins/([a-zA-Z0-9_\-]+)/',
    re.IGNORECASE,
)
_WP_INDICATORS = (
    "/wp-content/",
    "/wp-includes/",
    "wp-json",
    "wp-block",
    "wp-emoji",
    "wordpress",
)


def parse_wp_version(ver_str: Optional[str]) -> Optional[Tuple[int, int, int]]:
    """Parse version string into (major, minor, patch) integer tuple."""
    if not ver_str:
        return None
    matches = re.findall(r"\d+", str(ver_str))
    if not matches:
        return None
    major = int(matches[0])
    minor = int(matches[1]) if len(matches) > 1 else 0
    patch = int(matches[2]) if len(matches) > 2 else 0
    return (major, minor, patch)


def check_wp_cves(
    version: Optional[str],
    batch_api_status: Optional[int] = None,
    batch_api_open: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Check for known WordPress core vulnerabilities:
    - CVE-2026-63030: REST API Batch Route Confusion (CVSS 9.8 Critical)
    - CVE-2026-60137: WP_Query author__not_in SQL Injection (CVSS 5.9 / 9.8 in chain)
    - wp2shell full unauthenticated RCE chain detection
    """
    v = parse_wp_version(version)
    cves: List[Dict[str, Any]] = []

    cve_60137_vuln = False
    cve_63030_vuln = False

    if v is not None:
        # CVE-2026-60137: WordPress Core WP_Query author__not_in SQL Injection
        # Affected versions: 6.8.0-6.8.5 (fixed 6.8.6), 6.9.0-6.9.4 (fixed 6.9.5), 7.0.0-7.0.1 (fixed 7.0.2)
        if (6, 8, 0) <= v < (6, 8, 6):
            cve_60137_vuln = True
        elif (6, 9, 0) <= v < (6, 9, 5):
            cve_60137_vuln = True
        elif (7, 0, 0) <= v < (7, 0, 2):
            cve_60137_vuln = True

        # CVE-2026-63030: WordPress REST API Batch Route Confusion
        # Affected versions: 6.9.0-6.9.4 (fixed 6.9.5), 7.0.0-7.0.1 (fixed 7.0.2)
        if (6, 9, 0) <= v < (6, 9, 5):
            cve_63030_vuln = True
        elif (7, 0, 0) <= v < (7, 0, 2):
            cve_63030_vuln = True

    if cve_60137_vuln:
        cves.append({
            "cve": "CVE-2026-60137",
            "name": "WP_Query author__not_in SQL Injection",
            "cvss": 5.9,
            "severity": "HIGH",
            "affected_versions": "WordPress 6.8.0-6.8.5, 6.9.0-6.9.4, 7.0.0-7.0.1",
            "detected_version": version,
            "description": "Недостаточная фильтрация аргумента author__not_in в запросах WP_Query ядра WordPress, приводящая к SQL-инъекции. Компонент RCE цепочки wp2shell.",
            "remediation": "Обновите WordPress до версии 6.8.6, 6.9.5 или 7.0.2+",
        })

    if cve_63030_vuln:
        batch_note = ""
        if batch_api_status is not None:
            batch_note = f" (эндпоинт /wp-json/batch/v1 ответил кодом HTTP {batch_api_status})"
        cves.append({
            "cve": "CVE-2026-63030",
            "name": "REST API Batch Route Confusion",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "affected_versions": "WordPress 6.9.0-6.9.4, 7.0.0-7.0.1",
            "detected_version": version,
            "batch_endpoint_open": batch_api_open,
            "batch_api_status": batch_api_status,
            "description": f"Спуфинг маршрутизации REST API в /wp-json/batch/v1, позволяющий обойти границы аутентификации{batch_note}.",
            "remediation": "Срочно обновите WordPress до 6.9.5 или 7.0.2+, либо заблокируйте доступ к /wp-json/batch/v1 на уровне веб-сервера.",
        })

    is_wp2shell = cve_60137_vuln and cve_63030_vuln

    return {
        "cves": cves,
        "wp2shell_vulnerable": is_wp2shell,
        "has_critical_cve": any(c["severity"] == "CRITICAL" for c in cves),
        "total_cves": len(cves),
    }


_SSL_RESOLVER_CTX = ssl.create_default_context()
_SSL_RESOLVER_CTX.check_hostname = False
_SSL_RESOLVER_CTX.verify_mode = ssl.CERT_NONE
_SSL_RESOLVER_CTX.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3


def normalize_discovered_domain(domain_str: str) -> Optional[str]:
    """Validate and clean discovered domain string from SSL cert or reverse DNS."""
    if not domain_str:
        return None
    d = str(domain_str).strip().lower()
    if d.startswith("*."):
        d = d[2:]
    d = d.split(":")[0].strip()
    if not d or len(d) > 253 or " " in d or d.endswith("."):
        return None
    # Reject raw IP addresses
    if re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", d):
        return None
    # Reject local/internal dummy domains
    if d in ("localhost", "local", "internal", "domain", "example.com", "example.org"):
        return None
    if "." not in d:
        return None
    return d


async def extract_domains_from_ssl(ip: str, port: int = 443, timeout: float = 2.0) -> List[str]:
    """Connect to IP:port via TLS, fetch certificate, and extract CN & SAN domains."""
    domains: Set[str] = set()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=_SSL_RESOLVER_CTX, server_hostname=None),
            timeout=timeout,
        )
        try:
            sslobj = writer.get_extra_info("ssl_object")
            if sslobj:
                der = sslobj.getpeercert(binary_form=True)
                if der:
                    cert = x509.load_der_x509_certificate(der)
                    for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                        norm = normalize_discovered_domain(str(attr.value))
                        if norm:
                            domains.add(norm)
                    try:
                        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        for name in ext.value.get_values_for_type(x509.DNSName):
                            norm = normalize_discovered_domain(str(name))
                            if norm:
                                domains.add(norm)
                    except Exception:
                        pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        pass
    return sorted(domains)


class WPHunter:
    """High-speed asynchronous scanner for bulk WordPress detection and version analysis."""

    DEFAULT_PORTS = [80, 443]

    def __init__(
        self,
        concurrency: int = 150,
        timeout: float = 6.0,
        deep_scan: bool = True,
        max_body_bytes: int = 65536,
    ):
        self.concurrency = max(10, min(500, concurrency))
        self.timeout = timeout
        self.deep_scan = deep_scan
        self.max_body_bytes = max_body_bytes
        self.semaphore = asyncio.Semaphore(self.concurrency)

    @staticmethod
    def count_targets(
        raw_targets: List[str], ports: Optional[List[int]] = None
    ) -> Tuple[int, int]:
        """
        Fast calculation of input lines and total discrete IP/port targets without expanding into memory.
        Returns: (line_count, total_checks)
        """
        effective_ports = len(ports) if ports else 2
        total_ips = 0
        raw_count = 0

        for item in raw_targets:
            item = str(item).strip()
            if not item or item.startswith("#"):
                continue
            raw_count += 1
            if "/" in item:
                try:
                    net = ipaddress.ip_network(item, strict=False)
                    total_ips += net.num_addresses
                    continue
                except ValueError:
                    pass
            total_ips += 1

        return raw_count, total_ips * effective_ports

    @classmethod
    def partition_targets(
        cls, raw_targets: List[str], ports: Optional[List[int]] = None
    ) -> Tuple[List[Dict[str, Any]], List[Tuple[str, bool]], int]:
        """
        Partition raw targets into:
        1. direct_targets: already formatted domain or URL target dicts
        2. ip_specs: list of (spec, is_cidr) for Phase 1 domain resolution
        3. total_ips: total count of IP addresses represented
        """
        effective_ports = ports or [80, 443]
        direct_targets: List[Dict[str, Any]] = []
        ip_specs: List[Tuple[str, bool]] = []
        total_ips = 0

        for line in raw_targets:
            s = str(line).strip()
            if not s or s.startswith("#"):
                continue

            # Check if line is URL
            if s.startswith(("http://", "https://")):
                parsed = urlparse(s)
                host = parsed.hostname
                if not host:
                    continue
                scheme = parsed.scheme.lower()
                port = parsed.port or (443 if scheme == "https" else 80)
                direct_targets.append({
                    "target": host,
                    "source_ip": None,
                    "source_type": "user_input",
                    "port": port,
                    "scheme": scheme,
                })
                continue

            # Check if pure IP or CIDR block
            ip_or_cidr = s.split(":")[0].strip()
            if "/" in ip_or_cidr:
                try:
                    net = ipaddress.ip_network(ip_or_cidr, strict=False)
                    ip_specs.append((ip_or_cidr, True))
                    total_ips += net.num_addresses
                    continue
                except ValueError:
                    pass

            try:
                ipaddress.ip_address(ip_or_cidr)
                ip_specs.append((s, False))
                total_ips += 1
                continue
            except ValueError:
                pass

            # Otherwise line is a domain (e.g. 'eshdesign.ru' or 'domain.com:8443')
            port = None
            if ":" in s:
                parts = s.split(":")
                host = parts[0].strip()
                try:
                    port = int(parts[1])
                except ValueError:
                    port = None
            else:
                host = s

            if port:
                scheme = "https" if port == 443 else "http"
                direct_targets.append({
                    "target": host,
                    "source_ip": None,
                    "source_type": "user_input",
                    "port": port,
                    "scheme": scheme,
                })
            else:
                for p in effective_ports:
                    scheme = "https" if p == 443 else "http"
                    direct_targets.append({
                        "target": host,
                        "source_ip": None,
                        "source_type": "user_input",
                        "port": p,
                        "scheme": scheme,
                    })

        return direct_targets, ip_specs, total_ips

    @classmethod
    def iter_ips_from_specs(cls, ip_specs: List[Tuple[str, bool]]):
        """Streaming generator of string IPs from specs without allocating memory."""
        seen: Set[str] = set()
        for spec, is_cidr in ip_specs:
            if is_cidr:
                try:
                    net = ipaddress.ip_network(spec, strict=False)
                    if net.prefixlen >= 31:
                        hosts = list(net)
                    else:
                        hosts = net.hosts()
                    for host in hosts:
                        h_str = str(host)
                        if h_str not in seen:
                            if len(seen) > 200000:
                                seen.clear()
                            seen.add(h_str)
                            yield h_str
                except Exception:
                    continue
            else:
                h_str = spec.split(":")[0].strip()
                if h_str not in seen:
                    if len(seen) > 200000:
                        seen.clear()
                    seen.add(h_str)
                    yield h_str

    async def discover_domains_phase(
        self,
        ip_stream: Any,
        ports: List[int],
        total_ips: int,
        on_batch_found: Callable[[List[Dict[str, Any]]], None],
        progress_callback: Optional[Callable[[int, int, int], None]] = None,
        stop_check: Optional[Callable[[], bool]] = None,
    ) -> int:
        """
        Phase 1: Stream IPs, probe SSL port 443, extract domains from SSL SAN/CN.
        Intermediate results are dispatched to on_batch_found in chunks of 50 to store in SQLite.
        RAM usage stays virtually zero.
        """
        worker_count = min(self.concurrency, 200)
        queue: asyncio.Queue = asyncio.Queue(maxsize=worker_count * 2)
        total_discovered = 0
        completed_ips = 0
        batch_to_save: List[Dict[str, Any]] = []

        async def producer():
            try:
                for ip in ip_stream:
                    if stop_check and stop_check():
                        break
                    await queue.put(ip)
            finally:
                for _ in range(worker_count):
                    await queue.put(None)

        async def worker():
            nonlocal total_discovered, completed_ips
            while True:
                if stop_check and stop_check():
                    break
                ip = await queue.get()
                if ip is None:
                    queue.task_done()
                    break

                try:
                    # Fast TCP precheck on 443
                    has_443 = False
                    try:
                        _, writer = await asyncio.wait_for(
                            asyncio.open_connection(ip, 443),
                            timeout=1.2,
                        )
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass
                        has_443 = True
                    except Exception:
                        has_443 = False

                    discovered_domains: List[str] = []
                    if has_443:
                        discovered_domains = await extract_domains_from_ssl(ip, port=443, timeout=2.0)

                    items_for_ip: List[Dict[str, Any]] = []
                    if discovered_domains:
                        for dom in discovered_domains:
                            for p in ports:
                                scheme = "https" if p == 443 else "http"
                                items_for_ip.append({
                                    "target": dom,
                                    "source_ip": ip,
                                    "source_type": "ssl_san",
                                    "port": p,
                                    "scheme": scheme,
                                })
                    else:
                        # Fallback: if port 80 or 443 was open, keep the IP target itself
                        has_web = has_443
                        if not has_web and 80 in ports:
                            try:
                                _, writer80 = await asyncio.wait_for(
                                    asyncio.open_connection(ip, 80),
                                    timeout=1.2,
                                )
                                writer80.close()
                                try:
                                    await writer80.wait_closed()
                                except Exception:
                                    pass
                                has_web = True
                            except Exception:
                                has_web = False

                        if has_web:
                            for p in ports:
                                scheme = "https" if p == 443 else "http"
                                items_for_ip.append({
                                    "target": ip,
                                    "source_ip": ip,
                                    "source_type": "ip_fallback",
                                    "port": p,
                                    "scheme": scheme,
                                })

                    if items_for_ip:
                        total_discovered += len(items_for_ip)
                        batch_to_save.extend(items_for_ip)
                        if len(batch_to_save) >= 50:
                            chunk = list(batch_to_save)
                            batch_to_save.clear()
                            on_batch_found(chunk)

                finally:
                    completed_ips += 1
                    if progress_callback:
                        progress_callback(completed_ips, total_ips, total_discovered)
                    queue.task_done()

        producer_task = asyncio.create_task(producer())
        worker_tasks = [asyncio.create_task(worker()) for _ in range(worker_count)]

        await producer_task
        await queue.join()
        for w in worker_tasks:
            w.cancel()
        await asyncio.gather(*worker_tasks, return_exceptions=True)

        if batch_to_save:
            on_batch_found(batch_to_save)
            batch_to_save.clear()

        return total_discovered

    @staticmethod
    def iter_targets(
        raw_targets: List[str],
        ports: Optional[List[int]] = None,
        max_targets: Optional[int] = None,
    ):
        """
        Stream discrete (host, port, scheme) targets one by one without memory allocation.
        """
        effective_ports = ports or [80, 443]
        emitted = 0

        for item in raw_targets:
            item = str(item).strip()
            if not item or item.startswith("#"):
                continue

            # Check if input is a URL
            if item.startswith(("http://", "https://")):
                parsed = urlparse(item)
                host = parsed.hostname
                if not host:
                    continue
                scheme = parsed.scheme.lower()
                port = parsed.port or (443 if scheme == "https" else 80)
                yield {"host": host, "port": port, "scheme": scheme}
                emitted += 1
                if max_targets and emitted >= max_targets:
                    return
                continue

            # Check if input is a CIDR block
            if "/" in item:
                try:
                    net = ipaddress.ip_network(item, strict=False)
                    for ip in net.hosts():
                        ip_str = str(ip)
                        for port in effective_ports:
                            scheme = "https" if port in (443, 8443, 9443) else "http"
                            yield {"host": ip_str, "port": port, "scheme": scheme}
                            emitted += 1
                            if max_targets and emitted >= max_targets:
                                return
                    continue
                except ValueError:
                    pass

            # Check if input is host:port
            if ":" in item and not item.startswith("["):
                parts = item.split(":")
                host = parts[0].strip()
                try:
                    p = int(parts[1])
                    scheme = "https" if p in (443, 8443, 9443) else "http"
                    yield {"host": host, "port": p, "scheme": scheme}
                    emitted += 1
                    if max_targets and emitted >= max_targets:
                        return
                    continue
                except ValueError:
                    pass

            # Plain hostname or IP
            host_clean = item.strip("/")
            for port in effective_ports:
                scheme = "https" if port in (443, 8443, 9443) else "http"
                yield {"host": host_clean, "port": port, "scheme": scheme}
                emitted += 1
                if max_targets and emitted >= max_targets:
                    return

    @classmethod
    def parse_targets(
        cls,
        raw_targets: List[str],
        ports: Optional[List[int]] = None,
        max_targets: int = 50000,
    ) -> List[Dict[str, Any]]:
        """
        Convenience wrapper returning a list up to max_targets (for backward compatibility).
        """
        return list(cls.iter_targets(raw_targets, ports=ports, max_targets=max_targets))

    async def probe_target(
        self, session: aiohttp.ClientSession, target: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform fast 2-stage WordPress detection & fingerprinting on a single target.
        Includes ultra-fast TCP precheck for raw IPs to reject dead hosts in milliseconds.
        """
        host = target["host"]
        port = target["port"]
        scheme = target["scheme"]
        base_url = f"{scheme}://{host}" if (scheme == "http" and port == 80) or (scheme == "https" and port == 443) else f"{scheme}://{host}:{port}"

        result: Dict[str, Any] = {
            "url": base_url,
            "host": host,
            "port": port,
            "scheme": scheme,
            "status_code": None,
            "is_wordpress": False,
            "version": None,
            "version_source": None,
            "title": "",
            "server": "",
            "powered_by": "",
            "theme": None,
            "plugins": [],
            "security": {},
            "latency_ms": 0,
            "error": None,
        }

        async with self.semaphore:
            t0 = time.monotonic()

            # Fast TCP pre-check for raw IPs: eliminates 99.9% of dead broadband IPs in ms
            if re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host):
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=1.5
                    )
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                except Exception:
                    result["latency_ms"] = round((time.monotonic() - t0) * 1000, 1)
                    result["error"] = "Closed"
                    return result

            try:
                # Stage 1: Fast Probe Homepage
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                req_timeout = aiohttp.ClientTimeout(total=self.timeout)

                async with session.get(base_url, headers=headers, timeout=req_timeout, allow_redirects=True) as resp:
                    result["latency_ms"] = round((time.monotonic() - t0) * 1000, 1)
                    result["status_code"] = resp.status
                    result["server"] = resp.headers.get("Server", "")
                    result["powered_by"] = resp.headers.get("X-Powered-By", "")

                    # Read up to max_body_bytes to keep memory and network ultra fast
                    raw_body = await resp.content.read(self.max_body_bytes)
                    html = raw_body.decode("utf-8", errors="ignore")

                    # Check link header for wp-json
                    link_hdr = resp.headers.get("Link", "")
                    has_wp_link = "api.w.org" in link_hdr or "wp-json" in link_hdr
                    has_wp_cookie = any("wordpress" in c.lower() for c in resp.cookies.keys())

                    # Fast detection indicators
                    html_low = html.lower()
                    is_wp = (
                        has_wp_link
                        or has_wp_cookie
                        or any(marker in html_low for marker in _WP_INDICATORS)
                    )

                    if not is_wp:
                        return result

                    # Confirmed WordPress!
                    result["is_wordpress"] = True

                    # Extract page title
                    title_m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
                    if title_m:
                        result["title"] = title_m.group(1).strip()[:150]

                    # 1. Meta generator check
                    gen_m = _GENERATOR_REGEX.search(html)
                    if gen_m:
                        result["version"] = gen_m.group(1)
                        result["version_source"] = "meta_generator"

                    # 2. Asset query parameters check (e.g. wp-embed.min.js?ver=6.4.2)
                    if not result["version"]:
                        asset_vers = _CORE_ASSET_VER_REGEX.findall(html)
                        if asset_vers:
                            valid = [v for v in asset_vers if re.fullmatch(r"\d+\.\d+(?:\.\d+)?", v)]
                            if valid:
                                result["version"] = max(valid, key=valid.count)
                                result["version_source"] = "asset_query"

                    # 3. Detect Theme
                    themes = _THEME_REGEX.findall(html)
                    if themes:
                        result["theme"] = themes[0].strip()

                    # 4. Detect Plugins
                    plugins = sorted(set(_PLUGIN_REGEX.findall(html)))
                    result["plugins"] = plugins[:20]

            except Exception as exc:
                result["latency_ms"] = round((time.monotonic() - t0) * 1000, 1)
                result["error"] = str(exc)
                return result

            # Stage 2: Deep check (if version still unknown or deep_scan enabled)
            if result["is_wordpress"] and self.deep_scan:
                try:
                    await self._deep_probe(session, base_url, headers, req_timeout, result)
                except Exception as exc:
                    logger.debug(f"[WPHunter] Deep probe failed for {base_url}: {exc}")

            # Ensure CVE assessment (CVE-2026-63030, CVE-2026-60137) is always evaluated
            if result["is_wordpress"]:
                sec = result.setdefault("security", {})
                if "cves" not in sec:
                    cve_assessment = check_wp_cves(
                        version=result.get("version"),
                        batch_api_status=sec.get("batch_api_status"),
                        batch_api_open=sec.get("batch_api_open"),
                    )
                    sec.update(cve_assessment)

            return result

    async def _deep_probe(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        headers: Dict[str, str],
        timeout: aiohttp.ClientTimeout,
        result: Dict[str, Any],
    ) -> None:
        """Auxiliary queries: feed generator, readme, xmlrpc, users API, batch API, registration."""
        sec: Dict[str, Any] = {
            "xmlrpc_open": False,
            "xmlrpc_status": None,
            "users_api_status": None,
            "users_exposed": [],
            "registration_open": False,
            "batch_api_status": None,
            "batch_api_open": False,
        }

        # If version not found, check RSS Feed
        if not result["version"]:
            try:
                feed_url = f"{base_url.rstrip('/')}/feed/"
                async with session.get(feed_url, headers=headers, timeout=timeout, allow_redirects=True) as resp:
                    if resp.status == 200:
                        xml_data = (await resp.content.read(16384)).decode("utf-8", errors="ignore")
                        feed_m = _FEED_GENERATOR_REGEX.search(xml_data)
                        if feed_m:
                            result["version"] = feed_m.group(1)
                            result["version_source"] = "rss_feed"
            except Exception:
                pass

        # If still not found, check /readme.html
        if not result["version"]:
            try:
                readme_url = f"{base_url.rstrip('/')}/readme.html"
                async with session.get(readme_url, headers=headers, timeout=timeout, allow_redirects=True) as resp:
                    if resp.status == 200:
                        readme_data = (await resp.content.read(8192)).decode("utf-8", errors="ignore")
                        readme_m = _README_VERSION_REGEX.search(readme_data)
                        if readme_m:
                            result["version"] = readme_m.group(1)
                            result["version_source"] = "readme_html"
            except Exception:
                pass

        # Check XML-RPC
        try:
            xmlrpc_url = f"{base_url.rstrip('/')}/xmlrpc.php"
            async with session.get(xmlrpc_url, headers=headers, timeout=timeout, allow_redirects=True) as resp:
                sec["xmlrpc_status"] = resp.status
                sec["xmlrpc_open"] = resp.status in (200, 405)
        except Exception:
            sec["xmlrpc_open"] = False

        # Check REST API users enumeration
        try:
            users_url = f"{base_url.rstrip('/')}/wp-json/wp/v2/users"
            async with session.get(users_url, headers=headers, timeout=timeout, allow_redirects=True) as resp:
                sec["users_api_status"] = resp.status
                if resp.status == 200:
                    try:
                        data = await resp.json(content_type=None)
                        if isinstance(data, list):
                            logins = [u.get("slug") for u in data if isinstance(u, dict) and u.get("slug")]
                            sec["users_exposed"] = logins[:10]
                    except Exception:
                        pass
        except Exception:
            pass

        # Check REST API Batch Endpoint (CVE-2026-63030 route confusion indicator)
        try:
            batch_url = f"{base_url.rstrip('/')}/wp-json/batch/v1"
            async with session.get(batch_url, headers=headers, timeout=timeout, allow_redirects=True) as resp:
                sec["batch_api_status"] = resp.status
                # 200, 400 (rest_batch_empty), 401, 403, 405 mean batch controller route is active/mounted
                sec["batch_api_open"] = resp.status in (200, 400, 401, 403, 405)
        except Exception:
            sec["batch_api_status"] = None
            sec["batch_api_open"] = False

        # Check Open Registration
        try:
            reg_url = f"{base_url.rstrip('/')}/wp-login.php?action=register"
            async with session.get(reg_url, headers=headers, timeout=timeout, allow_redirects=True) as resp:
                if resp.status == 200:
                    html = (await resp.content.read(16384)).decode("utf-8", errors="ignore")
                    sec["registration_open"] = "registerform" in html
                else:
                    sec["registration_open"] = False
        except Exception:
            sec["registration_open"] = False

        # Evaluate CVEs
        cve_assessment = check_wp_cves(
            version=result.get("version"),
            batch_api_status=sec.get("batch_api_status"),
            batch_api_open=sec.get("batch_api_open"),
        )
        sec.update(cve_assessment)
        result["security"] = sec

    async def scan_targets(
        self,
        targets: Any,
        total_count: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int, Dict[str, Any]], None]] = None,
        stop_check: Optional[Callable[[], bool]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Run high-speed concurrent scan using a bounded worker pool.
        Zero memory bloat regardless of whether there are 100 or 1,000,000 targets.
        """
        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=0,
            limit_per_host=4,
            ttl_dns_cache=300,
        )
        total = total_count if total_count is not None else (len(targets) if isinstance(targets, list) else 0)
        completed = 0
        results: List[Dict[str, Any]] = []

        # Queue bounded to keep memory usage strictly constant (< 15MB)
        queue: asyncio.Queue = asyncio.Queue(maxsize=min(1000, self.concurrency * 4))

        async with aiohttp.ClientSession(connector=connector) as session:
            async def _worker():
                nonlocal completed
                while True:
                    item = await queue.get()
                    if item is None:
                        queue.task_done()
                        break
                    try:
                        if stop_check and stop_check():
                            queue.task_done()
                            continue
                        res = await self.probe_target(session, item)
                        completed += 1
                        if res.get("is_wordpress"):
                            results.append(res)
                        if progress_callback:
                            try:
                                progress_callback(completed, total, res)
                            except Exception:
                                pass
                    except Exception as e:
                        logger.debug("Worker error: %s", e)
                    finally:
                        queue.task_done()

            # Start worker pool
            workers = [asyncio.create_task(_worker()) for _ in range(self.concurrency)]

            # Feed queue without holding all coroutines in memory
            for t in targets:
                if stop_check and stop_check():
                    break
                await queue.put(t)

            # Signal workers to finish
            for _ in range(self.concurrency):
                await queue.put(None)

            await asyncio.gather(*workers, return_exceptions=True)

        return results
