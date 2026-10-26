"""
High-Speed WordPress Hunter Engine.
Asynchronous mass discovery, version fingerprinting, plugin/theme extraction,
and security posture auditing for hundreds of websites or CIDR ranges.
"""

import asyncio
import ipaddress
import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import aiohttp

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
