"""
High-Speed WordPress Hunter Engine.
Asynchronous mass discovery, version fingerprinting, plugin/theme extraction,
and security posture auditing for hundreds of websites.
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
    def parse_targets(
        raw_targets: List[str], ports: Optional[List[int]] = None
    ) -> List[Dict[str, Any]]:
        """
        Expand CIDRs, IPs, hostnames and URLs into discrete (host, port, scheme) targets.
        """
        effective_ports = ports or [80, 443]
        target_list: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, int, str]] = set()

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
                key = (host.lower(), port, scheme)
                if key not in seen:
                    seen.add(key)
                    target_list.append({"host": host, "port": port, "scheme": scheme})
                continue

            # Check if input is a CIDR block
            if "/" in item:
                try:
                    net = ipaddress.ip_network(item, strict=False)
                    # Limit expansion to /16 to avoid running out of memory
                    if net.num_addresses > 65536:
                        logger.warning("CIDR %s is too large, skipping expansion", item)
                        continue
                    for ip in net.hosts():
                        ip_str = str(ip)
                        for port in effective_ports:
                            scheme = "https" if port in (443, 8443, 9443) else "http"
                            key = (ip_str, port, scheme)
                            if key not in seen:
                                seen.add(key)
                                target_list.append({"host": ip_str, "port": port, "scheme": scheme})
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
                    key = (host.lower(), p, scheme)
                    if key not in seen:
                        seen.add(key)
                        target_list.append({"host": host, "port": p, "scheme": scheme})
                    continue
                except ValueError:
                    pass

            # Plain hostname or IP
            host_clean = item.strip("/")
            for port in effective_ports:
                scheme = "https" if port in (443, 8443, 9443) else "http"
                key = (host_clean.lower(), port, scheme)
                if key not in seen:
                    seen.add(key)
                    target_list.append({"host": host_clean, "port": port, "scheme": scheme})

        return target_list

    async def probe_target(
        self, session: aiohttp.ClientSession, target: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform fast 2-stage WordPress detection & fingerprinting on a single target.
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
                    await self._deep_fingerprint(session, base_url, result)
                except Exception as exc:
                    logger.debug("Deep fingerprint failed for %s: %s", base_url, exc)

        return result

    async def _deep_fingerprint(
        self, session: aiohttp.ClientSession, base_url: str, result: Dict[str, Any]
    ) -> None:
        """Probe auxiliary endpoints for version fallback and security checks."""
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        timeout = aiohttp.ClientTimeout(total=4.0)

        # 1. Fallback: Check /feed/ if version not yet discovered
        if not result["version"]:
            try:
                feed_url = f"{base_url.rstrip('/')}/feed/"
                async with session.get(feed_url, headers=headers, timeout=timeout, allow_redirects=True) as resp:
                    if resp.status == 200:
                        feed_text = (await resp.content.read(16384)).decode("utf-8", errors="ignore")
                        m = _FEED_GENERATOR_REGEX.search(feed_text)
                        if m:
                            result["version"] = m.group(1)
                            result["version_source"] = "feed"
            except Exception:
                pass

        # 2. Fallback: Check /readme.html
        if not result["version"]:
            try:
                readme_url = f"{base_url.rstrip('/')}/readme.html"
                async with session.get(readme_url, headers=headers, timeout=timeout, allow_redirects=True) as resp:
                    if resp.status == 200:
                        text = (await resp.content.read(4096)).decode("utf-8", errors="ignore")
                        m = _README_VERSION_REGEX.search(text)
                        if m:
                            result["version"] = m.group(1)
                            result["version_source"] = "readme"
            except Exception:
                pass

        # 3. Security posture fast checks: Users API, XML-RPC, Registration
        sec: Dict[str, Any] = {}
        # XML-RPC check
        try:
            xmlrpc_url = f"{base_url.rstrip('/')}/xmlrpc.php"
            async with session.get(xmlrpc_url, headers=headers, timeout=timeout, allow_redirects=False) as resp:
                sec["xmlrpc_status"] = resp.status
                sec["xmlrpc_open"] = resp.status in (200, 405)
        except Exception:
            sec["xmlrpc_open"] = False

        # Users API disclosure check
        try:
            users_url = f"{base_url.rstrip('/')}/wp-json/wp/v2/users"
            async with session.get(users_url, headers=headers, timeout=timeout, allow_redirects=True) as resp:
                sec["users_api_status"] = resp.status
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if isinstance(data, list) and data:
                        sec["users_exposed"] = [u.get("slug") or u.get("name") for u in data[:5] if isinstance(u, dict)]
                    else:
                        sec["users_exposed"] = []
                else:
                    sec["users_exposed"] = []
        except Exception:
            sec["users_exposed"] = []

        # Registration check
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

        result["security"] = sec

    async def scan_targets(
        self,
        targets: List[Dict[str, Any]],
        progress_callback: Optional[Callable[[int, int, Dict[str, Any]], None]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Run high-speed concurrent scan across all expanded targets.
        """
        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=0,
            limit_per_host=4,
            ttl_dns_cache=300,
        )
        total = len(targets)
        completed = 0
        results: List[Dict[str, Any]] = []

        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for t in targets:
                async def _worker(tgt=t):
                    nonlocal completed
                    res = await self.probe_target(session, tgt)
                    completed += 1
                    if progress_callback:
                        try:
                            progress_callback(completed, total, res)
                        except Exception:
                            pass
                    return res

                tasks.append(asyncio.create_task(_worker()))

            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in batch_results:
                if isinstance(r, dict):
                    results.append(r)

        return results
