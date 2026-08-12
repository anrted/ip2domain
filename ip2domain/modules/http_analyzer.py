import asyncio
import logging
import re
import ssl
import socket
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

import aiohttp

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-process result cache
# ---------------------------------------------------------------------------
_CACHE: Dict[str, Tuple[float, Dict]] = {}
_CACHE_TTL = 300  # seconds

# ---------------------------------------------------------------------------
# Security header definitions
# ---------------------------------------------------------------------------
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Opener-Policy",
    "Content-Type",                  # should be present with charset
]

# ---------------------------------------------------------------------------
# Technology fingerprint signatures (header + body patterns)
# ---------------------------------------------------------------------------
TECH_SIGNATURES: Dict[str, List[str]] = {
    "Nginx":          [r"server:\s*nginx"],
    "Apache":         [r"server:\s*apache"],
    "IIS":            [r"server:\s*microsoft-iis"],
    "LiteSpeed":      [r"server:\s*litespeed"],
    "Caddy":          [r"server:\s*caddy"],
    "Cloudflare":     [r"server:\s*cloudflare", r"cf-ray:"],
    "Fastly":         [r"via:.*fastly"],
    "Akamai":         [r"x-check-cacheable:", r"x-akamai"],
    "WordPress":      [r"wp-content", r"wp-includes", r"x-powered-by:\s*wordpress"],
    "PHP":            [r"x-powered-by:\s*php", r"set-cookie:\s*phpsessid"],
    "ASP.NET":        [r"x-powered-by:\s*asp\.net", r"x-aspnet-version"],
    "Express/Node.js":[r"x-powered-by:\s*express"],
    "Django":         [r"set-cookie:\s*csrftoken"],
    "Laravel":        [r"set-cookie:\s*laravel_session"],
    "Bitrix":         [r"set-cookie:\s*bitrix_", r"x-powered-cms:\s*bitrix"],
    "Joomla":         [r"set-cookie:\s*[\w]+joomla"],
    "Drupal":         [r"x-generator:\s*drupal", r"set-cookie:\s*drupal"],
    "Shopify":        [r"x-shopify-stage:", r"x-shopify-request-id:"],
    "Next.js":        [r"x-nextjs-cache:", r"x-powered-by:\s*next\.js"],
    "React":          [r"__react", r"react-dom"],
    "Ruby on Rails":  [r"x-runtime:", r"x-powered-by:\s*phusion"],
    "OpenResty":      [r"server:\s*openresty"],
    "Cockpit":        [r"set-cookie:\s*[^\n]*\bcockpit(?:=|;)"],
}

# Cookie security flag checks
COOKIE_FLAGS = ["HttpOnly", "Secure", "SameSite"]


class HTTPTechAnalyzer:
    """
    Asynchronous HTTP Security Headers & Technology Stack Analyzer.

    Improvements over v1:
    - 10 security headers (added CORP, COOP, Content-Type)
    - 20+ technology fingerprints (added LiteSpeed, Caddy, Fastly, Shopify, Next.js, etc.)
    - CORS misconfiguration detection
    - Cookie security flag analysis (HttpOnly, Secure, SameSite)
    - SSL/TLS certificate metadata (expiry, issuer, subject) via stdlib ssl
    - In-process result cache (TTL 300s)
    - Configurable response body scan limit
    - Grade breakdown per-header returned for richer UI display
    """

    def __init__(
        self,
        timeout: int = 10,
        user_agent: Optional[str] = None,
        max_body_bytes: int = 8000,
    ):
        self.timeout       = timeout
        self.user_agent    = user_agent or "ip2domain-SecurityAnalyzer/1.3"
        self.max_body_bytes = max_body_bytes

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze_target(self, target: str, force: bool = False) -> Dict[str, any]:
        """
        Analyze target over HTTPS then HTTP fallback.
        Returns full security + technology report dict.
        """
        key = target.strip().lower()

        if not force and key in _CACHE:
            ts, cached = _CACHE[key]
            if time.monotonic() - ts < _CACHE_TTL:
                return cached

        result = await self._do_analyze(key)
        _CACHE[key] = (time.monotonic(), result)
        return result

    def invalidate_cache(self, target: Optional[str] = None) -> None:
        if target:
            _CACHE.pop(target.strip().lower(), None)
        else:
            _CACHE.clear()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _do_analyze(self, target: str) -> Dict[str, any]:
        urls_to_try = [f"https://{target}", f"http://{target}"]

        headers_found: Dict[str, str] = {}
        tech_detected: Set[str]       = set()
        status_code:   Optional[int]  = None
        final_url:     Optional[str]  = None
        set_cookie_headers: List[str] = []
        cors_origin:   Optional[str]  = None

        timeout   = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(ssl=False, limit=10)

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            for url in urls_to_try:
                try:
                    async with session.get(
                        url,
                        headers={"User-Agent": self.user_agent},
                        # Redirects are deliberately not followed: an otherwise public
                        # hostname could redirect the scanner into an internal network.
                        allow_redirects=False,
                    ) as resp:
                        status_code = resp.status
                        final_url   = str(resp.url)

                        # Collect headers (title-case)
                        headers_found    = {k.title(): v for k, v in resp.headers.items()}
                        set_cookie_headers = resp.headers.getall("Set-Cookie", [])
                        cors_origin      = resp.headers.get("Access-Control-Allow-Origin")

                        # Fingerprint from headers
                        header_blob = "\n".join(
                            f"{k.lower()}: {v.lower()}" for k, v in resp.headers.items()
                        )
                        for tech, sigs in TECH_SIGNATURES.items():
                            if any(re.search(sig, header_blob) for sig in sigs):
                                tech_detected.add(tech)

                        # Fingerprint from body
                        try:
                            body = await resp.content.read(self.max_body_bytes)
                            body_text = body.decode("utf-8", errors="ignore").lower()
                            _body_fingerprint(body_text, tech_detected)
                        except Exception:
                            pass

                        break
                except Exception as e:
                    logger.debug(f"[HTTPAnalyzer] {url} failed: {e}")

        # Security headers analysis
        present_headers, missing_headers = self._check_security_headers(headers_found)
        grade = self._calculate_grade(len(present_headers), len(SECURITY_HEADERS))

        # Cookie flag analysis
        cookie_issues = _analyze_cookies(set_cookie_headers)

        # CORS analysis
        cors_issues = _analyze_cors(cors_origin)

        # Server & powered_by
        server    = headers_found.get("Server", "Unknown")
        powered_by = headers_found.get("X-Powered-By")
        if server and server != "Unknown":
            tech_detected.add(server.split("/")[0].strip())

        # SSL cert metadata (best-effort, non-blocking)
        ssl_info = await self._fetch_ssl_info(target)

        return {
            "target":              target,
            "url":                 final_url,
            "status_code":         status_code,
            "grade":               grade,
            "server":              server,
            "powered_by":          powered_by,
            "tech_stack":          sorted(tech_detected),
            "present_headers":     present_headers,
            "missing_headers":     missing_headers,
            "total_present":       len(present_headers),
            "total_security_headers": len(SECURITY_HEADERS),
            "cookie_issues":       cookie_issues,
            "cors_issues":         cors_issues,
            "ssl_info":            ssl_info,
        }

    def _check_security_headers(
        self, headers: Dict[str, str]
    ) -> Tuple[List[Dict], List[str]]:
        present = []
        missing = []
        for h in SECURITY_HEADERS:
            if h in headers:
                present.append({"header": h, "value": headers[h]})
            else:
                missing.append(h)
        return present, missing

    def _calculate_grade(self, present: int, total: int) -> str:
        pct = (present / total) * 100 if total else 0
        if pct >= 90: return "A+"
        if pct >= 75: return "A"
        if pct >= 55: return "B"
        if pct >= 35: return "C"
        if pct >= 15: return "D"
        return "F"

    async def _fetch_ssl_info(self, target: str) -> Dict[str, any]:
        """Non-blocking SSL cert fetch using asyncio executor."""
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, _get_ssl_cert, target),
                timeout=5,
            )
        except Exception:
            return {}


# ---------------------------------------------------------------------------
# Module-level helper functions
# ---------------------------------------------------------------------------

def _body_fingerprint(body: str, tech_set: Set[str]) -> None:
    """Scan body snippet for technology indicators."""
    patterns = {
        "WordPress":   ["wp-content", "wp-includes", "wordpress"],
        "Bitrix":      ["bitrix", "/bitrix/"],
        "Joomla":      ["/components/com_", "joomla"],
        "Drupal":      ["drupal.settings", "sites/all/modules"],
        "Shopify":     ["cdn.shopify.com", "shopify.com/s/"],
        "Next.js":     ["__next", "_next/static"],
        "React":       ["__react", "react-dom"],
        "Vue.js":      ["__vue__", "data-v-app"],
        "Angular":     ["ng-version", "ng-app"],
        "Bootstrap":   ["bootstrap.min.css", "bootstrap.min.js"],
        "Cockpit":     ["cockpit-ws", "cockpit.socket", "/cockpit/", "id=\"cockpit\""],
    }
    for tech, kws in patterns.items():
        if any(kw in body for kw in kws):
            tech_set.add(tech)


def _analyze_cookies(set_cookie_headers: List[str]) -> List[Dict[str, any]]:
    """Check cookies for missing HttpOnly, Secure, SameSite flags."""
    issues = []
    for cookie_str in set_cookie_headers:
        name = cookie_str.split("=")[0].strip()
        missing_flags = [
            flag for flag in COOKIE_FLAGS
            if flag.lower() not in cookie_str.lower()
        ]
        if missing_flags:
            issues.append({
                "cookie": name,
                "missing_flags": missing_flags,
                "severity": "medium" if "Secure" in missing_flags or "HttpOnly" in missing_flags else "low",
            })
    return issues


def _analyze_cors(origin_header: Optional[str]) -> List[str]:
    """Flag dangerous CORS configurations."""
    issues = []
    if origin_header == "*":
        issues.append("CORS: Access-Control-Allow-Origin: * (wildcard — credentials may be exposed)")
    elif origin_header and "null" in origin_header.lower():
        issues.append("CORS: Access-Control-Allow-Origin: null (dangerous — allows file:// origins)")
    return issues


def _get_ssl_cert(target: str, port: int = 443) -> Dict[str, any]:
    """Blocking SSL cert fetch — intended to run in executor."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        with socket.create_connection((target, port), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                proto  = ssock.version()

        if not cert:
            return {}

        # Parse expiry date
        not_after = cert.get("notAfter", "")
        expiry_dt = None
        days_left  = None
        if not_after:
            try:
                expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_dt - datetime.utcnow()).days
            except Exception:
                pass

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        sans    = []
        for ext in cert.get("subjectAltName", []):
            if ext[0] == "DNS":
                sans.append(ext[1])

        return {
            "subject_cn":   subject.get("commonName", ""),
            "issuer_o":     issuer.get("organizationName", ""),
            "issuer_cn":    issuer.get("commonName", ""),
            "not_after":    not_after,
            "days_left":    days_left,
            "expired":      days_left is not None and days_left < 0,
            "expiring_soon": days_left is not None and 0 <= days_left <= 30,
            "protocol":     proto,
            "cipher_name":  cipher[0] if cipher else "",
            "sans":         sans[:10],  # cap at 10
        }
    except Exception:
        return {}
