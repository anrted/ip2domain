"""Web Form Login Emulator for Camera Scanner v2.

Emulates POST login forms and API endpoints for:
- OpenWrt / LuCI web management
- Keenetic Web OS
- Hikvision Web Client & ISAPI userCheck
- Dahua Web Client
- TP-Link Web management
- Generic HTML forms (<form action="..." method="POST"> with user/pass inputs)
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)
_TIMEOUT = 2.5

DEFAULT_WEB_LOGIN_CREDS = [
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "password"),
    ("root", "root"),
    ("root", "admin"),
    ("root", ""),
    ("user", "user"),
]


def _extract_html_form_details(html: str, base_url: str) -> Optional[Dict[str, str]]:
    """Extract form action URL and username/password input names from HTML."""
    if not html:
        return None
    # Look for password input
    pwd_match = re.search(
        r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']password["\']|<input[^>]*type=["\']password["\'][^>]*name=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE,
    )
    if not pwd_match:
        return None
    pwd_field = pwd_match.group(1) or pwd_match.group(2)

    # Look for username input
    user_match = re.search(
        r'<input[^>]*name=["\']([^"\']*(?:user|login|name|account|uid)[^"\']*)["\']',
        html,
        re.IGNORECASE,
    )
    user_field = user_match.group(1) if user_match else "username"

    # Look for form action
    form_match = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', html, re.IGNORECASE)
    action = form_match.group(1) if form_match else ""
    action_url = urljoin(base_url, action) if action else base_url

    return {
        "action_url": action_url,
        "user_field": user_field,
        "pwd_field": pwd_field,
    }


async def _probe_luci_login(
    client: httpx.AsyncClient, base_url: str, creds: List[Tuple[str, str]]
) -> Optional[Tuple[str, str]]:
    """Test OpenWrt / LuCI form login."""
    luci_url = urljoin(base_url, "/cgi-bin/luci")
    for u, p in creds:
        try:
            data = {"luci_username": u, "luci_password": p}
            resp = await client.post(luci_url, data=data, timeout=_TIMEOUT)
            # LuCI sets sysauth cookie and redirects (302) on success
            set_cookie = resp.headers.get("set-cookie", "")
            location = resp.headers.get("location", "")
            if "sysauth" in set_cookie or "admin" in location:
                return u, p
            if resp.status_code == 200 and "sysauth" in set_cookie:
                return u, p
        except Exception:
            continue
    return None


async def _probe_keenetic_login(
    client: httpx.AsyncClient, base_url: str, creds: List[Tuple[str, str]]
) -> Optional[Tuple[str, str]]:
    """Test Keenetic Web API login (/auth endpoint)."""
    auth_url = urljoin(base_url, "/auth")
    for u, p in creds:
        try:
            # 1. Try JSON payload
            resp = await client.post(auth_url, json={"login": u, "password": p}, timeout=_TIMEOUT)
            if resp.status_code == 200 and ("status" in resp.text or "token" in resp.text):
                return u, p
            # 2. Try Digest / Basic challenge on /auth
            if resp.status_code == 401:
                resp_auth = await client.get(auth_url, auth=httpx.DigestAuth(u, p), timeout=_TIMEOUT)
                if resp_auth.status_code in (200, 302):
                    return u, p
                resp_basic = await client.get(auth_url, auth=(u, p), timeout=_TIMEOUT)
                if resp_basic.status_code in (200, 302):
                    return u, p
        except Exception:
            continue
    return None


async def _probe_hikvision_web_login(
    client: httpx.AsyncClient, base_url: str, creds: List[Tuple[str, str]]
) -> Optional[Tuple[str, str]]:
    """Test Hikvision ISAPI / userCheck endpoint."""
    check_url = urljoin(base_url, "/ISAPI/Security/userCheck")
    for u, p in creds:
        try:
            resp = await client.get(check_url, auth=httpx.DigestAuth(u, p), timeout=_TIMEOUT)
            if resp.status_code == 200 and ("statusValue" in resp.text or "statusString" in resp.text or "200" in resp.text):
                return u, p
            if resp.status_code == 401:
                resp = await client.get(check_url, auth=(u, p), timeout=_TIMEOUT)
                if resp.status_code == 200:
                    return u, p
        except Exception:
            continue
    return None


async def _probe_dahua_web_login(
    client: httpx.AsyncClient, base_url: str, creds: List[Tuple[str, str]]
) -> Optional[Tuple[str, str]]:
    """Test Dahua CGI login / magicBox deviceType."""
    check_url = urljoin(base_url, "/cgi-bin/magicBox.cgi?action=getDeviceType")
    for u, p in creds:
        try:
            resp = await client.get(check_url, auth=httpx.DigestAuth(u, p), timeout=_TIMEOUT)
            if resp.status_code == 200 and ("type=" in resp.text.lower() or "device" in resp.text.lower()):
                return u, p
        except Exception:
            continue
    return None


async def _probe_generic_form_post(
    client: httpx.AsyncClient, form_info: Dict[str, str], creds: List[Tuple[str, str]]
) -> Optional[Tuple[str, str]]:
    """Submit standard HTML form with user & password fields."""
    action_url = form_info["action_url"]
    user_f = form_info["user_field"]
    pwd_f = form_info["pwd_field"]

    for u, p in creds:
        try:
            data = {user_f: u, pwd_f: p}
            resp = await client.post(action_url, data=data, timeout=_TIMEOUT)
            set_cookie = resp.headers.get("set-cookie", "").lower()
            location = resp.headers.get("location", "").lower()

            # Typical successful login responses:
            # 1. 302/303 redirect to main page/dashboard with auth session cookie
            if resp.status_code in (301, 302, 303, 307):
                if any(k in set_cookie for k in ("session", "token", "auth", "sid", "id=", "user")):
                    return u, p
                if any(k in location for k in ("index", "main", "home", "admin", "dashboard", "preview")):
                    return u, p

            # 2. 200 OK with redirect script or session cookie and no failure keywords
            if resp.status_code == 200:
                resp_text = resp.text.lower()
                failure_keywords = (
                    "invalid username", "incorrect password", "wrong password",
                    "authentication failed", "login failed", "ошибка входа",
                    "неверный пароль", "неправильный логин", "bad password",
                )
                if not any(k in resp_text for k in failure_keywords):
                    if any(k in set_cookie for k in ("session", "token", "auth", "sid", "uid")):
                        return u, p
                    if "location.href" in resp_text and any(k in resp_text for k in ("index", "main", "home")):
                        return u, p
        except Exception:
            continue
    return None


async def probe_web_form_login(
    ip: str,
    port: int,
    base_url: str,
    brand: str = "",
    credentials: Optional[List[Tuple[str, str]]] = None,
    html_text: str = "",
) -> Optional[Tuple[str, str]]:
    """Main entrypoint: identifies form type and attempts login with credentials.

    Returns: (username, password) if login was successful, else None.
    """
    if not base_url:
        base_url = f"http://{ip}:{port}/"

    # Assemble deduplicated credentials list (cap at 6)
    creds_to_try: List[Tuple[str, str]] = []
    seen = set()
    for c in (credentials or []) + DEFAULT_WEB_LOGIN_CREDS:
        if c not in seen:
            creds_to_try.append(c)
            seen.add(c)
    creds_to_try = creds_to_try[:6]

    brand_l = (brand or "").lower()
    html_l = (html_text or "").lower()

    async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT, follow_redirects=False) as client:
        # 1. OpenWrt LuCI
        if "luci" in html_l or "openwrt" in brand_l or "luci" in brand_l:
            match = await _probe_luci_login(client, base_url, creds_to_try)
            if match:
                logger.info("[WebLogin] LuCI login success on %s:%d: %s:***", ip, port, match[0])
                return match

        # 2. Keenetic Web OS
        if "keenetic" in brand_l or "ndms" in html_l or "keenetic" in html_l:
            match = await _probe_keenetic_login(client, base_url, creds_to_try)
            if match:
                logger.info("[WebLogin] Keenetic login success on %s:%d: %s:***", ip, port, match[0])
                return match

        # 3. Hikvision Web Client
        if "hikvision" in brand_l or "doc/page/login.asp" in html_l:
            match = await _probe_hikvision_web_login(client, base_url, creds_to_try)
            if match:
                logger.info("[WebLogin] Hikvision ISAPI login success on %s:%d: %s:***", ip, port, match[0])
                return match

        # 4. Dahua Web Client
        if "dahua" in brand_l or "magicbox" in html_l:
            match = await _probe_dahua_web_login(client, base_url, creds_to_try)
            if match:
                logger.info("[WebLogin] Dahua CGI login success on %s:%d: %s:***", ip, port, match[0])
                return match

        # 5. Generic HTML Form Login
        form_info = _extract_html_form_details(html_text, base_url)
        if form_info:
            match = await _probe_generic_form_post(client, form_info, creds_to_try)
            if match:
                logger.info("[WebLogin] Generic form login success on %s:%d (%s): %s:***", ip, port, form_info['action_url'], match[0])
                return match

    return None
