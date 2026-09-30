"""WebDAV/WebSocket handshakes and bounded HTTP media signatures."""
import asyncio
import base64
import hashlib
import re
import secrets

from ..transports.http import http_sample
from .media_catalog import get_candidate_media_paths

WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def websocket_accept(key):
    return base64.b64encode(hashlib.sha1((key + WEBSOCKET_GUID).encode("ascii")).digest()).decode("ascii")


def websocket_confirmed(sample, key):
    return (
        sample.status == 101
        and sample.headers.get("upgrade", "").lower() == "websocket"
        and "upgrade" in {s.strip().lower() for s in sample.headers.get("connection", "").split(",")}
        and sample.headers.get("sec-websocket-accept") == websocket_accept(key)
        and not sample.headers.get("sec-websocket-protocol")  # None was offered.
        and not sample.headers.get("sec-websocket-extensions")
    )


def media_signature(sample):
    if sample.status not in (200, 206):
        return None
    body = sample.body
    content_type = sample.headers.get("content-type", "").lower()
    if body.startswith(b"#EXTM3U") and re.search(rb"(?m)^#EXT-X-[A-Z-]+:", body):
        return "hls"
    if content_type.startswith("multipart/x-mixed-replace"):
        match = re.search(r'boundary=(?:"([^"]+)"|([^;\s]+))', content_type)
        if match:
            boundary = (match.group(1) or match.group(2)).encode("ascii", "ignore")
            if body.startswith(b"--" + boundary) and b"\xff\xd8\xff" in body:
                return "mjpeg"
    if len(body) >= 377 and body[0] == body[188] == body[376] == 0x47:
        return "mpeg-ts"
    if body.startswith(b"\xff\xd8\xff"):
        return "http_snapshot"
    return None


async def enrich_web(observation, budget):
    if not budget.config.web_enrichment:
        return
    http = next((s for s in observation.services if s["protocol"] in ("http", "https")), None)
    if http is None:
        return
    tls = http["protocol"] == "https"

    # 1. Configured resource paths (runs webdav, websocket, http_media)
    for path in budget.config.resource_paths:
        for detector in ("webdav", "websocket", "http_media"):
            try:
                if detector == "webdav":
                    sample = await http_sample(budget, observation, path, method="OPTIONS", body_limit=0, tls=tls)
                    classes = {part.strip() for part in sample.headers.get("dav", "").split(",")}
                    detected = sample.status in range(200, 300) and bool(classes & {"1", "2", "3"})
                    if detected:
                        observation.service("webdav", ("storage", "web"), path=path, transport_security=tls,
                                            compliance_classes=sorted(classes & {"1", "2", "3"}))
                elif detector == "websocket":
                    key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
                    sample = await http_sample(budget, observation, path, body_limit=0, tls=tls, headers={
                        "Connection": "Upgrade", "Upgrade": "websocket",
                        "Sec-WebSocket-Key": key, "Sec-WebSocket-Version": "13",
                    })
                    detected = websocket_confirmed(sample, key)
                    if detected:
                        observation.service("websocket", ("web",), path=path, transport_security=tls,
                                            handshake_only=True)
                else:
                    req_headers = {"Range": "bytes=0-8191"} if path != "/" else None
                    sample = await http_sample(budget, observation, path, tls=tls, headers=req_headers)
                    protocol = media_signature(sample)
                    detected = protocol is not None
                    if detected:
                        observation.service(protocol, ("video",), path=path, transport_security=tls,
                                            verified_media=False, evidence="bounded_content_signature")
                    # Web Fingerprint extraction (title, server, realm, generator, body clues)
                    if sample.status in range(200, 500):
                        attrs = http.setdefault("attributes", {})
                        server_hdr = sample.headers.get("server", "")
                        if server_hdr and not attrs.get("server"):
                            attrs["server"] = server_hdr
                        auth_hdr = sample.headers.get("www-authenticate", "")
                        if auth_hdr and not attrs.get("realm"):
                            realm_match = re.search(r'realm=["\']?([^"\',;]+)', auth_hdr, re.IGNORECASE)
                            if realm_match:
                                attrs["realm"] = realm_match.group(1).strip()

                        body_text = sample.body.decode("utf-8", "replace")

                        # If response is a redirect or HTML location script, fetch destination page
                        redirect_url = sample.headers.get("location", "")
                        if not redirect_url:
                            js_match = re.search(r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', body_text)
                            if js_match:
                                redirect_url = js_match.group(1).split("?")[0].strip()

                        if redirect_url and not redirect_url.startswith(("http://", "https://", "//")):
                            try:
                                redir_path = redirect_url if redirect_url.startswith("/") else ("/" + redirect_url)
                                redir_sample = await http_sample(budget, observation, redir_path, tls=tls, headers={"Range": "bytes=0-8191"})
                                if redir_sample.status in range(200, 500) and redir_sample.body:
                                    redir_text = redir_sample.body.decode("utf-8", "replace")
                                    if redir_text.strip():
                                        body_text = redir_text
                            except Exception:
                                pass

                        title_match = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.IGNORECASE | re.DOTALL)
                        if title_match and not attrs.get("title"):
                            import html
                            raw_title = html.unescape(title_match.group(1).strip())
                            cleaned_title = " ".join(raw_title.split())[:200]
                            if cleaned_title:
                                attrs["title"] = cleaned_title

                        meta_gen = re.search(r'<meta[^>]+name=["\'](generator|application-name)["\'][^>]+content=["\']([^"\']+)["\']', body_text, re.IGNORECASE)
                        if meta_gen and not attrs.get("generator"):
                            attrs["generator"] = meta_gen.group(2).strip()

                        lower_body = (sample.body.decode("utf-8", "replace") + " " + body_text + " " + redirect_url).lower()
                        clues = []
                        for kw in (
                            "hikvision", "hiwatch", "dahua", "axis", "beward", "login.asp", "logincontroller",
                            "freepbx", "asterisk", "siemens", "d-link", "wireless router",
                            "octoprint", "klipper", "mainsail", "fluidd", "traccar", "orthanc", "routeros",
                            "mikrotik", "apc", "openwrt", "truenas", "synology", "qnap", "ubiquiti",
                            "unifi", "airmax", "grandstream", "yealink", "2n", "akuvox", "bas-ip",
                            "home assistant", "node-red", "wago", "schneider", "omron", "rockwell",
                            "danfoss", "tridium", "niagara", "bolid", "honeywell", "swarco",
                        ):
                            if kw in lower_body:
                                clues.append(kw)
                        if clues and not attrs.get("body_clues"):
                            attrs["body_clues"] = ", ".join(clues[:5])
                observation.attempt(detector, "detected" if detected else "no_match", path=path)
                await observation.checkpoint()
            except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
                observation.attempt(detector, "error", error_type=type(exc).__name__, path=path)
            except asyncio.TimeoutError:
                observation.attempt(detector, "timeout", path=path)

    # 2. Automated Media Catalog probing (HLS manifests, MJPEG streams, snapshots)
    if getattr(budget.config, "media_catalog", False):
        detected_brand = ""
        for s in observation.services:
            attrs = s.get("attributes", {})
            server_banner = f"{attrs.get('server', '')} {attrs.get('product', '')}".lower()
            for b in ("hikvision", "dahua", "axis", "beward", "uniview", "reolink", "hanwha", "samsung"):
                if b in server_banner:
                    detected_brand = b
                    break
            if detected_brand:
                break

        media_paths = get_candidate_media_paths(brand=detected_brand)
        already_tested = set(budget.config.resource_paths)
        for path in media_paths:
            if path in already_tested:
                continue
            try:
                sample = await http_sample(budget, observation, path, tls=tls,
                                           headers={"Range": "bytes=0-8191"})
                protocol = media_signature(sample)
                detected = protocol is not None
                if detected:
                    observation.service(protocol, ("video",), path=path, transport_security=tls,
                                        verified_media=False, evidence="bounded_content_signature")
                observation.attempt("http_media", "detected" if detected else "no_match", path=path)
                await observation.checkpoint()
            except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
                observation.attempt("http_media", "error", error_type=type(exc).__name__, path=path)
            except asyncio.TimeoutError:
                observation.attempt("http_media", "timeout", path=path)
