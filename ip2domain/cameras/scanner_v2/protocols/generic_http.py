"""Legacy HTTP camera fingerprinting, isolated from probe orchestration."""
from __future__ import annotations

import asyncio
import re
from typing import Dict, List, Optional, Tuple

import httpx

# Generic HTTP camera keyword patterns
_CAMERA_BRANDS = {
    "hikvision": "Hikvision",
    "hiwatch": "Hikvision",
    "ezviz": "Hikvision",
    "hilook": "Hikvision",
    "dahua": "Dahua",
    "imou": "Dahua",
    "lorex": "Dahua",
    "axis": "Axis",
    "foscam": "Foscam",
    "amcrest": "Amcrest",
    "reolink": "Reolink",
    "hanwha": "Hanwha",
    "wisenet": "Hanwha",
    "samsung": "Hanwha",
    "uniview": "Uniview",
    "unv": "Uniview",
    "topsvision": "Topsvision",
    "topsee": "Topsvision",
    "jovision": "Jovision",
    "xiongmai": "Xiongmai",
    "h264dvr": "Xiongmai",
    "netip": "Xiongmai",
    "netsurveillance": "Xiongmai",
    "cp plus": "CP Plus",
    "bosch": "Bosch",
    "pelco": "Pelco",
    "tiandy": "Tiandy",
    "vivotek": "Vivotek",
    "mobotix": "Mobotix",
    "grandstream": "Grandstream",
    "beward": "Beward",
    "trassir": "Trassir",
    "activecam": "ActiveCam",
    "polyvision": "Polyvision",
    "rvi-": "RVi",
    "rvi cctv": "RVi",
    "rvi group": "RVi",
    "dnvrs-webs": "Hikvision",
    "dnvrs": "Hikvision",
    "hikvision-webs": "Hikvision",
    "dvrdvs-webs": "Hikvision",
    "app-webs": "Hikvision",
    "flussonic": "Flussonic",
    "streamer": "Flussonic",
    "unimo": "Unimo",
    "udrocx": "Unimo",
    "vivotek": "Vivotek",
    "vvtk": "Vivotek",
    "vvtk-http-server": "Vivotek",
    "ants_dvr": "Generic DVR",
    "pcviewx": "Generic DVR",
    "novicam": "Novicam",
    "ltv": "LTV",
    "devline": "DevLine",
    "linia": "DevLine",
    "девляйн": "DevLine",
    "линия": "DevLine",
    "vesta": "VeSta",
    "веста": "VeSta",
    "si-cam": "Si-Cam",
    "sicam": "Si-Cam",
    "си-кам": "Si-Cam",
    "milesight": "Milesight",
    "tvt": "TVT",
    "sunell": "Sunell",
    "avigilon": "Avigilon",
    "flir": "FLIR",
    "ubiquiti": "Ubiquiti UniFi",
    "unifi video": "Ubiquiti UniFi",
    "tapo": "TP-Link Tapo",
    "tp-link": "TP-Link",
    "tplink": "TP-Link",
    "tl-sc": "TP-Link",
    "mag_52": "TP-Link",
    "vstarcam": "VStarcam",
    "sricam": "Sricam",
    "nvr": "Generic NVR",
    "dvr": "Generic DVR",
    "ipcam": "Generic IPCam",
    "ip camera": "Generic IPCam",
    "ip_camera": "Generic IPCam",
    "webcam": "Generic Webcam",
    "network camera": "Generic IPCam",
    "surveillance": "Generic Surveillance",
    "video server": "Generic Video Server",
    "beward": "Beward",
    "true ip": "True IP",
    "trueip": "True IP",
    "bas-ip": "BAS-IP",
    "basip": "BAS-IP",
    "akuvox": "Akuvox",
    "fanvil": "Fanvil",
    "comelit": "Comelit",
    "fermax": "Fermax",
    "sputnik": "Sputnik (Домофон)",
    "cyfral": "Cyfral",
    "metakom": "Metakom",
    "vizit": "VIZIT",
    "rubetek": "Rubetek",
    "intercom": "Generic Intercom",
    "видеодомофон": "Видеодомофон",
    "домофон": "IP Домофон",
    "door station": "Door Station",
    "door phone": "Door Phone",
    "vto": "Dahua VTO (Домофон)",
    "macroscop": "Macroscop",
    "макроскоп": "Macroscop",
    "dssl": "Trassir",
    "optimus": "Optimus",
    "оптимус": "Optimus",
    "satvision": "Satvision",
    "сатвижн": "Satvision",
    "tantos": "Tantos",
    "тантос": "Tantos",
    "raysharp": "RaySharp",
    "рейшарп": "RaySharp",
    "smartec": "Smartec",
    "смартек": "Smartec",
    "ipeye": "IPEYE",
    "айпиай": "IPEYE",
    "proto-x": "Proto-X",
    "protox": "Proto-X",
    "falcon eye": "Falcon Eye",
    "falconeye": "Falcon Eye",
    "бевард": "Beward",
    "поливижн": "Polyvision",
    "новикам": "Novicam",
    "ростелеком": "Rostelecom IPCam",
    "rostelecom": "Rostelecom IPCam",
    "qtech": "QTECH",
    "com hem": "Com Hem",
    "comhem": "Com Hem",
    "wi-fi hub": "Com Hem Wi-Fi Hub",
}


async def _extract_ssl_domain(ip: str, port: int, timeout: float = 1.5) -> Optional[str]:
    """Extract domain from SSL certificate SubjectAltName or CommonName asynchronously."""
    if port not in (443, 8443, 9443, 10443):
        return None
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx), timeout=timeout
        )
        try:
            ssock = writer.get_extra_info("ssl_object")
            cert = ssock.getpeercert(binary_form=True) if ssock else None
            if cert:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                c = x509.load_der_x509_certificate(cert, default_backend())
                # 1. SubjectAlternativeName
                for ext in c.extensions:
                    if ext.oid.dotted_string == "2.5.29.17":
                        for name in ext.value:
                            val = getattr(name, "value", str(name)).strip().lower()
                            if val and not val.startswith("*") and "." in val:
                                return val
                # 2. CommonName
                for attr in c.subject:
                    if attr.oid.dotted_string == "2.5.4.3":
                        val = str(attr.value).strip().lower()
                        if val and not val.startswith("*") and "." in val:
                            return val
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        pass
    return None



async def _probe_generic_http(
    ip: str,
    ports: List[int],
    credentials: List[Tuple[str, str]],
) -> Dict:
    """Probe HTTP title, Server header, WWW-Authenticate, and camera keyword detection."""
    result = {"success": False, "brand": "", "model": "", "title": "", "http_port": 0}
    if not ports:
        return result

    async with httpx.AsyncClient(verify=False, timeout=3.0, follow_redirects=True) as client:
        for port in ports[:4]:  # test max 4 HTTP ports
            # 1. Specialized TP-Link TL-SC camera metadata probe (/prod)
            try:
                prod_resp = await client.get(f"http://{ip}:{port}/prod", timeout=2.0)
                if prod_resp.status_code == 200 and "initProd" in prod_resp.text:
                    p_text = prod_resp.text
                    nbr_m = re.search(r'initProdNbr\s*=\s*["\']([^"\']+)["\']', p_text)
                    name_m = re.search(r'initProdFullName\s*=\s*["\']([^"\']+)["\']', p_text)
                    model_val = nbr_m.group(1).strip() if nbr_m else "TL-SC Camera"
                    title_val = name_m.group(1).strip() if name_m else "Wireless Surveillance Camera"
                    result.update({
                        "success": True,
                        "brand": "TP-Link",
                        "model": model_val,
                        "title": title_val,
                        "http_port": port,
                        "device_category": "camera",
                        "web_url": f"http://{ip}:{port}/",
                        "snapshot_path": "/jpg/image.jpg",
                        "rtsp_path": "/video.mp4",
                    })
                    # Probe root to see if credentials or auth is needed
                    try:
                        r0 = await client.get(f"http://{ip}:{port}/", timeout=2.0)
                        if r0.status_code == 401:
                            result["auth_required"] = True
                            for u, p in credentials[:2]:
                                if not u:
                                    continue
                                r_auth = await client.get(f"http://{ip}:{port}/jpg/image.jpg", auth=(u, p), timeout=2.0)
                                if r_auth.status_code == 200:
                                    result["credentials"] = {"user": u, "password": p}
                                    result["auth_required"] = False
                                    break
                    except Exception:
                        pass
                    return result
            except Exception:
                pass

            # 2. Specialized Video Intercom / preview.html probe
            try:
                for preview_path in ["/preview.html", "/view.html", "/intercom.html", "/door.html"]:
                    p_scheme = "https" if port in (443, 8443, 9443, 10443) or "443" in str(port) else "http"
                    p_resp = await client.get(f"{p_scheme}://{ip}:{port}{preview_path}", timeout=2.5)
                    p_text = p_resp.text.lower()
                    is_router_body = any(k in p_text for k in ("ismaintwan", "sslhostip", "wireless router", "broadband router", "login.jsp", "tplinkwifi"))
                    has_intercom_kw = any(k in p_text for k in (
                        "canvas", "video", "player", "intercom", "домофон", "vwebclient", "tantos",
                        "qualvision", "beward", "trueip", "bas-ip", "akuvox", "vto", "door station", "door phone"
                    ))
                    if p_resp.status_code in (200, 401) and not is_router_body and has_intercom_kw:
                        p_title_m = re.search(r"<title[^>]*>([^<]{1,128})</title>", p_resp.text, re.IGNORECASE)
                        p_title = p_title_m.group(1).strip() if p_title_m else "Видеодомофон"
                        int_brand = "Видеодомофон"
                        if "qualvision" in p_text or "qualvision" in p_title.lower() or "tantos" in p_text or "vwebclient" in p_text:
                            int_brand = "Qualvision / Tantos"
                        elif "beward" in p_text or "beward" in p_title.lower():
                            int_brand = "Beward"
                        elif "trueip" in p_text or "true ip" in p_text:
                            int_brand = "True IP"
                        elif "bas-ip" in p_text or "basip" in p_text:
                            int_brand = "BAS-IP"
                        elif "akuvox" in p_text:
                            int_brand = "Akuvox"
                        elif "dahua" in p_text or "vto" in p_text:
                            int_brand = "Dahua VTO"
                        elif "hikvision" in p_text:
                            int_brand = "Hikvision Intercom"

                        intercom_res = {
                            "success": True,
                            "brand": int_brand,
                            "model": p_title or "IP Intercom (Видеодомофон)",
                            "title": p_title or "Видеодомофон Web Preview",
                            "http_port": port,
                            "device_category": "intercom",
                            "web_url": f"{p_scheme}://{ip}:{port}{preview_path}",
                            "snapshot_path": preview_path,
                            "rtsp_path": "/live/ch0",
                            "auth_required": p_resp.status_code == 401,
                        }

                        # Test credentials (admin / empty string and common defaults)
                        test_creds = credentials if credentials else [("admin", ""), ("admin", "admin"), ("admin", "123456")]
                        for u, p in test_creds:
                            try:
                                r_test = await client.get(f"{p_scheme}://{ip}:{port}{preview_path}", auth=(u, p), timeout=2.0)
                                if r_test.status_code == 200:
                                    intercom_res["credentials"] = {"user": u, "password": p}
                                    intercom_res["auth_required"] = False
                                    break
                            except Exception:
                                pass
                        return intercom_res
            except Exception:
                pass

            creds_to_try = credentials[:2] if credentials else [("", "")]
            scheme = "https" if port in (443, 8443, 9443, 10443) or "443" in str(port) else "http"
            for user, password in creds_to_try:
                auth = (user, password) if user else None
                try:
                    try:
                        resp = await client.get(f"{scheme}://{ip}:{port}/", auth=auth, timeout=3.0)
                    except Exception:
                        if scheme == "http":
                            resp = await client.get(f"https://{ip}:{port}/", auth=auth, timeout=3.0)
                            scheme = "https"
                        else:
                            raise

                    if resp.status_code == 400 and ("https" in resp.text.lower() or "ssl" in resp.text.lower()):
                        resp = await client.get(f"https://{ip}:{port}/", auth=auth, timeout=3.0)
                        scheme = "https"

                    domain = ""
                    ssl_port = port if (scheme == "https" or port in (443, 8443, 9443, 10443)) else (443 if 443 in ports else (8443 if 8443 in ports else 0))
                    if ssl_port:
                        domain = (await _extract_ssl_domain(ip, ssl_port)) or ""
                    if not domain and port in (443, 8443, 9443, 10443):
                        domain = (await _extract_ssl_domain(ip, port)) or ""
                    if domain:
                        result["domain"] = domain
                    web_host = domain or ip
                    if (scheme == "https" and port == 443) or (443 in ports and scheme == "http"):
                        default_web_url = f"https://{web_host}/"
                    else:
                        default_web_url = f"{scheme}://{web_host}:{port}/"

                    text = resp.text[:4096]
                    server = resp.headers.get("server", "")
                    www_auth = resp.headers.get("www-authenticate", "")
                    title_m = re.search(r"<title[^>]*>([^<]{1,128})</title>", text, re.IGNORECASE)
                    title = title_m.group(1).strip() if title_m else ""
                    combined = (title + " " + server + " " + www_auth + " " + text).lower()
                    server_l = server.lower()

                    if resp.status_code == 401:
                        result["auth_required"] = True
                        default_http_creds = [("admin", "admin"), ("admin", "12345"), ("admin", "123456"), ("root", "root"), ("admin", "")]
                        try_creds = list(credentials or []) + [c for c in default_http_creds if c not in (credentials or [])]
                        for cand_u, cand_p in try_creds[:6]:
                            try:
                                cand_auth = httpx.DigestAuth(cand_u, cand_p) if "digest" in www_auth.lower() else (cand_u, cand_p)
                                cand_r = await client.get(f"{scheme}://{ip}:{port}/", auth=cand_auth, timeout=2.0)
                                if cand_r.status_code == 401 and "digest" not in www_auth.lower() and cand_u:
                                    cand_r = await client.get(f"{scheme}://{ip}:{port}/", auth=httpx.DigestAuth(cand_u, cand_p), timeout=2.0)
                                if cand_r.status_code == 200:
                                    result["credentials"] = {"user": cand_u, "password": cand_p}
                                    result["auth_required"] = False
                                    resp = cand_r
                                    text = resp.text[:4096]
                                    break
                            except Exception:
                                pass

                    if not result.get("credentials") and ("<form" in text.lower() or "login" in text.lower() or result.get("auth_required")):
                        try:
                            from .web_login import probe_web_form_login
                            f_match = await probe_web_form_login(
                                ip=ip, port=port, base_url=default_web_url,
                                brand=result.get("brand", ""), credentials=credentials,
                                html_text=text,
                            )
                            if f_match:
                                result["credentials"] = {"user": f_match[0], "password": f_match[1]}
                                result["auth_required"] = False
                        except Exception:
                            pass

                    # DevLine («Линия») CCTV server detection
                    if "devline" in server_l or "linia server" in server_l or "devline" in combined or "линия" in combined:
                        result.update({
                            "success": True,
                            "brand": "DevLine",
                            "model": "DevLine Линия (NVR/VMS)",
                            "title": title or "DevLine Линия Surveillance",
                            "http_port": port,
                            "device_category": "camera",
                            "web_url": default_web_url,
                            "snapshot_path": "/cameras/0/image",
                            "rtsp_path": "/live/stream/0",
                            "auth_required": resp.status_code == 401,
                        })
                        return result

                    # VeSta / Xiongmai Web interface detection
                    if any(k in combined for k in ("vesta", "dvr_preview", "stream_main.png", "webcapture.jpg", "snap.jpg?jpegcam=")):
                        v_brand = "VeSta" if "vesta" in combined else "Xiongmai"
                        result.update({
                            "success": True,
                            "brand": v_brand,
                            "model": title or f"{v_brand} DVR/NVR",
                            "title": title or f"{v_brand} Web Client",
                            "http_port": port,
                            "device_category": "camera",
                            "web_url": default_web_url,
                            "snapshot_path": "/webcapture.jpg?command=snap&channel=1",
                            "rtsp_path": "/user=admin&password=&channel=1&stream=0.sdp?real_stream",
                            "auth_required": resp.status_code == 401,
                        })
                        return result

                    # Si-Cam (СИ-КАМ) detection
                    if any(k in combined for k in ("si-cam", "sicam", "си-кам")):
                        result.update({
                            "success": True,
                            "brand": "Si-Cam",
                            "model": title or "Si-Cam Network Camera",
                            "title": title or "Si-Cam Surveillance",
                            "http_port": port,
                            "device_category": "camera",
                            "web_url": default_web_url,
                            "snapshot_path": "/cgi-bin/snapshot.cgi",
                            "rtsp_path": "/live/main",
                            "auth_required": resp.status_code == 401,
                        })
                        return result

                    # Com Hem / Sagemcom Wi-Fi Hub detection
                    if "com hem" in combined or "comhem" in combined or "wi-fi hub" in combined or "wifi hub" in combined:
                        result.update({
                            "success": True,
                            "brand": "Com Hem",
                            "model": title or "Wi-Fi Hub",
                            "title": title or "Com Hem Wi-Fi Hub",
                            "http_port": port,
                            "device_category": "router",
                            "web_url": f"{scheme}://{ip}:{port}/login.html" if "login" in combined else f"{scheme}://{ip}:{port}/",
                            "auth_required": True,
                        })
                        return result

                    # Check TP-Link realm signature (mag_52, mag_*)
                    if re.search(r'realm=["\']mag_\d+["\']', www_auth, re.IGNORECASE):
                        result.update({
                            "success": True,
                            "brand": "TP-Link",
                            "model": "TL-SC Camera",
                            "title": title or "Wireless Surveillance Camera",
                            "http_port": port,
                            "device_category": "camera",
                            "web_url": f"{scheme}://{ip}:{port}/",
                            "auth_required": resp.status_code == 401,
                            "snapshot_path": "/jpg/image.jpg",
                            "rtsp_path": "/video.mp4",
                        })
                        if auth and resp.status_code == 200:
                            result["credentials"] = {"user": user, "password": password}
                        return result

                    # Dedicated web / media server detection (Icecast, HPLC simulator, etc.)
                    if "icecast" in server_l or "icecast" in combined:
                        result.update({
                            "success": True,
                            "brand": "Icecast",
                            "model": server.strip() or "Icecast Media Server",
                            "title": title or "Icecast Streaming Media Server",
                            "http_port": port,
                            "device_category": "generic_web",
                            "web_url": f"{scheme}://{ip}:{port}/",
                        })
                        return result

                    if "hplc simulator" in combined or "hplcsim" in combined:
                        result.update({
                            "success": True,
                            "brand": "HPLC Simulator",
                            "model": "Web Application",
                            "title": title or "HPLC Simulator",
                            "http_port": port,
                            "device_category": "generic_web",
                            "web_url": f"{scheme}://{ip}:{port}/",
                        })
                        return result

                    # Menu planning / enterprise web application («МАП Комплекс» / MapWebServer)
                    if "mapwebserver" in combined or "мап комплекс" in combined:
                        result.update({
                            "success": True,
                            "brand": "МАП Комплекс (Меню)",
                            "model": "MapWebServer",
                            "title": title or "МАП Комплекс",
                            "http_port": port,
                            "device_category": "generic_web",
                            "web_url": f"{scheme}://{ip}:{port}/",
                        })
                        return result

                    # Schneider Electric PowerLogic ION 7650 / RomPager
                    if "powerlogic" in combined or "ion 7650" in combined or "ion7650" in combined or "powermeasurement" in combined:
                        result.update({
                            "success": True,
                            "brand": "Schneider Electric",
                            "model": "PowerLogic ION 7650",
                            "title": title or "PowerLogic ION 7650 Power Quality Analyzer",
                            "http_port": port,
                            "device_category": "iot",
                            "web_url": f"{scheme}://{ip}:{port}/",
                        })
                        return result

                    # Coolify self-hosting / PaaS platform
                    if "coolify" in combined or "coollabs" in combined:
                        result.update({
                            "success": True,
                            "brand": "Coolify",
                            "model": "Coolify Cloud Platform",
                            "title": title or "Coolify Self-Hosting Platform",
                            "http_port": port,
                            "device_category": "server",
                            "web_url": f"{scheme}://{ip}:{port}/",
                        })
                        return result

                    # Bluesis Telematics & Tracking Platform
                    if "bluesis" in combined:
                        result.update({
                            "success": True,
                            "brand": "Bluesis",
                            "model": "Bluesis Telematics Web",
                            "title": title or "Bluesis Telematics Platform",
                            "http_port": port,
                            "device_category": "iot",
                            "web_url": f"{scheme}://{ip}:{port}/",
                        })
                        return result

                    # Miltera Electronics and Software Technologies
                    if "miltera" in combined:
                        result.update({
                            "success": True,
                            "brand": "Miltera",
                            "model": "Miltera IoT / Telemetry Platform",
                            "title": title or "Miltera Electronics and Software Technologies",
                            "http_port": port,
                            "device_category": "iot",
                            "web_url": f"{scheme}://{ip}:{port}/",
                        })
                        return result

                    # Robustel IoT Cellular Gateway / Router
                    if "robustel" in combined or "robustos" in combined or "cs_auth_username" in combined:
                        result.update({
                            "success": True,
                            "brand": "Robustel",
                            "model": "Robustel Gateway / Router",
                            "title": title or "Robustel Router Web",
                            "http_port": port,
                            "device_category": "router",
                            "web_url": f"{scheme}://{ip}:{port}/auth/" if "/auth" in combined or "/auth" in str(resp.url) else f"{scheme}://{ip}:{port}/",
                        })
                        return result

                    # InHand Networks InRouter
                    if "inhand" in combined or "inrouter" in combined or "check_auth.jsp?_ajax=1" in combined:
                        result.update({
                            "success": True,
                            "brand": "InHand Networks",
                            "model": "InRouter Industrial Router",
                            "title": title or "InHand InRouter Login",
                            "http_port": port,
                            "device_category": "router",
                            "web_url": f"{scheme}://{ip}:{port}/login.jsp",
                        })
                        return result

                    # Teltonika RutOS Router
                    if "teltonika" in combined or "rutos" in combined or "/brand/tokens.css" in combined or "/brand/colors.css" in combined:
                        result.update({
                            "success": True,
                            "brand": "Teltonika",
                            "model": "RutOS Gateway / Router",
                            "title": title or "Teltonika RutOS Web",
                            "http_port": port,
                            "device_category": "router",
                            "web_url": f"{scheme}://{ip}:{port}/",
                        })
                        return result

                    # TR-069 CWMP Management
                    if port == 7547 or "tr069" in combined or "cwmp" in combined:
                        result.update({
                            "success": True,
                            "brand": "TR-069 CWMP",
                            "model": "TR-069 CPE Agent",
                            "title": title or "TR-069 CPE Management Service",
                            "http_port": port,
                            "device_category": "router",
                            "web_url": f"{scheme}://{ip}:{port}/",
                        })
                        return result

                    # Hikvision / HiWatch / OEM IP camera web redirect
                    if "doc/page/login.asp" in combined or "doc/page/login.asp" in text:
                        result.update({
                            "success": True,
                            "brand": "Hikvision",
                            "model": "IP Camera Web Client",
                            "title": title or "Hikvision IP Camera Web",
                            "http_port": port,
                            "device_category": "camera",
                            "web_url": f"{scheme}://{ip}:{port}/doc/page/login.asp",
                            "snapshot_path": "/ISAPI/Streaming/channels/101/picture",
                            "rtsp_path": "/Streaming/Channels/101",
                        })
                        return result

                    # Qualvision / Tantos Intercom
                    if "qualvision" in combined or "tantos" in combined or "vwebclient.exe" in combined or "vms.tantos.pro" in combined:
                        result.update({
                            "success": True,
                            "brand": "Qualvision / Tantos",
                            "model": "IP Intercom (Видеодомофон)",
                            "title": title or "Qualvision / Tantos Video Intercom",
                            "http_port": port,
                            "device_category": "intercom",
                            "web_url": f"{scheme}://{ip}:{port}/",
                            "snapshot_path": "/preview.html",
                            "rtsp_path": "/live/ch0",
                        })
                        return result

                    # Unimo DVR ActiveX (UDROCX_H264)
                    if "udrocx" in combined or "dvr_h264 activex" in combined or "unimo" in combined:
                        result.update({
                            "success": True,
                            "brand": "Unimo",
                            "model": "DVR_H264",
                            "title": title or "DVR_H264 ActiveX",
                            "http_port": port,
                            "device_category": "camera",
                            "web_url": f"{scheme}://{ip}:{port}/",
                            "snapshot_path": "/cgi-bin/webapp.cgi?MODE=8&ID=admin&PW=&VER=3000&CH=1",
                            "rtsp_path": "/live.sdp",
                        })
                        return result

                    # Ants DVR Web Client (ants_dvr / dvr_setup.exe)
                    if "ants_dvr" in combined or "dvr_setup.exe" in combined or "setdvrip" in combined:
                        result.update({
                            "success": True,
                            "brand": "Generic DVR",
                            "model": "Ants H.264 DVR",
                            "title": title or "Web Client (Ants DVR)",
                            "http_port": port,
                            "device_category": "camera",
                            "web_url": f"{scheme}://{ip}:{port}/",
                            "snapshot_path": "/cgi-bin/snapshot.cgi?channel=1",
                            "rtsp_path": "/live/ch0",
                        })
                        return result

                    # Chinese DVR / IP Camera with Live.html frameset (PCViewX / WebCamX / cookieFun)
                    if "connect the dvr server" in combined or "pcviewx" in combined or "webcamx" in combined or ("cookiefun.js" in combined and "ocxcookie" in combined) or "main_live.html" in combined:
                        result.update({
                            "success": True,
                            "brand": "Generic DVR",
                            "model": "H.264 DVR (Live WebViewer)",
                            "title": title or "DVR WebViewer Live",
                            "http_port": port,
                            "device_category": "camera",
                            "web_url": f"{scheme}://{ip}:{port}/Live.html",
                            "snapshot_path": "/snapshot.jpg",
                            "rtsp_path": "/live/ch0",
                        })
                        return result

                    # Vivotek Camera / NVR (VVTK-HTTP-Server / realm ND8322P)
                    if "vvtk-http-server" in server_l or "vivotek" in combined or "vvtk" in combined or 'realm="nd8322' in www_auth.lower():
                        m = re.search(r"vivotek\s+([a-z0-9_-]+)", title, re.IGNORECASE)
                        model_val = m.group(1).strip() if m else ("ND8322P" if "nd8322" in combined else "Vivotek Camera/NVR")
                        result.update({
                            "success": True,
                            "brand": "Vivotek",
                            "model": model_val,
                            "title": title or f"Vivotek {model_val}",
                            "http_port": port,
                            "device_category": "camera",
                            "web_url": f"{scheme}://{ip}:{port}/",
                            "snapshot_path": "/cgi-bin/camctrl/snapshot.cgi",
                            "rtsp_path": "/live.sdp",
                            "auth_required": resp.status_code == 401 or "digest" in www_auth.lower(),
                        })
                        return result

                    # Flussonic Streamer
                    if "streamer" in server_l or "flussonic" in server_l or "flussonic" in combined:
                        result.update({
                            "success": True,
                            "brand": "Flussonic",
                            "model": server.strip() or "Flussonic Streamer",
                            "title": title or "Flussonic Video Server",
                            "http_port": port,
                            "domain": domain,
                            "device_category": "camera",
                            "web_url": default_web_url,
                        })
                        return result

                    brand = ""

                    # 1. Specialized surveillance server headers
                    if any(s in server_l for s in ("dnvrs", "hikvision-webs", "app-webs", "dvrdvs-webs")):
                        brand = "Hikvision"
                    elif "streamer" in server_l or "flussonic" in server_l or "flussonic" in combined:
                        brand = "Flussonic"
                    elif "trassir" in server_l or "trassir" in combined or "dssl" in combined:
                        brand = "Trassir"
                    elif "macroscop" in server_l or "macroscop" in combined or "макроскоп" in combined:
                        brand = "Macroscop"
                    elif "reolink" in server_l or "reolink" in combined or ("data-application=web" in text and "reolink" in text.lower()):
                        brand = "Reolink"

                    # 2. Keyword detection from _CAMERA_BRANDS
                    if not brand:
                        for keyword, brand_name in _CAMERA_BRANDS.items():
                            if re.search(rf"\b{re.escape(keyword)}\b", combined, re.IGNORECASE):
                                brand = brand_name
                                break

                    # Require explicit camera / surveillance context
                    has_cam_context = bool(
                        re.search(r"\b(rtsp|ipcam|ipcamera|webcam|cctv|dvr|nvr|onvif|netcam)\b", combined, re.IGNORECASE)
                        or (("camera" in combined or "surveillance" in combined) and any(w in combined for w in ("login", "channel", "live", "video-stream", "view")))
                    )

                    # Strict RVi safety: prevent matching on ordinary websites that have "rvi" substring or word
                    if not brand and re.search(r"\brvi\b", combined, re.IGNORECASE):
                        if has_cam_context or "rvi-" in combined:
                            brand = "RVi"

                    if brand or has_cam_context:
                        result.update({
                            "success": True,
                            "brand": brand or "Generic IPCam",
                            "title": title,
                            "http_port": port,
                            "device_category": "camera",
                            "web_url": f"{scheme}://{ip}:{port}/",
                        })
                        if brand == "Macroscop":
                            result["snapshot_path"] = "/image?channelid=0"
                            result["rtsp_path"] = "/channel1"
                        elif brand == "Trassir":
                            result["snapshot_path"] = "/screenshot/0"
                            result["rtsp_path"] = "/trassir-video/0"
                        elif brand in ("RaySharp", "Tantos"):
                            result["snapshot_path"] = "/cgi-bin/snapshot.cgi?chn=0"
                            result["rtsp_path"] = "/ch0_0.264"
                        elif brand in ("TVT", "Novicam", "Optimus", "LTV", "Satvision"):
                            result["snapshot_path"] = "/cgi-bin/snapshot.cgi?channel=1"
                            result["rtsp_path"] = "/ch01.264"
                        return result

                    # Check router signatures
                    from .router import ROUTER_BRAND_SIGNATURES, GENERIC_ROUTER_KEYWORDS
                    for r_brand, patterns in ROUTER_BRAND_SIGNATURES:
                        if any(re.search(pat, combined, re.IGNORECASE) for pat in patterns):
                            result.update({
                                "success": True,
                                "brand": r_brand,
                                "model": title or f"{r_brand} Router",
                                "title": title,
                                "http_port": port,
                                "device_category": "router",
                                "web_url": f"http://{ip}:{port}/",
                            })
                            return result

                    if any(re.search(pat, combined, re.IGNORECASE) for pat in GENERIC_ROUTER_KEYWORDS):
                        result.update({
                            "success": True,
                            "brand": "Generic Router",
                            "model": title or "Broadband Router",
                            "title": title,
                            "http_port": port,
                            "device_category": "router",
                            "web_url": f"http://{ip}:{port}/",
                        })
                        return result

                    # Generic web device fallback (never drop active HTTP services)
                    server_label = (server.split("/")[0].strip() if server else "").strip()
                    result.update({
                        "success": True,
                        "brand": "Generic Web Device",
                        "model": server_label or "Web Service",
                        "title": title or f"HTTP {resp.status_code}",
                        "http_port": port,
                        "device_category": "generic_web",
                        "web_url": f"http://{ip}:{port}/",
                    })
                    return result
                except Exception:
                    continue
    return result


probe_generic_http = _probe_generic_http

