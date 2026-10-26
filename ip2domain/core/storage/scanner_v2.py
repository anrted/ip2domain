"""Camera Scanner v2 — SQLite storage mixin."""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
from typing import Dict, List, Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)



_CAMERA_BRANDS = (
    "hikvision", "hiwatch", "dahua", "axis", "uniview", "unv", "reolink",
    "xiongmai", "rvi-", "rvi cctv", "rvi group", "tiandy", "mobotix", "trassir", "novicam", "ltv",
    "milesight", "tvt", "sunell", "avigilon", "flir", "vivotek", "grandstream",
    "activecam", "polyvision", "tapo", "vstarcam", "sricam", "jovision",
    "topsvision", "beward", "nvsip", "ezviz", "hilook", "imou", "lorex", "foscam",
    "amcrest", "hanwha", "wisenet", "samsung", "cp plus", "bosch", "pelco",
    "herospeed", "srihome", "topsee", "unimo", "udrocx", "ants", "vvtk",
    "devline", "линия", "девляйн", "vesta", "веста", "si-cam", "sicam", "си-кам",
    "macroscop", "макроскоп", "dssl", "optimus", "оптимус", "satvision", "сатвижн",
    "tantos", "тантос", "raysharp", "рейшарп", "smartec", "смартек", "ipeye", "айпиай",
    "proto-x", "protox", "falcon eye", "falconeye", "sputnik", "ростелеком", "qtech"
)

_ROUTER_KEYWORDS = (
    "broadband / gpon", "tr-069", "mikrotik", "keenetic", "openwrt", "router",
    "gpon", "ont", "cpe", "gateway", "routeros", "airos", "edgeos", "zte",
    "huawei home gateway", "adsl", "vdsl", "modem", "zyxel", "d-link", "netgear",
    "teltonika", "robustel", "inhand", "cisco", "meraki", "fortinet",
    "huawei echolife", "eltex", "snr", "totolink", "tenda", "mercusys",
    "tp-link router", "wi-fi router", "dsl-", "tl-wr", "archer"
)

_WEB_SERVER_KEYWORDS = (
    "nginx", "apache", "microsoft-iis", "litespeed", "caddy", "lighttpd"
)

_GENERIC_WEB_TITLES = (
    "401 unauthorized", "403 forbidden", "404 not found", "500 internal",
    "welcome to nginx", "apache2 ubuntu default page", "iis windows server",
    "test page", "under construction", "index of /"
)


def _match_camera_brand(b: str, m: str, t: str) -> bool:
    """Accurately match camera vendor strings without substring collisions like 'rvi' in 'service'."""
    comb = f"{b} {m} {t}".lower()
    if b in ("generic web device", "unknown", "") and m in ("web service", "http", ""):
        return False
    if "rvi" in comb:
        if bool(re.search(r"\brvi\b", comb)) and "service" not in comb:
            return True
        if "rvi-" in comb or "rvi cctv" in comb or "rvi group" in comb:
            return True
    return any(cb in comb for cb in _CAMERA_BRANDS)


def classify_v2_device(
    brand: str = "",
    model: str = "",
    title: str = "",
    protos: Optional[List[str]] = None,
    streams: Optional[List[Dict]] = None,
    open_ports: Optional[List[int]] = None,
    cur_cat: str = "",
) -> str:
    """Classify a scan result into its canonical device category."""
    b = (brand or "").lower()
    m = (model or "").lower()
    t = (title or "").lower()
    p_str = " ".join(str(p) for p in (protos or [])).lower()

    if "sprecord" in b or "sprecord" in m or "sprecord" in p_str:
        return "sprecord"
    if any(ic in b or ic in m or ic in t for ic in ("intercom", "видеодомофон", "door station", "akuvox", "bas-ip", "true ip")):
        return "intercom"

    has_verified_stream = any(
        bool(s.get("verified")) and s.get("type") != "web_panel" and s.get("stream_type") != "web_panel"
        for s in (streams or [])
    )
    if has_verified_stream:
        return "camera"

    # Explicit check: Generic Web Device without camera ports or verified streams is always generic_web
    is_pure_generic_web = (
        b in ("generic web device", "generic", "unknown", "")
        and m in ("web service", "http", "")
        and not any(p in (554, 8554, 34567, 37777, 9780, 8899) for p in (open_ports or []))
        and not any(cp in p_str for cp in ("rtsp", "dhip", "sofia", "isapi", "onvif", "vesta", "devline"))
    )
    if is_pure_generic_web:
        return "generic_web"

    # Industrial automation, sensors, telemetry (Modbus, IEC 60870)
    if any(ind in b or ind in m or ind in t or ind in p_str for ind in ("modbus", "iec104", "iec 60870", "powerlogic", "scada", "plc", "метеостанция", "асудд")):
        return "industrial"
    if open_ports and any(p in (502, 2404) for p in open_ports) and not any(p in (554, 8554, 34567, 37777) for p in open_ports):
        return "industrial"

    # Remote desktop / terminals (RDP, VNC)
    if any(rd in b or rd in m or rd in p_str for rd in ("rdp", "vnc")):
        return "device"
    if open_ports and any(p in (3389, 5900) for p in open_ports) and not any(p in (554, 8554, 34567, 37777) for p in open_ports):
        return "device"

    is_router_sig = (
        any(rk in b or rk in m or rk in t for rk in _ROUTER_KEYWORDS)
        or "http_router" in p_str or "winbox" in p_str or "router" in p_str or "vpn" in p_str
        or (b == "ubiquiti unifi" and any(u in t for u in ("edgeos", "airos", "unifi network", "unifi os")))
        or ("tp-link" in b and not any(k in m or k in b for k in ("tapo", "kasa", "tl-sc")))
        or (open_ports and any(p in (1701, 1723, 8291, 7547, 8728, 8729) for p in open_ports) and not any(p in (554, 8554, 34567, 37777, 9780) for p in open_ports))
    )
    if is_router_sig:
        return "router"

    # Camera brand detection by brand, model, or title (DevLine, VeSta, Si-Cam, Hikvision, etc.)
    if _match_camera_brand(b, m, t):
        return "camera"

    if any(wk in b or wk in m or wk in t for wk in _WEB_SERVER_KEYWORDS):
        return "generic_web"

    if b in ("generic web device", "generic", "unknown", "") and (
        any(gt in t for gt in _GENERIC_WEB_TITLES) or not any(p in (554, 8554, 34567, 37777, 9780) for p in (open_ports or []))
    ):
        return "generic_web"

    if any(p in (554, 8554, 34567, 37777, 9780, 8899) for p in (open_ports or [])) or any(cp in p_str for cp in ("rtsp", "dhip", "sofia", "isapi", "onvif", "vesta", "devline")):
        return "camera"

    cur_norm = (cur_cat or "").lower().strip()
    return cur_norm if cur_norm in ("router", "generic_web", "server", "iot", "device") else "generic_web"


class ScannerV2StorageMixin:
    """Adds v2_results and v2_jobs tables to the StorageManager."""

    def _init_v2_tables(self):
        """Initialize v2 scanner tables (called from BaseStorage._init_db)."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS v2_results (
                    ip          TEXT PRIMARY KEY,
                    brand       TEXT DEFAULT '',
                    model       TEXT DEFAULT '',
                    serial      TEXT DEFAULT '',
                    protocols   TEXT DEFAULT '[]',
                    streams_json TEXT NOT NULL DEFAULT '[]',
                    result_json TEXT NOT NULL,
                    is_garbage  INTEGER DEFAULT 0,
                    in_go2rtc   INTEGER DEFAULT 0,
                    device_category TEXT DEFAULT '',
                    has_preview INTEGER DEFAULT 0,
                    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_v2_results_brand
                ON v2_results(brand, updated_at DESC)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_v2_results_active
                ON v2_results(is_garbage, updated_at DESC)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_v2_results_cat
                ON v2_results(device_category, is_garbage)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_v2_results_preview
                ON v2_results(is_garbage, has_preview DESC, updated_at DESC)
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS v2_jobs (
                    job_id      TEXT PRIMARY KEY,
                    status      TEXT NOT NULL DEFAULT 'queued',
                    targets_str TEXT DEFAULT '',
                    current_index INTEGER DEFAULT 0,
                    params_json TEXT NOT NULL DEFAULT '{}',
                    total_targets INTEGER DEFAULT 0,
                    found_cameras INTEGER DEFAULT 0,
                    engine_used TEXT DEFAULT '',
                    progress_pct INTEGER DEFAULT 0,
                    stage       TEXT DEFAULT '',
                    logs_json   TEXT DEFAULT '[]',
                    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Auto-migrate tables if created with earlier schema
            res_cols = [r[1] for r in conn.execute("PRAGMA table_info(v2_results)").fetchall()]
            if "device_category" not in res_cols:
                try:
                    conn.execute("ALTER TABLE v2_results ADD COLUMN device_category TEXT DEFAULT ''")
                    conn.execute("""
                        UPDATE v2_results SET device_category = 
                        CASE 
                            WHEN result_json LIKE '%"device_category": "router"%' OR result_json LIKE '%"categories":%"router"%' THEN 'router'
                            WHEN result_json LIKE '%"device_category": "intercom"%' THEN 'intercom'
                            WHEN result_json LIKE '%"device_category": "generic_web"%' THEN 'generic_web'
                            WHEN result_json LIKE '%"device_category": "sprecord"%' OR result_json LIKE '%"sprecord"%' THEN 'sprecord'
                            WHEN result_json LIKE '%"device_category": "device"%' THEN 'device'
                            ELSE 'camera'
                        END
                    """)
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_v2_results_cat ON v2_results(device_category, is_garbage)")
                except Exception:
                    pass
            if "has_preview" not in res_cols:
                try:
                    conn.execute("ALTER TABLE v2_results ADD COLUMN has_preview INTEGER DEFAULT 0")
                    conn.execute("""
                        UPDATE v2_results SET has_preview = 
                        CASE 
                            WHEN streams_json LIKE '%/v2_captures/%' OR streams_json LIKE '%"screenshot": "/%' OR result_json LIKE '%"web_screenshot": "/%' THEN 1
                            ELSE 0
                        END
                    """)
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_v2_results_preview ON v2_results(is_garbage, has_preview DESC, updated_at DESC)")
                except Exception:
                    pass

            if "has_verified" not in res_cols:
                try:
                    conn.execute("ALTER TABLE v2_results ADD COLUMN has_verified INTEGER DEFAULT 0")
                    conn.execute("""
                        UPDATE v2_results SET has_verified = 
                        CASE 
                            WHEN streams_json LIKE '%"verified": true%' THEN 1 
                            ELSE 0 
                        END
                    """)
                except Exception:
                    pass

            if "city" not in res_cols:
                try:
                    conn.execute("ALTER TABLE v2_results ADD COLUMN city TEXT DEFAULT ''")
                    conn.execute("ALTER TABLE v2_results ADD COLUMN region TEXT DEFAULT ''")
                    conn.execute("ALTER TABLE v2_results ADD COLUMN country_code TEXT DEFAULT ''")
                    conn.execute("""
                        UPDATE v2_results SET 
                            city = COALESCE(json_extract(result_json, '$.city'), ''),
                            region = COALESCE(json_extract(result_json, '$.region'), ''),
                            country_code = COALESCE(json_extract(result_json, '$.country_code'), '')
                    """)
                except Exception:
                    pass

            if "auth_required" not in res_cols:
                try:
                    conn.execute("ALTER TABLE v2_results ADD COLUMN auth_required INTEGER DEFAULT NULL")
                    conn.execute("""
                        UPDATE v2_results SET auth_required = 
                        CASE 
                            WHEN result_json LIKE '%"auth_required": true%' THEN 1
                            WHEN result_json LIKE '%"auth_required": false%' THEN 0
                            ELSE NULL
                        END
                    """)
                except Exception:
                    pass

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_v2_results_feed
                ON v2_results(is_garbage, has_verified DESC, has_preview DESC, updated_at DESC)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_v2_results_city
                ON v2_results(is_garbage, city)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_v2_results_country
                ON v2_results(is_garbage, country_code)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_v2_results_auth
                ON v2_results(is_garbage, auth_required)
            """)

            cols = [r[1] for r in conn.execute("PRAGMA table_info(v2_jobs)").fetchall()]
            if "current_index" not in cols:
                try:
                    conn.execute("ALTER TABLE v2_jobs ADD COLUMN current_index INTEGER DEFAULT 0")
                except Exception:
                    pass
            if "targets_str" not in cols:
                try:
                    conn.execute("ALTER TABLE v2_jobs ADD COLUMN targets_str TEXT DEFAULT ''")
                except Exception:
                    pass
            if "stage1_hosts_json" not in cols:
                try:
                    conn.execute("ALTER TABLE v2_jobs ADD COLUMN stage1_hosts_json TEXT DEFAULT ''")
                except Exception:
                    pass
            conn.commit()

    def save_v2_result(self, result: Dict) -> None:
        """Upsert a single camera result from v2 scanner."""
        ip = str(result.get("ip", "")).strip()
        if not ip:
            return
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            previous = conn.execute("SELECT result_json FROM v2_results WHERE ip = ?", (ip,)).fetchone()
            result = dict(result)
            target_is_private = False
            try:
                target_is_private = ipaddress.ip_address(ip).is_private
            except ValueError:
                pass

            def _clean_stream_key(u: str) -> str:
                return re.sub(r"://[^/@]+@", "://", u)

            def _is_routable_stream(s: Dict) -> bool:
                if target_is_private:
                    return True
                u = s.get("url") or ""
                try:
                    host = urlsplit(u).hostname
                    if host and ipaddress.ip_address(host).is_private:
                        return False
                except Exception:
                    pass
                return True

            if previous:
                old = json.loads(previous[0])

                # Only preserve previously verified streams from old scans; discard old dead/speculative guesses
                old_verified = [
                    s for s in old.get("streams", [])
                    if s.get("url") and s.get("verified") and _is_routable_stream(s)
                ]
                streams = {_clean_stream_key(s["url"]): s for s in old_verified}
                for stream in result.get("streams", []):
                    if stream.get("url") and _is_routable_stream(stream):
                        streams[_clean_stream_key(stream["url"])] = stream
                result["streams"] = list(streams.values())
                for key in ("protocols", "open_ports"):
                    result[key] = list(dict.fromkeys(old.get(key, []) + result.get(key, [])))
                def endpoint_key(e):
                    return (e.get("port"), e.get("transport", "tcp"), tuple(sorted(e.get("protocols", []))))
                endpoints = {endpoint_key(e): e for e in old.get("endpoints", [])}
                endpoints.update({endpoint_key(e): e for e in result.get("endpoints", [])})
                result["endpoints"] = list(endpoints.values())
                if not result.get("credentials") and old.get("credentials"):
                    result["credentials"] = old["credentials"]
            else:
                result["streams"] = [s for s in result.get("streams", []) if s.get("url") and _is_routable_stream(s)]

            cur_cat = str(result.get("device_category", "")).strip().lower()
            open_ports = result.get("open_ports", [])
            web_title = result.get("web_title", "")
            cat = classify_v2_device(
                brand=result.get("brand", ""),
                model=result.get("model", ""),
                title=web_title,
                protos=result.get("protocols", []),
                streams=result.get("streams", []),
                open_ports=open_ports,
                cur_cat=cur_cat,
            )
            result["device_category"] = cat
            if not result.get("categories") or result.get("categories") == ["camera"]:
                result["categories"] = [cat]

            has_prev = 1 if (
                any(bool(s.get("screenshot")) for s in result.get("streams", []))
                or bool(result.get("web_screenshot"))
            ) else 0

            has_ver = 1 if (
                any(bool(s.get("verified")) and s.get("type") != "web_panel" for s in result.get("streams", []))
                or ('"verified": true' in json.dumps(result.get("streams", [])))
            ) else 0

            auth_req = 1 if result.get("auth_required") is True else (0 if result.get("auth_required") is False else None)
            c_code = str(result.get("country_code") or "")
            c_city = str(result.get("city") or "")
            c_region = str(result.get("region") or "")

            conn.execute(
                """
                INSERT INTO v2_results (ip, brand, model, serial, protocols, streams_json, result_json,
                                        device_category, has_preview, has_verified, country_code, city, region,
                                        auth_required, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(ip) DO UPDATE SET
                    brand = excluded.brand,
                    model = excluded.model,
                    serial = excluded.serial,
                    protocols = excluded.protocols,
                    streams_json = excluded.streams_json,
                    result_json = excluded.result_json,
                    device_category = excluded.device_category,
                    has_preview = excluded.has_preview,
                    has_verified = excluded.has_verified,
                    country_code = CASE WHEN excluded.country_code != '' THEN excluded.country_code ELSE country_code END,
                    city = CASE WHEN excluded.city != '' THEN excluded.city ELSE city END,
                    region = CASE WHEN excluded.region != '' THEN excluded.region ELSE region END,
                    auth_required = COALESCE(excluded.auth_required, auth_required),
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    ip,
                    str(result.get("brand", "")),
                    str(result.get("model", "")),
                    str(result.get("serial", "")),
                    json.dumps(result.get("protocols", []), ensure_ascii=False),
                    json.dumps(result.get("streams", []), ensure_ascii=False),
                    json.dumps(result, ensure_ascii=False),
                    cat,
                    has_prev,
                    has_ver,
                    c_code,
                    c_city,
                    c_region,
                    auth_req,
                ),
            )

    def update_v2_stream(self, ip: str, stream: Dict) -> None:
        """Persist one captured URL without rolling back other concurrent updates."""
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT result_json FROM v2_results WHERE ip = ?", (ip,)).fetchone()
            if not row:
                return
            result = json.loads(row[0])
            for existing in result.get("streams", []):
                if existing.get("url") == stream.get("url"):
                    existing.update(stream)
                    break
            else:
                return
            has_prev = 1 if (
                any(bool(s.get("screenshot")) for s in result.get("streams", []))
                or bool(result.get("web_screenshot"))
            ) else 0
            has_ver = 1 if (
                any(bool(s.get("verified")) and s.get("type") != "web_panel" for s in result.get("streams", []))
            ) else 0
            conn.execute("UPDATE v2_results SET result_json = ?, streams_json = ?, has_preview = ?, has_verified = ? WHERE ip = ?",
                         (json.dumps(result, ensure_ascii=False), json.dumps(result.get("streams", []), ensure_ascii=False), has_prev, has_ver, ip))

    def update_v2_geo(self, ip: str, geo: Dict) -> bool:
        """Update only geolocation, preserving concurrently captured frames."""
        keys = {"city", "region", "country_code", "isp", "geo_precision", "geo_source",
                "geo_accuracy_radius_km", "geo_database_date"}
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT result_json FROM v2_results WHERE ip = ?", (ip,)).fetchone()
            if not row:
                return False
            result = json.loads(row[0])
            changed = any(result.get(key) != value for key, value in geo.items() if key in keys)
            if changed:
                result.update({key: value for key, value in geo.items() if key in keys})
                conn.execute(
                    "UPDATE v2_results SET result_json = ?, city = ?, region = ?, country_code = ? WHERE ip = ?",
                    (
                        json.dumps(result, ensure_ascii=False),
                        str(geo.get("city") or ""),
                        str(geo.get("region") or ""),
                        str(geo.get("country_code") or ""),
                        ip
                    )
                )
            return changed

    def _build_v2_where_clause(
        self,
        brand: str = "",
        protocol: str = "",
        has_preview: bool = False,
        verified_only: bool = False,
        auth_status: str = "all",
        category: str = "",
        geo: str = "",
        search: str = "",
    ) -> Tuple[str, List]:
        where = " WHERE is_garbage = 0"
        params = []
        if brand and brand != "all":
            where += " AND brand LIKE ?"
            params.append(f"%{brand}%")
        if protocol and protocol != "all":
            where += " AND protocols LIKE ?"
            params.append(f"%{protocol}%")
        if category and category != "all":
            where += " AND (device_category = ? OR result_json LIKE ?)"
            params.append(category)
            params.append(f'%"device_category": "{category}"%')
        if has_preview:
            where += " AND has_preview = 1"
        elif verified_only:
            where += " AND (has_preview = 1 OR has_verified = 1)"
        if auth_status in ("401", "locked", "auth_required"):
            where += " AND (auth_required = 1 OR result_json LIKE '%\"auth_required\": true%')"
        elif auth_status in ("open", "unauthenticated", "no_auth"):
            where += " AND (has_verified = 1 OR auth_required = 0 OR (result_json LIKE '%\"auth_required\": false%' AND streams_json LIKE '%\"url\"%'))"
        if geo and geo != "all":
            if geo == "__no_geo__":
                where += " AND (city = '' OR city IS NULL)"
            elif geo.startswith("country:"):
                code = geo.replace("country:", "").upper()
                where += " AND (country_code = ? OR json_extract(result_json, '$.country_code') = ?)"
                params.extend([code, code])
            elif geo.startswith("region:"):
                reg = geo.replace("region:", "")
                where += " AND (region = ? OR json_extract(result_json, '$.region') = ?)"
                params.extend([reg, reg])
            elif geo.startswith("city:"):
                cit = geo.replace("city:", "")
                where += " AND (city = ? OR json_extract(result_json, '$.city') = ?)"
                params.extend([cit, cit])
        if search:
            s = search.strip()
            where += " AND (ip LIKE ? OR brand LIKE ? OR model LIKE ? OR result_json LIKE ?)"
            params.extend([f"%{s}%", f"%{s}%", f"%{s}%", f"%{s}%"])
        return where, params

    def get_v2_results(
        self,
        limit: int = 48,
        offset: int = 0,
        brand: str = "",
        protocol: str = "",
        has_preview: bool = False,
        verified_only: bool = False,
        auth_status: str = "all",
        category: str = "",
        geo: str = "",
        search: str = "",
    ) -> List[Dict]:
        """Retrieve v2 scanner results with server-side pagination and SQL filtering."""
        where_clause, params = self._build_v2_where_clause(
            brand=brand,
            protocol=protocol,
            has_preview=has_preview,
            verified_only=verified_only,
            auth_status=auth_status,
            category=category,
            geo=geo,
            search=search,
        )
        with self._get_connection() as conn:
            query = f"SELECT result_json, in_go2rtc FROM v2_results{where_clause}"
            query += " ORDER BY has_verified DESC, has_preview DESC, updated_at DESC, ip ASC"
            if limit and limit > 0:
                query += " LIMIT ?"
                params.append(limit)
                if offset and offset > 0:
                    query += " OFFSET ?"
                    params.append(offset)

            from ip2domain.data.geo_city_db import normalize_geo
            rows = conn.execute(query, params).fetchall()
            results = []
            for row in rows:
                try:
                    r = json.loads(row["result_json"])
                    clean_geo = normalize_geo(r)
                    r.update(city=clean_geo["city"], region=clean_geo["region"])
                    r.setdefault("geo_precision", clean_geo["precision"])
                    r["in_go2rtc"] = bool(row["in_go2rtc"])

                    if "auth_required" not in r:
                        r["auth_required"] = None

                    results.append(r)
                except Exception:
                    pass

            return results

    def get_v2_results_count(
        self,
        brand: str = "",
        protocol: str = "",
        has_preview: bool = False,
        verified_only: bool = False,
        auth_status: str = "all",
        category: str = "",
        geo: str = "",
        search: str = "",
    ) -> int:
        """Count total results matching the query filters."""
        where_clause, params = self._build_v2_where_clause(
            brand=brand,
            protocol=protocol,
            has_preview=has_preview,
            verified_only=verified_only,
            auth_status=auth_status,
            category=category,
            geo=geo,
            search=search,
        )
        with self._get_connection() as conn:
            query = f"SELECT COUNT(*) FROM v2_results{where_clause}"
            row = conn.execute(query, params).fetchone()
            return row[0] if row else 0

    def get_v2_filtered_ips(
        self,
        brand: str = "",
        protocol: str = "",
        has_preview: bool = False,
        verified_only: bool = False,
        auth_status: str = "all",
        category: str = "",
        geo: str = "",
        search: str = "",
    ) -> List[str]:
        """Return list of distinct clean IP addresses matching the query filters."""
        where_clause, params = self._build_v2_where_clause(
            brand=brand,
            protocol=protocol,
            has_preview=has_preview,
            verified_only=verified_only,
            auth_status=auth_status,
            category=category,
            geo=geo,
            search=search,
        )
        with self._get_connection() as conn:
            query = f"SELECT DISTINCT ip FROM v2_results{where_clause} ORDER BY ip"
            rows = conn.execute(query, params).fetchall()
            ips = []
            for (raw_ip,) in rows:
                ip = (raw_ip or "").strip()
                if ip.startswith("http://") or ip.startswith("https://"):
                    ip = ip.split("//")[-1].split("/")[0]
                if ":" in ip and not ip.startswith("["):
                    ip = ip.split(":")[0]
                if ip:
                    ips.append(ip)
            return ips

    def get_v2_result(self, ip: str) -> Optional[Dict]:
        """Get a single v2 result by IP."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT result_json, in_go2rtc FROM v2_results WHERE ip = ?", (ip,)
            ).fetchone()
            if not row:
                return None
            try:
                r = json.loads(row["result_json"])
                r["in_go2rtc"] = bool(row["in_go2rtc"])
                return r
            except Exception:
                return None

    def clear_v2_results(self) -> None:
        """Delete all v2 results."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM v2_results")

    def delete_v2_result(self, ip: str) -> None:
        """Delete a single v2 result by IP."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM v2_results WHERE ip = ?", (ip,))

    def mark_v2_result_go2rtc(self, ip: str, in_go2rtc: bool) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE v2_results SET in_go2rtc = ? WHERE ip = ?",
                (1 if in_go2rtc else 0, ip),
            )

    def set_v2_garbage(self, ip: str, is_garbage: bool) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE v2_results SET is_garbage = ? WHERE ip = ?",
                (1 if is_garbage else 0, ip),
            )

    def get_v2_stats(self, force_refresh: bool = False) -> Dict:
        """Return protocol, brand, category and global geo statistics for v2 results with fast indexed queries and TTL cache."""
        now = time.time()
        cached = getattr(self, "_v2_stats_cache", None)
        if not force_refresh and cached and (now - cached.get("ts", 0) < 300):
            return cached["data"]

        with self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM v2_results WHERE is_garbage=0").fetchone()[0]
            by_brand = {}
            for row in conn.execute(
                "SELECT brand, COUNT(*) as cnt FROM v2_results WHERE is_garbage=0 GROUP BY brand ORDER BY cnt DESC LIMIT 50"
            ).fetchall():
                by_brand[row["brand"] or "Unknown"] = row["cnt"]

            by_category = {}
            for row in conn.execute(
                "SELECT device_category, COUNT(*) as cnt FROM v2_results WHERE is_garbage=0 GROUP BY device_category"
            ).fetchall():
                cat = row["device_category"] or "camera"
                by_category[cat] = row["cnt"]

            by_country = {}
            for row in conn.execute(
                "SELECT country_code as cc, COUNT(*) as cnt "
                "FROM v2_results WHERE is_garbage=0 AND country_code IS NOT NULL AND country_code != '' "
                "GROUP BY country_code ORDER BY cnt DESC LIMIT 30"
            ).fetchall():
                by_country[row["cc"]] = row["cnt"]

            by_city = {}
            for row in conn.execute(
                "SELECT city as c, COUNT(*) as cnt "
                "FROM v2_results WHERE is_garbage=0 AND city IS NOT NULL AND city != '' "
                "GROUP BY city ORDER BY cnt DESC LIMIT 200"
            ).fetchall():
                by_city[row["c"]] = row["cnt"]

            by_region = {}
            for row in conn.execute(
                "SELECT region as r, COUNT(*) as cnt "
                "FROM v2_results WHERE is_garbage=0 AND region IS NOT NULL AND region != '' "
                "GROUP BY region ORDER BY cnt DESC LIMIT 100"
            ).fetchall():
                by_region[row["r"]] = row["cnt"]

            data = {
                "total": total,
                "by_brand": by_brand,
                "by_category": by_category,
                "by_country": by_country,
                "by_city": by_city,
                "by_region": by_region,
            }
            self._v2_stats_cache = {"ts": now, "data": data}
            return data

    def stream_v2_export_401(self):
        """Streaming generator of 401 camera targets without massive memory allocation or sorting."""
        with self._get_connection() as conn:
            query = """
                SELECT ip, brand, model,
                       COALESCE(json_extract(result_json, '$.rtsp_port'), 554) as port,
                       COALESCE(city, json_extract(result_json, '$.city'), '') as city
                FROM v2_results
                WHERE is_garbage = 0 AND (auth_required = 1 OR result_json LIKE '%"auth_required": true%')
            """
            cursor = conn.execute(query)
            for row in cursor:
                yield {
                    "ip": (row["ip"] or "").strip(),
                    "port": int(row["port"] or 554),
                    "brand": (row["brand"] or "").replace(",", " "),
                    "model": (row["model"] or "").replace(",", " "),
                    "city": (row["city"] or "").replace(",", " "),
                }

    def batch_resolve_v2_geo(self, batch_size: int = 2000) -> Dict:
        """Batch-resolve missing cities/regions using chunked transactions."""
        from ip2domain.data.geo_city_db import geo_city_db, camera_geo_fields

        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT ip, result_json FROM v2_results
                WHERE is_garbage = 0 AND (city = '' OR city IS NULL OR region = '' OR region IS NULL)
                """
            ).fetchall()

            total_needed = len(rows)
            updated_count = 0
            counts = {"city": 0, "region": 0, "country": 0, "unknown": 0}

            batch = []
            for row in rows:
                ip = str(row["ip"] or "").strip()
                if not ip:
                    continue
                try:
                    res = json.loads(row["result_json"])
                except Exception:
                    res = {"ip": ip}

                geo = geo_city_db.find_by_ip(ip)
                fields = camera_geo_fields(geo or {})
                res.update(fields)
                precision = fields.get("geo_precision", "unknown")
                counts[precision] = counts.get(precision, 0) + 1

                batch.append((
                    json.dumps(res, ensure_ascii=False),
                    str(fields.get("city") or ""),
                    str(fields.get("region") or ""),
                    str(fields.get("country_code") or ""),
                    ip,
                ))

                if len(batch) >= batch_size:
                    with conn:
                        conn.executemany(
                            "UPDATE v2_results SET result_json = ?, city = ?, region = ?, country_code = ? WHERE ip = ?",
                            batch,
                        )
                    updated_count += len(batch)
                    batch.clear()

            if batch:
                with conn:
                    conn.executemany(
                        "UPDATE v2_results SET result_json = ?, city = ?, region = ?, country_code = ? WHERE ip = ?",
                        batch,
                    )
                updated_count += len(batch)
                batch.clear()

            self._v2_stats_cache = None

            return {
                "success": True,
                "total_checked": total_needed,
                "updated_count": updated_count,
                "precision_counts": counts,
            }

    # ── Job Persistence & Auto-Resume ─────────────────────────────────────────

    def save_v2_job(self, job_dict: Dict) -> None:
        """Create or update a scan job record in SQLite."""
        job_id = job_dict.get("job_id", "")
        if not job_id:
            return
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO v2_jobs (job_id, status, targets_str, current_index, params_json,
                                     total_targets, found_cameras, engine_used, progress_pct, stage, logs_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(job_id) DO UPDATE SET
                    status = excluded.status,
                    targets_str = CASE WHEN excluded.targets_str != '' THEN excluded.targets_str ELSE targets_str END,
                    current_index = excluded.current_index,
                    params_json = CASE WHEN excluded.params_json != '{}' THEN excluded.params_json ELSE params_json END,
                    total_targets = excluded.total_targets,
                    found_cameras = excluded.found_cameras,
                    engine_used = excluded.engine_used,
                    progress_pct = excluded.progress_pct,
                    stage = excluded.stage,
                    logs_json = excluded.logs_json,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    job_id,
                    job_dict.get("status", "queued"),
                    job_dict.get("targets_str", ""),
                    job_dict.get("current_index", 0),
                    json.dumps(job_dict.get("params", {}), ensure_ascii=False),
                    job_dict.get("total_targets", 0),
                    job_dict.get("results_count", len(job_dict.get("results", []))),
                    job_dict.get("engine_used", ""),
                    job_dict.get("progress_pct", 0),
                    job_dict.get("stage", ""),
                    json.dumps(job_dict.get("logs", []), ensure_ascii=False),
                ),
            )

    def update_v2_job_progress(
        self,
        job_id: str,
        current_index: int,
        progress_pct: int,
        stage: str,
        found_cameras: int,
        logs: Optional[List[str]] = None,
    ) -> None:
        """Lightweight update for scan progress and current target index."""
        with self._get_connection() as conn:
            if logs is not None:
                conn.execute(
                    """
                    UPDATE v2_jobs SET
                        current_index = ?,
                        progress_pct = ?,
                        stage = ?,
                        found_cameras = ?,
                        logs_json = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE job_id = ?
                    """,
                    (current_index, progress_pct, stage, found_cameras, json.dumps(logs[-30:], ensure_ascii=False), job_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE v2_jobs SET
                        current_index = ?,
                        progress_pct = ?,
                        stage = ?,
                        found_cameras = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE job_id = ?
                    """,
                    (current_index, progress_pct, stage, found_cameras, job_id),
                )

    def get_active_v2_job(self) -> Optional[Dict]:
        """Return the latest active/unfinished v2 scan job (status: queued or running)."""
        with self._get_connection() as conn:
            row = conn.execute(
                """
                SELECT job_id, status, targets_str, current_index, params_json, total_targets,
                       found_cameras, engine_used, progress_pct, stage, logs_json, created_at, updated_at
                FROM v2_jobs
                WHERE status IN ('running', 'queued')
                ORDER BY created_at DESC LIMIT 1
                """
            ).fetchone()
            if not row:
                return None
            return {
                "job_id": row["job_id"],
                "status": row["status"],
                "targets_str": row["targets_str"] or "",
                "current_index": row["current_index"] or 0,
                "params": json.loads(row["params_json"] or "{}"),
                "total_targets": row["total_targets"] or 0,
                "found_cameras": row["found_cameras"] or 0,
                "engine_used": row["engine_used"] or "",
                "progress_pct": row["progress_pct"] or 0,
                "stage": row["stage"] or "",
                "logs": json.loads(row["logs_json"] or "[]"),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }

    def get_v2_job(self, job_id: str) -> Optional[Dict]:
        """Get job record by job_id."""
        with self._get_connection() as conn:
            row = conn.execute(
                """
                SELECT job_id, status, targets_str, current_index, params_json, total_targets,
                       found_cameras, engine_used, progress_pct, stage, logs_json, created_at, updated_at
                FROM v2_jobs
                WHERE job_id = ?
                """,
                (job_id,),
            ).fetchone()
            if not row:
                return None
            return {
                "job_id": row["job_id"],
                "status": row["status"],
                "targets_str": row["targets_str"] or "",
                "current_index": row["current_index"] or 0,
                "params": json.loads(row["params_json"] or "{}"),
                "total_targets": row["total_targets"] or 0,
                "found_cameras": row["found_cameras"] or 0,
                "engine_used": row["engine_used"] or "",
                "progress_pct": row["progress_pct"] or 0,
                "stage": row["stage"] or "",
                "logs": json.loads(row["logs_json"] or "[]"),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }

    def mark_v2_job_status(self, job_id: str, status: str) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE v2_jobs SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE job_id = ?",
                (status, job_id),
            )

    def save_v2_stage1_hosts(self, job_id: str, responsive_hosts: list) -> None:
        """Persist Stage 1 responsive hosts [(ip, [ports]), ...] to DB for restart survival."""
        data = json.dumps(responsive_hosts, ensure_ascii=False)
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE v2_jobs SET stage1_hosts_json = ?, updated_at = CURRENT_TIMESTAMP WHERE job_id = ?",
                (data, job_id),
            )

    def get_v2_stage1_hosts(self, job_id: str) -> list:
        """Load saved Stage 1 responsive hosts for auto-resume into Stage 2."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT stage1_hosts_json FROM v2_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if not row or not row[0]:
                return []
            try:
                return json.loads(row[0])
            except Exception:
                return []

    def reclassify_v2_results(self, limit: Optional[int] = None) -> Dict[str, int]:
        """Reclassify existing records in v2_results table using updated signatures."""
        counts: Dict[str, int] = {}
        with self._get_connection() as conn:
            query = "SELECT ip, brand, model, protocols, streams_json, result_json, device_category FROM v2_results"
            if limit:
                query += f" LIMIT {int(limit)}"
            rows = conn.execute(query).fetchall()
            updates = []
            for row in rows:
                ip = row["ip"] if isinstance(row, dict) or hasattr(row, "keys") else row[0]
                brand = row["brand"] if isinstance(row, dict) or hasattr(row, "keys") else row[1]
                model = row["model"] if isinstance(row, dict) or hasattr(row, "keys") else row[2]
                protos_json = row["protocols"] if isinstance(row, dict) or hasattr(row, "keys") else row[3]
                streams_json = row["streams_json"] if isinstance(row, dict) or hasattr(row, "keys") else row[4]
                r_json = row["result_json"] if isinstance(row, dict) or hasattr(row, "keys") else row[5]
                cur_cat = row["device_category"] if isinstance(row, dict) or hasattr(row, "keys") else row[6]

                try:
                    r = json.loads(r_json) if r_json else {}
                except Exception:
                    r = {}
                try:
                    streams = json.loads(streams_json) if streams_json else []
                except Exception:
                    streams = []
                try:
                    protos = json.loads(protos_json) if protos_json else []
                except Exception:
                    protos = []

                new_cat = classify_v2_device(
                    brand=brand,
                    model=model,
                    title=r.get("web_title", ""),
                    protos=protos,
                    streams=streams,
                    open_ports=r.get("open_ports", []),
                    cur_cat=cur_cat,
                )
                counts[new_cat] = counts.get(new_cat, 0) + 1
                if new_cat != cur_cat or r.get("device_category") != new_cat:
                    r["device_category"] = new_cat
                    if not r.get("categories") or r.get("categories") == [cur_cat]:
                        r["categories"] = [new_cat]
                    updates.append((new_cat, json.dumps(r, ensure_ascii=False), ip))

                if len(updates) >= 2000:
                    conn.executemany(
                        "UPDATE v2_results SET device_category = ?, result_json = ? WHERE ip = ?",
                        updates,
                    )
                    conn.commit()
                    updates.clear()

            if updates:
                conn.executemany(
                    "UPDATE v2_results SET device_category = ?, result_json = ? WHERE ip = ?",
                    updates,
                )
                conn.commit()
                updates.clear()

        if hasattr(self, "_v2_stats_cache"):
            self._v2_stats_cache = None
        return counts

