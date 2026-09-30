"""Geo-IP Database and Range Provider for Russian and Belarusian Cities.

Powered by SQLite database indexing 40,000+ real-world subnets across
980+ Russian cities and Belarusian regions from GeoLite2 City & ASN databases.
"""
from __future__ import annotations

import ipaddress
import os
import re
import threading
from datetime import datetime, timezone
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_DB_PATH = Path(__file__).resolve().parent / "geo_subnets.sqlite3"


_GEO_PLACEHOLDERS = {"", "федеральный округ", "область", "регион", "неизвестно", "unknown", "federal district", "region", "oblast"}


def normalize_ip(value: str) -> str:
    raw = value.strip()
    try:
        return str(ipaddress.ip_interface(raw).ip)
    except ValueError:
        # Legacy scanner records may contain IPv4:port.
        if raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
            return str(ipaddress.ip_address(raw.rsplit(":", 1)[0]))
        raise


def normalize_geo(data: Dict[str, Any]) -> Dict[str, Any]:
    """Administrative labels and missing values must never masquerade as cities."""
    result = dict(data)
    city = str(result.get("city") or "").strip()
    region = str(result.get("region") or "").strip()
    if region.casefold() in _GEO_PLACEHOLDERS:
        region = ""
    if city.casefold() in _GEO_PLACEHOLDERS:
        city = ""
    elif re.search(r"(?:област|федеральн|республик|\bкрай\b|\boblast\b|\bdistrict\b|\brepublic\b)", city, re.I):
        region = region or city
        city = ""
    result.update(city=city, region=region,
                  precision="city" if city else "region" if region else "country" if result.get("country_code") else "unknown")
    if not city:
        result["city_en"] = ""
    result.setdefault("accuracy_radius_km", None)
    result.setdefault("source", "local_db")
    result.setdefault("database_date", "")
    return result


def camera_geo_fields(data: Dict[str, Any]) -> Dict[str, Any]:
    geo = normalize_geo(data)
    return {**{key: geo.get(key, "") for key in ("city", "region", "country_code", "isp")},
            "geo_precision": geo["precision"], "geo_source": geo["source"],
            "geo_accuracy_radius_km": geo["accuracy_radius_km"], "geo_database_date": geo["database_date"]}


@dataclass(frozen=True)
class SubnetRecord:
    cidr: str
    country_code: str  # 'RU' | 'BY'
    country_name: str  # 'Россия' | 'Беларусь'
    region: str
    city: str
    city_en: str
    isp: str
    asn: str
    org: str
    ip_count: int
    lat: float = 0.0
    lon: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class GeoCityDatabase:
    """SQLite-backed high-performance Geo-IP database for RU & BY."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else _DB_PATH
        self._readers = {}
        self._reader_lock = threading.RLock()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.create_function("GEO_CITY", 2, lambda city, region: normalize_geo({"city": city, "region": region})["city"], deterministic=True)
        conn.create_function("GEO_REGION", 2, lambda city, region: normalize_geo({"city": city, "region": region})["region"], deterministic=True)
        return conn

    def get_countries_summary(self) -> List[Dict[str, Any]]:
        """Get summary stats for RU and BY."""
        if not self.db_path.exists():
            return []

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT 
                    country_code,
                    country_name,
                    COUNT(*) as subnets,
                    SUM(ip_count) as total_ips,
                    COUNT(DISTINCT NULLIF(GEO_CITY(city, region), '')) as cities_count,
                    COUNT(DISTINCT region) as regions_count
                FROM subnets
                GROUP BY country_code
            """)
            rows = cur.fetchall()

        result = []
        for r in rows:
            code = r["country_code"]
            flag = "🇷🇺" if code == "RU" else "🇧🇾"
            result.append({
                "code": code,
                "name": r["country_name"],
                "flag": flag,
                "subnets": r["subnets"],
                "ip_count": r["total_ips"] or 0,
                "cities_count": r["cities_count"],
                "regions_count": r["regions_count"],
            })
        return sorted(result, key=lambda x: x["code"] != "RU")

    def get_regions(self, country: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get list of regions with subnet and IP counts."""
        if not self.db_path.exists():
            return []

        c_filter = country.upper().strip() if country and country.upper() != "ALL" else ""
        query = """
            SELECT 
                GEO_REGION(city, region) AS region,
                country_code,
                country_name,
                COUNT(*) as subnets,
                SUM(ip_count) as total_ips,
                COUNT(DISTINCT NULLIF(GEO_CITY(city, region), '')) as cities_count
            FROM subnets WHERE GEO_REGION(city, region) != ''
        """
        params: List[Any] = []
        if c_filter:
            query += " AND country_code = ?"
            params.append(c_filter)

        query += " GROUP BY country_code, GEO_REGION(city, region) ORDER BY subnets DESC, region ASC"

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            rows = cur.fetchall()

        return [
            {
                "region": r["region"],
                "country_code": r["country_code"],
                "country_name": r["country_name"],
                "subnets": r["subnets"],
                "ip_count": r["total_ips"] or 0,
                "cities_count": r["cities_count"],
            }
            for r in rows
        ]

    def get_cities(self, country: Optional[str] = None, region: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get list of cities with metrics."""
        if not self.db_path.exists():
            return []

        c_filter = country.upper().strip() if country and country.upper() != "ALL" else ""
        r_filter = region.strip() if region else ""

        query = """
            SELECT 
                city,
                city_en,
                region,
                country_code,
                country_name,
                COUNT(*) as subnets,
                SUM(ip_count) as total_ips,
                COUNT(DISTINCT isp) as isps_count,
                lat,
                lon
            FROM subnets
            WHERE GEO_CITY(city, region) != ''
        """
        params: List[Any] = []
        if c_filter:
            query += " AND country_code = ?"
            params.append(c_filter)
        if r_filter:
            query += " AND (region = ? OR region LIKE ?)"
            params.extend([r_filter, f"%{r_filter}%"])

        query += " GROUP BY country_code, region, city ORDER BY subnets DESC, total_ips DESC"

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            rows = cur.fetchall()

        return [
            {
                "city": r["city"],
                "city_en": r["city_en"],
                "region": r["region"],
                "country_code": r["country_code"],
                "country_name": r["country_name"],
                "subnets": r["subnets"],
                "ip_count": r["total_ips"] or 0,
                "isps_count": r["isps_count"],
                "lat": r["lat"],
                "lon": r["lon"],
            }
            for r in rows
        ]

    def get_providers(self, country: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get list of distinct ISPs and ASNs."""
        if not self.db_path.exists():
            return []

        c_filter = country.upper().strip() if country and country.upper() != "ALL" else ""
        query = """
            SELECT 
                isp,
                asn,
                country_code,
                COUNT(*) as subnets,
                SUM(ip_count) as total_ips
            FROM subnets
        """
        params: List[Any] = []
        if c_filter:
            query += " WHERE country_code = ?"
            params.append(c_filter)

        query += " GROUP BY isp, asn ORDER BY subnets DESC, total_ips DESC LIMIT 150"

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            rows = cur.fetchall()

        return [
            {
                "isp": r["isp"],
                "asn": r["asn"],
                "country_code": r["country_code"],
                "subnets": r["subnets"],
                "ip_count": r["total_ips"] or 0,
            }
            for r in rows
        ]

    def filter_subnets(
        self,
        country: Optional[str] = None,
        region: Optional[str] = None,
        city: Optional[str] = None,
        isp: Optional[str] = None,
        asn: Optional[str] = None,
        query: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Search and filter subnets with pagination."""
        if not self.db_path.exists():
            return [], 0

        c_filter = country.upper().strip() if country and country.upper() != "ALL" else ""
        r_filter = region.strip() if region else ""
        city_filter = city.strip() if city else ""
        isp_filter = isp.strip() if isp else ""
        asn_filter = asn.strip().upper() if asn else ""
        q_filter = query.strip() if query else ""

        where_clauses = ["1=1"]
        params: List[Any] = []

        if c_filter:
            where_clauses.append("country_code = ?")
            params.append(c_filter)

        if r_filter:
            where_clauses.append("region LIKE ?")
            params.append(f"%{r_filter}%")

        if city_filter:
            where_clauses.append("(city LIKE ? OR city_en LIKE ?)")
            params.append(f"%{city_filter}%")
            params.append(f"%{city_filter}%")

        if isp_filter:
            where_clauses.append("(isp LIKE ? OR org LIKE ?)")
            params.append(f"%{isp_filter}%")
            params.append(f"%{isp_filter}%")

        if asn_filter:
            where_clauses.append("asn LIKE ?")
            params.append(f"%{asn_filter}%")

        if q_filter:
            where_clauses.append("(cidr LIKE ? OR city LIKE ? OR city_en LIKE ? OR region LIKE ? OR isp LIKE ? OR asn LIKE ? OR org LIKE ?)")
            q_like = f"%{q_filter}%"
            params.extend([q_like, q_like, q_like, q_like, q_like, q_like, q_like])

        where_sql = " AND ".join(where_clauses)

        with self._get_connection() as conn:
            cur = conn.cursor()
            # Count
            cur.execute(f"SELECT COUNT(*) FROM subnets WHERE {where_sql}", params)
            total = cur.fetchone()[0]

            # Rows
            cur.execute(
                f"""
                SELECT cidr, country_code, country_name, region, city, city_en, isp, asn, org, ip_count, lat, lon
                FROM subnets
                WHERE {where_sql}
                ORDER BY ip_count DESC, id ASC
                LIMIT ? OFFSET ?
                """,
                params + [limit, offset],
            )
            rows = cur.fetchall()

        subnets = [
            {
                "cidr": r["cidr"],
                "country_code": r["country_code"],
                "country_name": r["country_name"],
                "region": r["region"],
                "city": r["city"],
                "city_en": r["city_en"],
                "isp": r["isp"],
                "asn": r["asn"],
                "org": r["org"],
                "ip_count": r["ip_count"],
                "lat": r["lat"],
                "lon": r["lon"],
            }
            for r in rows
        ]
        return [normalize_geo(item) for item in subnets], total

    def _read_mmdb(self, name: str, ip: str):
        path = self.db_path.parent / name
        if not path.exists():
            return None
        try:
            import maxminddb
            stamp = (path.stat().st_mtime_ns, path.stat().st_size)
            with self._reader_lock:
                old = self._readers.get(name)
                if old is None or old[0] != stamp:
                    reader = maxminddb.open_database(str(path))
                    if old is not None:
                        old[1].close()
                    self._readers[name] = (stamp, reader)
                reader = self._readers[name][1]
                record, prefix = reader.get_with_prefix_len(ip)
                epoch = reader.metadata().build_epoch
                return record, prefix, datetime.fromtimestamp(epoch, timezone.utc).date().isoformat()
        except (ImportError, OSError, ValueError, RuntimeError):
            return None

    def find_by_ip(self, ip_str: str) -> Optional[Dict[str, Any]]:
        """Resolve the exact address from MMDB; use the range index only as fallback."""
        try:
            ip = ipaddress.ip_address(normalize_ip(ip_str))
        except ValueError:
            return None
        match = self._read_mmdb("GeoLite2-City.mmdb", str(ip))
        indexed = None
        if not (match and match[0]) and self.db_path.exists() and ip.version == 4:
            with self._get_connection() as conn:
                row = conn.execute(
                    "SELECT * FROM subnets WHERE start_ip <= ? AND end_ip >= ? "
                    "ORDER BY (end_ip - start_ip) ASC, id ASC LIMIT 1", (int(ip), int(ip)),
                ).fetchone()
                if row:
                    indexed = normalize_geo(dict(row))
        if match and match[0]:
            record, prefix, date = match
            def name(value):
                names = (value or {}).get("names", {})
                return names.get("ru") or names.get("en") or ""
            country = record.get("country", {})
            subdivisions = record.get("subdivisions", [])
            location = record.get("location", {})
            network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
            # Do not fill absent city/region with the centroid or a broad range's label.
            result = {"cidr": str(network), "country_code": country.get("iso_code", ""),
                      "country_name": name(country), "city": name(record.get("city")),
                      "city_en": record.get("city", {}).get("names", {}).get("en", ""),
                      "region": name(subdivisions[-1]) if subdivisions else "",
                      "lat": location.get("latitude"), "lon": location.get("longitude"),
                      "accuracy_radius_km": location.get("accuracy_radius"),
                      "source": "geolite2_city", "database_date": date,
                      "ip_count": network.num_addresses,
                      **{k: (indexed or {}).get(k, "") for k in ("isp", "asn", "org")}}
            asn = self._read_mmdb("GeoLite2-ASN.mmdb", str(ip))
            if asn and asn[0]:
                result["asn"] = f"AS{asn[0]['autonomous_system_number']}" if asn[0].get("autonomous_system_number") else ""
                result["org"] = asn[0].get("autonomous_system_organization", "")
                result["isp"] = result["org"] or result["isp"]
            return normalize_geo(result)
        return indexed

    def get_all_cidrs_for_filter(
        self,
        country: Optional[str] = None,
        region: Optional[str] = None,
        city: Optional[str] = None,
        isp: Optional[str] = None,
        asn: Optional[str] = None,
        query: Optional[str] = None,
        max_limit: int = 5000,
    ) -> List[str]:
        """Fetch all CIDR strings matching the current filter without pagination."""
        if not self.db_path.exists():
            return []

        c_filter = country.upper().strip() if country and country.upper() != "ALL" else ""
        r_filter = region.strip() if region else ""
        city_filter = city.strip() if city else ""
        isp_filter = isp.strip() if isp else ""
        asn_filter = asn.strip().upper() if asn else ""
        q_filter = query.strip() if query else ""

        where_clauses = ["1=1"]
        params: List[Any] = []

        if c_filter:
            where_clauses.append("country_code = ?")
            params.append(c_filter)
        if r_filter:
            where_clauses.append("region LIKE ?")
            params.append(f"%{r_filter}%")
        if city_filter:
            where_clauses.append("(city LIKE ? OR city_en LIKE ?)")
            params.append(f"%{city_filter}%")
            params.append(f"%{city_filter}%")
        if isp_filter:
            where_clauses.append("(isp LIKE ? OR org LIKE ?)")
            params.append(f"%{isp_filter}%")
            params.append(f"%{isp_filter}%")
        if asn_filter:
            where_clauses.append("asn LIKE ?")
            params.append(f"%{asn_filter}%")
        if q_filter:
            where_clauses.append("(cidr LIKE ? OR city LIKE ? OR city_en LIKE ? OR region LIKE ? OR isp LIKE ? OR asn LIKE ? OR org LIKE ?)")
            q_like = f"%{q_filter}%"
            params.extend([q_like, q_like, q_like, q_like, q_like, q_like, q_like])

        where_sql = " AND ".join(where_clauses)

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(f"SELECT cidr FROM subnets WHERE {where_sql} ORDER BY ip_count DESC LIMIT ?", params + [max_limit])
            rows = cur.fetchall()

        return [r["cidr"] for r in rows]


# Global singleton
geo_city_db = GeoCityDatabase()
