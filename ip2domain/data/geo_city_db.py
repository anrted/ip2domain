"""Geo-IP Database and Range Provider for Russian and Belarusian Cities.

Powered by SQLite database indexing 40,000+ real-world subnets across
980+ Russian cities and Belarusian regions from GeoLite2 City & ASN databases.
"""
from __future__ import annotations

import ipaddress
import os
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_DB_PATH = Path(__file__).resolve().parent / "geo_subnets.sqlite3"


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

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
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
                    COUNT(DISTINCT city) as cities_count,
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
                region,
                country_code,
                country_name,
                COUNT(*) as subnets,
                SUM(ip_count) as total_ips,
                COUNT(DISTINCT city) as cities_count
            FROM subnets
        """
        params: List[Any] = []
        if c_filter:
            query += " WHERE country_code = ?"
            params.append(c_filter)

        query += " GROUP BY country_code, region ORDER BY subnets DESC, region ASC"

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
            WHERE 1=1
        """
        params: List[Any] = []
        if c_filter:
            query += " AND country_code = ?"
            params.append(c_filter)
        if r_filter:
            query += " AND region = ?"
            params.append(r_filter)

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
        return subnets, total

    def find_by_ip(self, ip_str: str) -> Optional[Dict[str, Any]]:
        """Find matching subnet for given IP string in local database."""
        if not self.db_path.exists():
            return None

        try:
            target_ip = ipaddress.ip_address(ip_str.strip())
            if target_ip.version != 4:
                return None
            ip_int = int(target_ip)
        except ValueError:
            return None

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT cidr, country_code, country_name, region, city, city_en, isp, asn, org, ip_count, lat, lon
                FROM subnets
                WHERE start_ip <= ? AND end_ip >= ?
                ORDER BY ip_count ASC
                LIMIT 1
                """,
                (ip_int, ip_int),
            )
            row = cur.fetchone()

        if row:
            return {
                "cidr": row["cidr"],
                "country_code": row["country_code"],
                "country_name": row["country_name"],
                "region": row["region"],
                "city": row["city"],
                "city_en": row["city_en"],
                "isp": row["isp"],
                "asn": row["asn"],
                "org": row["org"],
                "ip_count": row["ip_count"],
                "lat": row["lat"],
                "lon": row["lon"],
            }
        return None

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
