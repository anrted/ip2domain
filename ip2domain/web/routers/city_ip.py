"""City IP Finder Router — Russian and Belarusian IP Explorer.

Endpoints:
  GET   /api/geo/countries       Stats by country (RU / BY)
  GET   /api/geo/regions         Regions list with stats
  GET   /api/geo/cities          Cities list with subnet & IP metrics
  GET   /api/geo/providers       ISPs and ASNs
  GET   /api/geo/subnets         Search and filter subnets (with pagination)
  GET   /api/geo/all-cidrs       Get all CIDR strings for current filter
  GET   /api/geo/lookup          Reverse GeoIP lookup for IP / Subnet
  GET   /api/geo/asn-subnets     Live RIPE Stat ASN prefix lookup
"""
from __future__ import annotations

import re
from typing import List, Optional

import httpx
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

from ip2domain.data.geo_city_db import geo_city_db

router = APIRouter(prefix="/api/geo", tags=["city_ip"])


@router.get("/countries")
async def get_countries():
    """Return overview metrics for supported countries (RU and BY)."""
    return JSONResponse(content={"countries": geo_city_db.get_countries_summary()})


@router.get("/regions")
async def get_regions(country: Optional[str] = Query(None, description="Country code 'RU' or 'BY'")):
    """Return list of regions with counts."""
    return JSONResponse(content={"regions": geo_city_db.get_regions(country)})


@router.get("/cities")
async def get_cities(
    country: Optional[str] = Query(None, description="Country code 'RU' or 'BY'"),
    region: Optional[str] = Query(None, description="Region filter"),
):
    """Return list of cities with metrics."""
    return JSONResponse(content={"cities": geo_city_db.get_cities(country, region)})


@router.get("/providers")
async def get_providers(country: Optional[str] = Query(None, description="Country code 'RU' or 'BY'")):
    """Return list of distinct ISPs and ASNs."""
    return JSONResponse(content={"providers": geo_city_db.get_providers(country)})


@router.get("/subnets")
async def get_subnets(
    country: Optional[str] = Query(None, description="Country code 'RU' or 'BY'"),
    region: Optional[str] = Query(None, description="Region filter"),
    city: Optional[str] = Query(None, description="City filter"),
    isp: Optional[str] = Query(None, description="ISP name filter"),
    asn: Optional[str] = Query(None, description="ASN number filter"),
    q: Optional[str] = Query(None, description="General search query"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Search and filter subnets with pagination."""
    subnets, total = geo_city_db.filter_subnets(
        country=country,
        region=region,
        city=city,
        isp=isp,
        asn=asn,
        query=q,
        limit=limit,
        offset=offset,
    )
    total_ips = sum(s.get("ip_count", 0) for s in subnets)
    return JSONResponse(
        content={
            "total": total,
            "limit": limit,
            "offset": offset,
            "total_ips_in_page": total_ips,
            "subnets": subnets,
        }
    )


@router.get("/all-cidrs")
async def get_all_cidrs(
    country: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    city: Optional[str] = Query(None),
    isp: Optional[str] = Query(None),
    asn: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    limit: int = Query(5000, ge=1, le=10000),
):
    """Fetch all CIDR strings for the current active filter (for instant scanner transfer)."""
    cidrs = geo_city_db.get_all_cidrs_for_filter(
        country=country,
        region=region,
        city=city,
        isp=isp,
        asn=asn,
        query=q,
        max_limit=limit,
    )
    return JSONResponse(content={"total": len(cidrs), "cidrs": cidrs})


@router.get("/lookup")
async def lookup_geo(ip: str = Query(..., description="IP address or CIDR to lookup")):
    """Reverse lookup GeoIP information for an IP address or subnet."""
    raw = ip.strip()
    # 1. Check local indexed DB
    local_info = geo_city_db.find_by_ip(raw)
    if local_info:
        return JSONResponse(content={"found": True, "source": "local_db", "data": local_info})

    # 2. Try online fallback (ip-api / 2ip)
    clean_ip = re.sub(r"/.*$", "", raw).strip()
    try:
        async with httpx.AsyncClient(timeout=3.5) as client:
            resp = await client.get(f"http://ip-api.com/json/{clean_ip}?lang=ru")
            if resp.status_code == 200:
                d = resp.json()
                if d.get("status") == "success":
                    data = {
                        "cidr": f"{clean_ip}/32",
                        "country_code": d.get("countryCode", ""),
                        "country_name": d.get("country", ""),
                        "region": d.get("regionName", ""),
                        "city": d.get("city", ""),
                        "isp": d.get("isp", ""),
                        "asn": d.get("as", "").split(" ")[0],
                        "org": d.get("org", ""),
                        "lat": d.get("lat", 0.0),
                        "lon": d.get("lon", 0.0),
                        "ip_count": 1,
                    }
                    return JSONResponse(content={"found": True, "source": "ip-api", "data": data})
    except Exception:
        pass

    return JSONResponse(content={"found": False, "source": "none", "data": None, "query": raw})


@router.get("/asn-subnets")
async def get_asn_subnets(asn: str = Query(..., description="ASN e.g. AS12389 or 12389")):
    """Lookup announced prefixes for an ASN from RIPE Stat."""
    raw = str(asn or "").strip().upper()
    asn_num = re.sub(r'[^0-9]', '', raw)
    if not asn_num:
        raise HTTPException(status_code=400, detail="Укажите корректный ASN (например AS12389)")

    prefixes: List[str] = []
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.get(
                f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_num}",
                headers={"User-Agent": "ip2domain/1.5"}
            )
            if r.status_code == 200:
                data = r.json()
                for item in data.get("data", {}).get("prefixes", []):
                    pref = str(item.get("prefix") or "").strip()
                    if pref and ":" not in pref:  # IPv4
                        prefixes.append(pref)
    except Exception as exc:
        return JSONResponse(content={"asn": f"AS{asn_num}", "prefixes": [], "error": str(exc)})

    return JSONResponse(content={"asn": f"AS{asn_num}", "prefixes": prefixes, "total": len(prefixes)})
