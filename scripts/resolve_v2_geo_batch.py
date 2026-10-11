#!/usr/bin/env python3
"""Batch geo resolver for Camera Scanner v2 results.

1. Instantly resolves RU/BY IPs against the local geo_subnets.sqlite3 database.
2. Queries ipinfo.io asynchronously for foreign/unmatched IPs.
3. Updates v2_results in SQLite in atomic transactions.
"""
import asyncio
import json
import sqlite3
import time
from pathlib import Path
import httpx

from ip2domain.data.geo_city_db import geo_city_db, camera_geo_fields, normalize_geo

DB_PATH = Path("/root/ip2domain/ip2domain.db")

async def fetch_ipinfo_geo(client: httpx.AsyncClient, ip: str, sem: asyncio.Semaphore) -> dict:
    async with sem:
        try:
            resp = await client.get(f"https://ipinfo.io/{ip}/json", timeout=4.0)
            if resp.status_code == 200:
                data = resp.json()
                country = data.get("country", "")
                city = data.get("city", "")
                region = data.get("region", "")
                org = data.get("org", "")
                norm = normalize_geo({
                    "city": city,
                    "region": region,
                    "country_code": country,
                    "isp": org,
                    "source": "ipinfo.io",
                })
                return camera_geo_fields(norm)
        except Exception:
            pass
    return {}

async def main():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT ip, result_json FROM v2_results").fetchall()
    print(f"[*] Found {len(rows)} records in v2_results.")

    updates = []
    unmatched = []

    t0 = time.time()
    for row in rows:
        ip = row["ip"]
        res_json_str = row["result_json"]
        try:
            res_obj = json.loads(res_json_str)
        except Exception:
            res_obj = {}

        # 1. Local database lookup
        local_geo = geo_city_db.find_by_ip(ip)
        if local_geo and (local_geo.get("city") or local_geo.get("country_code")):
            fields = camera_geo_fields(local_geo)
            res_obj.update(fields)
            updates.append((json.dumps(res_obj, ensure_ascii=False), ip))
        else:
            unmatched.append((ip, res_obj))

    print(f"[*] Local resolution completed in {time.time() - t0:.2f}s: {len(updates)} matched, {len(unmatched)} unmatched.")

    # Apply local updates in batches
    if updates:
        batch_size = 1000
        for i in range(0, len(updates), batch_size):
            chunk = updates[i:i + batch_size]
            conn.executemany("UPDATE v2_results SET result_json = ? WHERE ip = ?", chunk)
            conn.commit()
        print(f"[+] Successfully wrote {len(updates)} local geo updates to SQLite.")

    # 2. Remote ipinfo.io lookup for unmatched IPs (concurrency limit = 6)
    if unmatched:
        print(f"[*] Resolving remaining {len(unmatched)} IPs via ipinfo.io...")
        sem = asyncio.Semaphore(6)
        remote_updates = []
        async with httpx.AsyncClient(headers={"User-Agent": "ip2domain-scanner/2.0"}) as client:
            tasks = [fetch_ipinfo_geo(client, ip, sem) for ip, _ in unmatched]
            results = await asyncio.gather(*tasks)

            for (ip, res_obj), geo_fields in zip(unmatched, results):
                if geo_fields and (geo_fields.get("city") or geo_fields.get("country_code")):
                    res_obj.update(geo_fields)
                    remote_updates.append((json.dumps(res_obj, ensure_ascii=False), ip))

        if remote_updates:
            conn.executemany("UPDATE v2_results SET result_json = ? WHERE ip = ?", remote_updates)
            conn.commit()
            print(f"[+] Successfully wrote {len(remote_updates)} remote ipinfo.io geo updates to SQLite.")

    conn.close()
    print("[*] All geo resolution done!")

if __name__ == "__main__":
    asyncio.run(main())
