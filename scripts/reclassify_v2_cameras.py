"""One-time reclassification script to fix 'rvi' in 'service' false positives,
demote web_panel verified flags, and restore correct device_category for web servers.
"""
import json
import sqlite3
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ip2domain.core.storage.scanner_v2 import classify_v2_device
from ip2domain.cameras.scanner_v2.aggregation import _brand_rank

DB_PATH = Path(__file__).resolve().parent.parent / "ip2domain.db"

def main():
    conn = sqlite3.connect(str(DB_PATH), timeout=60.0)
    c = conn.cursor()
    c.execute("PRAGMA journal_mode=WAL")
    
    rows = c.execute("SELECT ip, brand, model, streams_json, result_json FROM v2_results").fetchall()
    print(f"Total rows in v2_results: {len(rows)}")
    
    updated = 0
    reclassified_cams_to_web = 0
    brand_upgraded = 0
    
    batch = []
    
    for ip, brand, model, streams_json, result_json in rows:
        try:
            rj = json.loads(result_json) if result_json else {}
        except Exception:
            continue
        
        streams = rj.get("streams", [])
        streams_changed = False
        for s in streams:
            if s.get("type") == "web_panel" or s.get("stream_type") == "web_panel":
                if s.get("verified"):
                    s["verified"] = False
                    s["verification_status"] = "web_captured"
                    streams_changed = True
        
        # Upgrade brand if endpoint has a higher-ranked vendor
        curr_brand = rj.get("brand", "") or brand or ""
        endpoints = rj.get("endpoints", [])
        best_brand = curr_brand
        best_model = rj.get("model", "") or model or ""
        for ep in endpoints:
            ep_b = ep.get("brand", "")
            if _brand_rank(ep_b) > _brand_rank(best_brand):
                best_brand = ep_b
                best_model = ep.get("model", "") or best_model
        
        if best_brand != curr_brand:
            rj["brand"] = best_brand
            rj["model"] = best_model
            brand_upgraded += 1
        
        old_cat = rj.get("device_category", "")
        new_cat = classify_v2_device(
            brand=rj.get("brand", ""),
            model=rj.get("model", ""),
            title=rj.get("web_title", ""),
            protos=rj.get("protocols", []),
            streams=streams,
            open_ports=rj.get("open_ports", []),
            cur_cat="",
        )
        
        rj["device_category"] = new_cat
        rj["categories"] = [new_cat]
        
        if old_cat == "camera" and new_cat == "generic_web":
            reclassified_cams_to_web += 1
        
        has_prev = 1 if (
            any(bool(s.get("screenshot")) for s in streams)
            or bool(rj.get("web_screenshot"))
        ) else 0
        
        batch.append((
            rj.get("brand", ""),
            rj.get("model", ""),
            new_cat,
            json.dumps(streams, ensure_ascii=False),
            json.dumps(rj, ensure_ascii=False),
            has_prev,
            ip,
        ))
        
        if len(batch) >= 1000:
            c.executemany("""
                UPDATE v2_results SET
                    brand = ?,
                    model = ?,
                    device_category = ?,
                    streams_json = ?,
                    result_json = ?,
                    has_preview = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE ip = ?
            """, batch)
            conn.commit()
            updated += len(batch)
            batch = []
            print(f"Processed {updated} / {len(rows)}...")
    
    if batch:
        c.executemany("""
            UPDATE v2_results SET
                brand = ?,
                model = ?,
                device_category = ?,
                streams_json = ?,
                result_json = ?,
                has_preview = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE ip = ?
        """, batch)
        conn.commit()
        updated += len(batch)
        
    print(f"Finished! Total updated: {updated}")
    print(f"Fake cameras reclassified to generic_web: {reclassified_cams_to_web}")
    print(f"Brands upgraded to specific manufacturer: {brand_upgraded}")

if __name__ == "__main__":
    main()
