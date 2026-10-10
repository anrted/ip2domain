"""Database migration to ensure all surveillance devices in v2_results have device_category='camera'
and re-classify non-surveillance hosts (e.g. 37.17.36.8) as generic_web.
"""
import sqlite3
import json
import sys

def run_migration(db_path: str = "/root/ip2domain/ip2domain.db"):
    conn = sqlite3.connect(db_path, timeout=60.0)
    cur = conn.cursor()

    CAMERA_BRANDS = {
        'hikvision', 'hiwatch', 'dahua', 'axis', 'reolink', 'trassir', 'xiongmai', 'flussonic',
        'streamer', 'dnvrs', 'rvi', 'uniview', 'unv', 'tiandy', 'mobotix', 'generic nvr', 'generic dvr',
        'generic ipcam', 'generic webcam', 'generic surveillance', 'generic video server', 'generic rtsp',
        'unknown camera', 'tp-link', 'ezviz', 'hilook', 'imou', 'lorex', 'foscam', 'amcrest', 'hanwha',
        'wisenet', 'samsung', 'topsvision', 'topsee', 'jovision', 'h264', 'netip', 'netsurveillance',
        'cp plus', 'bosch', 'pelco', 'vivotek', 'grandstream', 'beward', 'activecam', 'polyvision',
        'novicam', 'ltv', 'milesight', 'tvt', 'sunell', 'avigilon', 'flir', 'ubiquiti unifi', 'tapo',
        'tl-sc', 'vstarcam', 'sricam', 'srihome', 'herospeed', 'onvif'
    }

    cur.execute("SELECT ip, brand, model, protocols, streams_json, result_json FROM v2_results")
    rows = cur.fetchall()

    updated = 0
    for ip, brand, model, protocols_raw, streams_raw, result_raw in rows:
        if not result_raw:
            continue
        try:
            data = json.loads(result_raw)
        except Exception:
            continue
        changed = False

        # Specific fix for 37.17.36.8 (commercial website misidentified as RVi)
        if ip == "37.17.36.8":
            brand = "Generic Web Device"
            model = "nginx"
            data["brand"] = brand
            data["model"] = model
            data["device_category"] = "generic_web"
            data["web_title"] = "Онлайн-кассы, платежные терминалы"
            data["web_url"] = "http://37.17.36.8:80/"
            data["streams"] = [{
                "url": "http://37.17.36.8:80/",
                "type": "web_panel",
                "codec": "",
                "resolution": "",
                "width": 0,
                "height": 0,
                "verified": False,
                "screenshot": "",
                "channel": 1,
                "subtype": 0,
                "verification_status": "unverified",
                "source_port": 80,
                "credentials": None,
                "auth_required": False
            }]
            changed = True
        elif ip == "93.85.235.253": # Flussonic video streamer with camera streams
            brand = "Flussonic"
            model = "Streamer 26.07"
            data["brand"] = brand
            data["model"] = model
            data["device_category"] = "camera"
            changed = True
        else:
            b_lower = (brand or "").lower()
            is_cam = any(cb in b_lower for cb in CAMERA_BRANDS)
            if is_cam and data.get("device_category") != "camera":
                data["device_category"] = "camera"
                changed = True

        if changed:
            cur.execute(
                "UPDATE v2_results SET brand = ?, model = ?, result_json = ?, streams_json = ? WHERE ip = ?",
                (brand, model, json.dumps(data, ensure_ascii=False), json.dumps(data.get("streams", []), ensure_ascii=False), ip)
            )
            updated += 1

    conn.commit()
    conn.close()
    print(f"Migration completed successfully: updated {updated} records.")


if __name__ == "__main__":
    db = sys.argv[1] if len(sys.argv) > 1 else "/root/ip2domain/ip2domain.db"
    run_migration(db)
