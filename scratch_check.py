import asyncio, json, httpx
from pathlib import Path
from ip2domain.core.storage import StorageManager
from ip2domain.cameras.scanner_v2.stage2_proto import probe_host_v2
from ip2domain.cameras.scanner_v2.stage3_stream import capture_stream_frame, _download_http_snapshot
from ip2domain.cameras.scanner_v2.models import DEFAULT_CREDENTIALS

hosts = [
    '194.186.216.34',
    '195.16.62.77',
    '79.104.43.114',
    '213.33.160.159',
    '95.30.25.122',
    '195.46.168.225',
    '81.211.16.75',
    '213.33.196.49',
    '212.119.243.104',
    '195.239.8.26',
]

cap_dir = Path('/root/ip2domain/ip2domain/web/v2_captures')
sm = StorageManager()
results = sm.get_v2_results(limit=1000)

async def check_all():
    out = []
    out.append("=== 1. DATABASE RECORDS ===")
    db_map = {r['ip']: r for r in results if r['ip'] in hosts}
    for h in hosts:
        rec = db_map.get(h)
        if rec:
            out.append(f"DB {h}: Brand={rec.get('brand')}, Model={rec.get('model')}, Protos={rec.get('protocols')}")
            for s in rec.get('streams', []):
                out.append(f"   -> {s.get('type')}: {s.get('url')} [verified={s.get('verified')}, sc={bool(s.get('screenshot'))}]")
        else:
            out.append(f"DB {h}: Not in DB")

    out.append("\n=== 2. LIVE PROBING & FRAME CAPTURE ===")
    test_ports = [80, 554, 8080, 8554, 88, 8000, 37777, 8899, 1984, 9000, 81]

    for h in hosts:
        out.append(f"\n--- Testing {h} ---")
        open_p = []
        for p in test_ports:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(h, p), timeout=0.6)
                writer.close()
                await writer.wait_closed()
                open_p.append(p)
            except Exception:
                pass
        out.append(f"{h} open ports: {open_p}")

        if not open_p:
            out.append(f"{h}: No camera ports open")
            continue

        cam_res = await probe_host_v2(h, open_p, DEFAULT_CREDENTIALS)
        if not cam_res:
            out.append(f"{h}: probe_host_v2 returned None (NOT a camera / No camera response)")
        else:
            out.append(f"{h}: Brand={cam_res.brand}, Model={cam_res.model}, Streams={len(cam_res.streams)}")
            for s in cam_res.streams[:4]:
                if s.stream_type == 'http_snapshot':
                    snap = await _download_http_snapshot(s.url, cap_dir, cam_res.credentials)
                    out.append(f"   [Snapshot] {s.url} -> live_frame={bool(snap)}")
                else:
                    ok, path, codec, w, h_dim = await capture_stream_frame(s.url, s.stream_type, cap_dir, cam_res.credentials)
                    out.append(f"   [Stream] {s.url} -> ok={ok}, codec={codec}, res={w}x{h_dim}")

    result_text = "\n".join(out)
    Path("/root/ip2domain/scratch_10hosts.txt").write_text(result_text)
    print(result_text)

if __name__ == "__main__":
    asyncio.run(check_all())
