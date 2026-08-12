import struct
import zlib
import asyncio
from pathlib import Path

from ip2domain.modules.remote_desktop_scanner import RemoteDesktopScanner, _encode_png


def test_remote_desktop_nmap_parser_distinguishes_rdp_and_vnc():
    xml = """<nmaprun><host><address addr="203.0.113.10" addrtype="ipv4"/><ports>
      <port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server" product="Microsoft Terminal Services"/><script id="rdp-ntlm-info" output="Product_Version: 10.0"/></port>
      <port protocol="tcp" portid="5901"><state state="open"/><service name="vnc" product="VNC protocol 3.8"/><script id="vnc-info" output="Protocol version: 3.8"/></port>
      <port protocol="tcp" portid="5902"><state state="closed"/></port>
    </ports></host></nmaprun>"""
    services = RemoteDesktopScanner._parse_nmap(xml)

    assert [service["protocol_type"] for service in services] == ["rdp", "vnc"]
    assert services[0]["port"] == 3389
    assert services[0]["target"] == "203.0.113.10"
    assert services[1]["scripts"][0]["id"] == "vnc-info"


def test_builtin_png_encoder_produces_valid_rgb_png():
    png = _encode_png(1, 1, b"\xff\x00\x00")
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    assert struct.unpack(">I", png[8:12])[0] == 13
    assert b"IDAT" in png and b"IEND" in png


def test_remote_desktop_api_accepts_multiple_unrelated_ranges(monkeypatch):
    import importlib
    from fastapi import BackgroundTasks

    web_app = importlib.import_module("ip2domain.web.app")

    monkeypatch.setattr(web_app, "private_targets_allowed", lambda: True)
    req = web_app.RemoteDesktopScanRequest(
        targets="2.63.132.0-2.63.132.3\n5.44.172.0-5.44.172.2",
        scan_rdp=True,
        scan_vnc=True,
    )
    result = asyncio.run(web_app.start_remote_desktop_scan(req, BackgroundTasks()))

    assert result["status"] == "queued"
    assert result["total_targets"] == 7


def test_remote_desktop_job_keeps_elapsed_time_fresh_while_nmap_is_quiet():
    app_py = (Path(__file__).resolve().parents[1] / "ip2domain" / "web" / "app.py").read_text(
        encoding="utf-8"
    )

    assert "while not scan_task.done():" in app_py
    assert "await asyncio.wait({scan_task}, timeout=2)" in app_py
    assert "latest_progress['stage']" in app_py


def test_remote_desktop_nmap_uses_bounded_batches():
    assert RemoteDesktopScanner.NMAP_BATCH_SIZE == 32
    assert RemoteDesktopScanner.NMAP_BATCH_CONCURRENCY == 4
