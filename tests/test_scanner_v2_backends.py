"""Unit tests for Phase 2 Discovery Backends and Unified ScanPlan contract."""
import asyncio
import pytest
from unittest.mock import AsyncMock, patch

from ip2domain.scanning.discovery.backends import (
    DiscoveryBackend,
    DiscoveryEvent,
    AsyncioDiscoveryBackend,
    MasscanDiscoveryBackend,
    check_discovery_tools,
    select_backend_name,
)
from ip2domain.cameras.scanner_v2.stage1_sweep import (
    asyncio_port_sweep,
    adaptive_port_sweep,
)


def test_discovery_backend_base_and_event():
    ev = DiscoveryEvent(ip="192.168.1.1", port=80, state="open", banner=b"HTTP/1.1 200 OK")
    assert ev.ip == "192.168.1.1"
    assert ev.port == 80
    assert ev.state == "open"
    assert b"HTTP" in ev.banner


def test_select_backend_name():
    # Explicit override takes priority
    assert select_backend_name(100, requested_engine="masscan") == "masscan"
    assert select_backend_name(100, requested_engine="asyncio") == "asyncio"

    # Auto selection: small target list <= 4096 uses asyncio
    assert select_backend_name(254, requested_engine="auto", tools={"masscan": True, "is_root": True}) == "asyncio"

    # Auto selection: large target list >= 4096 with masscan + root uses masscan
    assert select_backend_name(5000, requested_engine="auto", tools={"masscan": True, "is_root": True}) == "masscan"

    # Auto selection: large target list but non-root or missing masscan falls back to asyncio
    assert select_backend_name(5000, requested_engine="auto", tools={"masscan": False, "is_root": True}) == "asyncio"
    assert select_backend_name(5000, requested_engine="auto", tools={"masscan": True, "is_root": False}) == "asyncio"


@pytest.mark.anyio
async def test_asyncio_discovery_backend_sweep():
    backend = AsyncioDiscoveryBackend()

    # Mock _probe_port to simulate responsive port 80 and 554 on 192.168.1.10
    async def mock_probe(ip, port, timeout):
        if ip == "192.168.1.10" and port in (80, 554):
            return ip, port, True, b"RTSP/1.0 200 OK"
        return ip, port, False, b""

    with patch("ip2domain.scanning.discovery.backends.asyncio._probe_port", side_effect=mock_probe):
        targets = ["192.168.1.10", "192.168.1.11"]
        ports = (80, 443, 554, 8080)
        progress_called = []

        def on_progress(completed, total, cur_ip, found):
            progress_called.append((completed, total, found))

        results = await backend.sweep(
            targets=targets,
            ports=ports,
            concurrency=10,
            on_progress=on_progress,
        )

        assert len(results) == 1
        ip, open_ports = results[0]
        assert ip == "192.168.1.10"
        assert open_ports == [80, 554]
        assert len(progress_called) > 0


@pytest.mark.anyio
async def test_asyncio_discovery_backend_stream_events():
    backend = AsyncioDiscoveryBackend()

    async def mock_probe(ip, port, timeout):
        if port == 80:
            return ip, port, True, b"HTTP/1.1 200 OK"
        return ip, port, False, b""

    with patch("ip2domain.scanning.discovery.backends.asyncio._probe_port", side_effect=mock_probe):
        targets = ["192.168.1.1", "192.168.1.2"]
        ports = (80, 443)

        events = []
        async for ev in backend.stream_events(targets, ports, concurrency=5):
            events.append(ev)

        assert len(events) == 2
        assert all(ev.port == 80 and ev.state == "open" for ev in events)
        assert {ev.ip for ev in events} == {"192.168.1.1", "192.168.1.2"}


@pytest.mark.anyio
async def test_masscan_discovery_backend_missing_binary():
    backend = MasscanDiscoveryBackend(binary_path="/nonexistent/masscan_test_bin")
    with pytest.raises(RuntimeError):
        await backend.sweep(["192.168.1.1"], (80,))


@pytest.mark.anyio
async def test_stage1_asyncio_port_sweep_uses_backend():
    # Verify that camera scanner stage1_sweep.asyncio_port_sweep delegates to AsyncioDiscoveryBackend
    async def mock_probe(ip, port, timeout):
        if ip == "10.0.0.5" and port == 8000:
            return ip, port, True, b""
        return ip, port, False, b""

    with patch("ip2domain.scanning.discovery.backends.asyncio._probe_port", side_effect=mock_probe):
        res = await asyncio_port_sweep(["10.0.0.5"], (80, 8000), concurrency=10)
        assert len(res) == 1
        assert res[0][0] == "10.0.0.5"
        assert res[0][1] == [8000]
