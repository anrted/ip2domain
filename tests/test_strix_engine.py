import asyncio
from ip2domain.cameras.strix_engine import (
    check_single_port,
    probe_ip_ports,
    fast_port_sweep,
    DEFAULT_CAMERA_PORTS,
)


def test_probe_ip_ports_returns_list_of_ints():
    async def _run():
        ports = await probe_ip_ports("127.0.0.1", ports=(1, 2, 3), timeout=0.1)
        assert isinstance(ports, list)

    asyncio.run(_run())


def test_fast_port_sweep_empty_or_cancelled():
    async def _run():
        discovered = await fast_port_sweep([], concurrency=10, timeout=0.1)
        assert discovered == []

        is_cancelled = lambda: True
        discovered_cancelled = await fast_port_sweep(["127.0.0.1", "127.0.0.2"], concurrency=10, is_cancelled=is_cancelled)
        assert discovered_cancelled == []

    asyncio.run(_run())


def test_fast_port_sweep_progress_callback():
    async def _run():
        progress_records = []

        def on_progress(completed, total, cur_ip, found_count):
            progress_records.append((completed, total, cur_ip, found_count))

        targets = [f"127.0.0.{i}" for i in range(1, 6)]
        discovered = await fast_port_sweep(targets, ports=(554, 80), concurrency=5, timeout=0.1, on_progress=on_progress)
        assert len(progress_records) > 0
        assert progress_records[-1][1] == 5

    asyncio.run(_run())
