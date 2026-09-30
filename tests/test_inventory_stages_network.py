"""End-to-end tests against loopback only, including actual shared network limits."""
import asyncio
from contextlib import asynccontextmanager

from ip2domain.scanning.persistence import InventoryRepository
from ip2domain.scanning.pipeline import run_scan
from ip2domain.scanning.policies import ScanConfig
from ip2domain.scanning.transports.network import NetworkBudget


@asynccontextmanager
async def rtsp_server():
    handlers = set()
    requests = []
    async def handle(reader, writer):
        task = asyncio.current_task()
        handlers.add(task)
        try:
            request = await asyncio.wait_for(reader.read(4096), 1)
            requests.append(request)
            if request.startswith(b"OPTIONS rtsp:"):
                writer.write(b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n\r\n")
                await writer.drain()
        except (asyncio.TimeoutError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            handlers.discard(task)
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1], requests
    finally:
        server.close()
        await server.wait_closed()
        for task in list(handlers):
            task.cancel()
        await asyncio.gather(*handlers, return_exceptions=True)


def test_staged_pipeline_identifies_rtsp_random_port_without_second_sweep(tmp_path):
    async def scenario():
        async with rtsp_server() as (port, requests):
            config = ScanConfig(
                targets="127.0.0.1", tcp_ports=str(port), profile="deep_identification",
                active_consent=True, enabled_probes=("rtsp",), timeout=0.2,
                banner_timeout=0.02, retries=0, rate=10000,
                workers=2, discovery_workers=1, enrichment_workers=1,
            )
            repository = InventoryRepository(tmp_path / "loopback.db")
            identifier = repository.create(config, config.plan())
            await asyncio.wait_for(run_scan(repository, identifier), 8)
            scan = repository.get(identifier)
            assert scan["status"] == "completed"
            assert scan["stages"]["identify"]["done"] == 1
            assert scan["coverage"]["tested"] == 1
            assert scan["coverage"]["probe:tcp_connect:completed"] == 1
            result = repository.endpoints(identifier, protocol="rtsp")[0]
            assert result["port"] == port
            assert result["services"][0]["attributes"]["auth_required"]
            # Discovery's empty connect, TLS handshake, then RTSP OPTIONS.
            assert len(requests) == 3
    asyncio.run(scenario())


def test_global_budget_is_shared_between_stage_pools_and_cleans_up_waiters():
    async def scenario():
        config = ScanConfig(targets="192.0.2.0/24", workers=2, per_host=2, per_subnet=8)
        budget = NetworkBudget(config, config.plan().scope)
        release, started = asyncio.Event(), asyncio.Event()
        active = peak = 0
        async def endpoint(ip):
            nonlocal active, peak
            async with budget.endpoint(ip):
                active += 1
                peak = max(peak, active)
                if active == 2:
                    started.set()
                try:
                    await release.wait()
                finally:
                    active -= 1
        tasks = [asyncio.create_task(endpoint(f"192.0.2.{i}")) for i in range(1, 9)]
        await started.wait()
        assert peak == 2
        for task in tasks[2:]:
            task.cancel()
        release.set()
        await asyncio.gather(*tasks, return_exceptions=True)
        assert not budget._hosts and not budget._subnets
        assert active == 0
    asyncio.run(scenario())
