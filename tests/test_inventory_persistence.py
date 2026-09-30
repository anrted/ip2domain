import asyncio
from concurrent.futures import ThreadPoolExecutor

import pytest

from ip2domain.scanning.inventory import EndpointObservation
from ip2domain.scanning.persistence import InventoryRepository
from ip2domain.scanning.pipeline import run_scan
from ip2domain.scanning.policies import ScanConfig


@pytest.fixture
def repository(tmp_path):
    return InventoryRepository(tmp_path / "inventory.db")


def create(repository, **kwargs):
    config = ScanConfig(targets="192.0.2.1", tcp_ports="80-85", block_size=1, **kwargs)
    return repository.create(config, config.plan())


def test_claims_are_atomic_and_old_fencing_tokens_cannot_write(repository):
    identifier = create(repository)
    repository.transition(identifier, "running", ("queued",))
    with ThreadPoolExecutor(max_workers=4) as pool:
        claims = list(pool.map(lambda _: repository.claim(identifier, 30), range(4)))
    assert len({ordinal for ordinal, token in claims}) == 4
    ordinal, token = claims[0]
    repository.release(identifier, ordinal, token)
    retry_ordinal, retry_token = repository.claim(identifier, 30)
    assert retry_ordinal == ordinal and retry_token != token
    document = EndpointObservation("192.0.2.1", 80, "tcp", state="open").to_dict()
    assert not repository.save_endpoint(identifier, ordinal, token, document)
    assert repository.save_endpoint(identifier, ordinal, retry_token, document)
    assert not repository.finish(identifier, ordinal, token, {"tested": 1})
    assert repository.finish(identifier, ordinal, retry_token, {"tested": 1})
    assert not repository.finish(identifier, ordinal, retry_token, {"tested": 1})
    assert repository.get(identifier)["coverage"]["tested"] == 1
    assert len(repository.endpoints(identifier)) == 1


def test_partial_result_survives_block_replay(repository):
    identifier = create(repository)
    repository.transition(identifier, "running", ("queued",))
    ordinal, token = repository.claim(identifier, 30)
    observation = EndpointObservation("192.0.2.1", 80, "tcp", state="open")
    observation.service("http", ("web",))
    repository.save_endpoint(identifier, ordinal, token, observation.to_dict())
    repository.release(identifier, ordinal, token)
    ordinal, token = repository.claim(identifier, 30)
    repository.save_endpoint(identifier, ordinal, token, observation.to_dict())
    repository.finish(identifier, ordinal, token, {"tested": 1})
    assert len(repository.endpoints(identifier, protocol="http")) == 1
    assert repository.endpoints(identifier, protocol="rtsp") == []


def test_bounded_pipeline_persists_unknown_services_and_coverage(repository):
    async def scenario():
        active = peak = 0
        both_started = asyncio.Event()
        async def identify(observation, budget):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            if active == 2:
                both_started.set()
            await asyncio.wait_for(both_started.wait(), 3)
            observation.state = "open" if observation.port % 2 == 0 else "closed"
            observation.attempt("test", "completed")
            active -= 1
        identifier = create(repository, workers=2)
        await run_scan(repository, identifier, identify=identify)
        result = repository.get(identifier)
        assert result["status"] == "completed"
        assert result["coverage"]["tested"] == 6
        assert result["coverage"]["state:open"] == 3
        assert peak == 2
        rows = repository.endpoints(identifier)
        assert len(rows) == 3 and all(not row["services"] for row in rows)
    asyncio.run(scenario())


def test_cancel_then_resume_does_not_skip_unfinished_blocks(repository):
    async def scenario():
        started = asyncio.Event()
        async def wait(observation, budget):
            started.set()
            await asyncio.Event().wait()
        identifier = create(repository, workers=1)
        task = asyncio.create_task(run_scan(repository, identifier, identify=wait))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert repository.get(identifier)["status"] == "paused"
        async def identify(observation, budget):
            observation.state = "open"
        await run_scan(repository, identifier, identify=identify)
        result = repository.get(identifier)
        assert result["status"] == "completed"
        assert result["coverage"]["tested"] == 6
    asyncio.run(scenario())


def test_executor_ownership_is_exclusive_and_fenced(repository):
    first = create(repository)
    second = create(repository)
    owner = repository.acquire_executor(first)
    assert owner
    repository.transition(first, "running", ("queued",))
    assert not repository.executor_transition(first, "stale", "error")
    assert repository.status(first) == "running"
    assert repository.acquire_executor(second) is None
    assert not repository.resume(first)
    assert not repository.renew_executor(first, "wrong-token")
    repository.release_executor(first, "wrong-token")
    assert repository.acquire_executor(first) is None
    repository.release_executor(first, owner)
    assert repository.acquire_executor(second)


def test_partial_success_survives_retry_with_empty_metadata(repository):
    identifier = create(repository)
    repository.transition(identifier, "running", ("queued",))
    ordinal, token = repository.claim(identifier, 30)
    observation = EndpointObservation("192.0.2.1", 80, "tcp", state="open")
    observation.service("http", ("web",))
    repository.save_endpoint(identifier, ordinal, token, observation.to_dict())
    observation.services.clear()
    repository.save_endpoint(identifier, ordinal, token, observation.to_dict())
    assert repository.endpoints(identifier)[0]["services"][0]["protocol"] == "http"


def test_resume_skips_finished_ports_inside_a_block(repository):
    async def scenario():
        config = ScanConfig(targets="192.0.2.1", tcp_ports="80-82", workers=1, block_size=3)
        identifier = repository.create(config, config.plan())
        started = asyncio.Event()
        async def interrupted(observation, budget):
            observation.state = "open"
            if observation.port == 81:
                observation.service("rtsp", ("video",))
                await observation.checkpoint()
                started.set()
                await asyncio.Event().wait()
        task = asyncio.create_task(run_scan(repository, identifier, identify=interrupted))
        await started.wait()
        # RTSP is durable BEFORE the endpoint or its block finishes.
        assert repository.endpoints(identifier, protocol="rtsp")[0]["port"] == 81
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        seen = []
        async def resumed(observation, budget):
            seen.append(observation.port)
            observation.state = "open"
        await run_scan(repository, identifier, identify=resumed)
        assert seen == [81, 82]
        assert repository.get(identifier)["coverage"]["tested"] == 3
        assert repository.endpoints(identifier, protocol="rtsp")[0]["port"] == 81
    asyncio.run(scenario())
