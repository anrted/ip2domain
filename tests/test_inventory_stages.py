"""Durable stage queue regressions; all network operations are injected."""
import asyncio
import json

import pytest

from ip2domain.scanning.inventory import EndpointObservation
from ip2domain.scanning.persistence import InventoryRepository
from ip2domain.scanning.policies import ScanConfig
from ip2domain.scanning.staged_pipeline import run_staged_scan


@pytest.fixture
def repository(tmp_path):
    return InventoryRepository(tmp_path / "stages.db")


def create(repository, **kwargs):
    defaults = dict(targets="192.0.2.1", tcp_ports="80-83", workers=1,
                    discovery_workers=1, enrichment_workers=1, block_size=1)
    defaults.update(kwargs)
    config = ScanConfig(**defaults)
    return repository.create(config, config.plan())


async def until(predicate):
    async def wait():
        while not predicate():
            await asyncio.sleep(0.01)
    await asyncio.wait_for(wait(), 5)


def test_sweep_finishes_while_slow_identification_waits(repository):
    async def scenario():
        identifier = create(repository)
        started, release = asyncio.Event(), asyncio.Event()
        async def discover(observation, budget):
            observation.state = "open"
        async def identify(observation, budget):
            started.set()
            await release.wait()
            observation.service("rtsp", ("video",))
        task = asyncio.create_task(run_staged_scan(repository, identifier, handlers={
            "discover": discover, "identify": identify,
        }))
        try:
            await started.wait()
            await until(lambda: repository.get(identifier)["completed_blocks"] == 4)
            result = repository.get(identifier)
            assert result["status"] == "running"
            assert result["stages"]["identify"]["done"] == 0
            assert len(repository.endpoints(identifier)) == 4
            assert result["coverage"].get("tested", 0) == 0
            release.set()
            await asyncio.wait_for(task, 5)
            result = repository.get(identifier)
            assert result["status"] == "completed"
            assert result["coverage"]["tested"] == 4
            assert result["coverage"]["identified"] == 4
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    asyncio.run(scenario())


def test_backpressure_bounds_all_pending_stages_without_dropping_ports(repository):
    async def scenario():
        identifier = create(repository, queue_capacity=1)
        started, release = asyncio.Event(), asyncio.Event()
        async def discover(observation, budget):
            observation.state = "open"
        async def identify(observation, budget):
            started.set()
            await release.wait()
        task = asyncio.create_task(run_staged_scan(repository, identifier, handlers={
            "discover": discover, "identify": identify,
        }))
        try:
            await started.wait()
            await asyncio.sleep(0.15)
            stats = repository.get(identifier)["stages"]
            assert sum(s["queued"] + s["leased"] for k, s in stats.items() if k != "discover") == 1
            assert repository.get(identifier)["completed_blocks"] == 1
            release.set()
            await asyncio.wait_for(task, 5)
            assert repository.get(identifier)["coverage"]["tested"] == 4
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    asyncio.run(scenario())


def test_resume_enrichment_does_not_repeat_sweep_or_identification(repository):
    async def scenario():
        identifier = create(repository, tcp_ports="80", profile="deep_identification",
                            active_consent=True, web_enrichment=True, queue_capacity=1)
        counts = {"discover": 0, "identify": 0, "enrich": 0}
        started = asyncio.Event()
        async def discover(observation, budget):
            counts["discover"] += 1
            observation.state = "open"
        async def identify(observation, budget):
            counts["identify"] += 1
            observation.service("http", ("web",))
        async def enrich(observation, budget):
            counts["enrich"] += 1
            observation.service("hls", ("video",), path="/live.m3u8")
            observation.attempt("http_media", "detected")
            await observation.checkpoint()
            started.set()
            await asyncio.Event().wait()
        task = asyncio.create_task(run_staged_scan(repository, identifier, handlers={
            "discover": discover, "identify": identify, "enrich": enrich,
        }))
        await started.wait()
        assert repository.endpoints(identifier, protocol="hls")
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert repository.status(identifier) == "paused"
        assert repository.get(identifier)["stages"]["enrich"]["queued"] == 1
        async def finish(observation, budget):
            assert any(s["protocol"] == "hls" for s in observation.services)
        await asyncio.wait_for(run_staged_scan(repository, identifier, handlers={
            "discover": discover, "identify": identify, "enrich": finish,
        }), 5)
        assert counts == {"discover": 1, "identify": 1, "enrich": 1}
        assert repository.status(identifier) == "completed"
        assert repository.get(identifier)["coverage"]["tested"] == 1
        assert repository.get(identifier)["stages"]["enrich"]["coverage"]["probe:http_media:detected"] == 1
    asyncio.run(scenario())


def test_atomic_handoff_does_not_advance_checkpoint_when_queue_full(repository):
    identifier = create(repository)
    executor = repository.acquire_executor(identifier)
    repository.transition(identifier, "running", ("queued",))
    ordinal, token = repository.claim(identifier, 60)
    document = EndpointObservation("192.0.2.1", 80, "tcp", state="open").to_dict()
    assert repository.commit_discovery(identifier, ordinal, token, executor, 0, document,
                                       {"processed": 1}, "identify", 1) == "committed"
    second_ordinal, second_token = repository.claim(identifier, 60)
    other = EndpointObservation("192.0.2.1", 81, "tcp", state="open").to_dict()
    assert repository.commit_discovery(identifier, second_ordinal, second_token, executor, 0, other,
                                       {"processed": 1}, "identify", 1) == "full"
    assert repository.progress(identifier, second_ordinal) == (0, {})
    assert len(repository.endpoints(identifier)) == 1
    assert repository.progress(identifier, ordinal) == (1, {"processed": 1})


def test_stale_stage_tokens_and_executors_cannot_save_or_complete(repository):
    identifier = create(repository, tcp_ports="80")
    executor = repository.acquire_executor(identifier)
    repository.transition(identifier, "running", ("queued",))
    ordinal, token = repository.claim(identifier, 60)
    assert not repository.renew(identifier, ordinal, token, 60, executor_token="stale")
    assert not repository.finish(identifier, ordinal, token, {}, executor_token="stale")
    document = EndpointObservation("192.0.2.1", 80, "tcp", state="open").to_dict()
    repository.commit_discovery(identifier, ordinal, token, executor, 0, document,
                                {"processed": 1}, "identify", 2)
    repository.finish(identifier, ordinal, token, {"processed": 1})
    first = repository.claim_stage(identifier, "identify", executor)
    repository.release_stage(identifier, first, executor)
    second = repository.claim_stage(identifier, "identify", executor)
    assert first["token"] != second["token"]
    assert not repository.save_stage(identifier, first, executor, document, complete=True)
    assert not repository.complete_if_drained(identifier, executor)
    assert not repository.save_stage(identifier, second, "stale-executor", document, complete=True)
    assert repository.save_stage(identifier, second, executor, document, complete=True)
    assert repository.complete_if_drained(identifier, executor)


def test_failed_discovery_transaction_rolls_back_endpoint_queue_and_checkpoint(repository):
    identifier = create(repository, tcp_ports="80")
    executor = repository.acquire_executor(identifier)
    repository.transition(identifier, "running", ("queued",))
    ordinal, token = repository.claim(identifier, 60)
    document = EndpointObservation("192.0.2.1", 80, "tcp", state="open").to_dict()
    with pytest.raises(ValueError, match="unknown endpoint stage"):
        repository.commit_discovery(identifier, ordinal, token, executor, 0,
                                    document, {"processed": 1}, "invalid", 2)
    assert not repository.endpoints(identifier)
    assert repository.progress(identifier, ordinal) == (0, {})
    assert repository.get(identifier)["stages"]["identify"]["queued"] == 0


def test_expired_stage_lease_can_be_reclaimed_after_executor_restart(repository):
    identifier = create(repository, tcp_ports="80")
    executor = repository.acquire_executor(identifier)
    repository.transition(identifier, "running", ("queued",))
    ordinal, token = repository.claim(identifier, 60)
    document = EndpointObservation("192.0.2.1", 80, "tcp", state="open").to_dict()
    repository.commit_discovery(identifier, ordinal, token, executor, 0,
                                document, {"processed": 1}, "identify", 2)
    first = repository.claim_stage(identifier, "identify", executor)
    with repository.connect() as db:
        db.execute("UPDATE inventory_executor SET lease_until=0")
        db.execute("UPDATE inventory_stage_work SET lease_until=0 WHERE scan_id=?", (identifier,))
    newer = repository.acquire_executor(identifier)
    assert newer and newer != executor
    second = repository.claim_stage(identifier, "identify", newer)
    assert second["ordinal"] == first["ordinal"]
    assert second["token"] != first["token"]
    assert not repository.save_stage(identifier, first, executor, document, complete=True)
    assert repository.save_stage(identifier, second, newer, document, complete=True)


def test_failure_is_resumable_and_does_not_swallow_worker_exception(repository):
    async def scenario():
        identifier = create(repository, tcp_ports="80")
        async def discover(observation, budget):
            observation.state = "open"
        async def failing(observation, budget):
            raise RuntimeError("do not persist private error details")
        with pytest.raises(RuntimeError):
            await run_staged_scan(repository, identifier, handlers={"discover": discover, "identify": failing})
        assert repository.get(identifier)["error"] == "RuntimeError"
        assert repository.get(identifier)["status"] == "error"
        assert repository.get(identifier)["stages"]["identify"]["queued"] == 1
        assert repository.resume(identifier)
        async def good(observation, budget):
            observation.service("ssh", ("management",))
        await run_staged_scan(repository, identifier, handlers={"identify": good})
        assert repository.status(identifier) == "completed"
    asyncio.run(scenario())


def test_old_job_dispatch_preserves_sequential_checkpoint_meaning(repository, monkeypatch):
    from ip2domain.scanning.pipeline import run_scan
    identifier = create(repository)
    config = repository.get(identifier)["config"]
    config.pop("execution_mode")
    with repository.connect() as db:
        db.execute("UPDATE inventory_scans SET config=? WHERE id=?", (json.dumps(config), identifier))
    called = []
    async def sequential(*args, **kwargs):
        called.append(args[1])
    monkeypatch.setattr("ip2domain.scanning.sequential.run_scan", sequential)
    asyncio.run(run_scan(repository, identifier))
    assert called == [identifier]


def test_udp_has_no_false_discovery_verdict_or_empty_probe(repository):
    from ip2domain.scanning.stages import discover_endpoint
    async def scenario():
        identifier = create(repository, tcp_ports="", udp_ports="45678",
                            profile="deep_identification", active_consent=True)
        async def identify(observation, budget):
            assert observation.state == "not_tested"
            assert observation.attempts == []
            observation.state = "open_or_filtered"
        await run_staged_scan(repository, identifier, handlers={
            "discover": discover_endpoint, "identify": identify,
        })
        result = repository.get(identifier)
        assert result["coverage"]["tested"] == 1
        assert result["coverage"]["state:open_or_filtered"] == 1
    asyncio.run(scenario())
