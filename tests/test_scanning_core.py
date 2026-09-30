"""Network-free tests of the domain-neutral scanning contracts."""
import asyncio
import json

import pytest

from ip2domain.scanning import (
    DeviceClassification, Endpoint, ProbeContext, ProbeData, ProbeRegistry,
    ProbeRunner, ProbeSpec, ServiceObservation,
)
from ip2domain.scanning.runner import run_bounded


def test_registry_is_immutable_and_rejects_duplicate_ids():
    async def run(context):
        return ProbeData()

    base = ProbeRegistry([ProbeSpec("first", run)])
    extended = base.extend(ProbeSpec("second", run))
    assert [p.probe_id for p in base] == ["first"]
    assert [p.probe_id for p in extended] == ["first", "second"]
    with pytest.raises(ValueError, match="duplicate"):
        base.extend(ProbeSpec("first", run))
    with pytest.raises(ValueError):
        ProbeSpec("invalid", run, timeout=0)
    with pytest.raises(ValueError):
        Endpoint(0)
    with pytest.raises(ValueError):
        Endpoint(80, "unknown")
    with pytest.raises(ValueError):
        DeviceClassification("sensor", confidence=2)


def test_non_camera_service_and_multiple_categories_without_streams():
    async def scenario():
        async def mqtt(context):
            return ProbeData(
                detected=True,
                services=(ServiceObservation("mqtt", Endpoint(1883), ("iot",)),),
                classifications=(DeviceClassification("sensor", ("mqtt:device-type",), 0.8),),
                attributes={"password": "private-secret"},
            )

        async def rtp(context):
            return ProbeData(
                detected=True,
                services=(ServiceObservation("rtp", Endpoint(5004, "udp"), ("video", "voice")),),
            )

        registry = ProbeRegistry((
            ProbeSpec("mqtt", mqtt, lambda c: 1883 in c.ports()),
            ProbeSpec("rtp", rtp, lambda c: 5004 in c.ports("udp")),
        ))
        context = ProbeContext(
            "192.0.2.1", (Endpoint(1883), Endpoint(5004, "udp")),
            credentials=(("user", "private-secret"),),
        )
        observation = await ProbeRunner(registry).probe(context)
        assert observation.detected
        result = observation.to_dict()
        assert result["schema_version"] == 1
        assert result["probes"][0]["classifications"][0]["kind"] == "sensor"
        assert result["probes"][1]["services"][0]["categories"] == ["video", "voice"]
        assert "private-secret" not in json.dumps(result)
        assert "private-secret" not in repr(context)
        assert "private-secret" not in repr(observation)
        assert "streams" not in result

    asyncio.run(scenario())


def test_probe_errors_timeouts_and_order_are_isolated():
    async def scenario():
        async def good(context):
            await asyncio.sleep(0)
            return ProbeData(detected=True)

        async def broken(context):
            raise RuntimeError("password=do-not-log")

        async def slow(context):
            await asyncio.Event().wait()

        async def invalid(context):
            return {}

        registry = ProbeRegistry((
            ProbeSpec("good", good),
            ProbeSpec("broken", broken),
            ProbeSpec("slow", slow, timeout=0.01),
            ProbeSpec("invalid", invalid),
            ProbeSpec("skipped", broken, lambda c: False),
        ))
        observation = await ProbeRunner(registry, concurrency=2).probe(ProbeContext("192.0.2.1"))
        assert [o.probe_id for o in observation.outcomes] == ["good", "broken", "slow", "invalid"]
        assert [o.status for o in observation.outcomes] == ["completed", "error", "timeout", "error"]
        assert observation.outcomes[-1].error_type == "TypeError"
        assert observation.detected
        assert "do-not-log" not in json.dumps(observation.to_dict())

    asyncio.run(scenario())


def test_probe_limit_is_shared_across_hosts():
    async def scenario():
        active = peak = 0

        async def probe(context):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            try:
                await asyncio.sleep(0.001)
                return ProbeData()
            finally:
                active -= 1

        runner = ProbeRunner(ProbeRegistry(ProbeSpec(str(i), probe) for i in range(5)), concurrency=2)
        await asyncio.gather(*(runner.probe(ProbeContext(f"192.0.2.{i}")) for i in range(4)))
        assert peak == 2
        assert active == 0

    asyncio.run(scenario())


def test_external_cancellation_cleans_up_probes():
    async def scenario():
        started, stopped = asyncio.Event(), asyncio.Event()

        async def probe(context):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()

        runner = ProbeRunner(ProbeRegistry([ProbeSpec("wait", probe)]))
        task = asyncio.create_task(runner.probe(ProbeContext("192.0.2.1")))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert stopped.is_set()
        assert not [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    asyncio.run(scenario())


def test_bounded_workers_consume_lazily_and_cancel_cooperatively():
    async def scenario():
        consumed = []
        started = 0
        ready = asyncio.Event()
        release = asyncio.Event()
        cancelled = False

        def source():
            for i in range(1000000):
                consumed.append(i)
                yield i

        async def worker(item):
            nonlocal started
            started += 1
            if started == 3:
                ready.set()
            await release.wait()

        task = asyncio.create_task(run_bounded(source(), worker, 3, lambda: cancelled))
        await ready.wait()
        assert consumed == [0, 1, 2]
        cancelled = True
        release.set()
        await task
        assert len(consumed) == 3
        with pytest.raises(ValueError):
            await run_bounded([], worker, 0)

    asyncio.run(scenario())


def test_bounded_worker_failure_cleans_up_siblings():
    async def scenario():
        started, stopped = asyncio.Event(), asyncio.Event()

        async def worker(item):
            if item == 0:
                await started.wait()
                raise ValueError("worker failed")
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()

        with pytest.raises(ValueError, match="worker failed"):
            await run_bounded(range(100), worker, 2)
        assert stopped.is_set()

    asyncio.run(scenario())
