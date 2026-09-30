"""Independent discovery/identification/enrichment pools with one shared budget."""
import asyncio

from .leases import db_call, renewable_lease
from .policies import ScanConfig
from .stage_workers import StageWorkers
from .stages import discover_endpoint, identify_protocols, enrich_endpoint, enumerate_protocols, discover_resources
from .transports.network import NetworkBudget


async def run_staged_scan(repository, identifier, *, handlers=None, credentials=None):
    scan = await db_call(repository.get, identifier)
    if scan is None:
        raise ValueError("scan not found")
    config = ScanConfig(**scan["config"])
    if config.execution_mode != "staged":
        raise ValueError("scan was created for the sequential executor")
    plan = config.plan()
    if scan["status"] not in ("running", "queued", "paused"):
        return
    # A synchronous atomic claim cannot complete in a stray background thread
    # after cancellation of this coroutine.
    executor_token = repository.acquire_executor(identifier)
    if executor_token is None:
        raise ValueError("another executor owns this inventory database")
    selected = {
        "protocol": enumerate_protocols, "endpoint": discover_resources,
        "discover": discover_endpoint, "identify": identify_protocols, "enrich": enrich_endpoint,
        **(handlers or {}),
    }
    tasks = []

    async def renew():
        owns = await db_call(repository.renew_executor, identifier, executor_token)
        status = await db_call(repository.status, identifier)
        return owns and status in ("running", "finalizing", "completed")

    async with renewable_lease(
        renew, lambda: db_call(repository.release_executor, identifier, executor_token), interval=5,
    ):
        try:
            await db_call(repository.transition, identifier, "running", ("queued", "paused"))
            if await db_call(repository.status, identifier) != "running":
                return
            budget = NetworkBudget(config, plan.scope)
            from .authentication import CredentialVault
            budget.credentials = credentials or CredentialVault()
            budget.learned_signatures = repository.learned_signatures()
            if config.passive_interface:
                from .discovery.passive import capture_metadata
                async def save_passive(observation):
                    from .endpoint_store import write_endpoint
                    with repository.connect() as db:write_endpoint(db,identifier,observation.to_dict())
                await capture_metadata(budget,save_passive)
            workers = StageWorkers(repository, identifier, executor_token, plan, budget, selected)
            if handlers and "enrich" in handlers and "protocol" not in handlers:
                workers.successors = {"identify":"enrich"}
            tasks = [asyncio.create_task(workers.discover()) for _ in range(config.discovery_workers)]
            tasks += [asyncio.create_task(workers.stage("identify")) for _ in range(config.workers)]
            tasks += [asyncio.create_task(workers.stage("protocol")) for _ in range(config.protocol_workers)]
            tasks += [asyncio.create_task(workers.stage("endpoint")) for _ in range(config.endpoint_workers)]
            tasks += [asyncio.create_task(workers.stage("enrich")) for _ in range(config.enrichment_workers)]
            try:
                await asyncio.gather(*tasks)
                if repository.status(identifier) == "finalizing":
                    await db_call(repository.finalize_graph, identifier)
                    await db_call(repository.transition, identifier, "completed", ("finalizing",))
            finally:
                for task in tasks:
                    # gather already propagates external cancellation. A second
                    # cancel here would interrupt the worker's lease release.
                    if not task.done() and not task.cancelling():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            await db_call(repository.executor_transition, identifier, executor_token, "paused")
            raise
        except Exception as exc:
            await db_call(repository.executor_transition, identifier, executor_token, "error", type(exc).__name__)
            raise
