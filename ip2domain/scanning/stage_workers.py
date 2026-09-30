"""Bounded discovery and endpoint workers over the durable repository queues."""
import asyncio
from collections import Counter

from .inventory import EndpointObservation
from .leases import db_call, renewable_lease
from .stages import needs_enrichment


def counters_for(observation, *, start_attempt=0, terminal=False):
    counters = Counter({"processed": 1})
    if terminal:
        if observation.state != "not_tested":
            counters["tested"] += 1
        counters[f"state:{observation.state}"] += 1
        if observation.services:
            counters["identified"] += 1
    for attempt in observation.attempts[start_attempt:]:
        counters[f"probe:{attempt['detector']}:{attempt['status']}"] += 1
    return counters


class StageWorkers:
    def __init__(self, repository, identifier, executor_token, plan, budget, handlers):
        self.repo, self.id, self.executor = repository, identifier, executor_token
        self.plan, self.budget, self.handlers = plan, budget, handlers
        self.config = budget.config
        self.successors = {"identify":"protocol", "protocol":"endpoint", "endpoint":"enrich"}

    async def running(self):
        return await db_call(self.repo.status, self.id) == "running"

    async def idle(self):
        if await db_call(self.repo.complete_if_drained, self.id, self.executor):
            return False
        if not await self.running():
            return False
        await asyncio.sleep(0.1)
        return True

    async def discover(self):
        while await self.running():
            # The transaction is short; execute the claim synchronously so a
            # cancelled coroutine cannot orphan a thread-acquired claim.
            claim = self.repo.claim(self.id, 60)
            if claim is None:
                if not await self.idle():
                    return
                continue
            ordinal, token = claim
            async with renewable_lease(
                lambda: db_call(self.repo.renew, self.id, ordinal, token, 60, executor_token=self.executor),
                lambda: db_call(self.repo.release, self.id, ordinal, token),
            ):
                start, saved = await db_call(self.repo.progress, self.id, ordinal)
                counters = Counter(saved)
                block = self.plan.block(ordinal)
                for index, port in enumerate(block.ports[start:], start):
                    if not await self.running():
                        return
                    observation = EndpointObservation(
                        block.ip, port, block.transport, network_id=self.config.network_id,
                        hostname=self.config.hostname,
                    )
                    # No partial DB writes here: endpoint, queued successor and
                    # sweep checkpoint become durable in the same transaction.
                    await self.handlers["discover"](observation, self.budget)
                    next_stage = "identify" if block.transport == "udp" or observation.state == "open" else None
                    counters.update(counters_for(observation, terminal=next_stage is None))
                    while True:
                        outcome = await db_call(
                            self.repo.commit_discovery, self.id, ordinal, token, self.executor,
                            index, observation.to_dict(), dict(counters), next_stage,
                            self.config.queue_capacity, self.config.retain_all_states,
                        )
                        if outcome == "committed":
                            break
                        if outcome == "lost":
                            raise asyncio.CancelledError
                        # Backpressure keeps backlog bounded. Never drops an endpoint.
                        await asyncio.sleep(0.1)
                if not await db_call(self.repo.finish, self.id, ordinal, token, dict(counters), executor_token=self.executor):
                    raise asyncio.CancelledError

    async def stage(self, name):
        while await self.running():
            claim = self.repo.claim_stage(self.id, name, self.executor)
            if claim is None:
                if not await self.idle():
                    return
                continue
            async with renewable_lease(
                lambda: db_call(self.repo.renew_stage, self.id, claim, self.executor),
                lambda: db_call(self.repo.release_stage, self.id, claim, self.executor),
            ):
                observation = EndpointObservation(**claim["document"])
                start_attempt = claim["counters"].get("_attempt_start", len(observation.attempts))

                async def persist_partial(current):
                    if not await db_call(
                        self.repo.save_stage, self.id, claim, self.executor, current.to_dict(),
                        retain=self.config.retain_all_states,
                    ):
                        raise asyncio.CancelledError

                observation._checkpoint = persist_partial
                if name in ("protocol","endpoint"):
                    related=await db_call(self.repo.host,self.id,observation.ip)
                    if related:
                        observation._host_hints = related.get('fingerprints',[])
                await self.handlers[name](observation, self.budget)
                counters = counters_for(observation, start_attempt=start_attempt, terminal=name == "identify")
                next_stage = self.successors.get(name) if needs_enrichment(observation, self.config) else None
                if not await db_call(
                    self.repo.save_stage, self.id, claim, self.executor, observation.to_dict(),
                    counters=dict(counters), complete=True, next_stage=next_stage,
                    retain=self.config.retain_all_states,
                ):
                    raise asyncio.CancelledError
