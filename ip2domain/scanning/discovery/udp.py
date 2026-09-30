"""UDP results distinguish silence from closed and validate response correlation."""
from ..detection.scheduler import run_wire_probes
from ..detection.catalog import native_registry


async def identify_udp(observation, budget):
    observation.state = "open_or_filtered"
    if not budget.config.active:
        observation.state = "not_tested"
        observation.attempt("udp", "skipped_policy")
        return
    if not native_registry().select("udp", observation.port, budget.config.enabled_probes):
        observation.state = "not_tested"
        observation.attempt("udp", "skipped_selection")
        return
    await run_wire_probes(observation, budget)
