"""Public executor facade with explicit compatibility for pre-stage checkpoints."""
from .leases import db_call
from .stages import identify_endpoint
from .staged_pipeline import run_staged_scan


async def run_scan(repository, identifier, *, identify=None, credentials=None):
    """New jobs use durable stages; old jobs keep their original checkpoint meaning.

    The injected single-endpoint handler remains available for integrations/tests.
    It deliberately selects the sequential compatibility executor.
    """
    scan = await db_call(repository.get, identifier)
    if scan is None:
        raise ValueError("scan not found")
    if identify is None and scan["config"].get("execution_mode", "sequential") == "staged":
        return await run_staged_scan(repository, identifier, credentials=credentials)
    from .sequential import run_scan as run_sequential
    return await run_sequential(repository, identifier, identify=identify or identify_endpoint)
