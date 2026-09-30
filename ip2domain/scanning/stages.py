"""Network stage implementations, independent of queue/storage mechanics."""
import asyncio

from .classification import classify
from .detection.catalog import native_registry
from .detection.nmap import identify_nmap
from .discovery.tcp import discover_tcp, identify_tcp
from .discovery.udp import identify_udp
from .enrichment.web import enrich_web
from .enrichment.rtsp import enrich_rtsp


async def discover_endpoint(observation, budget):
    from .discovery.host import discover_host
    await discover_host(observation,budget)
    if observation.transport == "udp":
        # No empty UDP sweep: only a protocol-specific request can establish
        # evidence. Queue this endpoint without labelling it open or tested.
        observation.state = "not_tested"
        return
    async with budget.endpoint(observation.ip):
        await discover_tcp(observation, budget)


async def identify_protocols(observation, budget):
    async with budget.endpoint(observation.ip):
        identify = (identify_tcp(observation, budget, discovered=True)
                    if observation.transport == "tcp" else identify_udp(observation, budget))
        try:
            await asyncio.wait_for(identify, budget.config.endpoint_timeout)
        except asyncio.TimeoutError:
            observation.attempt("endpoint_budget", "timeout")
            attempted = {a["detector"] for a in observation.attempts}
            for probe in native_registry().select(
                observation.transport, observation.port, budget.config.enabled_probes,
            ):
                if probe.name not in attempted:
                    observation.attempt(probe.name, "skipped_budget")
        except (OSError, ValueError) as exc:
            observation.attempt("endpoint", "error", error_type=type(exc).__name__)
        if budget.config.nmap and observation.state == "open":
            try:
                await identify_nmap(observation, budget)
            except (OSError, ValueError) as exc:
                observation.attempt("nmap", "error", error_type=type(exc).__name__)
        from .evidence import capture
        from .fingerprint_engine import fingerprint
        if observation.state == "open" and not any(s['protocol'] != 'tls' for s in observation.services):
            observation.service("Unknown", (), raw_fingerprint=[e['id'] for e in observation.evidence], probable_protocol=None)
        fingerprint(observation, getattr(budget,'learned_signatures',()))
        observation.stage_results['service_detection']={'status':'completed'}


async def enrich_endpoint(observation, budget):
    from .plugins import run_plugins
    async with budget.endpoint(observation.ip):
        await run_plugins(observation, budget, ("enrich", "correlate"))


def needs_enrichment(observation, config):
    return config.web_enrichment and bool(observation.services)


async def identify_endpoint(observation, budget):
    """Compatibility entry point executing all stages for one endpoint."""
    await discover_endpoint(observation, budget)
    if observation.transport == "udp" or observation.state == "open":
        await identify_protocols(observation, budget)
    if needs_enrichment(observation, budget.config):
        await enumerate_protocols(observation, budget)
        await discover_resources(observation, budget)
        await enrich_endpoint(observation, budget)


async def enumerate_protocols(observation,budget):
    from .plugins import run_plugins
    async with budget.endpoint(observation.ip):
        await run_plugins(observation,budget,("fingerprint","enumerate","detect_auth"))

async def discover_resources(observation,budget):
    from .plugins import run_plugins
    async with budget.endpoint(observation.ip):
        await run_plugins(observation,budget,("discover_endpoints","authenticate"))
