"""Execution of selected wire probes, sharing transport and endpoint budgets."""
import asyncio
import time

from .catalog import native_registry
from ..transports.network import exchange, datagram


async def run_wire_probes(observation, budget, *, tls=False):
    config = budget.config
    registry = native_registry()
    selected = registry.select(observation.transport, observation.port, config.enabled_probes)
    started = time.monotonic()
    for index, probe in enumerate(selected):
        if "industrial" in probe.categories and not config.industrial_consent:
            observation.attempt(probe.name, "skipped_policy")
            continue
        remaining = config.endpoint_timeout - (time.monotonic() - started)
        if remaining <= 0:
            for skipped in selected[index:]:
                observation.attempt(skipped.name, "skipped_budget")
            return
        if config.protocol_families and not set(probe.categories)&set(config.protocol_families):
            observation.attempt(probe.name,"skipped_selection")
            continue
        wire = probe.build(observation, config)
        for attempt in range(config.retries + 1):
            try:
                from ..plugins.base import BudgetExhausted
                await budget.protocol_tick(observation.ip,probe.name)
                if observation.transport == "udp":
                    raw = await datagram(budget, observation.ip, observation.port, wire.payload, wire.limit)
                    observation.state = "open"
                else:
                    raw = await exchange(
                        budget, observation.ip, observation.port, wire.payload,
                        tls=tls, framing=wire.framing, minimum=wire.minimum, limit=wire.limit,
                    )
                from ..evidence import capture
                evidence=capture(observation,"wire_response",raw,source=probe.name,elapsed_ms=round((time.monotonic()-started)*1000,2))
                parsed = wire.parse(raw)
                if parsed is not None:
                    parsed = dict(parsed)
                    parsed["evidence"] = evidence
                    protocol = parsed.pop("protocol", None) or ((probe.secure_name or probe.name) if tls else probe.name)
                    observation.service(protocol, probe.categories, **parsed)
                    observation.attempt(probe.name, "detected", version=probe.version)
                    await observation.checkpoint()
                    # No unrelated binary traffic after a confirmed application.
                    for skipped in selected[index + 1:]:
                        observation.attempt(skipped.name, "skipped_identified")
                    return
                observation.attempt(probe.name, "no_match")
                break
            except BudgetExhausted:
                for skipped in selected[index:]:observation.attempt(skipped.name,"skipped_budget")
                return
            except ConnectionRefusedError:
                if observation.transport == "udp" and observation.state != "open":
                    observation.state = "closed"
                observation.attempt(probe.name, "refused")
                if observation.transport == "udp" and observation.state == "closed":
                    return
                break
            except asyncio.TimeoutError:
                observation.attempt(probe.name, "timeout")
            except OSError as exc:
                observation.attempt(probe.name, "error", error_type=type(exc).__name__)
                if observation.transport == "udp" and observation.state != "open":
                    observation.state = "filtered"
                break
            except (ValueError, IndexError) as exc:
                # Malformed peer data is an isolated detector failure.
                observation.attempt(probe.name, "invalid_response", error_type=type(exc).__name__)
                break
        await observation.checkpoint()
