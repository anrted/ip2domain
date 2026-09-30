"""Port-independent TCP identification with explicit risk and time budgets."""
from __future__ import annotations

import asyncio
import ssl

from ..protocols.text import banner_service
from ..transports.network import close_writer
from ..detection.scheduler import run_wire_probes

PROTECTED_PORTS = {9100, 9101, 9102}


async def discover_tcp(observation, budget):
    """Connect and collect a bounded server-first banner, without client payloads."""
    ip, port = observation.ip, observation.port
    try:
        reader, writer = await budget.connect(ip, port)
        observation.state = "open"
        observation.attempt("tcp_connect", "completed")
    except ConnectionRefusedError:
        observation.state = "closed"
        observation.attempt("tcp_connect", "refused")
        return
    except (asyncio.TimeoutError, OSError) as exc:
        observation.state = "filtered" if isinstance(exc, asyncio.TimeoutError) else "unreachable"
        observation.attempt("tcp_connect", observation.state, error_type=type(exc).__name__)
        return
    if writer is None:
        return
    try:
        await observation.checkpoint()
        try:
            data = await asyncio.wait_for(reader.read(2048), budget.config.banner_timeout)
            from ..evidence import capture
            if data: capture(observation,"banner",data,source="server-first")
            detected = banner_service(data)
            if detected:
                protocol, categories, attributes = detected
                observation.service(protocol, categories, **attributes)
                observation.attempt("banner", "detected")
                await observation.checkpoint()
                return
            observation.attempt("banner", "unrecognized" if data else "empty")
        except asyncio.TimeoutError:
            observation.attempt("banner", "timeout")
        except OSError as exc:
            # A server resetting a banner connection is ordinary endpoint
            # behaviour, not a reason to abort the entire discovery pool.
            observation.attempt("banner", "error", error_type=type(exc).__name__)
    finally:
        await close_writer(writer)


async def identify_tcp(observation, budget, *, discovered=False):
    if not discovered:
        await discover_tcp(observation, budget)
    if observation.state != "open" or any(a["detector"] == "banner" and a["status"] == "detected" for a in observation.attempts):
        return
    ip, port = observation.ip, observation.port
    if not budget.config.active or port in PROTECTED_PORTS:
        observation.attempt("active_identification", "skipped_policy")
        return

    if budget.config.enabled_probes == ():
        observation.attempt("active_identification", "skipped_selection")
        return

    # TLS is a transport wrapper, not a substitute for application identification.
    tls = False
    writer = None
    try:
        _, writer = await budget.connect(ip, port, tls=True)
        session = writer.get_extra_info("ssl_object")
        tls = True
        from ..evidence import capture
        import hashlib
        certificate=session.getpeercert(binary_form=True) or b""
        evidence=capture(observation,"tls_certificate",certificate,source="tls-handshake")
        observation.service("tls", (), version=session.version(), cipher=session.cipher()[0], alpn=session.selected_alpn_protocol(), certificate_sha256=hashlib.sha256(certificate).hexdigest(), evidence=evidence)
        observation.attempt("tls", "detected")
        await observation.checkpoint()
    except (asyncio.TimeoutError, OSError, ssl.SSLError) as exc:
        observation.attempt("tls", "no_match", error_type=type(exc).__name__)
    finally:
        await close_writer(writer)

    await run_wire_probes(observation, budget, tls=tls)
