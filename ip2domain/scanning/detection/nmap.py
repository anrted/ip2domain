"""Optional broad service detection adapter; never executes NSE scripts."""
from __future__ import annotations

import asyncio
import ipaddress
import shutil
import xml.etree.ElementTree as ET

from ..inventory import public_text

MAX_OUTPUT = 2 * 1024 * 1024
GROUPS = {
    "http": ("web",), "https": ("web",), "rtsp": ("video",),
    "rtmp": ("video",), "sip": ("voice",), "sips": ("voice",),
    "ssh": ("management",), "telnet": ("management",), "snmp": ("management",),
    "mqtt": ("iot",), "coap": ("iot",), "ftp": ("storage",),
    "microsoft-ds": ("storage",), "netbios-ssn": ("storage",), "nfs": ("storage",),
    "modbus": ("industrial",), "bacnet": ("industrial",), "opcua": ("industrial",),
    "dnp": ("industrial",), "EtherNetIP-1": ("industrial",),
    "ms-wbt-server": ("management",), "ipp": ("printing",),
}


def parse_xml(data, observation):
    # Nmap's own XML includes a bare DOCTYPE; never accept an external DTD.
    data = data.replace(b"<!DOCTYPE nmaprun>", b"")
    if len(data) > MAX_OUTPUT or b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise ValueError("unsafe or oversized nmap XML")
    root = ET.fromstring(data)
    for host in root.findall("host"):
        addresses = {a.get("addr") for a in host.findall("address")}
        if observation.ip not in addresses:
            continue
        for port in host.findall("./ports/port"):
            if port.get("protocol") != observation.transport or port.get("portid") != str(observation.port):
                continue
            state = port.find("state")
            if state is not None and state.get("state") in {
                "open", "closed", "filtered", "open|filtered", "closed|filtered", "unfiltered",
            }:
                reported = state.get("state").replace("|", "_or_")
                if observation.state != "open":
                    observation.state = reported
            service = port.find("service")
            if service is None:
                continue
            # Nmap also emits port-table guesses: NEVER promote those to detection.
            if service.get("method") != "probed" or int(service.get("conf", "0")) < 7:
                observation.attempt("nmap", "unconfirmed_hint")
                continue
            protocol = service.get("name", "unknown")
            if protocol in ("unknown", "tcpwrapped"):
                observation.attempt("nmap", "unidentified")
                continue
            attributes = {
                key: public_text(service.get(key))
                for key in ("product", "version", "extrainfo", "ostype", "devicetype", "tunnel")
                if service.get(key)
            }
            attributes["source"] = "nmap-service-probes"
            attributes["confidence"] = int(service.get("conf"))
            attributes["cpe"] = [public_text(c.text) for c in service.findall("cpe") if c.text]
            observation.service(protocol, GROUPS.get(protocol, ()), **attributes)
            observation.attempt("nmap", "detected")


async def identify_nmap(observation, budget):
    executable = shutil.which("nmap")
    if not executable:
        observation.attempt("nmap", "unavailable")
        return
    if observation.port in {9100, 9101, 9102} and not budget.config.nmap_all_ports:
        observation.attempt("nmap", "skipped_policy")
        return
    if observation.transport == "udp":
        # Native UDP is unprivileged. Do not silently launch privileged UDP scans.
        observation.attempt("nmap", "unsupported_transport")
        return
    ipaddress.ip_address(observation.ip)
    if not budget.scope.contains(observation.ip):
        raise ValueError("destination outside scope")
    config = budget.config
    command = [
        executable, "-n", "-Pn", "-sT", "-sV", "--version-all",
        "--max-retries", str(config.retries), "--max-rate", str(config.rate),
        "--host-timeout", f"{int(config.nmap_timeout)}s",
        "-p", str(observation.port), "-oX", "-",
    ]
    if ":" in observation.ip:
        command.append("-6")
    if config.nmap_all_ports:
        command.append("--allports")
    command.append(observation.ip)
    await budget.tick()
    process = await asyncio.create_subprocess_exec(
        *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    async def read():
        data = bytearray()
        while True:
            chunk = await process.stdout.read(65536)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_OUTPUT:
                raise ValueError("nmap output limit")
        await process.wait()
        return bytes(data)
    try:
        data = await asyncio.wait_for(read(), config.nmap_timeout + 2)
        if process.returncode != 0:
            observation.attempt("nmap", "error")
        else:
            parse_xml(data, observation)
            observation.attempt("nmap", "completed")
    except asyncio.TimeoutError:
        observation.attempt("nmap", "timeout")
    finally:
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()
