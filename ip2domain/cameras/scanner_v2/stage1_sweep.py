"""Adaptive Stage 1: Port Sweep.

Selects the best available engine based on CIDR size and available tools:
  - asyncio TCP connect  (<= 4096 hosts or no root/masscan)
  - masscan subprocess   (>= 4096 hosts, root, masscan installed)  [fastest]
  - nmap -sS             (>= 4096 hosts, root, masscan missing)    [medium]
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Tool availability (cached at first call)
# ─────────────────────────────────────────────────────────────────────────────

def check_tools() -> Dict[str, bool]:
    """Return live availability of scanning tools."""
    return {
        "masscan": bool(shutil.which("masscan")),
        "nmap": bool(shutil.which("nmap")),
        "ffmpeg": bool(shutil.which("ffmpeg")),
        "is_root": os.geteuid() == 0,
    }


# ─────────────────────────────────────────────────────────────────────────────
# asyncio TCP connect sweep (enhanced, up to 300 concurrent)
# ─────────────────────────────────────────────────────────────────────────────

async def _tcp_check(ip: str, port: int, timeout: float) -> Tuple[str, int]:
    writer = None
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        return ip, port
    except Exception:
        return ip, 0
    finally:
        if writer:
            try:
                writer.close()
            except Exception:
                pass


async def asyncio_port_sweep(
    targets: List[str],
    ports: Tuple[int, ...],
    concurrency: int = 150,
    timeout: float = 1.2,
    on_progress: Optional[Callable] = None,
    is_cancelled: Optional[Callable] = None,
) -> List[Tuple[str, List[int]]]:
    """High-concurrency asyncio TCP connect sweep.

    Returns list of (ip, [open_ports]) for responsive hosts.
    Concurrency is per-host: each host fires all port checks in parallel.
    """
    semaphore = asyncio.Semaphore(concurrency)
    result_map: Dict[str, List[int]] = {}
    completed = 0
    total = len(targets)
    lock = asyncio.Lock()

    async def probe_host(ip: str):
        nonlocal completed
        if is_cancelled and is_cancelled():
            return
        async with semaphore:
            tasks = [_tcp_check(ip, p, timeout) for p in ports]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            open_ports = [
                r[1] for r in results
                if isinstance(r, tuple) and len(r) == 2 and isinstance(r[1], int) and r[1] > 0
            ]
            async with lock:
                completed += 1
                if open_ports:
                    result_map[ip] = sorted(open_ports)
                if on_progress:
                    on_progress(completed, total, ip, len(result_map))

    batch_size = 1000
    for i in range(0, total, batch_size):
        if is_cancelled and is_cancelled():
            break
        batch = targets[i: i + batch_size]
        await asyncio.gather(*[asyncio.create_task(probe_host(ip)) for ip in batch], return_exceptions=True)

    return [(ip, ports_list) for ip, ports_list in result_map.items()]


# ─────────────────────────────────────────────────────────────────────────────
# masscan subprocess wrapper
# ─────────────────────────────────────────────────────────────────────────────

async def masscan_sweep(
    targets: List[str],
    ports: Tuple[int, ...],
    rate: int = 50000,
    on_progress: Optional[Callable] = None,
    is_cancelled: Optional[Callable] = None,
) -> List[Tuple[str, List[int]]]:
    """Run masscan to perform SYN sweep; much faster than asyncio for large CIDRs.

    Requires: masscan installed, root privileges.
    Returns list of (ip, [open_ports]).
    """
    masscan_bin = shutil.which("masscan")
    if not masscan_bin:
        raise RuntimeError("masscan not found")

    port_str = ",".join(str(p) for p in ports)
    # masscan expects CIDRs or IPs; build target list
    # For large ranges, write targets to temp file
    import tempfile, os
    tmp_targets = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    try:
        for t in targets:
            tmp_targets.write(t + "\n")
        tmp_targets.flush()
        tmp_targets.close()

        tmp_out = tmp_targets.name + ".json"
        cmd = [
            masscan_bin,
            "-iL", tmp_targets.name,
            "-p", port_str,
            "--rate", str(rate),
            "--output-format", "json",
            "--output-filename", tmp_out,
            "--wait", "2",
        ]
        logger.info("[v2 Stage1/masscan] Starting: rate=%d pps, ports=%s, targets=%d", rate, port_str, len(targets))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Poll stderr for progress while scanning
        scanned = 0
        total = len(targets)
        async def _read_stderr():
            nonlocal scanned
            async for line in proc.stderr:
                txt = line.decode(errors="ignore").strip()
                if is_cancelled and is_cancelled():
                    proc.kill()
                    return
                # masscan prints "rate: X.XX-kpps, X% done"
                if "%" in txt and on_progress:
                    try:
                        pct_part = [p for p in txt.split(",") if "%" in p][0]
                        pct = float(pct_part.strip().replace("%", "").split()[-1])
                        scanned = int(total * pct / 100)
                        on_progress(scanned, total, "", 0)
                    except Exception:
                        pass

        stderr_task = asyncio.create_task(_read_stderr())
        await proc.wait()
        await stderr_task

        if is_cancelled and is_cancelled():
            return []

        # Parse JSON output
        result_map: Dict[str, List[int]] = {}
        if os.path.exists(tmp_out):
            try:
                with open(tmp_out) as f:
                    content = f.read().strip()
                # masscan JSON is not valid: it has trailing comma; fix it
                if content.endswith(","):
                    content = content[:-1]
                if not content.startswith("["):
                    content = "[" + content + "]"
                entries = json.loads(content)
                for entry in entries:
                    ip = entry.get("ip", "")
                    port = entry.get("ports", [{}])[0].get("port", 0)
                    if ip and port:
                        result_map.setdefault(ip, [])
                        if port not in result_map[ip]:
                            result_map[ip].append(port)
            except Exception as exc:
                logger.warning("[v2 Stage1/masscan] JSON parse error: %s", exc)

        if on_progress:
            on_progress(total, total, "", len(result_map))

        return [(ip, sorted(ps)) for ip, ps in result_map.items()]

    finally:
        try:
            os.unlink(tmp_targets.name)
        except Exception:
            pass
        try:
            os.unlink(tmp_out)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# nmap -sS SYN scan fallback
# ─────────────────────────────────────────────────────────────────────────────

async def nmap_syn_sweep(
    targets: List[str],
    ports: Tuple[int, ...],
    on_progress: Optional[Callable] = None,
    is_cancelled: Optional[Callable] = None,
) -> List[Tuple[str, List[int]]]:
    """nmap -sS SYN scan fallback for large CIDRs when masscan is unavailable.

    Requires root. Faster than full TCP connect but slower than masscan.
    Processes targets in batches of 256 to stay manageable.
    """
    import xml.etree.ElementTree as ET
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        raise RuntimeError("nmap not found")

    port_str = ",".join(str(p) for p in ports)
    result_map: Dict[str, List[int]] = {}
    total = len(targets)
    completed = 0
    batch_size = 256

    for i in range(0, total, batch_size):
        if is_cancelled and is_cancelled():
            break
        batch = targets[i: i + batch_size]
        cmd = [
            nmap_bin, "-sS", "-T4", "-Pn", "-n",
            "--max-retries", "1", "--host-timeout", "30s",
            "-p", port_str, "-oX", "-",
        ] + batch

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            xml_text = stdout.decode(errors="ignore")

            root = ET.fromstring(xml_text)
            for host in root.findall("host"):
                addr = host.find("address")
                ip = addr.get("addr", "") if addr is not None else ""
                if not ip:
                    continue
                open_ports = []
                for port_node in host.findall("./ports/port"):
                    state = port_node.find("state")
                    if state is not None and state.get("state") == "open":
                        open_ports.append(int(port_node.get("portid", 0)))
                if open_ports:
                    result_map[ip] = sorted(open_ports)
        except Exception as exc:
            logger.warning("[v2 Stage1/nmap-sS] Batch error: %s", exc)

        completed += len(batch)
        if on_progress:
            on_progress(completed, total, "", len(result_map))

    return [(ip, ps) for ip, ps in result_map.items()]


# ─────────────────────────────────────────────────────────────────────────────
# Adaptive selector
# ─────────────────────────────────────────────────────────────────────────────

_ASYNCIO_THRESHOLD = 4096   # hosts — below this, asyncio is fast enough


async def adaptive_port_sweep(
    targets: List[str],
    ports: Tuple[int, ...],
    engine: str = "auto",
    masscan_rate: int = 50000,
    concurrency: int = 150,
    port_timeout: float = 1.2,
    on_progress: Optional[Callable] = None,
    is_cancelled: Optional[Callable] = None,
) -> Tuple[List[Tuple[str, List[int]]], str]:
    """Select the best sweep engine and run it.

    Args:
        engine: "auto" | "asyncio" | "masscan" | "nmap_syn"
    Returns:
        (results, engine_name_used)
    """
    tools = check_tools()
    n = len(targets)

    # Determine engine
    if engine == "masscan" or (
        engine == "auto"
        and n >= _ASYNCIO_THRESHOLD
        and tools["masscan"]
        and tools["is_root"]
    ):
        logger.info("[v2 Stage1] Using masscan (%d targets)", n)
        results = await masscan_sweep(targets, ports, rate=masscan_rate,
                                      on_progress=on_progress, is_cancelled=is_cancelled)
        return results, "masscan"

    elif engine == "nmap_syn" or (
        engine == "auto"
        and n >= _ASYNCIO_THRESHOLD
        and tools["nmap"]
        and tools["is_root"]
        and not tools["masscan"]
    ):
        logger.info("[v2 Stage1] Using nmap -sS (%d targets)", n)
        results = await nmap_syn_sweep(targets, ports, on_progress=on_progress, is_cancelled=is_cancelled)
        return results, "nmap_syn"

    else:
        logger.info("[v2 Stage1] Using asyncio TCP connect (%d targets, concurrency=%d)", n, concurrency)
        results = await asyncio_port_sweep(targets, ports, concurrency=concurrency,
                                           timeout=port_timeout, on_progress=on_progress,
                                           is_cancelled=is_cancelled)
        return results, "asyncio"
