import asyncio
import socket
import logging
import ipaddress
import secrets
from typing import Dict, List, Set, Tuple

logger = logging.getLogger(__name__)


class DomainVerifier:
    """
    Verifies whether discovered domains CURRENTLY resolve to the target IP address (Live A/AAAA verification).
    """

    @staticmethod
    async def resolve_domain(domain: str, timeout: float = 5.0) -> Set[str]:
        """Resolve a hostname with a bounded coroutine-level timeout."""
        loop = asyncio.get_running_loop()
        try:
            res = await asyncio.wait_for(
                loop.run_in_executor(
                    None, socket.getaddrinfo, domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM
                ),
                timeout=timeout,
            )
            return {str(ipaddress.ip_address(item[4][0])) for item in res}
        except Exception:
            return set()

    @classmethod
    async def verify_domain(cls, domain: str, expected_ip: str, timeout: float = 5.0) -> bool:
        """
        Resolves domain's A/AAAA records and checks if expected_ip is among resolved IPs.
        """
        try:
            expected = str(ipaddress.ip_address(expected_ip))
            return expected in await cls.resolve_domain(domain, timeout=timeout)
        except Exception:
            return False

    @staticmethod
    def _wildcard_test_parent(domain: str) -> str:
        """Return the closest parent worth probing, excluding apex domains."""
        from ip2domain.core.graph_builder import GraphBuilder

        apex = GraphBuilder.extract_apex_domain(domain)
        if domain == apex:
            return ""
        return domain.split(".", 1)[1]

    @classmethod
    async def resolve_domains(
        cls,
        domains: List[str],
        concurrency: int = 20,
        timeout: float = 5.0,
        reject_wildcards: bool = True,
    ) -> Tuple[Dict[str, Set[str]], Set[str]]:
        """Resolve candidates and reject names synthesized by wildcard DNS."""
        semaphore = asyncio.Semaphore(concurrency)

        async def _resolve(name: str) -> Tuple[str, Set[str]]:
            async with semaphore:
                return name, await cls.resolve_domain(name, timeout=timeout)

        resolved_pairs = await asyncio.gather(
            *[_resolve(domain) for domain in sorted(set(domains))],
            return_exceptions=True,
        )
        resolved = {
            name: ips
            for item in resolved_pairs
            if isinstance(item, tuple)
            for name, ips in [item]
            if ips
        }
        if not reject_wildcards or not resolved:
            return resolved, set()

        parents = {
            parent
            for domain in resolved
            for parent in [cls._wildcard_test_parent(domain)]
            if parent
        }

        async def _probe_parent(parent: str) -> Tuple[str, Set[str]]:
            probe_names = [
                f"ip2domain-{secrets.token_hex(12)}.{parent}",
                f"ip2domain-{secrets.token_hex(12)}.{parent}",
            ]
            async with semaphore:
                answers = await asyncio.gather(
                    *[cls.resolve_domain(name, timeout=timeout) for name in probe_names]
                )
            # Two positive random answers are required before treating a zone as wildcarded.
            if all(answers):
                return parent, set().union(*answers)
            return parent, set()

        wildcard_pairs = await asyncio.gather(
            *[_probe_parent(parent) for parent in sorted(parents)],
            return_exceptions=True,
        )
        wildcard_by_parent = {
            parent: ips
            for item in wildcard_pairs
            if isinstance(item, tuple)
            for parent, ips in [item]
            if ips
        }

        rejected = set()
        for domain, ips in resolved.items():
            parent = cls._wildcard_test_parent(domain)
            wildcard_ips = wildcard_by_parent.get(parent, set())
            if wildcard_ips and ips.issubset(wildcard_ips):
                rejected.add(domain)

        for domain in rejected:
            resolved.pop(domain, None)
        return resolved, rejected

    @classmethod
    async def filter_live_domains(cls, domains: List[str], expected_ip: str, concurrency: int = 20, timeout: float = 5.0) -> List[str]:
        """
        Filters input domain list, keeping only those that currently resolve to expected_ip.
        """
        try:
            expected = str(ipaddress.ip_address(expected_ip))
        except ValueError:
            return []
        resolved, _ = await cls.resolve_domains(
            domains, concurrency=concurrency, timeout=timeout, reject_wildcards=True
        )
        return sorted(domain for domain, ips in resolved.items() if expected in ips)
