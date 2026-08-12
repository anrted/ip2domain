import asyncio
import json
import logging
import re
import socket
from typing import Dict, List, Optional, Set, Tuple
import aiohttp

from ip2domain.core.idn_utils import decode_punycode
from ip2domain.core.domain_utils import normalize_domain, is_subdomain_of
from ip2domain.core.verifier import DomainVerifier

logger = logging.getLogger(__name__)

# Common subdomains fallback list for quick brute/probe
COMMON_SUBDOMAINS = [
    "www", "api", "dev", "app", "admin", "mail", "stage", "staging",
    "test", "vps", "web", "cdn", "shop", "blog", "portal", "panel",
    "db", "auth", "login", "vpn", "remote", "cloud", "ns1", "ns2",
    "m", "ftp", "pop", "smtp", "gitlab", "git", "status", "demo", "sub",
    "autodiscover", "sip", "exchange", "webmail", "store", "assets", "static"
]


class DomainReconEngine:
    """
    Asynchronous Forward Domain Recon Engine:
    Discovers subdomains (AXFR, CT logs, passive APIs, DNS probes), resolves A/AAAA records to IP addresses,
    and maps the full infrastructure graph (Domain -> Subdomains -> IPs).
    """

    def __init__(
        self,
        concurrency: int = 15,
        timeout: int = 8,
        user_agent: Optional[str] = None,
        enable_axfr: bool = True,
    ):
        self.concurrency = concurrency
        self.timeout = timeout
        self.user_agent = user_agent or "ip2domain/1.3 (Domain Recon Engine)"
        self.enable_axfr = enable_axfr
        self.last_rejected_wildcards: Set[str] = set()

    @staticmethod
    def is_domain_target(target: str) -> bool:
        """
        Returns True if target string is a domain name (not an IP address or CIDR range).
        """
        target_clean = normalize_domain(target)
        if not target_clean:
            return False
        # If contains slash or range dash with digits, it's CIDR or range
        if "/" in target_clean or (re.search(r"\d+\.\d+\.\d+\.\d+-\d+", target_clean)):
            return False
        # If pure IP address
        try:
            socket.inet_aton(target_clean)
            return False
        except socket.error:
            pass

        # Check domain pattern: e.g. example.com, sub.domain.co.uk, xn--e1afmkfd.xn--p1ai
        domain_pattern = r"^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z0-9-]{2,63}$"
        return bool(re.match(domain_pattern, target_clean))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run_domain_recon(
        self, target_domain: str, progress_callback=None
    ) -> List[Dict[str, any]]:
        """
        Main entry point for Domain -> Subdomains -> IPs reconnaissance.
        Returns list of dicts in standard scan_results format:
        [
            {
                "ip": "194.33.15.13",
                "domains": ["grinronn.ru", "www.grinronn.ru", "api.grinronn.ru"],
                "verified_live": True,
                "provider_details": {"crt.sh": ["..."], "DNS": ["..."]}
            }
        ]
        """
        domain_clean = normalize_domain(target_domain)
        if not domain_clean:
            raise ValueError("Invalid domain target")
        logger.info(f"[DomainReconEngine] Starting domain recon for: {domain_clean}")

        if progress_callback:
            progress_callback(10, f"Поиск поддоменов для {domain_clean}...")

        # Step 1: Discover all subdomains via CT logs & APIs
        subdomains = await self._discover_all_subdomains(domain_clean, progress_callback)
        subdomains.add(domain_clean)  # Include root domain itself

        if progress_callback:
            progress_callback(40, f"DNS резолвинг {len(subdomains)} поддоменов в IP...")

        # Step 2: Resolve all subdomains to IP addresses concurrently
        ip_to_domains, domain_to_ips = await self._resolve_subdomains_to_ips(
            subdomains, progress_callback
        )

        if progress_callback:
            progress_callback(90, f"Формирование топологии для {len(ip_to_domains)} IP...")

        # Step 3: Format into standard scan_results list
        results = []
        for ip, doms in ip_to_domains.items():
            results.append({
                "ip": ip,
                "domains": sorted(list(doms)),
                "total_domains": len(doms),
                "verified_live": True,
                "open_ports": [],
                "provider_details": {
                    "DomainRecon": [d for d in doms if is_subdomain_of(d, domain_clean)],
                }
            })

        if progress_callback:
            progress_callback(100, f"Доменный рекогносцировка завершена ({len(results)} IP)!")

        return results

    # ------------------------------------------------------------------
    # Subdomain Discovery Sources
    # ------------------------------------------------------------------

    async def _discover_all_subdomains(
        self, domain: str, progress_callback=None
    ) -> Set[str]:
        """Queries AXFR, passive sources and common DNS candidates concurrently."""
        tasks = [
            self._fetch_crtsh_subdomains(domain),
            self._fetch_hackertarget_subdomains(domain),
            self._fetch_subdomaincenter_subdomains(domain),
            self._fetch_certspotter_subdomains(domain),
            self._probe_common_subdomains(domain),
        ]
        if self.enable_axfr:
            tasks.insert(0, self._fetch_axfr_subdomains(domain))

        subdomain_sets = await asyncio.gather(*tasks, return_exceptions=True)
        all_subdomains: Set[str] = set()

        for s in subdomain_sets:
            if isinstance(s, set):
                all_subdomains.update(s)
            elif isinstance(s, Exception):
                logger.warning(f"[DomainReconEngine] Subdomain source error: {s}")

        logger.info(f"[DomainReconEngine] Found {len(all_subdomains)} total subdomains for {domain}")
        return all_subdomains

    async def _fetch_axfr_subdomains(self, domain: str) -> Set[str]:
        """Attempt an authorized public AXFR against each authoritative nameserver."""
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._perform_axfr_transfer, domain),
                timeout=max(5.0, min(float(self.timeout), 15.0) * 3),
            )
        except Exception as exc:
            logger.debug(f"[DomainReconEngine] AXFR timed out for {domain}: {exc}")
            return set()

    @staticmethod
    def _extract_axfr_names(zone, domain: str) -> Set[str]:
        found = set()
        for owner in zone.nodes:
            hostname = str(owner).rstrip(".").lower()
            if hostname.startswith("*."):
                continue
            normalized = normalize_domain(hostname)
            if normalized and is_subdomain_of(normalized, domain):
                found.add(normalized)
        return found

    def _perform_axfr_transfer(self, domain: str) -> Set[str]:
        found: Set[str] = set()
        try:
            import dns.query
            import dns.resolver
            import dns.zone
        except ImportError:
            return self._perform_axfr_with_dig(domain)

        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = self.timeout
            nameservers = sorted({
                str(answer.target).rstrip(".")
                for answer in resolver.resolve(domain, "NS")
            })
        except Exception as exc:
            logger.debug(f"[DomainReconEngine] AXFR NS lookup failed for {domain}: {exc}")
            return found

        for nameserver in nameservers:
            try:
                transfer = dns.query.xfr(
                    nameserver,
                    domain,
                    lifetime=min(float(self.timeout), 15.0),
                    relativize=False,
                )
                zone = dns.zone.from_xfr(transfer, relativize=False)
                found = self._extract_axfr_names(zone, domain)
                if found:
                    logger.info(
                        "[DomainReconEngine] AXFR succeeded via %s: %d name(s)",
                        nameserver, len(found),
                    )
                    break
            except Exception as exc:
                logger.debug(
                    "[DomainReconEngine] AXFR refused/failed via %s for %s: %s",
                    nameserver, domain, exc,
                )
        return found

    def _perform_axfr_with_dig(self, domain: str) -> Set[str]:
        """Use the system dig command when dnspython is unavailable."""
        import shutil
        import subprocess

        dig = shutil.which("dig")
        if not dig:
            logger.debug("[DomainReconEngine] AXFR skipped: dnspython/dig unavailable")
            return set()
        try:
            ns_result = subprocess.run(
                [dig, "+short", "NS", domain],
                capture_output=True,
                text=True,
                timeout=min(float(self.timeout), 15.0),
                check=False,
            )
            nameservers = sorted({line.strip().rstrip(".") for line in ns_result.stdout.splitlines() if line.strip()})
        except Exception as exc:
            logger.debug(f"[DomainReconEngine] dig NS lookup failed for {domain}: {exc}")
            return set()

        for nameserver in nameservers:
            try:
                result = subprocess.run(
                    [dig, "+time=5", "+tries=1", "AXFR", domain, f"@{nameserver}"],
                    capture_output=True,
                    text=True,
                    timeout=min(float(self.timeout), 15.0),
                    check=False,
                )
                if ";; XFR size:" not in result.stdout:
                    continue
                found = set()
                for line in result.stdout.splitlines():
                    fields = line.split()
                    if len(fields) < 5 or line.lstrip().startswith(";"):
                        continue
                    hostname = fields[0].rstrip(".").lower()
                    if hostname.startswith("*."):
                        continue
                    normalized = normalize_domain(hostname)
                    if normalized and is_subdomain_of(normalized, domain):
                        found.add(normalized)
                if found:
                    logger.info(
                        "[DomainReconEngine] AXFR succeeded via dig/%s: %d name(s)",
                        nameserver, len(found),
                    )
                    return found
            except Exception as exc:
                logger.debug(
                    "[DomainReconEngine] dig AXFR refused/failed via %s for %s: %s",
                    nameserver, domain, exc,
                )
        return set()

    async def _fetch_crtsh_subdomains(self, domain: str) -> Set[str]:
        """Queries Certificate Transparency log API (crt.sh)."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        subdomains = set()
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers={"User-Agent": self.user_agent}) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            name_val = entry.get("name_value", "")
                            # Split multiline SAN entries
                            for name in name_val.split("\n"):
                                name_clean = name.strip().lower().lstrip("*.")
                                if is_subdomain_of(name_clean, domain) and self.is_domain_target(name_clean):
                                    subdomains.add(name_clean)
        except Exception as e:
            logger.debug(f"[DomainReconEngine] crt.sh query failed for {domain}: {e}")

        return subdomains

    async def _fetch_hackertarget_subdomains(self, domain: str) -> Set[str]:
        """Queries HackerTarget hostsearch API."""
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        subdomains = set()
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers={"User-Agent": self.user_agent}) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.splitlines():
                            if "," in line:
                                host = line.split(",")[0].strip().lower()
                                if is_subdomain_of(host, domain) and self.is_domain_target(host):
                                    subdomains.add(host)
        except Exception as e:
            logger.debug(f"[DomainReconEngine] HackerTarget hostsearch failed for {domain}: {e}")

        return subdomains

    async def _fetch_subdomaincenter_subdomains(self, domain: str) -> Set[str]:
        """Queries Subdomain.Center API for subdomains."""
        url = f"https://api.subdomain.center/?domain={domain}"
        subdomains = set()
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers={"User-Agent": self.user_agent}) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        if isinstance(data, list):
                            for d in data:
                                name_clean = d.strip().lower().lstrip("*.")
                                if is_subdomain_of(name_clean, domain) and self.is_domain_target(name_clean):
                                    subdomains.add(name_clean)
        except Exception as e:
            logger.debug(f"[DomainReconEngine] SubdomainCenter query failed for {domain}: {e}")

        return subdomains

    async def _fetch_certspotter_subdomains(self, domain: str) -> Set[str]:
        """Queries CertSpotter CT log API."""
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        subdomains = set()
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers={"User-Agent": self.user_agent}) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        if isinstance(data, list):
                            for item in data:
                                for name in item.get("dns_names", []):
                                    name_clean = name.strip().lower().lstrip("*.")
                                    if is_subdomain_of(name_clean, domain) and self.is_domain_target(name_clean):
                                        subdomains.add(name_clean)
        except Exception as e:
            logger.debug(f"[DomainReconEngine] CertSpotter query failed for {domain}: {e}")

        return subdomains

    async def _probe_common_subdomains(self, domain: str) -> Set[str]:
        """Generates candidates from COMMON_SUBDOMAINS list."""
        candidates = {f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS}
        return candidates

    # ------------------------------------------------------------------
    # Async DNS Resolution
    # ------------------------------------------------------------------

    async def _resolve_subdomains_to_ips(
        self, subdomains: Set[str], progress_callback=None
    ) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
        """
        Resolves a set of subdomains to IP addresses concurrently via socket.getaddrinfo.
        Returns (ip_to_domains, domain_to_ips).
        """
        ip_to_domains: Dict[str, Set[str]] = {}
        domain_to_ips: Dict[str, Set[str]] = {}

        total = len(subdomains)
        completed = 0
        domain_to_ips, rejected = await DomainVerifier.resolve_domains(
            list(subdomains),
            concurrency=self.concurrency,
            timeout=self.timeout,
            reject_wildcards=True,
        )
        self.last_rejected_wildcards = rejected
        if rejected:
            logger.info(
                "[DomainReconEngine] Rejected %d wildcard DNS candidate(s): %s",
                len(rejected), ", ".join(sorted(rejected)[:10]),
            )

        for sub, ips in domain_to_ips.items():
            completed += 1
            if progress_callback and total > 0:
                pct = 40 + int((completed / total) * 50)
                progress_callback(pct, f"DNS проверен {completed}/{total}: {sub}")
            for ip in ips:
                ip_to_domains.setdefault(ip, set()).add(sub)

        return ip_to_domains, domain_to_ips
