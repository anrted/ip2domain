import asyncio
import logging
import re
from typing import Dict, List, Set
from urllib.parse import urlsplit
import aiohttp

from ip2domain.providers.manager import ProviderManager
from ip2domain.core.verifier import DomainVerifier
from ip2domain.core.idn_utils import decode_punycode
from ip2domain.core.domain_utils import normalize_domain

logger = logging.getLogger(__name__)


class LookupEngine:
    """
    Asynchronous engine that scans target IPs concurrently using configured providers.
    """

    def __init__(
        self,
        provider_manager: ProviderManager,
        concurrency: int = 10,
        timeout: int = 15,
        user_agent: str = None,
        verify_live: bool = True,
        enrich_subdomains: bool = True,
        max_enrichment_apexes: int = 20,
    ):
        self.provider_manager = provider_manager
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = timeout
        self.user_agent = (
            user_agent
            or "ip2domain/1.3.0 (Reverse IP Lookup & Network Intelligence Tool)"
        )
        self.verify_live = verify_live
        self.enrich_subdomains = enrich_subdomains
        self.max_enrichment_apexes = max_enrichment_apexes
        self._historical_by_ip: Dict[str, Set[str]] = {}

    @staticmethod
    def _extract_http_url_hostnames(text: str) -> Set[str]:
        """Extract only URL hostname components, never arbitrary dotted page text."""
        url_re = re.compile(r"(?i)(?:https?:)?//([^/\s\"'<>:]+)(?::\d+)?")
        return {
            normalized
            for value in url_re.findall(text or "")
            for normalized in [normalize_domain(value)]
            if normalized
        }

    async def _discover_http_names(self, ip: str, session: aiohttp.ClientSession) -> Set[str]:
        """Extract URL hostnames from direct HTTP responses and verify their IP binding."""

        async def _probe(url: str) -> Set[str]:
            found = set()
            try:
                async with session.get(
                    url,
                    allow_redirects=False,
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as response:
                    location = response.headers.get("Location")
                    if location:
                        hostname = urlsplit(location).hostname
                        normalized = normalize_domain(hostname) if hostname else None
                        if normalized:
                            found.add(normalized)
                    header_text = " ".join(
                        value for key, value in response.headers.items()
                        if key.lower() in {
                            "content-security-policy", "content-security-policy-report-only",
                            "link", "report-to", "nel", "refresh",
                        }
                    )
                    body = (await response.content.read(262_144)).decode("utf-8", errors="ignore")
                    # Arbitrary body text produces false DNS names from JavaScript
                    # properties and filenames. Only hostname components of URLs qualify.
                    found.update(self._extract_http_url_hostnames(header_text + " " + body))
            except Exception as exc:
                logger.debug("[LookupEngine] Direct HTTP probe failed for %s: %s", url, exc)
            return found

        urls = [
            f"http://{ip}/", f"https://{ip}/",
            f"http://{ip}:8080/", f"https://{ip}:8443/",
        ]
        gathered = await asyncio.gather(*[_probe(url) for url in urls], return_exceptions=True)
        found = set()
        for result in gathered:
            if isinstance(result, set):
                found.update(result)
        if not found:
            return set()

        # A URL on the page is a relation to this IP only when live DNS confirms it.
        # This rejects unrelated third-party assets such as mc.yandex.ru.
        resolved, _ = await DomainVerifier.resolve_domains(
            sorted(found)[:256], concurrency=20,
            timeout=min(4.0, float(self.timeout)), reject_wildcards=False,
        )
        return {domain for domain, addresses in resolved.items() if ip in addresses}

    async def _lookup_single(
        self, ip: str, session: aiohttp.ClientSession, sub_progress_cb=None
    ) -> Dict[str, any]:
        async with self.semaphore:
            if sub_progress_cb: sub_progress_cb(ip, 0.1, f"Запрос Reverse IP к провайдерам ({ip})")
            provider_results = await self.provider_manager.lookup_ip(ip, session)

            # Consolidate all unique domains across providers for this IP (decoding Punycode IDNs)
            all_domains: Set[str] = set()
            for provider_name, domains in list(provider_results.items()):
                normalized_domains = sorted({n for n in (normalize_domain(d) for d in domains) if n})
                provider_results[provider_name] = normalized_domains
                all_domains.update(normalized_domains)

            if sub_progress_cb: sub_progress_cb(ip, 0.25, f"Анализ HTTP-заголовков и ссылок ({ip})")
            http_domains = await self._discover_http_names(ip, session)
            if http_domains:
                provider_results["ActiveHTTP"] = sorted(http_domains)
                all_domains.update(http_domains)

            # 1. Active TLS Certificate SAN Extraction (Direct probe to target IP for SubjectAltName)
            if sub_progress_cb: sub_progress_cb(ip, 0.35, f"Анализ SSL/TLS сертификатов и SAN ({ip})")
            tls_domains: Set[str] = set()
            try:
                import ssl, socket
                from cryptography import x509
                from cryptography.x509.oid import ExtensionOID, NameOID

                loop = asyncio.get_running_loop()

                def _probe_tls_port(port: int, server_name: str = None) -> List[str]:
                    found = []
                    try:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        with socket.create_connection((ip, port), timeout=2.0) as sock:
                            with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                                der = ssock.getpeercert(binary_form=True)
                                cert = x509.load_der_x509_certificate(der)
                                for attribute in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                                    clean_n = normalize_domain(attribute.value)
                                    if clean_n:
                                        found.append(clean_n)
                                try:
                                    ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                                    for name in ext.value.get_values_for_type(x509.DNSName):
                                        clean_n = normalize_domain(name)
                                        if clean_n:
                                            found.append(clean_n)
                                except Exception:
                                    pass
                    except Exception:
                        pass
                    return found

                # Probe the default certificate and repeat port 443 with known names
                # as SNI. Different virtual hosts on one IP often expose different SANs.
                tls_tasks = [
                    loop.run_in_executor(None, _probe_tls_port, p, None)
                    for p in [443, 8443, 9443, 10443]
                ]
                tls_tasks.extend(
                    loop.run_in_executor(None, _probe_tls_port, 443, name)
                    for name in sorted(all_domains)[:12]
                )
                tls_results = await asyncio.gather(*tls_tasks, return_exceptions=True)
                for res in tls_results:
                    if isinstance(res, list):
                        tls_domains.update(res)
            except Exception as e:
                logger.debug(f"[LookupEngine] TLS SAN notice for {ip}: {e}")

            if tls_domains:
                provider_results["TLS_SAN"] = sorted(list(tls_domains))
                all_domains.update(tls_domains)

            # 2. SQLite DB Historical Match: Load all previously recorded domains for this IP
            db_historical_domains = self._historical_by_ip.get(ip, set())

            if db_historical_domains:
                provider_results["SQLiteDB"] = sorted(list(db_historical_domains))
                all_domains.update(db_historical_domains)

            # 3. Perform Targeted Subdomain Enrichment:
            # Extract apex domains from current providers + SQLite DB matches
            if sub_progress_cb: sub_progress_cb(ip, 0.65, f"Поиск поддоменов CT Logs & CertSpotter ({ip})")
            enrichment_domains: Set[str] = set()
            try:
                from ip2domain.core.domain_recon import DomainReconEngine
                from ip2domain.core.graph_builder import GraphBuilder

                apex_domains = sorted({GraphBuilder.extract_apex_domain(d) for d in all_domains if "." in d})
                apex_domains = apex_domains[:self.max_enrichment_apexes] if self.enrich_subdomains else []
                recon = DomainReconEngine(concurrency=20, timeout=4, enable_axfr=False)

                async def _check_apex(apex_dom: str):
                    try:
                        subdoms = await recon._discover_all_subdomains(apex_dom)
                        subdoms.add(apex_dom)
                        ip_to_doms, _ = await recon._resolve_subdomains_to_ips(subdoms)
                        return {d for d in ip_to_doms.get(ip, set()) if normalize_domain(d)}
                    except Exception:
                        return set()

                tasks = [_check_apex(a) for a in apex_domains]
                gathered = await asyncio.gather(*tasks, return_exceptions=True)
                for res in gathered:
                    if isinstance(res, set):
                        enrichment_domains.update(res)
            except Exception as e:
                logger.debug(f"[LookupEngine] Subdomain enrichment notice for {ip}: {e}")

            if enrichment_domains:
                provider_results["DomainEnrichment"] = sorted(list(enrichment_domains))
                all_domains.update(enrichment_domains)

            candidate_domains = sorted(all_domains)
            domains_list = candidate_domains

            if self.verify_live and domains_list:
                if sub_progress_cb: sub_progress_cb(ip, 0.85, f"Живая проверка DNS A-записей ({ip})")
                domains_list = await DomainVerifier.filter_live_domains(domains_list, ip)

            if sub_progress_cb: sub_progress_cb(ip, 1.0, f"Готово ({ip})")

            return {
                "ip": ip,
                "domains": domains_list,
                "provider_details": provider_results,
                "candidate_domains": candidate_domains,
                "rejected_candidates": sorted(set(candidate_domains) - set(domains_list)),
                "total_domains": len(domains_list),
                "verified_live": self.verify_live,
            }

    async def run(
        self, ips: List[str], progress_callback=None
    ) -> List[Dict[str, any]]:
        """
        Executes lookups for all provided IP addresses in parallel.
        """
        headers = {"User-Agent": self.user_agent}
        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)
        total = len(ips)
        completed = 0

        # Read historical data once per job rather than scanning the entire JSON history per IP.
        try:
            from ip2domain.core.storage import StorageManager
            history = StorageManager().get_global_scan_results()
            self._historical_by_ip = {
                item["ip"]: {d for d in (normalize_domain(x) for x in item.get("domains", [])) if d}
                for item in history
                if item.get("ip") in set(ips)
            }
        except Exception as exc:
            logger.debug(f"[LookupEngine] Historical preload skipped: {exc}")
            self._historical_by_ip = {}

        async def _wrapped_lookup(ip: str, session: aiohttp.ClientSession):
            nonlocal completed

            def _sub_cb(target_ip: str, sub_ratio: float, msg: str):
                if progress_callback and total > 0:
                    current_pct = int(((completed + sub_ratio) / total) * 90)
                    progress_callback(completed, total, msg, current_pct)

            res = await self._lookup_single(ip, session, sub_progress_cb=_sub_cb)
            completed += 1
            if progress_callback:
                progress_callback(completed, total, f"Поиск завершен для {ip}", int((completed / total) * 90))
            return res

        async with aiohttp.ClientSession(headers=headers, timeout=timeout_cfg) as session:
            tasks = [_wrapped_lookup(ip, session) for ip in ips]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            cleaned_results = []
            for ip, res in zip(ips, results):
                if isinstance(res, Exception):
                    logger.error(f"Failed processing IP {ip}: {res}")
                    cleaned_results.append({
                        "ip": ip,
                        "domains": [],
                        "provider_details": {},
                        "total_domains": 0,
                        "error": str(res),
                    })
                else:
                    cleaned_results.append(res)

            return cleaned_results
