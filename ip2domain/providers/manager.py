import asyncio
import logging
import os
from typing import Dict, List, Type
import aiohttp

from ip2domain.providers.base import BaseProvider
from ip2domain.providers.ptr import PTRProvider
from ip2domain.providers.hackertarget import HackerTargetProvider
from ip2domain.providers.alienvault import AlienVaultProvider
from ip2domain.providers.rapiddns import RapidDNSProvider
from ip2domain.providers.subdomaincenter import SubdomainCenterProvider
from ip2domain.providers.certspotter import CertSpotterProvider
from ip2domain.providers.hackertarget_banner import HackerTargetBannerProvider
from ip2domain.providers.urlscan import URLScanProvider
from ip2domain.providers.virustotal import VirusTotalProvider
from ip2domain.providers.shodan import ShodanProvider
from ip2domain.providers.censys import CensysProvider

logger = logging.getLogger(__name__)

# Registry of all built-in providers
AVAILABLE_PROVIDERS: Dict[str, Type[BaseProvider]] = {
    PTRProvider.name: PTRProvider,
    HackerTargetProvider.name: HackerTargetProvider,
    HackerTargetBannerProvider.name: HackerTargetBannerProvider,
    AlienVaultProvider.name: AlienVaultProvider,
    RapidDNSProvider.name: RapidDNSProvider,
    SubdomainCenterProvider.name: SubdomainCenterProvider,
    CertSpotterProvider.name: CertSpotterProvider,
    URLScanProvider.name: URLScanProvider,
    VirusTotalProvider.name: VirusTotalProvider,
    ShodanProvider.name: ShodanProvider,
    CensysProvider.name: CensysProvider,
}


def _environment_api_key(provider_name: str):
    if provider_name == "censys":
        api_id = os.environ.get("IP2DOMAIN_CENSYS_API_ID")
        api_secret = os.environ.get("IP2DOMAIN_CENSYS_API_SECRET")
        return f"{api_id}:{api_secret}" if api_id and api_secret else None
    return os.environ.get(f"IP2DOMAIN_{provider_name.upper()}_API_KEY")


def register_provider(provider_cls: Type[BaseProvider]):
    """
    Function allowing users/plugins to easily register custom providers at runtime.
    """
    AVAILABLE_PROVIDERS[provider_cls.name] = provider_cls


class ProviderManager:
    """
    Orchestrates execution of selected providers for an IP.
    """

    def __init__(self, selected_providers: List[str] = None, api_keys: Dict[str, str] = None):
        self.api_keys = api_keys or {}
        self.providers: List[BaseProvider] = []

        if not selected_providers or "all" in selected_providers:
            provider_names = list(AVAILABLE_PROVIDERS.keys())
        else:
            provider_names = selected_providers

        for name in provider_names:
            name_lower = name.lower()
            if name_lower in AVAILABLE_PROVIDERS:
                cls = AVAILABLE_PROVIDERS[name_lower]
                key = self.api_keys.get(name_lower) or _environment_api_key(name_lower)
                self.providers.append(cls(api_key=key))
            else:
                logger.warning(f"Provider '{name}' is not registered.")

    async def lookup_ip(self, ip: str, session: aiohttp.ClientSession) -> Dict[str, List[str]]:
        """
        Runs enabled providers concurrently for a single IP.
        Returns dict of provider_name -> list of domain names found.
        """
        results = {}
        tasks = []

        for p in self.providers:
            if p.accepts_ip:
                tasks.append((p.name, asyncio.create_task(p.lookup_async(ip, session))))

        for name, task in tasks:
            try:
                domains = await task
                results[name] = domains
            except Exception as e:
                logger.error(f"Error executing provider '{name}' for IP {ip}: {e}")
                results[name] = []

        return results
