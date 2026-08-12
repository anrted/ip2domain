import logging
from typing import List
import aiohttp
from ip2domain.providers.base import BaseProvider

logger = logging.getLogger(__name__)


class CertSpotterProvider(BaseProvider):
    """
    CertSpotter CT Log API provider.
    """
    name = "certspotter"
    description = "CertSpotter Certificate Transparency Search"
    accepts_ip = False

    async def lookup_async(self, domain: str, session: aiohttp.ClientSession) -> List[str]:
        if not domain or domain.replace(".", "").isdigit():
            return []

        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        domains = set()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        }
        try:
            async with session.get(url, headers=headers, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if isinstance(data, list):
                        for item in data:
                            dns_names = item.get("dns_names", [])
                            for d in dns_names:
                                clean_d = d.strip().lower().lstrip("*.")
                                if clean_d.endswith(domain):
                                    domains.add(clean_d)
        except Exception as e:
            logger.debug(f"[CertSpotterProvider] Error for {domain}: {e}")

        return list(domains)
