import logging
from typing import List
import aiohttp
from ip2domain.providers.base import BaseProvider

logger = logging.getLogger(__name__)


class SubdomainCenterProvider(BaseProvider):
    """
    Subdomain.Center API provider for passive subdomain discovery.
    """
    name = "subdomaincenter"
    description = "Subdomain.Center Passive Subdomain Intelligence"
    accepts_ip = False

    async def lookup_async(self, ip_or_domain: str, session: aiohttp.ClientSession) -> List[str]:
        # If input is IP, SubdomainCenter won't match directly, but works for domain targets
        if not ip_or_domain or ip_or_domain.replace(".", "").isdigit():
            return []

        url = f"https://api.subdomain.center/?domain={ip_or_domain}"
        domains = set()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        }
        try:
            async with session.get(url, headers=headers, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if isinstance(data, list):
                        for d in data:
                            if isinstance(d, str) and d.strip():
                                domains.add(d.strip().lower())
        except Exception as e:
            logger.debug(f"[SubdomainCenterProvider] Error for {ip_or_domain}: {e}")

        return list(domains)
