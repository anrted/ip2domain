import logging
from typing import List
import aiohttp
from ip2domain.providers.base import BaseProvider

logger = logging.getLogger(__name__)


class HackerTargetProvider(BaseProvider):
    name = "hackertarget"
    description = "HackerTarget Reverse IP API"

    async def lookup_async(self, ip: str, session: aiohttp.ClientSession) -> List[str]:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        domains = []
        headers = {"X-API-Key": self.api_key} if self.api_key else {}
        try:
            async with session.get(url, headers=headers, timeout=10) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if "API count exceed" in text or "error" in text.lower():
                        return []
                    lines = text.strip().splitlines()
                    for line in lines:
                        domain = line.strip().lower()
                        if domain and "." in domain and not domain.startswith("no records"):
                            domains.append(domain)
        except Exception as e:
            logger.debug(f"HackerTarget error for {ip}: {e}")
        return domains
