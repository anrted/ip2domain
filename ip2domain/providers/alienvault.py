import logging
from typing import List
import aiohttp
from ip2domain.providers.base import BaseProvider

logger = logging.getLogger(__name__)


class AlienVaultProvider(BaseProvider):
    name = "alienvault"
    description = "AlienVault OTX Passive DNS API"

    async def lookup_async(self, ip: str, session: aiohttp.ClientSession) -> List[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
        domains = set()
        try:
            headers = {}
            if self.api_key:
                headers["X-OTX-API-KEY"] = self.api_key

            async with session.get(url, headers=headers, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    passive_dns = data.get("passive_dns", [])
                    for record in passive_dns:
                        hostname = record.get("hostname", "").strip().lower()
                        if hostname and "." in hostname:
                            domains.add(hostname)
        except Exception as e:
            logger.debug(f"AlienVault error for {ip}: {e}")
        return list(domains)
