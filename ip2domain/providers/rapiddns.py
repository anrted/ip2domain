import logging
import re
from typing import List
import aiohttp
from ip2domain.providers.base import BaseProvider

logger = logging.getLogger(__name__)


class RapidDNSProvider(BaseProvider):
    name = "rapiddns"
    description = "RapidDNS Passive DNS service"

    async def lookup_async(self, ip: str, session: aiohttp.ClientSession) -> List[str]:
        url = f"https://rapiddns.io/s/{ip}?full=1#result"
        domains = set()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        try:
            async with session.get(url, headers=headers, timeout=12) as resp:
                if resp.status == 200:
                    html = await resp.text()
                    # Extract domains from <td> tags or matching patterns
                    matches = re.findall(r"<td>([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})</td>", html)
                    for m in matches:
                        domain = m.strip().lower()
                        if domain and domain != ip and not domain.endswith(".in-addr.arpa"):
                            domains.add(domain)
        except Exception as e:
            logger.debug(f"RapidDNS error for {ip}: {e}")
        return list(domains)
