import asyncio
import socket
from typing import List
import aiohttp
from ip2domain.providers.base import BaseProvider


class PTRProvider(BaseProvider):
    name = "ptr"
    description = "Reverse DNS (PTR) record lookup using standard DNS"

    async def lookup_async(self, ip: str, session: aiohttp.ClientSession) -> List[str]:
        loop = asyncio.get_running_loop()
        try:
            # gethostbyaddr returns (hostname, aliaslist, ipaddrlist)
            result = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            hostname = result[0]
            if hostname and hostname != ip:
                return [hostname.lower()]
        except (socket.herror, socket.gaierror, socket.timeout, Exception):
            pass
        return []
