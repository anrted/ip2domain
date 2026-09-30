"""Optional multi-signal host discovery. Silence never suppresses the port pipeline."""
import asyncio
from pathlib import Path
import re
import shutil
import socket
from ..evidence import capture

async def discover_host(observation,budget):
    cache=budget.__dict__.setdefault('_host_discovery',{})
    ip=observation.ip
    if ip in cache:return
    cache[ip]=True
    if len(cache)>4096:cache.pop(next(iter(cache)))
    result={'status':'completed','signals':[],'alive':False}
    try:
        for line in Path('/proc/net/arp').read_text().splitlines()[1:]:
            fields=line.split()
            if fields and fields[0]==ip and len(fields)>=6 and fields[3]!='00:00:00:00:00:00':
                result['signals'].append(dict(method='arp-cache',mac=fields[3],interface=fields[5],freshness='cached'))
    except OSError:pass
    if budget.config.reverse_dns:
        try:
            name,_=await asyncio.wait_for(asyncio.get_running_loop().getnameinfo((ip,0),socket.NI_NAMEREQD),budget.config.timeout)
            result['signals'].append(dict(method='reverse-dns',name=name))
        except (OSError,asyncio.TimeoutError):pass
    if budget.config.icmp_discovery and shutil.which('ping'):
        await budget.tick()
        process=await asyncio.create_subprocess_exec('ping','-n','-c','1','-W','1',ip,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
        try:
            stdout,_=await asyncio.wait_for(process.communicate(),2)
            if process.returncode==0:
                result['alive']=True
                match=re.search(rb'time[=<]([0-9.]+)',stdout)
                result['signals'].append(dict(method='icmp',rtt_ms=float(match[1]) if match else None))
        finally:
            if process.returncode is None:process.kill();await process.wait()
    observation.stage_results['host_discovery']=result
    if result['signals']:capture(observation,'host_discovery',str(result['signals']),source='host-discovery')
