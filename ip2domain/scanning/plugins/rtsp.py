"""Independent RTSP/RTSPS inventory: OPTIONS and DESCRIBE, no PLAY/RECORD."""
import asyncio
import re
from urllib.parse import urlsplit
from .base import ProtocolPlugin, BudgetExhausted
from ..endpoint_engine import rtsp_candidates
from ..fingerprint_engine import best
from ..evidence import identity, clean_uri


def parse_sdp(body):
    text=body.decode('utf-8','replace')
    if not text.startswith('v=0') or not re.search(r'(?m)^o=',text) or not re.search(r'(?m)^s=',text):return None
    tracks=[];current=None
    for line in text.replace('\r','').split('\n'):
        if line.startswith('m='):
            parts=line[2:].split()
            if len(parts)<4:continue
            current=dict(media=parts[0],transport=parts[2],payload_types=parts[3:],codecs=[],control='')
            tracks.append(current)
        elif current is not None:
            match=re.match(r'a=rtpmap:(\d+) ([^/]+)/([0-9]+)(?:/(\d+))?',line)
            if match:current['codecs'].append(dict(payload=match[1],codec=match[2].upper(),clock=int(match[3]),channels=int(match[4] or 1)))
            elif line.startswith('a=control:'):current['control']=clean_uri(line[10:])
            elif line.startswith('a=fmtp:'):current.setdefault('fmtp',[]).append(line[7:][:1024])
            elif line.startswith('a=framesize:'):current['resolution']=line.split(' ',1)[-1]
    return tracks or None

class RTSPPlugin(ProtocolPlugin):
    name='rtsp';protocols=('rtsp','rtsps')
    async def discover_endpoints(self,ctx):
        o=ctx.observation
        proto=next(s['protocol'] for s in o.services if s['protocol'] in self.protocols)
        known=best(o); derived=[]
        if not known.get('vendor'):
            hints=getattr(o,'_host_hints',[])
            vendors={f.get('vendor') for f in hints if f.get('vendor')}
            if len(vendors)==1:known['vendor']=next(iter(vendors))
        for endpoint in o.endpoints:
            if endpoint['protocol'] in self.protocols:
                u=urlsplit(endpoint['uri'])
                if u.hostname==o.ip and (u.port or 554)==o.port:derived.append(u.path+('?' + u.query if u.query else ''))
        candidates=rtsp_candidates(vendor=known.get('vendor',''),channels=ctx.config.max_channels,model=known.get('model',''),derived=derived)
        completed={e['uri'] for e in o.endpoints if e.get('status')=='discovered'}
        count=0
        for candidate in candidates:
            if count>=ctx.config.max_candidates:break
            count+=1;path=candidate.pop('path')
            try:
                response=await ctx.authenticated_request(proto,path,'DESCRIBE',headers={'Accept':'application/sdp'})
                ep=ctx.endpoint(proto,path,response,**candidate)
                tracks=parse_sdp(response.body) if response.status==200 else None
                if tracks:
                    channel=candidate.get('channel')
                    channel_id=identity(o.ip,o.port,channel) if channel else None
                    stream=dict(id=identity(ep['id'],'stream'),endpoint_id=ep['id'],uri=ep['uri'],protocol=proto,
                                channel_id=channel_id,channel=channel,profile=candidate.get('profile','unknown'),
                                tracks=tracks,codec=next((t['codecs'][0]['codec'] for t in tracks if t['codecs']),'Unknown'),
                                verified_media=False,verification='sdp',evidence=[response.evidence])
                    if not any(s['id']==stream['id'] for s in o.streams):o.streams.append(stream)
                    if channel and not any(c['id']==channel_id for c in o.channels):o.channels.append(dict(id=channel_id,channel=channel,source='rtsp-endpoint',confidence=.7,evidence=[response.evidence]))
                await o.checkpoint()
            except (OSError,ValueError,asyncio.TimeoutError,asyncio.IncompleteReadError,asyncio.LimitOverrunError) as exc:
                o.attempt('rtsp_endpoint','timeout' if isinstance(exc,asyncio.TimeoutError) else 'error',path=path,error_type=type(exc).__name__)
        o.stage_results['rtsp_candidates']={'tested':count,'limit':ctx.config.max_candidates,'channels_limit':ctx.config.max_channels}
