"""Bounded HTTP resource enumeration and product/media metadata."""
import asyncio
import hashlib
import json
import re
from urllib.parse import urlsplit,urljoin
from .base import ProtocolPlugin
from ..fingerprint_engine import ROOT,profiles,best
from ..evidence import identity,clean_uri
from ..enrichment.web import media_signature,websocket_accept

class HTTPPlugin(ProtocolPlugin):
    name='http';protocols=('http','https')
    async def discover_endpoints(self,ctx):
        o=ctx.observation;protocol=next(s['protocol'] for s in o.services if s['protocol'] in self.protocols)
        paths=list(ctx.config.resource_paths)+json.loads((ROOT/'endpoints/http.json').read_text())['paths']
        vendor=best(o).get('vendor','')
        for profile in profiles():
            if profile['vendor']==vendor:paths.extend(profile['http_patterns'])
        seen=set();index=0
        while index<len(paths) and len(seen)<ctx.config.max_candidates:
            path=paths[index];index+=1
            if path in seen:continue
            seen.add(path)
            # Only explicit safe paths, API descriptions and media metadata; never harvest arbitrary links.
            try:
                sample=await ctx.authenticated_request(protocol,path)
                endpoint=ctx.endpoint(protocol,path,sample,source='http-corpus',confidence=1.)
                text=sample.body.decode('utf-8','replace')
                title=re.search(r'<title[^>]*>(.*?)</title>',text,re.I|re.S)
                attrs=dict(status=sample.status,server=sample.headers.get('server',''),title=re.sub(r'\s+',' ',title[1])[:256] if title else '')
                if path=='/':
                    service=next(s for s in o.services if s['protocol']==protocol);service['attributes'].update(attrs)
                if path.endswith('favicon.ico') and sample.status==200:endpoint['favicon_sha256']=hashlib.sha256(sample.body).hexdigest()
                location=sample.headers.get('location','')
                if location:
                    endpoint['redirect']=clean_uri(location)
                    u=urlsplit(location)
                    if not u.netloc and location.startswith('/') and not location.startswith('//'):paths.append(location)
                media=media_signature(sample)
                if sample.body.startswith(b'FLV\x01'):media='http-flv'
                if media:
                    o.service(media,('video',),path=path,evidence=sample.evidence)
                    codecs=re.findall(r'CODECS="([^"]+)"',text) if media=='hls' else []
                    stream=dict(id=identity(endpoint['id'],'media'),endpoint_id=endpoint['id'],uri=endpoint['uri'],protocol=media,codec=','.join(codecs) or ('MJPEG' if media=='mjpeg' else 'Unknown'),verification='content-signature',verified_media=False,evidence=[sample.evidence])
                    if not any(s['id']==stream['id'] for s in o.streams):o.streams.append(stream)
                    if media=='hls':
                        for line in text.splitlines():
                            if line and not line.startswith('#') and '.m3u8' in line:
                                uri=urljoin(endpoint['uri'],line);u=urlsplit(uri)
                                if u.hostname==o.ip and (u.port or (443 if u.scheme=='https' else 80))==o.port:paths.append(u.path+('?' + u.query if u.query else ''))
                if path in ('/openapi.json','/swagger.json') and sample.status==200:
                    try:
                        spec=json.loads(text)
                        if isinstance(spec,dict) and ('openapi' in spec or 'swagger' in spec):
                            endpoint['api_info']=spec.get('info',{})
                            for route,methods in list(spec.get('paths',{}).items())[:ctx.config.max_candidates]:
                                if not isinstance(route,str) or not route.startswith('/'):continue
                                o.endpoints.append(dict(id=identity(endpoint['uri'],route),uri=clean_uri(urljoin(endpoint['uri'],route)),protocol=protocol,source='openapi',status='advertised',methods=list(methods),confidence=1.,evidence=[sample.evidence]))
                    except (ValueError,TypeError):pass
                await self.fingerprint(ctx)
                await o.checkpoint()
            except (OSError,ValueError,asyncio.TimeoutError,asyncio.IncompleteReadError,asyncio.LimitOverrunError) as exc:o.attempt('http_endpoint','error',path=path,error_type=type(exc).__name__)
        # Capability negotiation has no application messages or WebDAV writes.
        sample=await ctx.request(protocol,'/','OPTIONS')
        if sample.headers.get('dav'):o.service('webdav',('storage',),compliance=sample.headers['dav'],evidence=sample.evidence)
