"""Lifecycle shared by built-in and entry-point protocol plugins."""
import asyncio
import json
import re
import time
from dataclasses import dataclass
from urllib.parse import urlsplit
from ..authentication import CredentialVault, authorization, mechanism
from ..evidence import capture, clean_uri, identity
from ..fingerprint_engine import fingerprint, best
from ..transports.network import close_writer
from ..transports.http import parse_headers, _body

@dataclass
class Response:
    status: int
    headers: dict
    body: bytes
    evidence: str

class PluginContext:
    def __init__(self, observation, budget):
        self.observation=observation; self.budget=budget; self.config=budget.config
        self.started=time.monotonic(); self.requests=0
        self.vault=getattr(budget,'credentials',CredentialVault())
        self.failed_auth=budget.__dict__.setdefault('_failed_auth',{}).setdefault(observation.ip,set()); self.auth_cache={}
        observation._secrets=[c.password for c in self.vault.entries if c.host==observation.ip and c.password]

    async def request(self, protocol, path='/', method='GET', body=b'', headers=None, *, port=None, tls=None):
        o=self.observation
        port=port or o.port
        tls=protocol in ('https','rtsps') if tls is None else tls
        if not path.startswith('/') or any(ord(c)<33 or ord(c)>126 for c in path) or path.startswith('//'):
            raise ValueError('invalid origin-relative endpoint')
        if method not in ('GET','HEAD','OPTIONS','DESCRIBE','POST'):raise ValueError('write method forbidden')
        if method=='POST' and not getattr(self,'soap_readonly',False):raise ValueError('POST only through ONVIF allowlist')
        if self.requests>=self.config.max_requests_per_host or time.monotonic()-self.started>self.config.endpoint_timeout:
            raise BudgetExhausted()
        self.requests+=1
        await self.budget.protocol_tick(o.ip,protocol)
        host=f'[{o.ip}]' if ':' in o.ip else o.ip
        uri=f'{protocol}://{host}:{port}{path}'
        version='RTSP/1.0' if protocol in ('rtsp','rtsps') else 'HTTP/1.1'
        target=uri if version.startswith('RTSP') else path
        values={'Host':f'{host}:{port}','User-Agent':'ip2domain-inventory/2','Connection':'close',**(headers or {})}
        if version.startswith('RTSP'):values['CSeq']='1'
        if body:values['Content-Length']=str(len(body))
        raw=(f'{method} {target} {version}\r\n'+''.join(f'{k}: {v}\r\n' for k,v in values.items())+'\r\n').encode()+body
        reader,writer=await self.budget.connect(o.ip,port,tls=tls)
        try:
            async def read():
                writer.write(raw);await writer.drain()
                head=await reader.readuntil(b'\r\n\r\n')
                if version.startswith('RTSP'):
                    if not re.match(rb'RTSP/[12]\.0 [1-5]\d\d ',head):raise ValueError('not RTSP')
                    status,parsed=parse_headers(re.sub(rb'^RTSP/[12]\.0',b'HTTP/1.1',head))
                    if parsed.get('cseq')!='1':raise ValueError('RTSP CSeq mismatch')
                else:status,parsed=parse_headers(head)
                payload=b''
                if method not in ('HEAD','OPTIONS') and status not in (204,304) and ('content-length' in parsed or parsed.get('transfer-encoding')):
                    payload=await _body(reader,parsed,65536)
                elif method not in ('HEAD','OPTIONS') and 200<=status<300:
                    try:payload=await asyncio.wait_for(_body(reader,parsed,65536),self.config.timeout)
                    except asyncio.TimeoutError:payload=b''
                evidence=capture(o,'protocol_response',head+payload,source=clean_uri(uri),protocol=protocol)
                return Response(status,parsed,payload,evidence)
            return await asyncio.wait_for(read(),self.config.timeout)
        finally:await close_writer(writer)

    async def authenticated_request(self,protocol,path='/',method='GET',body=b'',headers=None,**kwargs):
        response=await self.request(protocol,path,method,body,headers,**kwargs)
        o=self.observation; scheme=mechanism(response.headers)
        item=dict(id=identity(o.ip,o.port,protocol,path,scheme),protocol=protocol,endpoint=clean_uri(path),mechanism=scheme,
                  status='required' if response.status==401 else 'observed',evidence=[response.evidence])
        existing=next((a for a in o.authentication if a['id']==item['id']),None)
        if existing is not None:item=existing
        elif scheme!='none':o.authentication.append(item)
        credential=self.vault.get(o.ip,protocol)
        if response.status!=401 or not self.config.allow_credentials or not credential or protocol in self.failed_auth:return response
        authority=f'[{o.ip}]' if ':' in o.ip else o.ip
        uri=f'{protocol}://{authority}:{kwargs.get("port",o.port)}{path}' if protocol.startswith('rtsp') else path
        value=authorization(response.headers.get('www-authenticate',''),credential,method,uri)
        if not value:return response
        response=await self.request(protocol,path,method,body,{**(headers or {}),'Authorization':value},**kwargs)
        item['credential_id']=credential.id
        item['status']='valid' if 200<=response.status<300 else 'rejected' if response.status in (401,403) else 'unverified'
        if response.status in (401,403):self.failed_auth.add(protocol)
        return response

    def endpoint(self, protocol, path, response, **metadata):
        o=self.observation;host=f'[{o.ip}]' if ':' in o.ip else o.ip
        uri=clean_uri(path if '://' in path else f'{protocol}://{host}:{o.port}{path}')
        item=dict(id=identity(o.ip,o.port,protocol,uri),uri=uri,protocol=protocol,
                  status='discovered' if 200<=response.status<300 else 'authentication_required' if response.status==401 else 'not_found' if response.status==404 else 'responded',
                  status_code=response.status,authentication=mechanism(response.headers),evidence=[response.evidence],**metadata)
        old=next((e for e in o.endpoints if e['id']==item['id']),None)
        if old:old.update(item)
        else:o.endpoints.append(item)
        return item

class BudgetExhausted(Exception): pass

class ProtocolPlugin:
    name='generic'; protocols=()
    def detect(self,observation):return any(s['protocol'] in self.protocols for s in observation.services)
    async def fingerprint(self,ctx):fingerprint(ctx.observation,getattr(ctx.budget,'learned_signatures',()))
    async def enumerate(self,ctx):
        # A confirmed wire handshake already supplies the base enumeration.
        return [s for s in ctx.observation.services if s['protocol'] in self.protocols]
    async def discover_endpoints(self,ctx):
        o=ctx.observation
        for s in await self.enumerate(ctx):
            uri=f'{s["protocol"]}://{o.ip}:{o.port}'
            if not any(e['uri']==uri for e in o.endpoints):
                o.endpoints.append(dict(id=identity(uri),uri=uri,protocol=s['protocol'],source='protocol-handshake',confidence=1.,status='discovered',evidence=[e['id'] for e in o.evidence]))
    async def detect_auth(self,ctx):
        o=ctx.observation
        for s in o.services:
            attrs=s.get('attributes',{})
            if attrs.get('auth_required'):
                item=dict(id=identity(o.ip,o.port,s['protocol'],'auth'),protocol=s['protocol'],mechanism=attrs.get('authentication','protocol-specific'),status='required')
                if item not in o.authentication:o.authentication.append(item)
    async def authenticate(self,ctx):
        # Authentication is performed only by a protocol-specific read request.
        return ctx.observation.authentication
    async def enrich(self,ctx):await self.fingerprint(ctx)
    async def correlate(self,ctx):
        ctx.observation.stage_results['correlation']={'status':'ready','identity':best(ctx.observation)}


def plugin_registry():
    from .rtsp import RTSPPlugin
    from .onvif import ONVIFPlugin
    from .web import HTTPPlugin
    from .generic import NativePlugin
    from .dicom import DICOMPlugin
    from .management import ManagementPlugin
    result=[ONVIFPlugin(),HTTPPlugin(),RTSPPlugin(),ManagementPlugin(),DICOMPlugin(),NativePlugin()]
    from importlib.metadata import entry_points
    points=entry_points()
    points=points.select(group='ip2domain.inventory.plugins') if hasattr(points,'select') else points.get('ip2domain.inventory.plugins',())
    result.extend(p.load()() for p in points)
    return result

async def run_plugins(observation,budget,phases=None):
    context=PluginContext(observation,budget)
    for plugin in plugin_registry():
        if not plugin.detect(observation):continue
        for stage in phases or ('fingerprint','enumerate','discover_endpoints','detect_auth','authenticate','enrich','correlate'):
            key=plugin.name+':'+stage
            if observation.stage_results.get(key,{}).get('status')=='completed':continue
            try:
                await getattr(plugin,stage)(context)
                observation.stage_results[key]={'status':'completed'}
            except BudgetExhausted:
                observation.stage_results[key]={'status':'budget_exhausted'};break
            except (OSError,ValueError,asyncio.TimeoutError,asyncio.IncompleteReadError,asyncio.LimitOverrunError) as exc:
                observation.stage_results[key]={'status':'timeout' if isinstance(exc,asyncio.TimeoutError) else 'error','error_type':type(exc).__name__}
            await observation.checkpoint()
