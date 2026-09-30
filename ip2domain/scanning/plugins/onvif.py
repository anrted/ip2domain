"""ONVIF capabilities and media inventory with an explicit read-only operation map."""
import asyncio
import base64
from datetime import datetime,timezone
import hashlib
import secrets
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape
from .base import ProtocolPlugin, BudgetExhausted
from ..evidence import identity, clean_uri

SOAP='http://www.w3.org/2003/05/soap-envelope'
DEVICE='http://www.onvif.org/ver10/device/wsdl'
MEDIA='http://www.onvif.org/ver10/media/wsdl'
MEDIA2='http://www.onvif.org/ver20/media/wsdl'
ALLOW={
 DEVICE:('GetDeviceInformation','GetServices','GetCapabilities'),
 MEDIA:('GetProfiles','GetStreamUri','GetVideoSources'),
 MEDIA2:('GetProfiles','GetStreamUri','GetVideoSourceConfigurations'),
 'http://www.onvif.org/ver20/ptz/wsdl':('GetServiceCapabilities','GetNodes'),
 'http://www.onvif.org/ver10/events/wsdl':('GetServiceCapabilities','GetEventProperties'),
 'http://www.onvif.org/ver20/imaging/wsdl':('GetServiceCapabilities',),
 'http://www.onvif.org/ver20/analytics/wsdl':('GetServiceCapabilities',),
 'http://www.onvif.org/ver10/recording/wsdl':('GetServiceCapabilities',),
 'http://www.onvif.org/ver10/replay/wsdl':('GetServiceCapabilities',),
 'http://www.onvif.org/ver10/receiver/wsdl':('GetServiceCapabilities',),
 'http://www.onvif.org/ver10/deviceIO/wsdl':('GetServiceCapabilities',),
 'http://www.onvif.org/ver10/accesscontrol/wsdl':('GetServiceCapabilities',),
 'http://www.onvif.org/ver10/doorcontrol/wsdl':('GetServiceCapabilities',),
 'http://www.onvif.org/ver10/thermal/wsdl':('GetServiceCapabilities',),
 'http://www.onvif.org/ver10/webrtc/wsdl':('GetServiceCapabilities',),
}

def local(tag):return tag.rsplit('}',1)[-1]
def elements(root,name):return [e for e in root.iter() if local(e.tag)==name]
def value(root,name,default=''):
    return next((e.text for e in root.iter() if local(e.tag)==name and e.text),default)
def xml(body):
    if b'<!DOCTYPE' in body.upper() or b'<!ENTITY' in body.upper():raise ValueError('DTD forbidden')
    try:return ET.fromstring(body)
    except ET.ParseError as exc:raise ValueError('invalid XML') from exc


def wsse(credential):
    nonce=secrets.token_bytes(20);created=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    digest=base64.b64encode(hashlib.sha1(nonce+created.encode()+credential.password.encode()).digest()).decode()
    prefix='http://docs.oasis-open.org/wss/2004/01/'
    return f'<s:Header><wsse:Security xmlns:wsse="{prefix}oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="{prefix}oasis-200401-wss-wssecurity-utility-1.0.xsd"><wsse:UsernameToken><wsse:Username>{escape(credential.username)}</wsse:Username><wsse:Password Type="{prefix}oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest}</wsse:Password><wsse:Nonce EncodingType="{prefix}oasis-200401-wss-soap-message-security-1.0#Base64Binary">{base64.b64encode(nonce).decode()}</wsse:Nonce><wsu:Created>{created}</wsu:Created></wsse:UsernameToken></wsse:Security></s:Header>'

async def call(ctx,url,namespace,operation,inner=''):
    if operation not in ALLOW.get(namespace,()):raise ValueError('ONVIF operation not read-only allowlisted')
    u=urlsplit(url);o=ctx.observation
    # Peer supplied XAddrs never silently expand destinations or send secrets elsewhere.
    if u.scheme not in ('http','https') or u.hostname!=o.ip or u.username or u.password:
        raise ValueError('ONVIF XAddr outside host scope')
    path=u.path or '/'
    if u.query:path+='?'+u.query
    credential=ctx.vault.get(o.ip,'onvif') if ctx.config.allow_credentials else None
    header=wsse(credential) if credential and 'onvif' not in ctx.failed_auth else ''
    body=f'<s:Envelope xmlns:s="{SOAP}" xmlns:t="{namespace}" xmlns:tt="http://www.onvif.org/ver10/schema">{header}<s:Body><t:{operation}>{inner}</t:{operation}></s:Body></s:Envelope>'.encode()
    ctx.soap_readonly=True
    try:
        response=await ctx.authenticated_request(u.scheme,path,'POST',body,{'Content-Type':f'application/soap+xml; charset=utf-8; action="{namespace}/{operation}"'},port=u.port or (443 if u.scheme=='https' else 80))
    finally:ctx.soap_readonly=False
    if response.status in (401,403):
        if credential:ctx.failed_auth.add('onvif')
        o.authentication.append(dict(id=identity(url,'onvif-auth'),protocol='onvif',mechanism='wsse/http',status='required',evidence=[response.evidence]))
        return None,response
    if not response.body:return None,response
    root=xml(response.body)
    if elements(root,'Fault'):
        if 'NotAuthorized' in response.body.decode(errors='replace') and credential:ctx.failed_auth.add('onvif')
        return None,response
    if not elements(root,operation+'Response'):return None,response
    if credential:
        item=dict(id=identity(url,credential.id),protocol='onvif',mechanism='wsse',status='valid',credential_id=credential.id,evidence=[response.evidence])
        if not any(a['id']==item['id'] for a in o.authentication):o.authentication.append(item)
    return root,response

class ONVIFPlugin(ProtocolPlugin):
    name='onvif';protocols=('http','https','onvif','ws-discovery')
    async def enumerate(self,ctx):
        o=ctx.observation
        candidates=[e['uri'] for e in o.endpoints if e.get('protocol')=='onvif']
        for service in o.services:
            if service['protocol']=='ws-discovery': candidates.extend(service.get('attributes',{}).get('xaddrs',[]))
            if service['protocol'] in ('http','https'):
                candidates.append(f'{service["protocol"]}://{o.ip}:{o.port}/onvif/device_service')
        services=[]
        for url in dict.fromkeys(candidates):
            root,response=await call(ctx,url,DEVICE,'GetDeviceInformation')
            if root is None:continue
            o.service('onvif',('video','physical_security'),xaddr=clean_uri(url))
            attrs={k:value(root,v) for k,v in [('vendor','Manufacturer'),('model','Model'),('firmware','FirmwareVersion'),('serial','SerialNumber'),('hardware_id','HardwareId')]}
            attrs.update(id=identity(url,'onvif-identity'),confidence=1.,evidence=[response.evidence],version=1)
            o.fingerprints.append(attrs)
            ep=dict(id=identity(url),uri=clean_uri(url),protocol='onvif',source='device-information',status='discovered',confidence=1.,evidence=[response.evidence])
            if not any(e['id']==ep['id'] for e in o.endpoints):o.endpoints.append(ep)
            root,res=await call(ctx,url,DEVICE,'GetServices','<t:IncludeCapability>true</t:IncludeCapability>')
            if root is not None:
                for service in elements(root,'Service'):
                    ns=value(service,'Namespace');addr=value(service,'XAddr')
                    if ns and addr:services.append((ns,addr))
            caps,res=await call(ctx,url,DEVICE,'GetCapabilities','<t:Category>All</t:Category>')
            if caps is not None:
                for e in caps.iter():
                    if local(e.tag)=='Media':
                        addr=value(e,'XAddr')
                        if addr:services.append((MEDIA,addr))
            for namespace,addr in dict.fromkeys(services):
                endpoint=dict(id=identity(addr,namespace),uri=clean_uri(addr),protocol='onvif',namespace=namespace,source='onvif-capabilities',status='advertised',confidence=1.,evidence=[res.evidence])
                if not any(e['id']==endpoint['id'] for e in o.endpoints):o.endpoints.append(endpoint)
                try:
                    if namespace in (MEDIA,MEDIA2):await self.media(ctx,addr,namespace)
                    elif namespace in ALLOW:
                        for operation in ALLOW[namespace]:
                            rr,resp=await call(ctx,addr,namespace,operation)
                            o.stage_results['onvif:'+namespace+':'+operation]={'status':'completed' if rr is not None else 'unavailable','evidence':[resp.evidence]}
                except (OSError,ValueError,asyncio.TimeoutError) as exc:
                    o.attempt('onvif_service','error',namespace=namespace,error_type=type(exc).__name__)
            await o.checkpoint()

    async def media(self,ctx,url,namespace):
        o=ctx.observation
        root,response=await call(ctx,url,namespace,'GetProfiles')
        if root is None:return
        for profile in elements(root,'Profiles')[:ctx.config.max_channels*4]:
            token=profile.get('token')
            if not token:continue
            channel=value(profile,'SourceToken',token)
            channel_id=identity(o.ip,'onvif-source',channel)
            if not any(c['id']==channel_id for c in o.channels):o.channels.append(dict(id=channel_id,channel=channel,source='onvif-video-source',confidence=1.,evidence=[response.evidence]))
            if namespace==MEDIA:
                inner=f'<t:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream><tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></t:StreamSetup><t:ProfileToken>{escape(token)}</t:ProfileToken>'
            else:inner=f'<t:Protocol>RTSP</t:Protocol><t:ProfileToken>{escape(token)}</t:ProfileToken>'
            rr,res=await call(ctx,url,namespace,'GetStreamUri',inner)
            uri=value(rr,'Uri') if rr is not None else ''
            if not uri:continue
            uri=clean_uri(uri);u=urlsplit(uri)
            endpoint=dict(id=identity(uri),uri=uri,protocol=u.scheme,source='onvif-profile',status='advertised',confidence=1.,authentication='unknown',evidence=[res.evidence])
            if not any(e['id']==endpoint['id'] for e in o.endpoints):o.endpoints.append(endpoint)
            stream=dict(id=identity(uri,token),endpoint_id=endpoint['id'],uri=uri,protocol=u.scheme,channel=channel,channel_id=channel_id,
                        profile=token,name=value(profile,'Name'),codec=value(profile,'Encoding','Unknown'),width=value(profile,'Width'),height=value(profile,'Height'),
                        verified_media=False,verification='onvif-profile',evidence=[response.evidence,res.evidence])
            if not any(s['id']==stream['id'] for s in o.streams):o.streams.append(stream)
            # Validate the advertised RTSP URI even when its port was not in the original port list.
            if u.scheme in ('rtsp','rtsps') and u.hostname==o.ip and not u.username:
                from .rtsp import parse_sdp
                try:
                    sample=await ctx.authenticated_request(u.scheme,u.path+('?' + u.query if u.query else ''),'DESCRIBE',headers={'Accept':'application/sdp'},port=u.port or (322 if u.scheme=='rtsps' else 554))
                    tracks=parse_sdp(sample.body) if sample.status==200 else None
                    if tracks:stream.update(tracks=tracks,verification='sdp',evidence=stream['evidence']+[sample.evidence])
                except (OSError,ValueError,asyncio.TimeoutError):pass
            await o.checkpoint()
    async def discover_endpoints(self,ctx):
        # enumerate() obtains actual service XAddrs and profile URIs, never fabricated paths.
        return [e for e in ctx.observation.endpoints if e.get('source','').startswith('onvif')]
