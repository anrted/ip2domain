"""Inventory acceptance: real loopback responders, no camera module dependencies."""
import asyncio
import base64
import json
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from ip2domain.scanning.authentication import CredentialVault,authorization
from ip2domain.scanning.endpoint_engine import rtsp_candidates
from ip2domain.scanning.inventory import EndpointObservation
from ip2domain.scanning.policies import ScanConfig
from ip2domain.scanning.persistence import InventoryRepository
from ip2domain.scanning.pipeline import run_scan
from ip2domain.scanning.plugins.base import PluginContext
from ip2domain.scanning.plugins.rtsp import RTSPPlugin,parse_sdp
from ip2domain.scanning.plugins.onvif import ONVIFPlugin,call,DEVICE
from ip2domain.scanning.transports.network import NetworkBudget

SDP=b'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Camera\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:trackID=1\r\nm=audio 0 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n'

@asynccontextmanager
async def responder(reply):
    requests=[];tasks=set()
    async def handle(reader,writer):
        task=asyncio.current_task();tasks.add(task)
        try:
            head=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),.3)
            body=b''
            import re
            length=re.search(rb'(?im)^Content-Length: (\d+)',head)
            if length:body=await reader.readexactly(int(length[1]))
            requests.append(head+body)
            result=reply(head,body)
            if result:writer.write(result);await writer.drain()
        except (OSError,asyncio.TimeoutError,asyncio.IncompleteReadError):pass
        finally:
            writer.close()
            try:await writer.wait_closed()
            except OSError:pass
            tasks.discard(task)
    server=await asyncio.start_server(handle,'127.0.0.1',0)
    try:yield server.sockets[0].getsockname()[1],requests
    finally:
        server.close();await server.wait_closed()
        for task in list(tasks):task.cancel()
        await asyncio.gather(*list(tasks),return_exceptions=True)

def config(port,**kw):
    return ScanConfig('127.0.0.1',tcp_ports=str(port),profile='deep_identification',active_consent=True,web_enrichment=True,
        enabled_probes=('rtsp',),timeout=.3,banner_timeout=.02,retries=0,rate=10000,per_host_rate=1000,per_protocol_rate=10000,
        discovery_workers=1,workers=2,protocol_workers=1,endpoint_workers=1,enrichment_workers=1,max_candidates=8,max_channels=2,**kw)

def rtsp_reply(head,body):
    method=head.split()[0]
    if method not in (b'OPTIONS',b'DESCRIBE'):return b''
    payload=SDP if method==b'DESCRIBE' else b''
    return b'RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Hikvision RTSP\r\nContent-Type: application/sdp\r\nContent-Length: '+str(len(payload)).encode()+b'\r\n\r\n'+payload

def test_corpus_is_generated_and_vendor_ranked():
    rows=list(rtsp_candidates(channels=64))
    assert len(rows)>1000
    assert len({r['path'] for r in rows})==len(rows)
    assert next(rtsp_candidates('Hikvision'))['path']=='/Streaming/Channels/101'
    assert len({r['channel'] for r in rows if 'channel' in r})==64

def test_sdp_requires_structure_and_retains_all_tracks():
    assert parse_sdp(b'not an SDP') is None
    tracks=parse_sdp(SDP)
    assert len(tracks)==2 and tracks[0]['codecs'][0]['codec']=='H264'
    assert tracks[1]['media']=='audio'

def test_credentials_are_scoped_and_never_guessed():
    vault=CredentialVault([dict(host='127.0.0.1',protocol='rtsp',username='operator',password='unique-password')])
    assert vault.get('127.0.0.2','rtsp') is None
    assert vault.get('127.0.0.1','http') is None
    assert 'unique-password' not in repr(vault.entries)
    with pytest.raises(ValueError):CredentialVault([dict(host='127.0.0.1',protocol='rtsp',username='a',password=p) for p in ('a','b')])
    header=authorization('Digest realm="test", nonce="nonce", algorithm=SHA-256, qop="auth"',vault.entries[0],'DESCRIBE','rtsp://127.0.0.1/x')
    assert 'algorithm=SHA-256' in header and 'qop=auth' in header and 'unique-password' not in header

def test_complete_pipeline_random_port_graph_and_events(tmp_path):
    async def scenario():
        async with responder(rtsp_reply) as (port,requests):
            cfg=config(port);repo=InventoryRepository(tmp_path/'inventory.db');job=repo.create(cfg,cfg.plan())
            await asyncio.wait_for(run_scan(repo,job),15)
            assert repo.status(job)=='completed'
            host=repo.host(job,'127.0.0.1')
            assert len(host['streams'])>=2 and host['evidence']
            assert host['services'][0]['protocol']=='rtsp'
            assert host['devices'] and host['endpoints'] and host['fingerprints']
            assert all(not s['verified_media'] for s in host['streams'])
            assert {'host_discovered','port_open','service_detected','endpoint_found','stream_found','scan_completed'} <= {e['type'] for e in repo.events(job)}
            assert not any(b'Authorization:' in req or b'PLAY ' in req for req in requests)
            assert repo.get(job)['stages']['endpoint']['done']==1
            # Reopening migrates idempotently and preserves graph + completed job.
            assert InventoryRepository(tmp_path/'inventory.db').host(job,'127.0.0.1')['streams']==host['streams']
    asyncio.run(scenario())

def test_auth_challenge_no_defaults_and_secret_redaction():
    async def scenario():
        expected=b'Authorization: Basic '+base64.b64encode(b'operator:unique-password')
        def reply(head,body):
            if expected in head:return rtsp_reply(head,body)
            return b'RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Basic realm="inventory"\r\nContent-Length: 0\r\n\r\n'
        async with responder(reply) as (port,requests):
            o=EndpointObservation('127.0.0.1',port,'tcp',state='open');o.service('rtsp')
            cfg=config(port,allow_credentials=True);budget=NetworkBudget(cfg,cfg.plan().scope)
            await RTSPPlugin().discover_endpoints(PluginContext(o,budget))
            assert not o.streams and not any(b'Authorization:' in r for r in requests)
            budget.credentials=CredentialVault([dict(host='127.0.0.1',protocol='rtsp',username='operator',password='unique-password')])
            await RTSPPlugin().discover_endpoints(PluginContext(o,budget))
            assert o.streams and any(a.get('status')=='valid' for a in o.authentication)
            assert 'unique-password' not in json.dumps(o.to_dict())
    asyncio.run(scenario())

def test_onvif_readonly_profiles_multiple_sources():
    async def scenario():
        port_holder={}
        def reply(head,body):
            text=body.decode();port=port_holder['port'];ns='http://www.onvif.org/ver10/media/wsdl'
            if 'GetDeviceInformation>' in text:part='<GetDeviceInformationResponse><Manufacturer>Hikvision</Manufacturer><Model>NVR-test</Model><FirmwareVersion>1.2.3</FirmwareVersion><SerialNumber>TEST-SERIAL</SerialNumber></GetDeviceInformationResponse>'
            elif 'GetServices>' in text:part=f'<GetServicesResponse><Service><Namespace>{ns}</Namespace><XAddr>http://127.0.0.1:{port}/onvif/media</XAddr></Service></GetServicesResponse>'
            elif 'GetCapabilities>' in text:part='<GetCapabilitiesResponse/>'
            elif 'GetProfiles>' in text:part='<GetProfilesResponse>'+''.join(f'<Profiles token="p{i}"><Name>Camera {i}</Name><VideoSourceConfiguration><SourceToken>source{i//2}</SourceToken></VideoSourceConfiguration><VideoEncoderConfiguration><Encoding>H264</Encoding></VideoEncoderConfiguration></Profiles>' for i in range(4))+'</GetProfilesResponse>'
            elif 'GetStreamUri>' in text:
                import re
                token=re.search(r'<t:ProfileToken>(.*?)</t:ProfileToken>',text)[1]
                part=f'<GetStreamUriResponse><MediaUri><Uri>rtsp://127.0.0.1:{port}/{token}</Uri></MediaUri></GetStreamUriResponse>'
            elif head.startswith(b'DESCRIBE'):return rtsp_reply(head,body)
            else:part='<Fault/>'
            data=f'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>{part}</s:Body></s:Envelope>'.encode()
            return b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(data)).encode()+b'\r\n\r\n'+data
        async with responder(reply) as (port,requests):
            port_holder['port']=port
            o=EndpointObservation('127.0.0.1',port,'tcp',state='open');o.service('http')
            cfg=config(port);ctx=PluginContext(o,NetworkBudget(cfg,cfg.plan().scope))
            await ONVIFPlugin().enumerate(ctx)
            assert len(o.channels)==2 and len(o.streams)==4
            assert o.fingerprints[0]['serial']=='TEST-SERIAL'
            with pytest.raises(ValueError):await call(ctx,f'http://127.0.0.1:{port}/onvif/device_service',DEVICE,'SystemReboot')
            with pytest.raises(ValueError):await call(ctx,'http://192.0.2.1/device',DEVICE,'GetDeviceInformation')
            assert not any(b'SystemReboot' in r for r in requests)
    asyncio.run(scenario())
