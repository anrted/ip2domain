"""Read-only metadata for explicitly authenticated management protocols."""
import asyncio
import secrets
import struct
from .base import ProtocolPlugin
from ..evidence import capture,identity
from ..protocols.ber import fields,content,integer,number,sequence,tlv
from ..transports.network import datagram,exchange

class ManagementPlugin(ProtocolPlugin):
    name='management';protocols=('snmp','mqtt','mqtts')
    async def enumerate(self,ctx):
        return [s for s in ctx.observation.services if s['protocol'] in self.protocols]
    async def authenticate(self,ctx):
        o=ctx.observation
        if not ctx.config.allow_credentials:return
        for service in await self.enumerate(ctx):
            protocol=service['protocol'];credential=ctx.vault.get(o.ip,protocol)
            if not credential or protocol in ctx.failed_auth:continue
            await ctx.budget.protocol_tick(o.ip,protocol)
            if protocol.startswith('mqtt'):
                def string(value):
                    data=value.encode();return struct.pack('!H',len(data))+data
                client='inventory-'+secrets.token_hex(8)
                # Clean Session, username/password, no Will, no subscriptions/publish.
                body=b'\x00\x04MQTT\x04\xc2\x00\x05'+string(client)+string(credential.username)+string(credential.password)
                size=len(body);encoded=bytearray()
                while True:
                    digit=size%128;size//=128;encoded.append(digit|(128 if size else 0))
                    if not size:break
                raw=await exchange(ctx.budget,o.ip,o.port,b'\x10'+encoded+body,tls=protocol=='mqtts',framing='fixed',minimum=4,limit=4)
                from ..protocols.binary import mqtt_response
                response=mqtt_response(raw);valid=response is not None and response['return_code']==0
                evidence=capture(o,'mqtt_connack',raw,source=protocol)
                status='valid' if valid else 'rejected'
            else:
                # SNMP v2c GET sysDescr/sysObjectID; community must be supplied as password.
                request_id=secrets.randbits(30)
                oid1=b'\x2b\x06\x01\x02\x01\x01\x01\x00';oid2=b'\x2b\x06\x01\x02\x01\x01\x02\x00'
                binds=sequence(*(sequence(tlv(6,oid),tlv(5,b'')) for oid in (oid1,oid2)))
                packet=sequence(integer(1),tlv(4,credential.password.encode()),tlv(0xa0,integer(request_id)+integer(0)+integer(0)+binds))
                raw=await datagram(ctx.budget,o.ip,o.port,packet)
                try:
                    message=fields(content(fields(raw)[0],0x30));pdu=fields(content(message[2],0xa2))
                    valid=number(message[0])==1 and number(pdu[0])==request_id and number(pdu[1])==0
                    attrs={}
                    if valid:
                        for bind in fields(content(pdu[3],0x30)):
                            pair=fields(content(bind,0x30));oid=content(pair[0],6)
                            if oid==oid1:attrs['product']=content(pair[1],4).decode('utf8','replace')
                            elif oid==oid2:attrs['object_id_hex']=pair[1][1].hex()
                        service['attributes'].update(attrs)
                except (ValueError,IndexError):valid=False
                # Community echoes in responses are never evidence.
                evidence=capture(o,'snmp_system',str(attrs) if valid else b'',source='SNMP GetResponse')
                status='valid' if valid else 'rejected'
            o.authentication.append(dict(id=identity(o.ip,o.port,protocol,credential.id),protocol=protocol,mechanism='community' if protocol=='snmp' else 'username/password',status=status,credential_id=credential.id,evidence=[evidence]))
            if status=='rejected':ctx.failed_auth.add(protocol)
            await o.checkpoint()
