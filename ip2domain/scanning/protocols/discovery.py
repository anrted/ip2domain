"""Correlated read-only discovery requests; no multicast scope expansion."""
import secrets
import uuid
import struct
import xml.etree.ElementTree as ET
from ..detection.wire import WireRequest


def ws_discovery(o,c):
    mid='urn:uuid:'+str(uuid.uuid4())
    payload=f'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"><s:Header><a:MessageID>{mid}</a:MessageID><a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action></s:Header><s:Body><d:Probe/></s:Body></s:Envelope>'.encode()
    def parse(data):
        if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():return None
        try:root=ET.fromstring(data)
        except ET.ParseError:return None
        def vals(name):return [e.text or '' for e in root.iter() if e.tag.rsplit('}',1)[-1]==name]
        if mid not in vals('RelatesTo') or not vals('ProbeMatch'):return None
        return dict(xaddrs=[u for v in vals('XAddrs') for u in v.split()],types=vals('Types'),scopes=vals('Scopes'))
    return WireRequest(payload,parse,framing='datagram')


def ssdp(o,c):
    packet=f'M-SEARCH * HTTP/1.1\r\nHOST: {o.ip}:{o.port}\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'.encode()
    def parse(data):
        text=data.decode('iso8859-1')
        if not text.startswith('HTTP/1.1 200'):return None
        fields={k.strip().lower():v.strip() for line in text.split('\r\n')[1:] if ':' in line for k,v in [line.split(':',1)]}
        if not fields.get('usn') or not fields.get('st'):return None
        return dict(server=fields.get('server',''),usn=fields['usn'],location=fields.get('location',''),service_type=fields['st'])
    return WireRequest(packet,parse,framing='datagram')


def mdns(o,c):
    from .dns_codec import encode_name,parse_dns
    query=b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'+encode_name('_services._dns-sd._udp.local.')+b'\x00\x0c\x80\x01'
    def parse(data):
        try:response=parse_dns(data)
        except ValueError:return None
        if response['transaction']!=0 or not response['flags']&0x8000:return None
        answers=[r for r in response['records'] if r['name']=='_services._dns-sd._udp.local.']
        return dict(records=answers) if answers else None
    return WireRequest(query,parse,framing='datagram')


def iax(o,c):
    call=secrets.randbelow(32767)+1;stamp=secrets.randbits(32)
    payload=struct.pack('!HHIBBBB',call|0x8000,0,stamp,0,0,6,2) # IAX PING, no call NEW
    def parse(data):
        if len(data)<12:return None
        src,dst,ts,oseq,iseq,kind,sub=struct.unpack('!HHIBBBB',data[:12])
        if not src&0x8000 or dst&0x7fff!=call or ts!=stamp or kind!=6 or sub not in (3,4):return None
        return dict(frame='PONG' if sub==3 else 'ACK')
    return WireRequest(payload,parse,framing='datagram')


def knx(o,c):
    # Description request, HPAI IP/port zero: reply over the connected UDP channel.
    payload=b'\x06\x10\x02\x03\x00\x0e\x08\x01'+b'\x00'*6
    def parse(data):
        if len(data)<8 or data[:4]!=b'\x06\x10\x02\x04' or int.from_bytes(data[4:6],'big')!=len(data):return None
        return dict(description=data[6:].hex())
    return WireRequest(payload,parse,framing='datagram')
