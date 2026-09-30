"""IPP Get-Printer-Attributes, never Print-Job or job enumeration."""
import secrets
import struct
from ..detection.wire import WireRequest

def attr(tag,name,value):
    name=name.encode();value=value.encode()
    return bytes([tag])+struct.pack('!H',len(name))+name+struct.pack('!H',len(value))+value

def request(o,c):
    request_id=secrets.randbits(30)
    host=f'[{o.ip}]' if ':' in o.ip else o.ip
    uri=f'ipp://{host}:{o.port}/ipp/print'
    body=b'\x02\x00\x00\x0b'+struct.pack('!I',request_id)+b'\x01'+attr(0x47,'attributes-charset','utf-8')+attr(0x48,'attributes-natural-language','en')+attr(0x45,'printer-uri',uri)+attr(0x44,'requested-attributes','printer-description')+b'\x03'
    payload=f'POST /ipp/print HTTP/1.1\r\nHost: {host}:{o.port}\r\nContent-Type: application/ipp\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode()+body
    def parse(raw):
        head,sep,data=raw.partition(b'\r\n\r\n')
        if not sep or not head.startswith(b'HTTP/1.1 200') or b'application/ipp' not in head.lower() or len(data)<9:return None
        if data[0] not in (1,2) or int.from_bytes(data[4:8],'big')!=request_id:return None
        code=int.from_bytes(data[2:4],'big');offset=8;attrs={};last=''
        while offset<len(data):
            tag=data[offset];offset+=1
            if tag==3:break
            if tag<16:continue
            if offset+2>len(data):return None
            size=int.from_bytes(data[offset:offset+2],'big');offset+=2
            if offset+size+2>len(data):return None
            name=data[offset:offset+size].decode('ascii','replace') or last;offset+=size;last=name
            length=int.from_bytes(data[offset:offset+2],'big');offset+=2
            if offset+length>len(data):return None
            value=data[offset:offset+length];offset+=length
            if name in ('printer-name','printer-make-and-model','printer-info','printer-uri-supported','ipp-versions-supported','operations-supported','printer-device-id'):
                attrs.setdefault(name,[]).append(int.from_bytes(value,'big') if tag in (0x21,0x23) else value.decode('utf8','replace'))
        return dict(status_code=code,attributes=attrs,model='; '.join(attrs.get('printer-make-and-model',[])),auth_required=code in (0x401,0x403))
    return WireRequest(payload,parse,framing='http_body',limit=32768)
