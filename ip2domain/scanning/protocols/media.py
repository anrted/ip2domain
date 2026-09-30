"""Media header recognizers; no frame decoding or media recording."""
import secrets
import struct
from ..detection.wire import WireRequest


def rtp(data):
    if len(data)<12 or data[0]>>6!=2 or 192<=data[1]<=223:return None
    size=12+4*(data[0]&15)
    if len(data)<size:return None
    if data[0]&16:
        if len(data)<size+4:return None
        size+=4+int.from_bytes(data[size+2:size+4],'big')*4
    if size>len(data):return None
    if data[0]&32 and (not data[-1] or data[-1]>len(data)-size):return None
    pt=data[1]&127
    return dict(payload_type=pt,sequence=int.from_bytes(data[2:4],'big'),timestamp=int.from_bytes(data[4:8],'big'),ssrc=data[8:12].hex(),codec={0:'PCMU',8:'PCMA',9:'G722',26:'JPEG',33:'MPEG-TS'}.get(pt,'Unknown'))


def rtcp(data):
    offset=0;packets=[]
    while offset<len(data):
        if offset+4>len(data) or data[offset]>>6!=2 or not 200<=data[offset+1]<=207:return None
        size=4*(int.from_bytes(data[offset+2:offset+4],'big')+1)
        if size<8 or offset+size>len(data):return None
        kind=data[offset+1]
        if kind==200 and size<28:return None
        if kind==201 and size<8:return None
        packets.append(dict(type=kind,ssrc=data[offset+4:offset+8].hex()));offset+=size
    return dict(packets=packets) if packets else None


def srt(o,c):
    socket_id=secrets.randbits(31);sequence=secrets.randbits(31)
    # UDT/SRT induction handshake, no stream id, encryption credentials or media packets.
    payload=struct.pack('!4I',0x80000000,0,0,0)+struct.pack('!12I',4,2,sequence,1500,8192,1,socket_id,0,0,0,0,0)
    def parse(data):
        if len(data)<64 or data[:2]!=b'\x80\x00' or int.from_bytes(data[12:16],'big')!=socket_id:return None
        version,kind,seq,mtu,window,handshake,peer,cookie=struct.unpack('!8I',data[16:48])
        if version not in (4,5) or seq!=sequence or handshake!=1:return None
        # SRT magic is in low 16 bits of the type field for version 5.
        if version==5 and kind&0xffff==0x4a17:return dict(version=5,mtu=mtu,window=window,handshake='induction')
        return dict(protocol='udt',version=version,handshake='induction')
    return WireRequest(payload,parse,framing='datagram',limit=2048)
