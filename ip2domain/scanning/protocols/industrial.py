"""Non-mutating industrial protocol identification (no register or process writes)."""
import secrets
import struct
from ..detection.wire import WireRequest


def crc_dnp(data):
    crc=0
    for byte in data:
        crc^=byte
        for _ in range(8):crc=(crc>>1)^0xa6bc if crc&1 else crc>>1
    return (~crc)&0xffff


def dnp3(o,c):
    # Link status request; does not reset a link or request process data.
    dest=c.dnp3_address;source=65534
    header=b'\x05\x64\x05\xc9'+struct.pack('<HH',dest,source)
    packet=header+struct.pack('<H',crc_dnp(header))
    def parse(data):
        if len(data)!=10 or data[:3]!=b'\x05\x64\x05' or crc_dnp(data[:8])!=int.from_bytes(data[8:10],'little'):return None
        dst,src=struct.unpack('<HH',data[4:8])
        if dst!=source or src!=dest or data[3]&0x0f!=0x0b:return None
        return dict(link_address=src,operation='link-status')
    return WireRequest(packet,parse,framing='fixed',minimum=10,limit=10)


def iec104(o,c):
    # TESTFR act only: no STARTDT, interrogation or command ASDUs.
    return WireRequest(b'\x68\x04\x43\x00\x00\x00',lambda d:dict(operation='TESTFR') if d==b'\x68\x04\x83\x00\x00\x00' else None,framing='fixed',minimum=6,limit=6)


def enip_identity(data):
    if len(data)<26 or data[:2]!=b'\x63\x00' or int.from_bytes(data[2:4],'little')+24!=len(data) or any(data[8:12]):return None
    count=int.from_bytes(data[24:26],'little');pos=26;items=[]
    for _ in range(min(count,32)):
        if pos+4>len(data):return None
        kind,size=struct.unpack('<HH',data[pos:pos+4]);pos+=4
        item=data[pos:pos+size];pos+=size
        if len(item)!=size:return None
        if kind==0x000c and size>=34:
            vendor,device_type,product=struct.unpack('<HHH',item[18:24]);length=item[32]
            if 33+length>=size:return None
            items.append(dict(vendor_id=vendor,device_type_id=device_type,product_code=product,firmware=f'{item[24]}.{item[25]}',serial=str(int.from_bytes(item[28:32],'little')),product=item[33:33+length].decode('utf8','replace')))
    return dict(identities=items,**items[0]) if items else None
