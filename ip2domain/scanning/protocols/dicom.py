"""DICOM Verification SOP association and C-ECHO only; no dataset transfers."""
import struct
from ..detection.wire import WireRequest
VERIFY=b'1.2.840.10008.1.1';IMPLICIT=b'1.2.840.10008.1.2';APP=b'1.2.840.10008.3.1.1.1'

def item(tag,data):return bytes([tag,0])+struct.pack('!H',len(data))+data

def pdu(tag,data):return bytes([tag,0])+struct.pack('!I',len(data))+data

def association(called='ANY-SCP',calling='INVENTORY'):
    def ae(value):
        if not 1<=len(value)<=16 or not value.isascii():raise ValueError('invalid AE title')
        return value.encode().ljust(16,b' ')
    context=item(0x20,b'\x01\x00\x00\x00'+item(0x30,VERIFY)+item(0x40,IMPLICIT))
    user=item(0x50,item(0x51,struct.pack('!I',16384)))
    return pdu(1,b'\x00\x01\x00\x00'+ae(called)+ae(calling)+b'\x00'*32+item(0x10,APP)+context+user)

def items(data):
    offset=0
    while offset<len(data):
        if offset+4>len(data):raise ValueError('short DICOM item')
        tag=data[offset];size=int.from_bytes(data[offset+2:offset+4],'big');offset+=4
        if offset+size>len(data):raise ValueError('short DICOM value')
        yield tag,data[offset:offset+size];offset+=size

def parse_association(data):
    if len(data)<10 or len(data)!=6+int.from_bytes(data[2:6],'big'):return None
    if data[0]==3 and len(data)==10:return dict(association='rejected',reason=data[-1])
    if data[0]!=2 or len(data)<74 or data[6:8]!=b'\x00\x01':return None
    result=dict(association='accepted',verification_accepted=False)
    try:
        for tag,value in items(data[74:]):
            if tag==0x10 and value!=APP:return None
            if tag==0x21 and len(value)>=4:
                if value[0]==1 and value[2]==0:
                    result['verification_accepted']=any(t==0x40 and v==IMPLICIT for t,v in items(value[4:]))
            if tag==0x50:
                for t,v in items(value):
                    if t==0x52:result['implementation_class_uid']=v.decode('ascii','replace')
                    if t==0x55:result['implementation_version']=v.decode('ascii','replace')
    except ValueError:return None
    return result

def echo():
    def element(tag,value):return struct.pack('<HHI',0,tag,len(value))+value
    uid=VERIFY+(b'\x00' if len(VERIFY)%2 else b'')
    body=element(2,uid)+element(0x100,struct.pack('<H',0x30))+element(0x110,struct.pack('<H',1))+element(0x800,struct.pack('<H',0x101))
    body=element(0,struct.pack('<I',len(body)))+body
    return pdu(4,struct.pack('!I',len(body)+2)+b'\x01\x03'+body)

def echo_status(raw):
    if len(raw)<12 or raw[0]!=4 or int.from_bytes(raw[2:6],'big')+6!=len(raw):return None
    if raw[10:12]!=b'\x01\x03':return None
    data=raw[12:];offset=0;attrs={}
    while offset+8<=len(data):
        group,tag,size=struct.unpack('<HHI',data[offset:offset+8]);offset+=8
        if group!=0 or size>len(data)-offset:return None
        attrs[tag]=data[offset:offset+size];offset+=size
    if attrs.get(0x100)!=b'\x30\x80' or attrs.get(0x120)!=b'\x01\x00':return None
    return int.from_bytes(attrs[0x900],'little') if len(attrs.get(0x900,b''))==2 else None

def request(o,c):return WireRequest(association(c.dicom_ae_title),parse_association,framing='dicom',limit=16384)
