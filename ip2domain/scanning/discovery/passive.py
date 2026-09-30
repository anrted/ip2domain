"""Bounded, scoped Ethernet metadata capture; payloads never become evidence."""
import asyncio
import socket
import struct
from pathlib import Path
from ..protocols.media import rtp,rtcp
from ..inventory import EndpointObservation
from ..evidence import capture


def lldp(data):
    offset=0;result={}
    while offset+2<=len(data):
        header=int.from_bytes(data[offset:offset+2],'big');offset+=2
        kind,size=header>>9,header&511
        if offset+size>len(data):return None
        value=data[offset:offset+size];offset+=size
        if kind==0:break
        if kind in (1,2):result['chassis_id' if kind==1 else 'port_id']=value.hex()
        elif kind in (5,6):result['system_name' if kind==5 else 'system_description']=value.decode('utf8','replace')[:512]
        elif kind==7 and len(value)==4:result['capabilities']=int.from_bytes(value[:2],'big')
    return result if 'chassis_id' in result and 'port_id' in result else None

def cdp(data):
    if len(data)<4 or data[0] not in (1,2):return None
    offset=4;result={}
    while offset+4<=len(data):
        kind,size=struct.unpack('!HH',data[offset:offset+4])
        if size<4 or offset+size>len(data):return None
        value=data[offset+4:offset+size];offset+=size
        key={1:'device_id',3:'port_id',5:'software_version',6:'platform'}.get(kind)
        if key:result[key]=value.decode('utf8','replace')[:512]
    return result if 'device_id' in result else None

def mavlink(data):
    # Only HEARTBEAT metadata, never retain location or send control packets.
    if len(data)<17 or data[0] not in (0xfe,0xfd):return None
    v2=data[0]==0xfd;header=10 if v2 else 6;size=data[1]
    message=int.from_bytes(data[7:10],'little') if v2 else data[5]
    if message!=0 or size!=9 or len(data)<header+size+2:return None
    crc=0xffff
    for b in data[1:header+size]+bytes([50]):
        tmp=b^(crc&255);tmp^=(tmp<<4)&255;crc=((crc>>8)^(tmp<<8)^(tmp<<3)^(tmp>>4))&65535
    if int.from_bytes(data[header+size:header+size+2],'little')!=crc:return None
    payload=data[header:header+size]
    return dict(version=2 if v2 else 1,system_id=data[5] if v2 else data[3],component_id=data[6] if v2 else data[4],vehicle_type=payload[4],autopilot=payload[5])

async def capture_metadata(budget,callback):
    if not budget.config.passive_interface:return
    interface=budget.config.passive_interface
    if interface not in {name for _,name in socket.if_nameindex()}:raise ValueError('unknown capture interface')
    mac_to_ip={}
    try:
        for line in Path('/proc/net/arp').read_text().splitlines()[1:]:
            fields=line.split()
            if len(fields)>=6 and fields[5]==interface and budget.scope.contains(fields[0]):mac_to_ip[fields[3]]=fields[0]
    except OSError:pass
    sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));sock.setblocking(False);sock.bind((interface,0))
    loop=asyncio.get_running_loop();deadline=loop.time()+budget.config.passive_seconds
    # Two sequential RTP packets with the same SSRC are required; one random datagram isn't proof.
    sequences={}
    try:
        while loop.time()<deadline:
            try:frame=await asyncio.wait_for(loop.sock_recv(sock,4096),deadline-loop.time())
            except asyncio.TimeoutError:break
            if len(frame)<14:continue
            ethertype=int.from_bytes(frame[12:14],'big');body=frame[14:];proto=None;attrs=None;port=0;transport='ethernet'
            mac=':'.join(f'{x:02x}' for x in frame[6:12]);ip=mac_to_ip.get(mac)
            if ethertype==0x88cc:proto='lldp';attrs=lldp(body)
            elif body.startswith(b'\xaa\xaa\x03\x00\x00\x0c\x20\x00'):proto='cdp';attrs=cdp(body[8:])
            elif ethertype==0x8892 and len(body)>=12 and body[:2] in (b'\xfe\xff',b'\xfe\xfd'):
                proto='profinet-dcp';attrs=dict(frame_id=body[:2].hex(),service_id=body[2],service_type=body[3])
            elif ethertype==0x0800 and len(body)>=28:
                ihl=(body[0]&15)*4
                if ihl<20 or body[9]!=17 or len(body)<ihl+8 or int.from_bytes(body[6:8],'big')&0x3fff:continue
                ip=socket.inet_ntoa(body[12:16])
                if not budget.scope.contains(ip):continue
                udp=body[ihl:];port=int.from_bytes(udp[:2],'big');transport='udp';payload=udp[8:]
                attrs=rtcp(payload)
                if attrs:proto='rtcp'
                else:
                    attrs=rtp(payload)
                    if attrs:
                        key=(ip,port,attrs['ssrc']);previous=sequences.get(key);sequences[key]=attrs['sequence']
                        if previous is None or (attrs['sequence']-previous)&65535!=1:continue
                        proto='rtp'
                    else:
                        attrs=mavlink(payload)
                        if attrs:proto='mavlink'
            if not ip or not proto or not attrs:continue
            o=EndpointObservation(ip,port,transport,state='open',network_id=budget.config.network_id)
            ev=capture(o,'passive_metadata',str(attrs),source=proto)
            o.service(proto,(),**attrs,evidence=ev);await callback(o)
    finally:sock.close()
