"""Bounded DNS parser used by unicast and mDNS evidence extraction."""
import ipaddress
import struct

def encode_name(name):return b''.join(bytes([len(label)])+label.encode('ascii') for label in name.rstrip('.').split('.'))+b'\x00'

def name_at(data,offset,depth=0):
    if depth>16:raise ValueError('DNS pointer loop')
    parts=[]
    while True:
        if offset>=len(data):raise ValueError('short DNS name')
        length=data[offset];offset+=1
        if length==0:return '.'.join(parts)+'.',offset
        if length&0xc0==0xc0:
            if offset>=len(data):raise ValueError('short DNS pointer')
            pointer=((length&63)<<8)|data[offset];suffix,_=name_at(data,pointer,depth+1)
            return '.'.join(parts)+('.' if parts else '')+suffix,offset+1
        if length>63 or offset+length>len(data):raise ValueError('invalid DNS label')
        parts.append(data[offset:offset+length].decode('ascii','replace'));offset+=length
        if sum(map(len,parts))>253:raise ValueError('oversized DNS name')

def parse_dns(data):
    if len(data)<12:raise ValueError('short DNS header')
    xid,flags,qd,an,ns,ar=struct.unpack('!6H',data[:12]);offset=12
    if qd+an+ns+ar>512:raise ValueError('too many DNS records')
    questions=[];records=[]
    for _ in range(qd):
        name,offset=name_at(data,offset)
        if offset+4>len(data):raise ValueError('short DNS question')
        typ,cls=struct.unpack('!HH',data[offset:offset+4]);offset+=4;questions.append(dict(name=name,type=typ))
    for _ in range(an+ns+ar):
        name,offset=name_at(data,offset)
        if offset+10>len(data):raise ValueError('short DNS RR')
        typ,cls,ttl,length=struct.unpack('!HHIH',data[offset:offset+10]);offset+=10
        end=offset+length
        if end>len(data):raise ValueError('short DNS RDATA')
        raw=data[offset:end];value=raw.hex()
        if typ in (2,5,12):value=name_at(data,offset)[0]
        elif typ==1 and length==4 or typ==28 and length==16:value=str(ipaddress.ip_address(raw))
        elif typ==33 and length>=7:
            priority,weight,port=struct.unpack('!HHH',raw[:6]);value=dict(priority=priority,weight=weight,port=port,target=name_at(data,offset+6)[0])
        elif typ==16:
            values=[];cursor=0
            while cursor<len(raw):
                size=raw[cursor];cursor+=1
                if cursor+size>len(raw):raise ValueError('invalid TXT')
                values.append(raw[cursor:cursor+size].decode('utf8','replace'));cursor+=size
            value=values
        records.append(dict(name=name,type=typ,ttl=ttl,value=value));offset=end
    return dict(transaction=xid,flags=flags,questions=questions,records=records)
