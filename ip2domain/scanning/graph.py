"""Inventory graph projection: service identity is not physical device identity."""
from .evidence import identity

def host_inventory(documents, *, scan_id='', ip='', config=None):
    config=config or {}
    host=dict(id=identity(scan_id,config.get('network_id','local'),ip),host=ip,ip=ip,network_id=config.get('network_id','local'),site_id=config.get('site_id',''),target_group=config.get('target_group',''),tags=config.get('tags',[]),comments=config.get('comments',''),
              ports=[],services=[],protocols=[],products=[],vendors=[],models=[],firmware=[],endpoints=[],devices=[],channels=[],streams=[],authentication=[],fingerprints=[],evidence=[])
    groups={};service_groups={}; stream_uris={}
    for doc in documents:
        port_id=identity(host['id'],doc['transport'],doc['port'])
        host['ports'].append(dict(id=port_id,port=doc['port'],transport=doc['transport'],state=doc['state'],service=','.join(s['protocol'] for s in doc['services']) or 'Unknown'))
        fingerprints=doc.get('fingerprints',[])
        # Strong serial identifies one unit. Vendor alone is never sufficient to merge unrelated services.
        strongest=sorted(fingerprints,key=lambda f:f.get('confidence',0),reverse=True)
        serial=next((f.get('serial') for f in strongest if f.get('serial')),None)
        model=next((f.get('model') for f in strongest if f.get('model')),None)
        vendor=next((f.get('vendor') for f in strongest if f.get('vendor')),None)
        key=('serial',vendor,serial) if serial else ('model',vendor,model) if vendor and model else ('service',port_id)
        device=groups.setdefault(key,dict(id=identity(host['id'],key),type='Unknown',vendor=vendor or 'Unknown',model=model or 'Unknown',firmware='Unknown',confidence=0.,services=[],channels=[],streams=[],evidence=[],correlation_basis=key[0]))
        for fp in reversed(strongest):
            for field in ('vendor','model','firmware','product','serial'):
                if fp.get(field):device[field]=fp[field]
            if fp.get('device_type'):device['type']=fp['device_type']
            device['confidence']=max(device['confidence'],fp.get('confidence',0))
            device['evidence'].extend(e for e in fp.get('evidence',[]) if e not in device['evidence'])
        for svc in doc['services']:
            service_id=identity(port_id,svc['protocol'],svc.get('attributes',{}).get('path',''))
            row={**svc,'id':service_id,'port_id':port_id,'host_id':host['id'],'ip':ip,'port':doc['port'],'transport':doc['transport'],'device_id':device['id']}
            host['services'].append(row);device['services'].append(service_id)
            protocol=dict(id=identity(svc['protocol']),name=svc['protocol'])
            if protocol not in host['protocols']:host['protocols'].append(protocol)
        for kind in ('endpoints','channels','streams','authentication','fingerprints','evidence'):
            for item in doc.get(kind,[]):
                item=dict(item)
                if kind in ('channels','streams'):item['device_id']=device['id']
                if not any(x['id']==item['id'] for x in host[kind]):host[kind].append(item)
                if kind in ('streams','channels') and item['id'] not in device[kind]:device[kind].append(item['id'])
        service_groups[port_id]=device
    # Exact URI identity links ONVIF advertised profiles and independently described RTSP streams.
    for stream in host['streams']:
        uri=stream.get('uri')
        if uri in stream_uris:
            other=stream_uris[uri]
            stream['same_stream_as']=other['id']
            if stream.get('verification')=='sdp':other.update(tracks=stream.get('tracks',[]),verification='sdp',codec=stream.get('codec',other.get('codec')))
        else:stream_uris[uri]=stream
    # Merge devices only when a protocol-derived exact stream URI proves the link.
    for stream in host['streams']:
        if not stream.get('same_stream_as'):continue
        other=next(x for x in host['streams'] if x['id']==stream['same_stream_as'])
        if other['device_id']==stream['device_id']:continue
        left=next((d for d in groups.values() if d['id']==other['device_id']),None)
        right=next((d for d in groups.values() if d['id']==stream['device_id']),None)
        if not left or not right:continue
        for field in ('services','channels','streams','evidence'):
            left[field]=list(dict.fromkeys(left[field]+right[field]))
        for field in ('vendor','model','firmware','type','serial','product'):
            if left.get(field) in (None,'Unknown') and right.get(field):left[field]=right[field]
        left['confidence']=max(left['confidence'],right['confidence']);left['correlation_basis']='exact-stream-uri'
        for kind in ('services','channels','streams'):
            for row in host[kind]:
                if row.get('device_id')==right['id']:row['device_id']=left['id']
        groups={k:v for k,v in groups.items() if v['id']!=right['id']}
    for device in groups.values():
        # Distinct source tokens are logical sources, not a claim about hardware serials.
        if len(device['channels'])>1 and device['type']=='Unknown':device['type']='multi-channel-video-source'
        host['devices'].append(device)
        for channel_id in device['channels']:
            channel=next(c for c in host['channels'] if c['id']==channel_id)
            child=dict(id=identity(device['id'],channel_id),parent_id=device['id'],type='logical-video-source',channel_id=channel_id,
                       confidence=channel.get('confidence',0),evidence=channel.get('evidence',[]),streams=[s['id'] for s in host['streams'] if s.get('channel_id')==channel_id])
            host['devices'].append(child)
        for key,kind in [('vendor','vendors'),('product','products'),('model','models'),('firmware','firmware')]:
            val=device.get(key)
            if val and val!='Unknown':
                row=dict(id=identity(key,val),name=val,device_id=device['id'],evidence=device['evidence'])
                if row not in host[kind]:host[kind].append(row)
    host['device']=next(iter(groups.values()),{'type':'Unknown','confidence':0})
    return host
