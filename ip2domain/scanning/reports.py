"""Small dependency-free PDF inventory report (metadata, no captured media)."""
import textwrap

def pdf_report(repository,identifier):
    scan=repository.get(identifier)
    lines=['Scanner v2 - Service inventory', 'Scan: '+identifier, 'Status: '+scan['status']]
    offset=0
    while True:
        rows=repository.hosts(identifier,100,offset)
        if not rows:break
        for host in rows:
            d=host['device'];lines.extend(['',host['ip']+' | '+str(d.get('type','Unknown')),
                'Vendor: '+str(d.get('vendor','Unknown'))+' Model: '+str(d.get('model','Unknown')),
                'Firmware: '+str(d.get('firmware','Unknown'))+' Confidence: '+str(d.get('confidence',0)),
                'Ports: '+', '.join(str(p['port'])+'/'+p['transport'] for p in host['ports']),
                'Services: '+', '.join(s['protocol'] for s in host['services']),
                f'Devices: {len(host["devices"])} Channels: {len(host["channels"])} Streams: {len(host["streams"])} Evidence: {len(host["evidence"])}'])
        offset+=len(rows)
    wrapped=[part for line in lines for part in (textwrap.wrap(line,95) or [''])]
    pages=[wrapped[i:i+52] for i in range(0,len(wrapped),52)]
    objects=[b'<< /Type /Catalog /Pages 2 0 R >>',b'',b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>']
    kids=[]
    for page in pages:
        pid=len(objects)+1;cid=pid+1;kids.append(f'{pid} 0 R')
        objects.append(f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents {cid} 0 R >>'.encode())
        text='BT /F1 10 Tf 40 800 Td 14 TL\n'
        for line in page:
            safe=line.encode('latin-1','replace').decode('latin-1').replace('\\','\\\\').replace('(','\\(').replace(')','\\)')
            text+='('+safe+') Tj T*\n'
        content=(text+'ET').encode('latin-1');objects.append(f'<< /Length {len(content)} >>\nstream\n'.encode()+content+b'\nendstream')
    objects[1]=f'<< /Type /Pages /Kids [{" ".join(kids)}] /Count {len(kids)} >>'.encode()
    output=bytearray(b'%PDF-1.4\n');offsets=[0]
    for i,obj in enumerate(objects,1):
        offsets.append(len(output));output.extend(f'{i} 0 obj\n'.encode()+obj+b'\nendobj\n')
    xref=len(output);output.extend(f'xref\n0 {len(offsets)}\n0000000000 65535 f \n'.encode())
    for off in offsets[1:]:output.extend(f'{off:010d} 00000 n \n'.encode())
    output.extend(f'trailer << /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode())
    return bytes(output)
