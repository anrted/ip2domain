"""Versioned additive migrations and queryable graph entities alongside durable jobs."""
import json
import time
from .evidence import identity
from .graph import host_inventory

KINDS=('targets','hosts','ports','services','protocols','products','vendors','models','firmware','devices','endpoints','credentials','authentication','streams','channels','fingerprints','evidence')
SCHEMA='''CREATE TABLE IF NOT EXISTS inventory_migrations(version INTEGER PRIMARY KEY, applied REAL NOT NULL);
CREATE TABLE IF NOT EXISTS inventory_events(id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, event_key TEXT NOT NULL, type TEXT NOT NULL, document TEXT NOT NULL, created REAL NOT NULL, UNIQUE(scan_id,event_key));
CREATE INDEX IF NOT EXISTS inventory_events_scan ON inventory_events(scan_id,id);
CREATE TABLE IF NOT EXISTS inventory_signatures(id TEXT PRIMARY KEY,version INTEGER NOT NULL,document TEXT NOT NULL,updated REAL NOT NULL);
'''+''.join(f'''CREATE TABLE IF NOT EXISTS inventory_v2_{kind}(scan_id TEXT NOT NULL,id TEXT NOT NULL,host TEXT NOT NULL,document TEXT NOT NULL,PRIMARY KEY(scan_id,id)); CREATE INDEX IF NOT EXISTS inventory_v2_{kind}_host ON inventory_v2_{kind}(scan_id,host);''' for kind in KINDS)

def event(db,scan_id,kind,key,document):
    db.execute('INSERT OR IGNORE INTO inventory_events(scan_id,event_key,type,document,created) VALUES(?,?,?,?,?)',(scan_id,key,kind,json.dumps(document),time.time()))

def put(db,scan_id,kind,host,document):
    document=dict(document,host=host) if kind!="hosts" else document
    db.execute(f'INSERT INTO inventory_v2_{kind} VALUES(?,?,?,?) ON CONFLICT(scan_id,id) DO UPDATE SET document=excluded.document',(scan_id,document['id'],host,json.dumps(document)))

def project(db,scan_id,document):
    ip=document['ip'];hid=identity(scan_id,document['network_id'],ip)
    record_host(db,scan_id,document)
    if document['state']=='open':event(db,scan_id,'host_discovered',hid,dict(host_id=hid,ip=ip))
    pid=identity(hid,document['transport'],document['port'])
    put(db,scan_id,'ports',ip,dict(id=pid,host_id=hid,port=document['port'],transport=document['transport'],state=document['state']))
    if document['state']=='open':event(db,scan_id,'port_open',pid,dict(ip=ip,port=document['port'],transport=document['transport']))
    for s in document['services']:
        sid=identity(pid,s['protocol'],s.get('attributes',{}).get('path',''))
        put(db,scan_id,'services',ip,dict(s,id=sid,host_id=hid,port_id=pid,ip=ip,port=document['port']))
        proto=dict(id=identity(s['protocol']),name=s['protocol']);put(db,scan_id,'protocols',ip,proto)
        event(db,scan_id,'service_detected',sid,dict(service_id=sid,ip=ip,protocol=s['protocol']))
        event(db,scan_id,'protocol_detected','protocol:'+sid,dict(service_id=sid,protocol=s['protocol']))
    events={'endpoints':'endpoint_found','streams':'stream_found','fingerprints':'fingerprint_detected','authentication':'authentication_detected','devices':'device_detected'}
    for kind in ('endpoints','streams','channels','fingerprints','evidence','authentication','devices'):
        for value in document.get(kind,[]):
            put(db,scan_id,kind,ip,value)
            if kind in events:event(db,scan_id,events[kind],kind+':'+value['id'],dict(id=value['id'],ip=ip))
            if kind=='authentication' and value.get('status')=='valid':event(db,scan_id,'credential_valid','credential:'+value['id'],dict(credential_id=value.get('credential_id'),ip=ip))

class GraphRepositoryMixin:
    def migrate_graph(self):
        with self.connect() as db:
            db.executescript(SCHEMA)
            if not db.execute('SELECT 1 FROM inventory_migrations WHERE version=2').fetchone():
                # Preserve old endpoint documents and checkpoints, add projections in place.
                for row in db.execute('SELECT scan_id,document FROM inventory_endpoints').fetchall():project(db,row['scan_id'],json.loads(row['document']))
                db.execute('INSERT INTO inventory_migrations VALUES(2,?)',(time.time(),))
            if not db.execute('SELECT 1 FROM inventory_migrations WHERE version=3').fetchone():
                from .evidence import sanitize_document
                for table in ('inventory_endpoints','inventory_stage_work'):
                    for row in db.execute(f'SELECT rowid,document FROM {table}').fetchall():
                        raw=json.loads(row['document']);clean=sanitize_document(raw)
                        if raw!=clean:db.execute(f'UPDATE {table} SET document=? WHERE rowid=?',(json.dumps(clean),row['rowid']))
                for kind in KINDS:
                    for row in db.execute(f'SELECT rowid,document FROM inventory_v2_{kind}').fetchall():
                        raw=json.loads(row['document']);clean=sanitize_document(raw)
                        if raw!=clean:db.execute(f'UPDATE inventory_v2_{kind} SET document=? WHERE rowid=?',(json.dumps(clean),row['rowid']))
                db.execute('INSERT INTO inventory_migrations VALUES(3,?)',(time.time(),))

    def hosts(self,scan_id,limit=100,offset=0):
        with self.connect() as db:
            ips=[r[0] for r in db.execute('SELECT DISTINCT host FROM inventory_v2_hosts WHERE scan_id=? ORDER BY host LIMIT ? OFFSET ?',(scan_id,limit,offset))]
        return [self.host(scan_id,ip) for ip in ips]

    def host(self,scan_id,ip):
        with self.connect() as db:
            scan=db.execute('SELECT config FROM inventory_scans WHERE id=?',(scan_id,)).fetchone()
            if not scan:return None
            rows=[json.loads(r[0]) for r in db.execute('SELECT document FROM inventory_endpoints WHERE scan_id=? AND ip=?',(scan_id,ip))]
        with self.connect() as db:
            h=db.execute('SELECT document FROM inventory_v2_hosts WHERE scan_id=? AND host=?',(scan_id,ip)).fetchone()
        if not rows and not h:return None
        result=host_inventory(rows,scan_id=scan_id,ip=ip,config=json.loads(scan[0]))
        if h:
            saved=json.loads(h[0])
            for key in ('state','discovery','target_id'):result[key]=saved.get(key)
        return result

    def entities(self,scan_id,kind,limit=100,offset=0,query=''):
        if kind not in KINDS:raise ValueError('unknown entity kind')
        with self.connect() as db:
            rows=db.execute(f'SELECT document FROM inventory_v2_{kind} WHERE scan_id=? AND document LIKE ? ORDER BY host,id LIMIT ? OFFSET ?',(scan_id,'%'+query+'%',limit,offset))
            return [json.loads(r[0]) for r in rows]

    def finalize_graph(self,scan_id):
        offset=0
        while True:
            hosts=self.hosts(scan_id,100,offset)
            if not hosts:break
            with self.connect() as db:
                for host in hosts:
                    for kind in KINDS:
                        if kind in ('targets','credentials'):continue
                        values=[host] if kind=='hosts' else host.get(kind,[])
                        for value in values:
                            put(db,scan_id,kind,host['ip'],value)
                            if kind=='devices':event(db,scan_id,'device_detected','device:'+value['id'],dict(id=value['id'],ip=host['ip']))
            offset+=len(hosts)
        with self.connect() as db:event(db,scan_id,'scan_completed','scan_completed',dict(id=scan_id))

    def events(self,scan_id,after=0,limit=500):
        with self.connect() as db:
            return [dict(id=r['id'],type=r['type'],data=json.loads(r['document']),created=r['created']) for r in db.execute('SELECT * FROM inventory_events WHERE scan_id=? AND id>? ORDER BY id LIMIT ?',(scan_id,after,limit))]

    def learned_signatures(self):
        with self.connect() as db:return [json.loads(r[0]) for r in db.execute('SELECT document FROM inventory_signatures')]

    def save_signature(self,signature):
        if not isinstance(signature,dict) or not isinstance(signature.get('id'),str) or type(signature.get('version')) is not int:raise ValueError('signature requires id and integer version')
        if not isinstance(signature.get('contains'),list) or not signature['contains'] or any(not isinstance(s,str) or not 3<=len(s)<=256 for s in signature['contains']):raise ValueError('signature requires bounded literal matchers')
        allowed={'id','version','contains','vendor','product','model','firmware','device_type','category','confidence'}
        if set(signature)-allowed:raise ValueError('unknown signature field')
        if not 0<=signature.get('confidence',.7)<=1:raise ValueError('invalid confidence')
        with self.connect() as db:
            old=db.execute('SELECT version FROM inventory_signatures WHERE id=?',(signature['id'],)).fetchone()
            if old and old[0]>=signature['version']:raise ValueError('signature version must increase')
            db.execute('INSERT OR REPLACE INTO inventory_signatures VALUES(?,?,?,?)',(signature['id'],signature['version'],json.dumps(signature),time.time()))
        return signature


def record_host(db,scan_id,document):
    ip=document['ip'];hid=identity(scan_id,document['network_id'],ip)
    previous=db.execute('SELECT document FROM inventory_v2_hosts WHERE scan_id=? AND id=?',(scan_id,hid)).fetchone()
    host=json.loads(previous[0]) if previous else dict(id=hid,ip=ip,network_id=document['network_id'],target_id=identity(scan_id,'targets'),state='unknown',discovery=[])
    discovery=document.get('stage_results',{}).get('host_discovery',{})
    alive=document['state'] in ('open','closed') or discovery.get('alive')
    if alive:host['state']='alive'
    for signal in discovery.get('signals',[]):
        if signal not in host.setdefault('discovery',[]):host['discovery'].append(signal)
    put(db,scan_id,'hosts',ip,host)
    if alive:event(db,scan_id,'host_discovered',hid,dict(host_id=hid,ip=ip))
