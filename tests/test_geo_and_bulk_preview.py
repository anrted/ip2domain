"""Offline GeoIP precision and bulk-preview lifecycle regressions."""
import asyncio
import json
import sqlite3
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from ip2domain.data.geo_city_db import GeoCityDatabase, normalize_geo, normalize_ip, camera_geo_fields
from ip2domain.core.storage import StorageManager


def geo_db(tmp_path):
    path = tmp_path / 'geo.sqlite3'
    with sqlite3.connect(path) as conn:
        conn.execute('''CREATE TABLE subnets(id INTEGER PRIMARY KEY, cidr TEXT, country_code TEXT,
            country_name TEXT, city TEXT, city_en TEXT, region TEXT, isp TEXT, asn TEXT, org TEXT,
            start_ip INTEGER, end_ip INTEGER, ip_count INTEGER, lat REAL, lon REAL)''')
        import ipaddress
        for i, cidr, city, region in [(1, '192.0.2.0/24', 'Федеральный округ', 'Федеральный округ'),
                                     (2, '192.0.2.128/25', 'Test City', 'Test Region')]:
            network = ipaddress.ip_network(cidr)
            conn.execute('INSERT INTO subnets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (i,cidr,'RU','Россия',city,'',region,'Provider','AS64500','Provider',
                 int(network.network_address),int(network.broadcast_address),network.num_addresses,0,0))
    return GeoCityDatabase(str(path))


@pytest.mark.parametrize('city,region,expected_city,expected_region', [
    ('Федеральный округ','Федеральный округ','',''),
    ('Область','Область','',''),
    ('Московская область','','','Московская область'),
    ('Сибирский федеральный округ','','','Сибирский федеральный округ'),
    ('Москва','Москва','Москва','Москва'),
])
def test_geo_never_calls_administrative_area_a_city(city,region,expected_city,expected_region):
    geo=normalize_geo({'city':city,'region':region,'country_code':'RU'})
    assert (geo['city'],geo['region']) == (expected_city,expected_region)
    assert geo['precision'] == ('city' if expected_city else 'region' if expected_region else 'country')


def test_subnet_fallback_uses_most_specific_range(tmp_path):
    db=geo_db(tmp_path)
    assert db.find_by_ip('192.0.2.150')['city']=='Test City'
    assert db.find_by_ip('192.0.2.1')['city']==''
    assert db.find_by_ip('192.0.2.1')['precision']=='country'
    assert db.find_by_ip('192.0.2.150:554')['city']=='Test City'
    assert db.find_by_ip('192.0.2.150/25')['city']=='Test City'
    assert db.find_by_ip('not an IP') is None
    assert all(c['city']!='Федеральный округ' for c in db.get_cities())
    assert all(c['region']!='Федеральный округ' for c in db.get_regions())
    assert db.get_countries_summary()[0]['cities_count']==1
    assert db.filter_subnets()[0][0]['city']==''


def test_exact_mmdb_country_only_does_not_invent_index_city(tmp_path,monkeypatch):
    db=geo_db(tmp_path)
    def read(name,ip):
        if 'ASN' in name:return ({'autonomous_system_number':64501,'autonomous_system_organization':'Exact ISP'},24,'2026-09-01')
        return ({'country':{'iso_code':'RU','names':{'ru':'Россия'}},'location':{'accuracy_radius':500}},24,'2026-09-01')
    monkeypatch.setattr(db,'_read_mmdb',read)
    result=db.find_by_ip('192.0.2.150')
    assert result['city']=='' and result['region']==''
    assert result['precision']=='country'
    assert result['source']=='geolite2_city'
    assert result['accuracy_radius_km']==500
    assert result['database_date']=='2026-09-01'
    assert result['isp']=='Exact ISP'


def test_mmdb_uses_smallest_subdivision_and_keeps_accuracy(tmp_path,monkeypatch):
    db=geo_db(tmp_path)
    def read(name,ip):
        if 'ASN' in name:return None
        return ({'country':{'iso_code':'RU'},'city':{'names':{'ru':'Город'}},
                 'subdivisions':[{'names':{'ru':'Округ'}},{'names':{'ru':'Область N'}}],
                 'location':{'accuracy_radius':25,'latitude':0.,'longitude':1.}},25,'2026-09-01')
    monkeypatch.setattr(db,'_read_mmdb',read)
    result=db.find_by_ip('192.0.2.150')
    assert result['region']=='Область N'
    assert result['cidr']=='192.0.2.128/25'
    assert camera_geo_fields(result)['geo_accuracy_radius_km']==25


def test_geo_update_does_not_replace_concurrent_streams(tmp_path):
    storage=StorageManager(str(tmp_path/'cameras.db'))
    storage.save_v2_result({'ip':'192.0.2.1','city':'Федеральный округ','streams':[{'url':'rtsp://192.0.2.1/live','verified':False}]})
    storage.update_v2_stream('192.0.2.1', {'url':'rtsp://192.0.2.1/live','verified':True,'screenshot':'frame.jpg'})
    assert storage.update_v2_geo('192.0.2.1',camera_geo_fields({'country_code':'RU'}))
    result=storage.get_v2_result('192.0.2.1')
    assert result['city']==''
    assert result['streams'][0]['screenshot']=='frame.jpg'
    assert not storage.update_v2_geo('192.0.2.1',camera_geo_fields({'country_code':'RU'}))


def test_geo_api_reports_actual_precision_and_no_limit(monkeypatch,tmp_path):
    from ip2domain.web.routers import scanner_v2 as router
    from ip2domain.data.geo_city_db import geo_city_db
    storage=StorageManager(str(tmp_path/'api.db'))
    storage.save_v2_result({'ip':'192.0.2.1','city':'Федеральный округ','region':'Федеральный округ'})
    monkeypatch.setattr(router,'storage',storage)
    monkeypatch.setattr(geo_city_db,'find_by_ip',lambda _: {'country_code':'RU','source':'geolite2_city'})
    result=json.loads(asyncio.run(router.resolve_all_cameras_geo()).body)
    assert result['precision_counts']=={'city':0,'region':0,'country':1,'unknown':0}
    assert result['updated_count']==1
    assert result['results'][0]['city']==''
    result=json.loads(asyncio.run(router.resolve_all_cameras_geo()).body)
    assert result['updated_count']==0


def test_geo_api_checks_local_cidr_before_network(monkeypatch):
    from ip2domain.web.routers import city_ip as router
    seen=[]
    def lookup(ip):
        seen.append(ip)
        return {'city':'Test City','source':'geolite2_city','precision':'city'}
    monkeypatch.setattr(router.geo_city_db,'find_by_ip',lookup)
    result=json.loads(asyncio.run(router.lookup_geo('192.0.2.100/24')).body)
    assert seen==['192.0.2.100']
    assert result['source']=='geolite2_city'


def test_bulk_lifecycle_multiple_streams_and_concurrent_geo(monkeypatch,tmp_path):
    from ip2domain.cameras.scanner_v2 import bulk_capture,stage3_stream
    storage=StorageManager(str(tmp_path/'bulk.db'))
    storage.save_v2_result({'ip':'192.0.2.1','streams':[{'url':f'rtsp://192.0.2.1:{554+i}/live','type':'rtsp'} for i in range(4)]})
    monkeypatch.setattr(bulk_capture,'storage',storage)
    monkeypatch.setattr(bulk_capture,'_V2_CAPTURE_DIR',tmp_path)
    entered=asyncio.Event(); release=asyncio.Event()
    async def frame(*args,**kwargs):
        entered.set()
        await release.wait()
        storage.update_v2_geo('192.0.2.1', {'city':'Concurrent City'})
        return True,str(tmp_path/'frame.jpg'),'H264',640,480
    mock=AsyncMock(side_effect=frame)
    monkeypatch.setattr(stage3_stream,'capture_stream_frame',mock)
    async def run():
        manager=bulk_capture.BulkCaptureManager()
        assert (await manager.start())['success']
        await entered.wait()
        assert not (await manager.start())['success']
        release.set()
        await manager._task
        status=manager.get_status()
        assert status['status']=='completed'
        assert status['processed_streams']==status['total_streams']==status['verified_streams']==4
        assert not status['is_running']
    asyncio.run(run())
    assert storage.get_v2_result('192.0.2.1')['city']=='Concurrent City'
    assert mock.await_count==4


def test_bulk_stop_does_not_report_success(monkeypatch,tmp_path):
    from ip2domain.cameras.scanner_v2 import bulk_capture,stage3_stream
    storage=StorageManager(str(tmp_path/'stop.db'))
    storage.save_v2_result({'ip':'192.0.2.1','streams':[{'url':f'rtsp://192.0.2.1/{i}'} for i in range(3)]})
    monkeypatch.setattr(bulk_capture,'storage',storage)
    entered=asyncio.Event(); release=asyncio.Event()
    async def frame(*args,**kwargs):
        entered.set(); await release.wait()
        return False,'','',0,0
    mock=AsyncMock(side_effect=frame)
    monkeypatch.setattr(stage3_stream,'capture_stream_frame',mock)
    async def run():
        manager=bulk_capture.BulkCaptureManager()
        await manager.start()
        await entered.wait()
        await manager.stop()
        release.set()
        await manager._task
        status=manager.get_status()
        assert status['status']=='cancelled'
        assert status['processed_streams']==1
        assert status['total_streams']==3
    asyncio.run(run())
    assert mock.await_count==1


def test_bulk_failure_and_empty_target_list(monkeypatch,tmp_path):
    from ip2domain.cameras.scanner_v2 import bulk_capture
    def fail(**kwargs):raise RuntimeError('test storage unavailable')
    monkeypatch.setattr(bulk_capture.storage,'get_v2_results',fail)
    manager=bulk_capture.BulkCaptureManager()
    asyncio.run(manager._run(2,True,0,None))
    assert manager.get_status()['status']=='error'
    assert manager.get_status()['error']=='test storage unavailable'
    monkeypatch.setattr(bulk_capture.storage,'get_v2_results',lambda **kwargs:[{'ip':'192.0.2.1','streams':[{'url':'rtsp://192.0.2.1/live'}]}])
    other=bulk_capture.BulkCaptureManager()
    asyncio.run(other._run(2,True,0,[]))
    assert other.get_status()['status']=='completed'
    assert other.get_status()['total_streams']==0


def test_bulk_rejects_negative_limits():
    from ip2domain.web.routers.scanner_v2 import BulkCaptureRequest
    from pydantic import ValidationError
    with pytest.raises(ValidationError):BulkCaptureRequest(max_streams_per_cam=-1)


def test_bulk_button_handles_errors_stop_and_refresh():
    script=r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
async function scenario(status,startOk=true) {
 const elements={}; const messages=[]; let reloads=0,intervals=0;
 const element=id=>elements[id]||(elements[id]={style:{},textContent:'',disabled:false});
 const ctx={window:{V2State:{results:[]},v2LoadStoredResults:async()=>{reloads++;}},
 document:{readyState:'loading',addEventListener:()=>{},getElementById:element},console,
 setInterval:()=>{intervals++;return 1;},clearInterval:()=>{},setTimeout:()=>{},confirm:()=>true,
 fetch:async url=>url.endsWith('/start')?{ok:startOk,status:startOk?200:500,json:async()=>({success:true})}:
 {ok:true,json:async()=>status}};
 vm.createContext(ctx);vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),ctx);
 ctx._showV2Toast=msg=>messages.push(msg);
 await ctx.v2StartBulkCapture(element('v2-btn-bulk-capture'));
 await new Promise(setImmediate);
 return {messages,reloads,intervals,elements};
}
(async()=>{
 let result=await scenario({status:'completed',is_running:false,total_streams:3,processed_streams:3,verified_streams:2});
 assert(result.reloads>0);assert(result.messages.some(m=>m.includes('Проверка завершена')));
 result=await scenario({status:'cancelled',is_running:false,stop_requested:true,total_streams:3,processed_streams:1});
 assert(result.messages.some(m=>m.includes('остановлена')));assert(!result.messages.some(m=>m.includes('Проверка завершена')));
 result=await scenario({status:'error',is_running:false,error:'test error',total_streams:3,processed_streams:1});
 assert(result.messages.some(m=>m.includes('Ошибка проверки')));
 result=await scenario({},false);assert.equal(result.intervals,0);assert.equal(result.elements['v2-btn-bulk-capture'].disabled,false);
 result=await scenario({status:'running',is_running:true,total_streams:3,processed_streams:1,failed_streams:1});
 assert(result.reloads>0);
})().catch(e=>{console.error(e);process.exit(1);});
'''
    subprocess.run(['node','-e',script,str(Path('ip2domain/web/static/cameras/scanner_v2/export.js').resolve())],check=True,capture_output=True,text=True)


def test_corrupt_mmdb_falls_back_to_normalized_sqlite(tmp_path):
    db=geo_db(tmp_path)
    (tmp_path/'GeoLite2-City.mmdb').write_bytes(b'not a maxmind database')
    assert db.find_by_ip('192.0.2.1')['city']==''
    assert db.find_by_ip('192.0.2.150')['city']=='Test City'


def test_geo_stage_also_resolves_cameras_without_frames(monkeypatch):
    from ip2domain.cameras.scanner_v2 import engine
    from ip2domain.cameras.scanner_v2.models import ScanJob,CameraResult
    job=ScanJob(job_id='geo-no-preview',results=[CameraResult(ip='192.0.2.1')])
    monkeypatch.setattr(engine.geo_city_db,'find_by_ip',lambda _: {'country_code':'RU','source':'geolite2_city','accuracy_radius_km':300})
    asyncio.run(engine._resolve_job_geo(job,None))
    assert job.stage4_status=='done'
    assert job.stage4_completed==1
    assert job.results[0].geo_precision=='country'
    assert job.results[0].city==''


def test_geo_resolve_includes_more_than_ten_thousand_results(monkeypatch):
    from ip2domain.web.routers import scanner_v2 as router
    from ip2domain.data.geo_city_db import geo_city_db
    class Storage:
        def get_v2_results(self,limit=10000):
            results=[{'ip':f'192.0.2.{i}'} for i in range(10002)]
            return results[:limit] if limit else results
        def update_v2_geo(self,ip,fields):return True
    monkeypatch.setattr(router,'storage',Storage())
    monkeypatch.setattr(geo_city_db,'find_by_ip',lambda _: {'country_code':'RU'})
    result=json.loads(asyncio.run(router.resolve_all_cameras_geo()).body)
    assert result['total_cameras']==10002
    assert result['updated_count']==10002
