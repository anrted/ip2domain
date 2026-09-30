"""Offline regressions for per-port identity and per-stream frame verification."""
import asyncio
import json
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from PIL import Image

from ip2domain.cameras.scanner_v2 import engine, stage3_stream as capture
from ip2domain.cameras.scanner_v2.aggregation import merge_host_cameras, universal_observation_to_camera_result
from ip2domain.cameras.scanner_v2.models import CameraResult, StreamInfo
from ip2domain.core.storage import StorageManager
from ip2domain.scanning.protocols.binary import rtmp_request, rtmp_response


def test_all_streams_are_captured_even_after_success(monkeypatch, tmp_path):
    streams = [StreamInfo(f'rtsp://192.0.2.1:{554 + i % 3}/channel/{i}', verified=(i == 0)) for i in range(40)]
    streams.append(StreamInfo('http://192.0.2.1/video', stream_type='mjpeg'))
    streams.append(StreamInfo('http://192.0.2.1/snap', stream_type='http_snapshot'))
    cam = CameraResult(ip='192.0.2.1', streams=streams)
    async def frame(url, stype, directory, credentials):
        i = next(i for i, s in enumerate(streams) if s.url == url)
        return (i != 2, str(directory / f'{i}.jpg') if i != 2 else '', 'H264', 640, 480)
    mock = AsyncMock(side_effect=frame)
    monkeypatch.setattr(capture, 'capture_stream_frame', mock)
    monkeypatch.setattr(capture, '_download_http_snapshot', AsyncMock(return_value=str(tmp_path / 'snapshot.jpg')))
    assert asyncio.run(capture.verify_camera_streams(cam, tmp_path)) == 41
    assert mock.await_count == 41
    assert all(s.verification_status != 'pending' for s in cam.streams)
    assert len({s.screenshot_path for s in cam.streams if s.verified}) == 41
    assert next(s for s in cam.streams if s.url.endswith('/channel/2')).verification_status == 'failed'


def test_capture_cooperative_stop_preserves_unchecked_status(monkeypatch, tmp_path):
    cam = CameraResult(ip='192.0.2.1', streams=[StreamInfo(f'rtsp://192.0.2.1/{i}') for i in range(3)])
    stopped = False
    def done(stream):
        nonlocal stopped
        stopped = True
    mock = AsyncMock(return_value=(True, 'one.jpg', '', 0, 0))
    monkeypatch.setattr(capture, 'capture_stream_frame', mock)
    asyncio.run(capture.verify_camera_streams(cam, tmp_path, is_cancelled=lambda: stopped, on_stream=done))
    assert mock.await_count == 1
    assert sum(s.verification_status == 'pending' for s in cam.streams) == 2


def test_multiple_ports_keep_credentials_and_device_identity(monkeypatch, tmp_path):
    cams = [CameraResult(ip='192.0.2.1', brand=f'Brand{i}', serial=f'S{i}', rtsp_port=port,
                         open_ports=[port], protocols=['rtsp_direct'], credentials={'user': f'user{i}'},
                         streams=[StreamInfo(f'rtsp://192.0.2.1:{port}/live')])
            for i, port in enumerate([554, 8554, 10554])]
    merged = merge_host_cameras(cams)
    assert merged.open_ports == [554, 8554, 10554]
    assert {e['serial'] for e in merged.endpoints} == {'S0', 'S1', 'S2'}
    assert merged.credentials == {}
    mock = AsyncMock(return_value=(True, 'image.jpg', '', 0, 0))
    monkeypatch.setattr(capture, 'capture_stream_frame', mock)
    asyncio.run(capture.verify_camera_streams(merged, tmp_path))
    assert [c.args[3]['user'] for c in mock.await_args_list] == ['user0', 'user1', 'user2']


def test_partial_storage_updates_preserve_other_ports(tmp_path):
    storage = StorageManager(str(tmp_path / 'streams.db'))
    storage.save_v2_result({'ip': '192.0.2.1', 'open_ports': [554], 'streams': [
        {'url': 'rtsp://192.0.2.1:554/live', 'verified': True, 'screenshot': 'a.jpg'}]})
    storage.save_v2_result({'ip': '192.0.2.1', 'open_ports': [8554], 'streams': [
        {'url': 'rtsp://192.0.2.1:8554/live', 'verified': True, 'screenshot': 'b.jpg'}]})
    storage.save_v2_result({'ip': '192.0.2.1', 'streams': [
        {'url': 'rtsp://192.0.2.1:554/live', 'verified': False, 'screenshot': '', 'verification_status': 'failed'}]})
    result = storage.get_v2_result('192.0.2.1')
    assert result['open_ports'] == [554, 8554]
    assert len(result['streams']) == 2
    assert result['streams'][0]['verified'] is False
    assert result['streams'][1]['screenshot'] == 'b.jpg'
    assert storage.get_v2_results()[0]['auth_required'] is None


@pytest.mark.parametrize('status', [None, 403, 407])
def test_unrelated_status_is_not_reported_as_401(status):
    cam = universal_observation_to_camera_result({'ip': '192.0.2.1', 'port': 80,
        'services': [{'protocol': 'hls', 'attributes': {'status_code': status, 'auth_required': status in (403, 407)}}]})
    assert cam.auth_required is None
    assert cam.streams[0].auth_required is None


def test_auth_challenge_is_scoped_to_service():
    cam = universal_observation_to_camera_result({'ip': '192.0.2.1', 'port': 80,
        'services': [{'protocol': 'rtsp', 'attributes': {'status_code': 401}},
                     {'protocol': 'hls', 'attributes': {'path': '/open.m3u8', 'status_code': 200}}]})
    assert cam.auth_required is True
    assert next(s for s in cam.streams if s.stream_type == 'hls').auth_required is None


def test_rtmp_requires_complete_correlated_server_handshake():
    request = rtmp_request()
    assert rtmp_response(request) is None
    assert rtmp_response(request + request) is None
    response = b'\x03' + b'\x01' * 1536 + request[1:]
    assert rtmp_response(response)['protocol'] == 'rtmp'
    assert rtmp_response(response[:-1]) is None
    assert rtmp_response(response[:-1] + bytes([response[-1] ^ 1])) is None


@pytest.mark.parametrize('returncode,write_frame,expected', [(1, False, False), (1, True, False), (0, True, True)])
def test_ffmpeg_never_reuses_stale_frames(monkeypatch, tmp_path, returncode, write_frame, expected):
    url = 'rtmp://192.0.2.1:1935/live'
    old = capture._capture_path(tmp_path, url)
    Image.new('RGB', (40, 40), 'red').save(old)
    class Process:
        def __init__(self, output):
            self.returncode = None
            self.output = Path(output)
        async def communicate(self):
            if write_frame:
                Image.new('RGB', (40, 40), 'blue').save(self.output)
            self.returncode = returncode
            return b'', b''
    async def spawn(*args, **kwargs):
        assert args[-1] != str(old)
        return Process(args[-1])
    monkeypatch.setattr(capture.shutil, 'which', lambda _: '/usr/bin/ffmpeg')
    monkeypatch.setattr(capture.asyncio, 'create_subprocess_exec', spawn)
    result = asyncio.run(capture.capture_stream_frame(url, 'rtmp', tmp_path))
    assert result[0] is expected
    assert not list(tmp_path.glob('.capture_*'))
    with Image.open(old) as img:
        pixel = img.getpixel((0, 0))
    assert (pixel[2] > pixel[0]) is expected


def test_cancelled_ffmpeg_is_killed_and_reaped(monkeypatch, tmp_path):
    async def scenario():
        started = asyncio.Event()
        class Process:
            returncode = None
            killed = False
            reaped = False
            async def communicate(self):
                if self.killed:
                    self.reaped = True
                    return b'', b''
                started.set()
                await asyncio.Future()
            def kill(self):
                self.killed = True
                self.returncode = -9
        proc = Process()
        monkeypatch.setattr(capture.shutil, 'which', lambda _: '/usr/bin/ffmpeg')
        monkeypatch.setattr(capture.asyncio, 'create_subprocess_exec', AsyncMock(return_value=proc))
        task = asyncio.create_task(capture.capture_stream_frame('rtsp://192.0.2.1/live', 'rtsp', tmp_path))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert proc.killed and proc.reaped
        assert not list(tmp_path.glob('.capture_*'))
    asyncio.run(scenario())


def test_staged_pipeline_pages_and_captures_all_ports(monkeypatch, tmp_path):
    import ip2domain.scanning.persistence as persistence
    import ip2domain.scanning.staged_pipeline as staged
    storage = StorageManager(str(tmp_path / 'staged.db'))
    ignored = {'ip': '192.0.2.1', 'port': 22, 'services': []}
    last_page = [{'ip': '192.0.2.1', 'port': port, 'services': [
        {'protocol': 'http_snapshot', 'attributes': {'path': '/snapshot'}}]} for port in [80, 8080]]
    offsets = []
    class Repository:
        def __init__(self, path): pass
        def create(self, config, plan): return 'scan'
        def get(self, identifier): return {'status': 'completed'}
        def endpoints(self, identifier, limit, offset):
            offsets.append(offset)
            return [ignored] * 1000 if offset < 5000 else last_page if offset == 5000 else []
    monkeypatch.setattr(persistence, 'InventoryRepository', Repository)
    monkeypatch.setattr(staged, 'run_staged_scan', AsyncMock())
    mock = AsyncMock(side_effect=lambda url, directory, credentials: str(directory / (str(len(url)) + '.jpg')))
    monkeypatch.setattr(capture, '_download_http_snapshot', mock)
    job = engine.create_job('multistream-staged')
    try:
        asyncio.run(engine.run_v2_scan_pipeline(job.job_id, '192.0.2.1', engine='staged',
            local_discovery=False, capture_dir=tmp_path, storage=storage))
        assert job.status == 'completed', job.error
        assert job.stage3_status == 'done'
        assert offsets == [0, 1000, 2000, 3000, 4000, 5000, 5002]
        assert len(job.results) == 1
        assert len(job.results[0].streams) == mock.await_count == 2
        assert all(s['verified'] for s in storage.get_v2_result('192.0.2.1')['streams'])
    finally:
        engine._ACTIVE_JOBS.pop(job.job_id, None)


def test_staged_errors_do_not_become_completed(monkeypatch, tmp_path):
    import ip2domain.scanning.persistence as persistence
    monkeypatch.setattr(persistence, 'InventoryRepository', lambda _: (_ for _ in ()).throw(RuntimeError('test error')))
    job = engine.create_job('multistream-error')
    try:
        asyncio.run(engine.run_v2_scan_pipeline(job.job_id, '192.0.2.1', engine='staged',
            local_discovery=False, capture_dir=tmp_path))
        assert job.status == 'error'
    finally:
        engine._ACTIVE_JOBS.pop(job.job_id, None)


def test_bulk_does_not_skip_host_with_one_preview(monkeypatch, tmp_path):
    from ip2domain.cameras.scanner_v2 import bulk_capture
    storage = StorageManager(str(tmp_path / 'bulk.db'))
    image = tmp_path / 'existing.jpg'
    Image.new('RGB', (160, 120)).save(image)
    streams = [StreamInfo(f'rtsp://192.0.2.1:554/{i}') for i in range(30)]
    streams[0].verified = True
    streams[0].screenshot_path = str(image)
    storage.save_v2_result(CameraResult(ip='192.0.2.1', streams=streams).to_dict())
    monkeypatch.setattr(bulk_capture, 'storage', storage)
    monkeypatch.setattr(bulk_capture, '_V2_CAPTURE_DIR', tmp_path)
    mock = AsyncMock(return_value=(True, str(image), 'H264', 640, 480))
    monkeypatch.setattr(capture, 'capture_stream_frame', mock)
    manager = bulk_capture.BulkCaptureManager()
    asyncio.run(manager._run(concurrency=2, only_unverified=True, max_streams_per_cam=0, target_ips=None))
    assert mock.await_count == 29
    assert manager.get_status()['total_streams'] == manager.get_status()['processed_streams'] == 29
    assert all(s['verified'] for s in storage.get_v2_result('192.0.2.1')['streams'])


def test_onvif_enumerates_all_profiles_on_media_service(monkeypatch):
    from ip2domain.cameras.scanner_v2.protocols import onvif
    calls = []
    async def soap(client, url, body, user, password):
        calls.append((url, body))
        if 'GetDeviceInformation' in body:
            return '<Envelope><Manufacturer>Test</Manufacturer><Model>NVR</Model></Envelope>'
        if 'GetCapabilities' in body:
            return '<Envelope><Media><XAddr>http://192.0.2.1:8080/media</XAddr></Media></Envelope>'
        if 'GetProfiles' in body:
            assert body == '<trt:GetProfiles/>'
            assert url.endswith(':8080/media')
            return '<Envelope>' + ''.join(f'<Profiles token="p{i}"><VideoEncoderConfiguration token="not-a-profile"/></Profiles>' for i in range(30)) + '</Envelope>'
        assert '<trt:GetStreamUri>' in body
        token = body.split('<trt:ProfileToken>')[1].split('<')[0]
        return f'<Envelope><Uri>rtsp://192.0.2.1:8554/{token}?a=1&amp;b=2</Uri></Envelope>'
    monkeypatch.setattr(onvif, '_soap_post', soap)
    result = asyncio.run(onvif.probe_onvif('192.0.2.1', [80], [('operator', 'provided')]))
    assert len(result['rtsp_urls']) == 30
    assert all('&b=2' in u for u in result['rtsp_urls'])
    assert len(calls) == 33
    assert 'secext-1.0.xsd' in onvif._soap('', 'operator', 'provided')


def test_results_ui_keeps_selected_stream_frame(tmp_path):
    source = Path('ip2domain/web/static/cameras/scanner_v2/results.js').resolve()
    script = r'''
const fs = require('fs'), vm = require('vm'), assert = require('assert');
const ctx = {window: {V2State: {results: [], selectedStreams: {}, previewCache: {}}},
 document: {getElementById: () => null}, _esc: x => String(x || ''),
 _formatShortStreamUrl: x => x, console};
vm.createContext(ctx); vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), ctx);
assert.equal(ctx._isCam401({streams: []}), false);
const cam = {ip: '192.0.2.1', streams: [
 {url:'rtsp://192.0.2.1:554/a', verified:true, screenshot:'/a.jpg'},
 {url:'rtsp://192.0.2.1:8554/b', verified:false, screenshot:''}]};
ctx.window.V2State.selectedStreams[cam.ip] = cam.streams[1].url;
let html = ctx.v2RenderCameraCard(cam);
assert(!html.includes('path=%2Fa.jpg'));
assert.equal(ctx.window.V2State.selectedStreams[cam.ip], cam.streams[1].url);
assert(html.includes('1 подтверждено · 2 URL'));
assert(!ctx.v2RenderCameraCard({ip:'192.0.2.2',streams:[]}).includes('🔓 Доступна'));
ctx.window.V2State.previewCache[cam.ip] = 'blob:wrong-ip-only-frame';
ctx.window.V2State.results = [cam];
ctx.v2UpdateResultsCount = () => {}; ctx.v2RenderResults = () => {};
ctx.v2MergeResults([{...cam, streams:[{url:cam.streams[1].url, verified:false}]}]);
assert(!ctx.window.V2State.results[0].streams[0].screenshot);
'''
    subprocess.run(['node', '-e', script, str(source)], check=True, capture_output=True, text=True)


def test_legacy_probe_visits_each_port(monkeypatch):
    from ip2domain.cameras.scanner_v2 import stage2_proto
    from ip2domain.scanning import HostObservation, ProbeData, ProbeOutcome
    visited = []
    async def observe(ip, ports, credentials, protocols=None):
        visited.extend(ports)
        port = ports[0]
        data = ProbeData(detected=True, attributes={'success': True, 'open_port': port,
            'rtsp_urls': [f'rtsp://{ip}:{port}/live'], 'credentials': {'user': f'user{port}'}})
        return HostObservation(ip, (), (ProbeOutcome('rtsp', 'completed', data),))
    monkeypatch.setattr(stage2_proto, 'probe_host_observation_v2', observe)
    camera = asyncio.run(stage2_proto.probe_host_v2('192.0.2.1', [554, 8554, 10554], []))
    assert visited == [554, 8554, 10554]
    assert len(camera.streams) == 3
    assert [s.credentials['user'] for s in camera.streams] == ['user554', 'user8554', 'user10554']


def test_advertised_inventory_channels_are_not_discarded():
    obs = {'ip': '192.0.2.1', 'port': 80,
           'streams': [{'uri': f'rtsp://192.0.2.1:8554/ch{i}', 'protocol': 'rtsp'} for i in range(35)],
           'fingerprints': [{'vendor': 'Test', 'model': 'NVR', 'serial': 'different-device'}]}
    camera = universal_observation_to_camera_result(obs)
    assert camera.brand == 'Test'
    assert len(camera.streams) == 35
    assert len({s.url for s in camera.streams}) == 35


def test_rtmp_legacy_reads_fragmented_handshake(monkeypatch):
    from ip2domain.cameras.scanner_v2.protocols import rtmp
    async def scenario():
        reader = asyncio.StreamReader()
        packet = b'\x03' + b'\x01' * 1536 + rtmp_request()[1:]
        class Writer:
            def write(self, data):
                assert data == rtmp_request()
                reader.feed_data(packet[:100])
                asyncio.get_running_loop().call_soon(reader.feed_data, packet[100:])
            async def drain(self): pass
            def close(self): pass
            async def wait_closed(self): pass
        monkeypatch.setattr(rtmp.asyncio, 'open_connection', AsyncMock(return_value=(reader, Writer())))
        result = await rtmp.probe_rtmp('192.0.2.1', [1935])
        assert result['success']
    asyncio.run(scenario())


def test_capture_worker_error_is_not_silently_completed(monkeypatch, tmp_path):
    job = engine.create_job('capture-stage-error')
    job.results = [CameraResult(ip='192.0.2.1', streams=[StreamInfo('rtsp://192.0.2.1/live')])]
    monkeypatch.setattr(engine, 'verify_camera_streams', AsyncMock(side_effect=RuntimeError('test failure')))
    try:
        with pytest.raises(RuntimeError):
            asyncio.run(engine._capture_job_streams(job, tmp_path, None))
        assert job.stage3_status == 'error'
    finally:
        engine._ACTIVE_JOBS.pop(job.job_id, None)


def test_preview_failure_updates_only_selected_stream(monkeypatch, tmp_path):
    from ip2domain.web.routers import scanner_v2 as router
    from fastapi import HTTPException
    storage = StorageManager(str(tmp_path / 'preview.db'))
    streams = [{'url': f'rtsp://192.0.2.1:{port}/live', 'verified': True, 'screenshot': f'{port}.jpg'} for port in (554, 8554)]
    storage.save_v2_result({'ip': '192.0.2.1', 'streams': streams})
    monkeypatch.setattr(router, 'storage', storage)
    monkeypatch.setattr(capture, 'capture_stream_frame', AsyncMock(return_value=(False, '', '', 0, 0)))
    with pytest.raises(HTTPException) as exc:
        asyncio.run(router.get_stream_preview(ip='192.0.2.1', stream_url=streams[0]['url'], user='', password=''))
    assert exc.value.status_code == 404
    result = storage.get_v2_result('192.0.2.1')['streams']
    assert result[0]['verified'] is False
    assert result[0]['verification_status'] == 'failed'
    assert result[1]['verified'] is True
    assert result[1]['screenshot'] == '8554.jpg'


def test_storage_updates_endpoint_metadata_without_duplicates(tmp_path):
    storage = StorageManager(str(tmp_path / 'endpoints.db'))
    for model in ['old', 'new']:
        storage.save_v2_result({'ip': '192.0.2.1', 'endpoints': [
            {'port': 8554, 'protocols': ['rtsp'], 'model': model}]})
    endpoints = storage.get_v2_result('192.0.2.1')['endpoints']
    assert len(endpoints) == 1
    assert endpoints[0]['model'] == 'new'
