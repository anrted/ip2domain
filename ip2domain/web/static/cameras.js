'use strict';

let centraMap = null;
let centraCameras = [];

function centraCameraNumber(camera) {
    return String(camera?.id || '').replace(/^I-/i, '');
}

function centraEntrance(camera) {
    const value = Number(camera?.entrance || String(camera?.id || '').match(/-(\d+)$/)?.[1]);
    return Number.isInteger(value) && value > 0 ? `Подъезд ${value}` : centraCameraNumber(camera);
}

function centraCameraOrder(camera) {
    const match = String(camera?.id || '').match(/^I-(\d+)-(\d+)$/i);
    return match ? [Number(match[1]), Number(match[2])] : [Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER];
}

function switchCameraTab(tab) {
    ['scanner', 'centra'].forEach((name) => {
        const active = name === tab;
        document.getElementById(`camera-${name}-tab`).classList.toggle('active', active);
        document.getElementById(`camera-${name}-tab`).setAttribute('aria-selected', String(active));
        document.getElementById(`camera-${name}-panel`).classList.toggle('active', active);
    });
    if (tab === 'centra') {
        if (!centraCameras.length) loadCentraCameras();
        setTimeout(resizeCentraMap, 80);
    }
}
window.switchCameraTab = switchCameraTab;

function loadYandexMaps(apiKey) {
    if (window.ymaps) return Promise.resolve(window.ymaps);
    if (window._centraYmapsPromise) return window._centraYmapsPromise;
    window._centraYmapsPromise = new Promise((resolve, reject) => {
        const script = document.createElement('script');
        const key = apiKey ? `&apikey=${encodeURIComponent(apiKey)}` : '';
        script.src = `https://api-maps.yandex.ru/2.1/?lang=ru_RU${key}`;
        script.onload = () => window.ymaps.ready(() => resolve(window.ymaps));
        script.onerror = () => reject(new Error('Не удалось загрузить API Яндекс.Карт'));
        document.head.appendChild(script);
    });
    return window._centraYmapsPromise;
}

async function loadCentraCameras() {
    const mapNode = document.getElementById('centra-map');
    try {
        const response = await fetch('/api/cameras/centra');
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось загрузить камеры Centra');
        centraCameras = (data.cameras || []).sort((left, right) => {
            const a = centraCameraOrder(left), b = centraCameraOrder(right);
            return a[0] - b[0] || a[1] - b[1];
        });
        document.getElementById('centra-count').textContent = `${centraCameras.length} камер`;
        renderCentraList();
        if (!centraCameras.length) {
            mapNode.innerHTML = '<div class="empty-state">Камеры не настроены</div>';
            return;
        }
        const ymaps = await loadYandexMaps(data.yandex_maps_api_key || '');
        await Promise.all(centraCameras.map(async (camera) => {
            if (Array.isArray(camera.coordinates) && camera.coordinates.length === 2) return;
            if (!camera.address && !camera.title) return;
            try {
                const result = await ymaps.geocode(camera.address || camera.title, {results: 1});
                camera.coordinates = result.geoObjects.get(0)?.geometry.getCoordinates();
            } catch (_) {}
        }));
        const mappedCameras = centraCameras.filter((camera) => Array.isArray(camera.coordinates));
        if (!mappedCameras.length) {
            mapNode.innerHTML = '<div class="empty-state">Камеры найдены, но их адреса не удалось разместить на карте</div>';
            return;
        }
        mapNode.innerHTML = '';
        centraMap = new ymaps.Map('centra-map', {center: mappedCameras[0].coordinates, zoom: 14, controls: ['zoomControl', 'fullscreenControl']});
        const clusterer = new ymaps.Clusterer({clusterDisableClickZoom: false, clusterOpenBalloonOnClick: true, groupByCoordinates: false});
        centraCameras.forEach((camera, index) => {
            if (!Array.isArray(camera.coordinates)) return;
            const placemark = new ymaps.Placemark(camera.coordinates, {
                iconContent: centraEntrance(camera),
                hintContent: `${centraEntrance(camera)} · ${camera.title}`,
                balloonContentHeader: `${_esc(centraEntrance(camera))} · ${_esc(camera.title)}`,
                balloonContentBody: `${_esc(camera.address || '')}<br><button class="btn btn-small" type="button" onclick="openCentraCamera(${index})">Открыть трансляцию</button>`
            }, {preset: 'islands#violetStretchyIcon'});
            placemark.events.add('click', () => selectCentraCamera(index, false));
            clusterer.add(placemark);
        });
        centraMap.geoObjects.add(clusterer);
        if (mappedCameras.length > 1) centraMap.setBounds(clusterer.getBounds(), {checkZoomRange: true, zoomMargin: 45});
    } catch (error) {
        mapNode.innerHTML = `<div class="empty-state" style="color:#f87171">${_esc(error.message)}</div>`;
    }
}
window.loadCentraCameras = loadCentraCameras;

async function startCentraDiscovery(event) {
    event.preventDefault();
    const button = document.getElementById('centra-discovery-button');
    const progress = document.getElementById('centra-discovery-progress');
    const body = {
        start_id: Number(document.getElementById('centra-start-id').value),
        end_id: Number(document.getElementById('centra-end-id').value),
        entrances: Number(document.getElementById('centra-entrances').value),
        concurrency: Number(document.getElementById('centra-concurrency').value)
    };
    try {
        button.disabled = true;
        progress.style.display = 'block';
        progress.textContent = 'Запуск поиска...';
        const response = await fetch('/api/cameras/centra/discover', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось запустить поиск');
        localStorage.setItem('ip2domain_centra_job', data.job_id);
        pollCentraDiscovery(data.job_id);
    } catch (error) {
        button.disabled = false;
        progress.innerHTML = `<span style="color:#f87171">${_esc(error.message)}</span>`;
    }
}
window.startCentraDiscovery = startCentraDiscovery;

function pollCentraDiscovery(jobId) {
    if (window._centraPoller) clearInterval(window._centraPoller);
    const timer = setInterval(async () => {
        const button = document.getElementById('centra-discovery-button');
        const progress = document.getElementById('centra-discovery-progress');
        try {
            const response = await fetch(`/api/cameras/centra/discover/${jobId}`);
            const job = await response.json();
            if (!response.ok) throw new Error(job.detail || 'Задание не найдено');
            const pct = job.progress_pct || 0;
            progress.innerHTML = `<div class="progress-header"><span>${_esc(job.stage || 'Проверка...')}</span><span>${pct}%</span></div><div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div>`;
            if (job.status === 'completed') {
                clearInterval(timer); button.disabled = false;
                centraCameras = []; await loadCentraCameras();
            } else if (job.status === 'error' || job.status === 'interrupted') {
                throw new Error(job.error || 'Поиск прерван');
            }
        } catch (error) {
            clearInterval(timer); button.disabled = false;
            progress.innerHTML = `<span style="color:#f87171">${_esc(error.message)}</span>`;
        }
    }, 2000);
    window._centraPoller = timer;
}

function renderCentraList() {
    document.getElementById('centra-camera-list').innerHTML = centraCameras.map((camera, index) =>
        `<button type="button" class="centra-camera-item" data-centra-index="${index}" onclick="selectCentraCamera(${index}, true)"><span class="centra-camera-number">${_esc(centraEntrance(camera))}</span><strong>${_esc(camera.title || camera.id)}</strong><small>Камера ${_esc(centraCameraNumber(camera))} · ${_esc(camera.address || camera.id)}</small></button>`
    ).join('');
}

function selectCentraCamera(index, openPlayer) {
    const camera = centraCameras[index];
    if (!camera) return;
    document.querySelectorAll('.centra-camera-item').forEach((item) => item.classList.toggle('active', Number(item.dataset.centraIndex) === index));
    if (centraMap && Array.isArray(camera.coordinates)) { centraMap.setCenter(camera.coordinates, Math.max(centraMap.getZoom(), 16), {duration: 250}); }
    if (openPlayer) openCentraCamera(index);
}
window.selectCentraCamera = selectCentraCamera;

function openCentraCamera(index) {
    const camera = centraCameras[index];
    if (!camera?.embed_url) return;
    let dialog = document.getElementById('centra-player-dialog');
    if (!dialog) {
        dialog = document.createElement('dialog');
        dialog.id = 'centra-player-dialog';
        dialog.className = 'centra-player-dialog';
        dialog.addEventListener('close', () => { dialog.querySelector('iframe').src = 'about:blank'; });
        document.body.appendChild(dialog);
    }
    dialog.innerHTML = `<div class="centra-player-head"><strong>${_esc(centraEntrance(camera))} · ${_esc(camera.title || camera.id)} <small>(${_esc(centraCameraNumber(camera))})</small></strong><button class="centra-player-close" type="button" onclick="document.getElementById('centra-player-dialog').close()" aria-label="Закрыть">×</button></div><iframe class="centra-player" src="${_esc(camera.embed_url)}" title="${_esc(camera.title || 'Камера Centra')}" allow="autoplay; fullscreen" allowfullscreen referrerpolicy="no-referrer"></iframe>`;
    dialog.showModal();
}
window.openCentraCamera = openCentraCamera;

function resizeCentraMap() { if (centraMap?.container) centraMap.container.fitToViewport(); }
window.resizeCentraMap = resizeCentraMap;

async function clearCameraResults() {
    const response = await fetch('/api/cameras/results', {method: 'DELETE'});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || 'Не удалось очистить результаты');
    document.getElementById('camera-results').innerHTML = '<div class="empty-state">Результаты очищены</div>';
}

function refreshCameraTargets() {
    const list = document.getElementById('camera-graph-targets');
    if (!list) return;
    const ips = new Set();
    ((typeof currentGraphData !== 'undefined' && currentGraphData?.nodes) || []).forEach((node) => {
        if (node.group === 'ip') ips.add(String(node.label || node.id || '').replace(/^ip:/, ''));
    });
    list.innerHTML = [...ips].sort().slice(0, 20).map((ip) =>
        `<button type="button" class="text-button" onclick="addCameraTarget('${_esc(ip)}')">${_esc(ip)}</button>`).join('');
}
window.refreshCameraTargets = refreshCameraTargets;

function addCameraTarget(ip) {
    const input = document.getElementById('camera-target');
    const existing = input.value.split(/\s+/).filter(Boolean);
    if (!existing.includes(ip)) input.value = [...existing, ip].join('\n');
}

async function startCameraScan(event) {
    event.preventDefault();
    const button = document.getElementById('camera-scan-button');
    const progress = document.getElementById('camera-progress');
    try {
        const body = {targets: document.getElementById('camera-target').value.trim(),
                      ports: _remotePorts(document.getElementById('camera-ports').value)};
        button.disabled = true;
        button.innerHTML = '<span class="spinner" style="width:14px;height:14px;"></span> Запуск...';
        progress.style.display = 'block';
        progress.textContent = 'Подготовка проверки...';
        const response = await fetch('/api/cameras/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось запустить проверку');
        localStorage.setItem('ip2domain_camera_job', data.job_id);
        pollCameraScan(data.job_id);
    } catch (error) {
        button.disabled = false;
        button.textContent = '▶ Запустить проверку';
        progress.innerHTML = `<span style="color:#f87171">${_esc(error.message)}</span>`;
    }
}

function pollCameraScan(jobId) {
    if (window._cameraPoller) clearInterval(window._cameraPoller);
    const timer = setInterval(async () => {
        const button = document.getElementById('camera-scan-button');
        const progress = document.getElementById('camera-progress');
        try {
            const response = await fetch(`/api/cameras/scan/${jobId}`);
            const job = await response.json();
            if (!response.ok) throw new Error(job.detail || 'Задание не найдено');
            const pct = job.progress_pct || 0;
            progress.innerHTML = `<div class="progress-header"><span>${_esc(job.stage || 'Проверка...')}</span><span>${pct}%</span></div><div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div>`;
            button.innerHTML = `<span class="spinner" style="width:14px;height:14px;"></span> Проверка... ${pct}%`;
            if (job.status === 'completed') {
                clearInterval(timer); button.disabled = false; button.textContent = '↻ Запустить повторно';
                renderCameraResults(job.results || {});
            } else if (job.status === 'error' || job.status === 'interrupted') {
                clearInterval(timer); button.disabled = false; button.textContent = '▶ Запустить проверку';
                progress.innerHTML = `<span style="color:#f87171">${_esc(job.error || 'Проверка прервана')}</span>`;
            }
        } catch (error) {
            clearInterval(timer); button.disabled = false; button.textContent = '▶ Запустить проверку';
            progress.innerHTML = `<span style="color:#f87171">${_esc(error.message)}</span>`;
        }
    }, 2000);
    window._cameraPoller = timer;
}

function renderCameraResults(result) {
    const container = document.getElementById('camera-results');
    const devices = result.devices || [];
    if (!devices.length) {
        container.innerHTML = '<div class="empty-state">Признаки IP-камер не обнаружены</div>';
        return;
    }
    window._cameraDevices = {};
    container.innerHTML = devices.map((device, index) => {
        const deviceKey = `camera-${index}`;
        window._cameraDevices[deviceKey] = device;
        const findings = (device.findings || []).map((item) =>
            `<div class="camera-finding"><b>${_esc(item.criterion)}</b><span>${_esc(item.value)}</span><small>${_esc(item.reliability)}</small></div>`).join('');
        const serviceLinks = (device.services || []).map((service) => {
            const name = String(service.service || '').toLowerCase();
            let scheme = '';
            if (name.includes('rtsp')) scheme = 'rtsp';
            else if (service.tunnel === 'ssl' || name.includes('https') || Number(service.port) === 443 || Number(service.port) === 8443) scheme = 'https';
            else if (name.includes('http') || [80, 8000, 8080, 8081, 8899].includes(Number(service.port))) scheme = 'http';
            if (!scheme) return `<span class="camera-service-link">${_esc(device.target)}:${service.port}</span>`;
            const url = `${scheme}://${device.target}:${service.port}/`;
            return `<a class="camera-service-link" href="${_esc(url)}" target="_blank" rel="noopener noreferrer">${_esc(url)}</a>`;
        }).join('');
        const services = (device.services || []).map((service) =>
            `<details><summary>${_esc(device.target)}:${service.port} · ${_esc(service.product || service.service || 'неизвестный сервис')}</summary>${(service.scripts || []).map((script) => `<pre>${_esc(script.id)}: ${_esc(script.output)}</pre>`).join('')}</details>`).join('');
        return `<article class="remote-service-card"><div class="remote-service-head"><span class="remote-protocol vnc">CAM</span><div><b>${_esc(device.target)}</b><small>${_esc(device.hostname || 'PTR не найден')}</small></div><span class="camera-score">${device.score}% · ${_esc(device.confidence)}</span></div><div class="camera-service-links">${serviceLinks}</div><div class="camera-findings">${findings}</div><div class="remote-script-list">${services}</div><button type="button" class="btn btn-ghost btn-small" id="${deviceKey}-vuln-button" onclick="startCameraVulnScan('${deviceKey}')">Проверить уязвимости</button><div id="${deviceKey}-vuln-results"></div></article>`;
    }).join('');
}

async function startCameraVulnScan(deviceKey) {
    const device = (window._cameraDevices || {})[deviceKey];
    if (!device) return;
    const button = document.getElementById(`${deviceKey}-vuln-button`);
    const container = document.getElementById(`${deviceKey}-vuln-results`);
    const openPorts = (device.services || []).map((service) => ({
        port: Number(service.port), protocol: service.transport || 'tcp',
        service: service.service || '', version: service.product || '',
        tunnel: service.tunnel || '', http_detected: /http/i.test(service.service || '')
    }));
    const techStack = [...new Set([
        ...(device.findings || []).flatMap((item) => [item.value || '']),
        ...(device.services || []).flatMap((item) => [item.product || '']),
        'DVR/IP Camera'
    ].filter(Boolean))];
    try {
        button.disabled = true;
        button.innerHTML = '<span class="spinner" style="width:14px;height:14px;"></span> Запуск...';
        const response = await fetch('/api/vuln/scan', {method:'POST', headers:{'Content-Type':'application/json'},
            body:JSON.stringify({target:device.target, target_type:'ip', tech_stack:techStack, open_ports:openPorts})});
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось запустить проверку');
        container.innerHTML = _vulnRunningHtml('Инициализация DVR-проверок...');
        pollCameraVulnScan(data.job_id, deviceKey);
    } catch (error) {
        button.disabled = false;
        button.textContent = 'Проверить уязвимости';
        container.innerHTML = `<div style="color:#f87171">${_esc(error.message)}</div>`;
    }
}

async function pollCameraVulnScan(jobId, deviceKey) {
    const button = document.getElementById(`${deviceKey}-vuln-button`);
    const container = document.getElementById(`${deviceKey}-vuln-results`);
    try {
        const response = await fetch(`/api/vuln/scan/${jobId}`);
        const job = await response.json();
        if (!response.ok) throw new Error(job.detail || 'Задание не найдено');
        if (job.status === 'completed') {
            button.disabled = false; button.textContent = 'Пересканировать уязвимости';
            if (job.results) renderVulnResults(job.results, container);
            return;
        }
        if (job.status === 'error' || job.status === 'interrupted') throw new Error(job.error || 'Проверка прервана');
        button.innerHTML = `<span class="spinner" style="width:14px;height:14px;"></span> Проверка... ${job.progress_pct || 0}%`;
        container.innerHTML = _vulnRunningHtml(job.stage || 'DVR-проверки...');
        setTimeout(() => pollCameraVulnScan(jobId, deviceKey), 2500);
    } catch (error) {
        button.disabled = false; button.textContent = 'Проверить уязвимости';
        container.innerHTML = `<div style="color:#f87171">${_esc(error.message)}</div>`;
    }
}

async function restoreCameraScan() {
    try {
        const savedResponse = await fetch('/api/cameras/results');
        if (savedResponse.ok) renderCameraResults(await savedResponse.json());
    } catch (_) {}
    const jobId = localStorage.getItem('ip2domain_camera_job');
    if (!jobId) return;
    try {
        const response = await fetch(`/api/cameras/scan/${jobId}`);
        if (!response.ok) return;
        const job = await response.json();
        const progress = document.getElementById('camera-progress');
        if (job.status === 'completed' && job.results) {
            progress.style.display = 'block'; progress.textContent = `Завершено · проверено ${job.total_targets || 0} IP`;
            renderCameraResults(job.results);
        } else if (job.status === 'queued' || job.status === 'running') {
            document.getElementById('camera-scan-button').disabled = true;
            progress.style.display = 'block'; pollCameraScan(jobId);
        }
    } catch (_) {}
}

document.addEventListener('DOMContentLoaded', restoreCameraScan);
document.addEventListener('DOMContentLoaded', async () => {
    const jobId = localStorage.getItem('ip2domain_centra_job');
    if (!jobId) return;
    try {
        const response = await fetch(`/api/cameras/centra/discover/${jobId}`);
        if (!response.ok) return;
        const job = await response.json();
        if (job.status === 'queued' || job.status === 'running') {
            document.getElementById('centra-discovery-button').disabled = true;
            document.getElementById('centra-discovery-progress').style.display = 'block';
            pollCentraDiscovery(jobId);
        }
    } catch (_) {}
});
