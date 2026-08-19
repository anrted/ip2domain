'use strict';
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

async function loadAsnPrefixesForScanner() {
    const input = document.getElementById('camera-asn-input');
    const btn = document.getElementById('camera-asn-btn');
    const status = document.getElementById('camera-asn-status');
    const area = document.getElementById('camera-target');
    if (!input || !area) return;

    const asnVal = input.value.trim();
    if (!asnVal) {
        if (status) {
            status.style.color = '#ef4444';
            status.textContent = 'Укажите номер ASN (напр. 12958)';
        }
        return;
    }

    if (btn) btn.disabled = true;
    if (status) {
        status.style.color = '#93c5fd';
        status.textContent = `Запрос префиксов для ${asnVal}...`;
    }

    try {
        const resp = await fetch(`/api/asn/lookup?asn=${encodeURIComponent(asnVal)}`);
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || 'Не удалось получить префиксы');

        const v4 = data.prefixes_v4 || [];
        const v6 = data.prefixes_v6 || [];
        const all = [...v4];

        if (!all.length) {
            if (status) {
                status.style.color = '#eab308';
                status.textContent = `Для ${data.asn} не найдено IPv4 диапазонов (${v6.length} IPv6 пропущено)`;
            }
            return;
        }

        const lines = new Set(area.value.split('\n').map(l => l.trim()).filter(Boolean));
        all.forEach(p => lines.add(p));
        area.value = Array.from(lines).join('\n');

        if (status) {
            status.style.color = '#4ade80';
            status.textContent = `✓ Загружено ${v4.length} IPv4 диапазонов (${data.asn}, источник: ${data.source || '2ip.io/RIPE'})`;
            setTimeout(() => { if (status.textContent.startsWith('✓')) status.textContent = ''; }, 6000);
        }
    } catch (err) {
        if (status) {
            status.style.color = '#ef4444';
            status.textContent = err.message;
        }
    } finally {
        if (btn) btn.disabled = false;
    }
}
window.loadAsnPrefixesForScanner = loadAsnPrefixesForScanner;

async function startCameraScan(event) {
    event.preventDefault();
    const button = document.getElementById('camera-scan-button');
    const progress = document.getElementById('camera-progress');
    try {
        const body = {targets: document.getElementById('camera-target').value.trim(),
                      ports: _remotePorts(document.getElementById('camera-ports').value),
                      concurrency: Number(document.getElementById('camera-concurrency').value || 0)};
        button.disabled = true;
        button.innerHTML = '<span class="spinner" style="width:14px;height:14px;"></span> Запуск...';
        progress.style.display = 'block';
        progress.textContent = 'Подготовка проверки...';
        const response = await fetch('/api/cameras/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось запустить проверку');
        localStorage.setItem('ip2domain_camera_job', data.job_id);
        activeCameraScanJobId = data.job_id;
        cameraDevicesVersion = -1;
        const cancelButton = document.getElementById('camera-cancel-button');
        cancelButton.disabled = false;
        cancelButton.style.display = '';
        pollCameraScan(data.job_id);
    } catch (error) {
        button.disabled = false;
        button.textContent = '▶ Запустить проверку';
        progress.innerHTML = `<span style="color:#f87171">${_esc(error.message)}</span>`;
    }
}

function pollCameraScan(jobId) {
    if (window._cameraPoller) clearInterval(window._cameraPoller);
    activeCameraScanJobId = jobId;
    const pollOnce = async () => {
        const button = document.getElementById('camera-scan-button');
        const cancelButton = document.getElementById('camera-cancel-button');
        const progress = document.getElementById('camera-progress');
        try {
            const response = await fetch(`/api/cameras/scan/${jobId}`);
            const job = await response.json();
            if (!response.ok) throw new Error(job.detail || 'Задание не найдено');
            const pct = job.progress_pct || 0;
            progress.innerHTML = `<div class="progress-header"><span>${_esc(job.stage || 'Проверка...')}</span><span>${pct}%</span></div><div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div>`;
            button.innerHTML = `<span class="spinner" style="width:14px;height:14px;"></span> Проверка... ${pct}%`;
            if (Number(job.devices_version || 0) !== cameraDevicesVersion) {
                cameraDevicesVersion = Number(job.devices_version || 0);
                if (cameraDevicesVersion > 0) {
                    const liveResponse = await fetch('/api/cameras/results');
                    if (liveResponse.ok) renderCameraResults(await liveResponse.json());
                }
            }
            if (job.status === 'completed') {
                clearInterval(window._cameraPoller); activeCameraScanJobId = null;
                button.disabled = false; button.textContent = '↻ Запустить повторно';
                cancelButton.style.display = 'none';
                renderCameraResults(job.results || {});
                return true;
            } else if (job.status === 'cancelled') {
                clearInterval(window._cameraPoller); activeCameraScanJobId = null;
                button.disabled = false; button.textContent = '▶ Запустить проверку';
                cancelButton.style.display = 'none';
                if (job.results) renderCameraResults(job.results);
                return true;
            } else if (job.status === 'error' || job.status === 'interrupted') {
                clearInterval(window._cameraPoller); activeCameraScanJobId = null;
                button.disabled = false; button.textContent = '▶ Запустить проверку';
                cancelButton.style.display = 'none';
                progress.innerHTML = `<span style="color:#f87171">${_esc(job.error || 'Проверка прервана')}</span>`;
                return true;
            } else if (job.status === 'cancelling') {
                cancelButton.disabled = true;
                cancelButton.textContent = 'Остановка...';
            }
        } catch (error) {
            clearInterval(window._cameraPoller); activeCameraScanJobId = null;
            button.disabled = false; button.textContent = '▶ Запустить проверку';
            cancelButton.style.display = 'none';
            progress.innerHTML = `<span style="color:#f87171">${_esc(error.message)}</span>`;
            return true;
        }
        return false;
    };
    pollOnce().then((done) => {
        if (!done) window._cameraPoller = setInterval(pollOnce, 1000);
    });
}

async function cancelCameraScan() {
    if (!activeCameraScanJobId) return;
    const button = document.getElementById('camera-cancel-button');
    button.disabled = true;
    button.textContent = 'Остановка...';
    await fetch(`/api/cameras/scan/${activeCameraScanJobId}/cancel`, {method:'POST'});
}
window.cancelCameraScan = cancelCameraScan;

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
        const protocols = cameraConnectionTypes(device);
        const findings = (device.findings || []).map((item) =>
            `<div class="camera-finding"><b>${_esc(item.criterion)}</b><span>${_esc(item.value)}</span></div>`).join('');
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
            `<div class="camera-service-row"><span>${_esc(device.target)}:${service.port}</span><b>${_esc(service.product || service.service || 'сервис')}</b></div>`).join('');
        const badges = protocols.filter((item) => item !== 'other').map((item) => `<span class="camera-protocol-badge ${item}">${item.toUpperCase()}</span>`).join('');
        return `<article class="remote-service-card camera-compact-card" data-camera-protocols="${protocols.join(' ')}"><div class="camera-compact-head"><div><b>${_esc(device.target)}</b><small>${_esc(device.hostname || 'PTR не найден')}</small></div><div class="camera-compact-meta">${badges}<span class="camera-score">${device.score}% · ${_esc(device.confidence)}</span></div></div><div class="camera-service-links">${serviceLinks}</div><details class="camera-details"><summary>Технические сведения · ${(device.services || []).length} сервисов · ${(device.findings || []).length} признаков</summary><div class="camera-findings">${findings}</div><div class="camera-service-list">${services}</div></details><div class="camera-card-actions"><button type="button" class="btn btn-small" onclick="connectToScannedCamera('${deviceKey}')">Подключиться</button><button type="button" class="btn btn-ghost btn-small" id="${deviceKey}-vuln-button" onclick="startCameraVulnScan('${deviceKey}')">Уязвимости</button></div><div id="${deviceKey}-vuln-results"></div></article>`;
    }).join('');
    applyCameraConnectionFilter();
}

function cameraConnectionTypes(device) {
    const types = new Set();
    (device.services || []).forEach((service) => {
        const name = String(service.service || '').toLowerCase();
        const scripts = (service.scripts || []).map((item) => `${item.id} ${item.output}`).join(' ').toLowerCase();
        if (name.includes('rtsp') || scripts.includes('rtsp-methods')) types.add('rtsp');
        if (name.includes('http') || [80,443,8000,8080,8081,8443,8899].includes(Number(service.port))) types.add('http');
        if (scripts.includes('onvif') || String(service.product || '').toLowerCase().includes('onvif')) types.add('onvif');
    });
    if ((device.findings || []).some((item) => String(item.criterion).toLowerCase().includes('onvif'))) types.add('onvif');
    if (!types.size) types.add('other');
    return [...types];
}

function setCameraConnectionFilter(filter) {
    cameraConnectionFilter = filter;
    document.querySelectorAll('#camera-connection-filters [data-camera-filter]').forEach((button) =>
        button.classList.toggle('active', button.dataset.cameraFilter === filter));
    applyCameraConnectionFilter();
}
window.setCameraConnectionFilter = setCameraConnectionFilter;

function applyCameraConnectionFilter() {
    document.querySelectorAll('#camera-results .camera-compact-card').forEach((card) => {
        card.hidden = cameraConnectionFilter !== 'all' && !card.dataset.cameraProtocols.split(' ').includes(cameraConnectionFilter);
    });
}

function connectToScannedCamera(deviceKey) {
    const device = (window._cameraDevices || {})[deviceKey];
    if (!device) return;
    const httpService = (device.services || []).find((service) => {
        const name = String(service.service || '').toLowerCase();
        return name.includes('http') || [80,443,8000,8080,8081,8443,8899].includes(Number(service.port));
    });
    const rtspServices = (device.services || []).filter((service) => String(service.service || '').toLowerCase() === 'rtsp' ||
        (service.scripts || []).some((script) => script.id === 'rtsp-methods'));
    const rtspService = rtspServices[0];
    let dialog = document.getElementById('ip-camera-connect-dialog');
    if (!dialog) {
        dialog = document.createElement('dialog');
        dialog.id = 'ip-camera-connect-dialog';
        dialog.className = 'centra-player-dialog ip-camera-connect-dialog';
        dialog.addEventListener('close', () => {
            clearInterval(ipCameraPreviewTimer); ipCameraPreviewTimer = null;
            const media = dialog.querySelector('.ip-camera-preview img');
            if (media) media.src = '';
            if (activeIPCameraConnectionId) fetch(`/api/cameras/connect/session/${activeIPCameraConnectionId}`, {method:'DELETE'}).catch(() => {});
            activeIPCameraConnectionId = null;
        });
        dialog.addEventListener('click', (event) => { if (event.target === dialog) dialog.close(); });
        document.body.appendChild(dialog);
    }
    const scheme = httpService && (httpService.tunnel === 'ssl' || String(httpService.service || '').includes('https') || [443,8443].includes(Number(httpService.port))) ? 'https' : 'http';
    const webUrl = httpService ? `${scheme}://${device.target}:${httpService.port}/` : '';
    const previewUrl = rtspService ? `/api/cameras/connect/snapshot.jpg?target=${encodeURIComponent(device.target)}&port=${rtspService.port}` : '';
    const rtspPortOptions = rtspServices.map((service) => `<option value="${Number(service.port)}">${Number(service.port)} · ${_esc(service.product || service.service || 'RTSP')}</option>`).join('');
    dialog.innerHTML = `<div class="centra-player-head"><strong>Подключение · ${_esc(device.target)}</strong><button class="centra-player-close" type="button" onclick="document.getElementById('ip-camera-connect-dialog').close()">×</button></div><div class="ip-camera-connect-body">${rtspService ? `<section><h3>RTSP-предпросмотр</h3><form class="ip-camera-auth" onsubmit="authorizeIPCamera(event,'${deviceKey}')"><input name="username" autocomplete="username" value="admin" placeholder="Логин"><input name="password" type="password" autocomplete="current-password" value="admin" placeholder="Пароль"><label class="ip-camera-path"><span>RTSP-порт</span><select name="rtsp_port">${rtspPortOptions}</select></label><label class="ip-camera-path"><span>Путь или RTSP URL</span><input name="rtsp_path" list="common-rtsp-paths" value="auto" placeholder="/CAM_ID.password.mp2"></label><datalist id="common-rtsp-paths"><option value="auto" label="Автоматически"><option value="/"><option value="/live.sdp"><option value="/h264.sdp"><option value="/stream1"><option value="/Streaming/Channels/1"><option value="/Streaming/Channels/101"><option value="/cam/realmonitor?channel=1&subtype=0"><option value="/CAM_ID.password.mp2"></datalist><button class="btn btn-small" type="submit">Подключиться</button></form><div class="ip-camera-auth-status"></div><div class="ip-camera-view-modes"><button type="button" class="active" onclick="setIPCameraViewMode('snapshot')">Кадры</button><button type="button" onclick="setIPCameraViewMode('video')">Живое видео</button></div><div class="ip-camera-preview"><span class="spinner"></span><img alt="RTSP ${_esc(device.target)}"></div><small>Видео передаётся как MJPEG без звука. По умолчанию используется admin/admin.</small></section>` : ''}${webUrl ? `<section><h3>Web-интерфейс</h3><a class="btn btn-small" href="${_esc(webUrl)}" target="_blank" rel="noopener noreferrer">Открыть ${_esc(webUrl)}</a><iframe src="${_esc(webUrl)}" title="Web-интерфейс камеры" referrerpolicy="no-referrer"></iframe></section>` : ''}${!rtspService && !webUrl ? '<div class="empty-state">Поддерживаемый способ подключения не обнаружен</div>' : ''}</div>`;
    dialog.showModal();
    if (previewUrl) {
        const image = dialog.querySelector('.ip-camera-preview img');
        dialog.dataset.previewUrl = previewUrl;
        dialog.dataset.target = device.target;
        dialog.dataset.port = String(rtspService.port);
        const refresh = () => {
            if (image.dataset.loading === 'true') return;
            image.dataset.loading = 'true';
            image.onload = async () => {
                image.dataset.loading = 'false';
                image.closest('.ip-camera-preview').classList.add('loaded');
                if (activeIPCameraConnectionId) {
                    const response = await fetch(`/api/cameras/connect/session/${activeIPCameraConnectionId}`);
                    const data = response.ok ? await response.json() : {};
                    const status = dialog.querySelector('.ip-camera-auth-status');
                    if (data.selected_rtsp_path) status.textContent = `Подключено · найден путь ${data.selected_rtsp_path}`;
                }
            };
            image.onerror = () => { image.dataset.loading = 'false'; image.closest('.ip-camera-preview').classList.add('failed'); image.alt = 'RTSP-предпросмотр недоступен'; };
            const session = activeIPCameraConnectionId ? `&connection_id=${activeIPCameraConnectionId}` : '';
            image.src = `${dialog.dataset.previewUrl}${session}&refresh=true&_=${Date.now()}`;
        };
        dialog._refreshIPCamera = refresh;
        refresh();
        ipCameraPreviewTimer = setInterval(refresh, 5000);
    }
}
window.connectToScannedCamera = connectToScannedCamera;

async function authorizeIPCamera(event, deviceKey) {
    event.preventDefault();
    const device = (window._cameraDevices || {})[deviceKey];
    const selectedPort = Number(event.currentTarget.elements.rtsp_port?.value || 0);
    const rtspService = (device?.services || []).find((service) => Number(service.port) === selectedPort &&
        (String(service.service || '').toLowerCase() === 'rtsp' ||
         (service.scripts || []).some((script) => script.id === 'rtsp-methods')));
    if (!device || !rtspService) return;
    const form = event.currentTarget;
    const status = form.parentElement.querySelector('.ip-camera-auth-status');
    const submit = form.querySelector('button');
    submit.disabled = true; status.textContent = 'Авторизация…';
    try {
        if (activeIPCameraConnectionId) await fetch(`/api/cameras/connect/session/${activeIPCameraConnectionId}`, {method:'DELETE'});
        const response = await fetch('/api/cameras/connect/session', {method:'POST', headers:{'Content-Type':'application/json'},
            body:JSON.stringify({target:device.target, port:Number(rtspService.port),
                username:form.elements.username.value, password:form.elements.password.value,
                rtsp_path:form.elements.rtsp_path.value || '/'})});
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось создать подключение');
        activeIPCameraConnectionId = data.connection_id;
        const dialog = document.getElementById('ip-camera-connect-dialog');
        dialog.dataset.previewUrl = `/api/cameras/connect/snapshot.jpg?target=${encodeURIComponent(device.target)}&port=${selectedPort}`;
        dialog.dataset.target = device.target;
        dialog.dataset.port = String(selectedPort);
        form.elements.password.value = '';
        const preview = form.parentElement.querySelector('.ip-camera-preview');
        preview.classList.remove('failed', 'loaded');
        const image = preview.querySelector('img');
        image.dataset.loading = 'false';
        image.src = '';
        status.textContent = 'Данные приняты, подключение к RTSP…';
        dialog._refreshIPCamera?.();
    } catch (error) {
        status.textContent = error.message;
    } finally {
        submit.disabled = false;
    }
}
window.authorizeIPCamera = authorizeIPCamera;

function setIPCameraViewMode(mode) {
    const dialog = document.getElementById('ip-camera-connect-dialog');
    const image = dialog?.querySelector('.ip-camera-preview img');
    if (!dialog || !image || !activeIPCameraConnectionId) return;
    dialog.querySelectorAll('.ip-camera-view-modes button').forEach((button) =>
        button.classList.toggle('active', button.textContent.includes(mode === 'video' ? 'видео' : 'Кадры')));
    clearInterval(ipCameraPreviewTimer); ipCameraPreviewTimer = null;
    image.dataset.loading = 'false';
    image.closest('.ip-camera-preview').classList.remove('failed');
    if (mode === 'video') {
        const params = new URLSearchParams({target:dialog.dataset.target, port:dialog.dataset.port,
            connection_id:activeIPCameraConnectionId});
        image.src = `/api/cameras/connect/stream.mjpeg?${params}`;
    } else {
        dialog._refreshIPCamera?.();
        ipCameraPreviewTimer = setInterval(dialog._refreshIPCamera, 5000);
    }
}
window.setIPCameraViewMode = setIPCameraViewMode;

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
            document.getElementById('camera-cancel-button').style.display = '';
            progress.style.display = 'block'; pollCameraScan(jobId);
        } else if (job.status === 'cancelling') {
            document.getElementById('camera-scan-button').disabled = true;
            document.getElementById('camera-cancel-button').style.display = '';
            progress.style.display = 'block'; pollCameraScan(jobId);
        }
    } catch (_) {}
}

document.addEventListener('DOMContentLoaded', () => {
    // Only restore camera scan results if there was an active job or cameras view / scanner tab is open
    const jobId = localStorage.getItem('ip2domain_camera_job');
    const scannerPanel = document.getElementById('camera-scanner-panel');
    if (jobId || (scannerPanel && scannerPanel.classList.contains('active'))) {
        restoreCameraScan();
    }
});

