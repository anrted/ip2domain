/* Camera Scanner v2 — Frontend Client
   Handles: v1/v2 switcher, scan form, SSE-style polling, results rendering,
   stream selection & preview capture (supports 300+ streams per camera)
*/

'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// State
// ─────────────────────────────────────────────────────────────────────────────
const V2State = {
    currentJobId: null,
    pollTimer: null,
    pollInterval: 2000,
    results: [],           // CameraResult[]
    selectedStreams: {},   // { [ip]: streamUrl }
    filterBrand: 'all',
    filterProtocol: 'all',
    credentials: [
        { user: 'admin', password: '' },
        { user: 'admin', password: 'admin' },
        { user: 'admin', password: '12345' },
        { user: 'admin', password: '123456' },
        { user: 'root',  password: '' },
        { user: 'root',  password: 'root' },
    ],
};

// ─────────────────────────────────────────────────────────────────────────────
// v1 / v2 switcher
// ─────────────────────────────────────────────────────────────────────────────
function switchCameraVersion(version) {
    const v1Tabs   = document.querySelectorAll('.camera-tab');
    const v1Panels = document.querySelectorAll('.camera-tab-panel');
    const v2Panel  = document.getElementById('camera-v2-panel');
    const btn1 = document.getElementById('cam-ver-btn-v1');
    const btn2 = document.getElementById('cam-ver-btn-v2');

    if (version === 'v2') {
        v1Tabs.forEach(t => t.style.display = 'none');
        v1Panels.forEach(p => { p.style.display = 'none'; p.classList.remove('active'); });
        v2Panel.classList.add('v2-active');
        btn1.classList.remove('active');
        btn2.classList.add('active', 'active-v2');
        localStorage.setItem('ip2domain_cam_version', 'v2');
        v2OnActivate();
    } else {
        v1Tabs.forEach(t => t.style.display = '');
        v2Panel.classList.remove('v2-active');
        btn1.classList.add('active');
        btn2.classList.remove('active', 'active-v2');
        localStorage.setItem('ip2domain_cam_version', 'v1');
        const activeTab = document.querySelector('.camera-tab.active');
        if (activeTab) {
            const tabId = activeTab.id.replace('camera-', '').replace('-tab', '');
            switchCameraTab(tabId);
        } else {
            switchCameraTab('go2rtc');
        }
    }
}

function v2OnActivate() {
    v2LoadTools();
    v2RenderCredentials();
    v2LoadStoredResults();
    v2CheckActiveScan();
}

async function v2CheckActiveScan() {
    const savedJobId = localStorage.getItem('ip2domain_v2_active_job');
    if (!savedJobId) {
        v2LoadStoredResults();
        return;
    }
    try {
        const resp = await fetch(`/api/v2/scan/${savedJobId}`);
        if (!resp.ok) {
            localStorage.removeItem('ip2domain_v2_active_job');
            v2LoadStoredResults();
            return;
        }
        const job = await resp.json();
        if (['queued', 'running'].includes(job.status)) {
            V2State.currentJobId = savedJobId;
            v2ShowProgress();
            v2SetScanState('running');
            v2UpdateProgress(job);
            v2MergeResults(job.results || []);
            v2StartPolling();
        } else {
            localStorage.removeItem('ip2domain_v2_active_job');
            if (job.results && job.results.length) {
                v2MergeResults(job.results);
            }
            v2LoadStoredResults();
        }
    } catch (e) {
        v2LoadStoredResults();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tools status
// ─────────────────────────────────────────────────────────────────────────────
async function v2LoadTools() {
    const container = document.getElementById('v2-tools-status');
    if (!container) return;
    container.innerHTML = '<span class="v2-tool-badge">Проверка...</span>';
    try {
        const resp = await fetch('/api/v2/tools');
        if (!resp.ok) return;
        const tools = await resp.json();
        const badges = [];
        badges.push(v2ToolBadge('masscan', tools.masscan));
        badges.push(v2ToolBadge('nmap', tools.nmap));
        badges.push(v2ToolBadge('ffmpeg', tools.ffmpeg));
        badges.push(v2ToolBadge(tools.is_root ? 'root ✓' : 'no-root', tools.is_root, !tools.is_root ? 'warn' : 'ok'));

        const masscanOpt = document.getElementById('v2-engine-masscan');
        const nmapOpt = document.getElementById('v2-engine-nmap');
        if (masscanOpt && !tools.masscan) {
            masscanOpt.closest('.v2-radio-item').style.opacity = '0.45';
            masscanOpt.disabled = true;
        }
        if (nmapOpt && !tools.nmap) {
            nmapOpt.closest('.v2-radio-item').style.opacity = '0.45';
            nmapOpt.disabled = true;
        }
        container.innerHTML = badges.join('');
    } catch (e) {
        container.innerHTML = '<span class="v2-tool-badge warn">Ошибка проверки</span>';
    }
}

function v2ToolBadge(name, ok, cls) {
    const c = cls || (ok ? 'ok' : 'missing');
    const icon = ok ? '✓' : '✗';
    return `<span class="v2-tool-badge ${c}">${icon} ${name}</span>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Credentials management
// ─────────────────────────────────────────────────────────────────────────────
function v2RenderCredentials() {
    const list = document.getElementById('v2-creds-list');
    if (!list) return;
    list.innerHTML = V2State.credentials.map((c, i) => `
        <div class="v2-cred-row">
            <input type="text" value="${_esc(c.user)}" placeholder="login"
                oninput="V2State.credentials[${i}].user = this.value">
            <input type="password" value="${_esc(c.password)}" placeholder="password"
                oninput="V2State.credentials[${i}].password = this.value">
            <button class="v2-del-btn" onclick="v2RemoveCred(${i})" title="Удалить">✕</button>
        </div>
    `).join('');
}

function v2RemoveCred(idx) {
    V2State.credentials.splice(idx, 1);
    v2RenderCredentials();
}

function v2AddCred() {
    V2State.credentials.push({ user: '', password: '' });
    v2RenderCredentials();
    const inputs = document.querySelectorAll('#v2-creds-list .v2-cred-row input[type="text"]');
    if (inputs.length) inputs[inputs.length - 1].focus();
}

// ─────────────────────────────────────────────────────────────────────────────
// Rate slider
// ─────────────────────────────────────────────────────────────────────────────
function v2OnRateChange(val) {
    const display = document.getElementById('v2-rate-display');
    if (display) display.textContent = Number(val).toLocaleString() + ' pps';
}

// ─────────────────────────────────────────────────────────────────────────────
// Start scan
// ─────────────────────────────────────────────────────────────────────────────
async function v2StartScan(event) {
    if (event) event.preventDefault();

    if (V2State.currentJobId) {
        alert('Сканирование уже выполняется. Дождитесь его завершения или нажмите «Отмена».');
        return;
    }

    const targets = document.getElementById('v2-targets').value.trim();
    if (!targets) {
        alert('Укажите IP-адреса или CIDR-диапазоны для сканирования');
        return;
    }

    const engine = document.querySelector('input[name="v2-engine"]:checked')?.value || 'auto';
    const masscanRate = parseInt(document.getElementById('v2-rate-slider')?.value || '50000');
    const captureFrames = document.getElementById('v2-capture-frames')?.checked !== false;
    const localDiscovery = document.getElementById('v2-local-discovery')?.checked !== false;

    const protocols = [];
    document.querySelectorAll('.v2-proto-check:checked').forEach(cb => protocols.push(cb.value));

    const payload = {
        targets,
        engine,
        masscan_rate: masscanRate,
        concurrency: 150,
        port_timeout: 1.2,
        stage2_concurrency: 20,
        protocols,
        credentials: V2State.credentials.filter(c => c.user),
        capture_frames: captureFrames,
        local_discovery: localDiscovery,
    };

    try {
        const resp = await fetch('/api/v2/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await resp.json();
        if (!resp.ok) {
            alert('Ошибка запуска: ' + (data.detail || resp.status));
            return;
        }
        V2State.currentJobId = data.job_id;
        localStorage.setItem('ip2domain_v2_active_job', data.job_id);
        V2State.results = [];

        v2ShowProgress();
        v2SetScanState('running');
        v2StartPolling();
    } catch (err) {
        alert('Ошибка сети: ' + err.message);
    }
}

function v2SetScanState(state) {
    const startBtn = document.getElementById('v2-start-btn');
    const cancelBtn = document.getElementById('v2-cancel-btn');
    const spinner = document.getElementById('v2-start-spinner');
    if (state === 'running') {
        startBtn.disabled = true;
        cancelBtn.classList.add('visible');
        if (spinner) spinner.style.display = 'inline-block';
    } else {
        startBtn.disabled = false;
        cancelBtn.classList.remove('visible');
        if (spinner) spinner.style.display = 'none';
    }
}

async function v2CancelScan() {
    if (!V2State.currentJobId) return;
    const jid = V2State.currentJobId;
    localStorage.removeItem('ip2domain_v2_active_job');
    V2State.currentJobId = null;
    v2StopPolling();
    v2SetScanState('idle');
    try {
        await fetch(`/api/v2/scan/${jid}/cancel`, { method: 'POST' });
        v2AddLog('Сканирование отменено пользователем.', 'warn');
    } catch (e) {}
}

// ─────────────────────────────────────────────────────────────────────────────
// Polling
// ─────────────────────────────────────────────────────────────────────────────
function v2StartPolling() {
    v2StopPolling();
    V2State.pollTimer = setInterval(v2Poll, V2State.pollInterval);
    v2Poll();
}

function v2StopPolling() {
    if (V2State.pollTimer) {
        clearInterval(V2State.pollTimer);
        V2State.pollTimer = null;
    }
}

async function v2Poll() {
    if (!V2State.currentJobId) return;
    try {
        const resp = await fetch(`/api/v2/scan/${V2State.currentJobId}`);
        if (!resp.ok) {
            if (resp.status === 404) {
                localStorage.removeItem('ip2domain_v2_active_job');
                V2State.currentJobId = null;
                v2StopPolling();
                v2SetScanState('idle');
            }
            return;
        }
        const job = await resp.json();
        v2UpdateProgress(job);
        v2MergeResults(job.results || []);

        if (['completed', 'cancelled', 'error'].includes(job.status)) {
            localStorage.removeItem('ip2domain_v2_active_job');
            V2State.currentJobId = null;
            v2StopPolling();
            v2SetScanState('idle');
            if (job.status === 'completed') {
                v2AddLog(`✓ Сканирование завершено. Найдено ${job.results_count} камер.`, 'ok');
            } else if (job.status === 'error') {
                v2AddLog(`✗ Ошибка: ${job.error}`, 'err');
            }
            v2LoadStoredResults();
        }
    } catch (e) {}
}

// ─────────────────────────────────────────────────────────────────────────────
// Progress rendering
// ─────────────────────────────────────────────────────────────────────────────
function v2ShowProgress() {
    document.getElementById('v2-progress-card').classList.add('visible');
    document.getElementById('v2-results-card').classList.add('visible');
    document.getElementById('v2-log-panel').innerHTML = '';
    v2ResetStages();
}

function v2ResetStages() {
    ['discovery', 'port_sweep', 'fingerprint', 'capture'].forEach(s => {
        v2SetStageStatus(s, 'pending');
    });
    document.getElementById('v2-progress-fill').style.width = '0%';
    document.getElementById('v2-progress-pct').textContent = '0%';
}

const _STAGE_IDS = {
    discovery: 'v2-stage-discovery',
    port_sweep: 'v2-stage-sweep',
    fingerprint: 'v2-stage-finger',
    capture: 'v2-stage-capture',
};

const _STATUS_ICONS = {
    pending: '⏳', running: '🔄', done: '✓', skipped: '—', error: '✗'
};

function v2SetStageStatus(stageName, status, value) {
    const el = document.getElementById(_STAGE_IDS[stageName]);
    if (!el) return;
    el.className = `v2-stage-item ${status}`;
    const icon = el.querySelector('.v2-stage-status-icon');
    const val  = el.querySelector('.v2-stage-value');
    if (icon) icon.textContent = _STATUS_ICONS[status] || '';
    if (val && value !== undefined) val.textContent = value;
}

function v2UpdateProgress(job) {
    const stages = job.stages || {};

    v2SetStageStatus('discovery', stages.discovery?.status || 'pending',
        stages.discovery?.found > 0 ? `${stages.discovery.found} камер` : '—');
    v2SetStageStatus('port_sweep', stages.port_sweep?.status || 'pending',
        stages.port_sweep?.responsive > 0 ? `${stages.port_sweep.responsive} хостов` : '—');
    v2SetStageStatus('fingerprint', stages.fingerprint?.status || 'pending',
        `${stages.fingerprint?.completed || 0} / ${stages.fingerprint?.total || 0}`);
    v2SetStageStatus('capture', stages.capture?.status || 'pending',
        stages.capture?.completed > 0 ? `${stages.capture.completed} кадров` : '—');

    const pct = job.progress_pct || 0;
    document.getElementById('v2-progress-fill').style.width = pct + '%';
    document.getElementById('v2-progress-pct').textContent = pct + '%';

    const stageText = document.getElementById('v2-progress-stage-text');
    if (stageText) stageText.textContent = job.stage || '';

    const engineEl = document.getElementById('v2-engine-used');
    if (engineEl && job.engine_used) {
        engineEl.textContent = job.engine_used;
        engineEl.style.display = 'inline';
    }

    const logPanel = document.getElementById('v2-log-panel');
    if (logPanel && job.logs && job.logs.length) {
        const last10 = job.logs.slice(-10);
        logPanel.innerHTML = last10.map(line => {
            let cls = '';
            if (line.includes('✓') || line.includes('✅')) cls = 'log-ok';
            else if (line.includes('✗') || line.includes('Ошибка')) cls = 'log-err';
            else if (line.includes('⚠') || line.includes('Пропущен')) cls = 'log-warn';
            return `<div class="${cls}">${_esc(line)}</div>`;
        }).join('');
        logPanel.scrollTop = logPanel.scrollHeight;
    }
}

function v2AddLog(msg, cls) {
    const logPanel = document.getElementById('v2-log-panel');
    if (!logPanel) return;
    const div = document.createElement('div');
    div.className = cls ? `log-${cls}` : '';
    div.textContent = msg;
    logPanel.appendChild(div);
    logPanel.scrollTop = logPanel.scrollHeight;
}

// ─────────────────────────────────────────────────────────────────────────────
// Results
// ─────────────────────────────────────────────────────────────────────────────
function v2MergeResults(incoming) {
    if (!incoming || !incoming.length) return;
    const existing = new Set(V2State.results.map(r => r.ip));
    for (const cam of incoming) {
        if (!existing.has(cam.ip)) {
            V2State.results.push(cam);
            existing.add(cam.ip);
        } else {
            const idx = V2State.results.findIndex(r => r.ip === cam.ip);
            if (idx >= 0) V2State.results[idx] = cam;
        }
    }
    v2UpdateResultsCount();
    v2RenderResults();
}

function v2UpdateResultsCount() {
    const el = document.getElementById('v2-results-count');
    if (el) el.textContent = `${V2State.results.length} камер`;
}

async function v2LoadStoredResults() {
    try {
        const resp = await fetch('/api/v2/results?limit=500');
        if (!resp.ok) return;
        const data = await resp.json();
        if (data.results && data.results.length) {
            V2State.results = data.results;
            v2UpdateResultsCount();
            v2RenderResults();
            document.getElementById('v2-results-card').classList.add('visible');
        }
    } catch (e) {}
}

function v2RenderResults() {
    const grid = document.getElementById('v2-camera-grid');
    if (!grid) return;

    let filtered = V2State.results;
    if (V2State.filterBrand !== 'all') {
        filtered = filtered.filter(c => (c.brand || '').toLowerCase().includes(V2State.filterBrand.toLowerCase()));
    }
    if (V2State.filterProtocol !== 'all') {
        filtered = filtered.filter(c => (c.protocols || []).includes(V2State.filterProtocol));
    }

    if (!filtered.length) {
        grid.innerHTML = `<div class="v2-empty-state" style="grid-column:1/-1">
            <div class="v2-empty-icon">📷</div>
            <p>Камеры не найдены. Запустите сканирование.</p>
        </div>`;
        return;
    }

    grid.innerHTML = filtered.map(cam => v2RenderCameraCard(cam)).join('');
}

// ─────────────────────────────────────────────────────────────────────────────
// Camera Card (Handles 300+ streams gracefully & on-demand previews)
// ─────────────────────────────────────────────────────────────────────────────
function v2RenderCameraCard(cam) {
    const safeIp = cam.ip.replace(/\./g, '_');
    const streams = cam.streams || [];
    const totalStreams = streams.length;

    // Determine current selected stream URL for this camera
    if (!V2State.selectedStreams[cam.ip]) {
        const firstVerified = streams.find(s => s.verified && s.url);
        V2State.selectedStreams[cam.ip] = firstVerified?.url || (streams[0]?.url || '');
    }
    const currentStreamUrl = V2State.selectedStreams[cam.ip];

    // Find any stream that has a verified screenshot
    const streamWithScreen = streams.find(s => s.screenshot && (s.url === currentStreamUrl || s.verified));
    const screenshotPath = streamWithScreen?.screenshot || '';

    // Preview area HTML
    let previewHtml = '';
    if (screenshotPath) {
        previewHtml = `
            <div class="v2-preview-wrapper" id="v2-preview-box-${safeIp}">
                <img class="v2-camera-screenshot" src="/api/v2/capture?path=${encodeURIComponent(screenshotPath)}"
                     alt="${_esc(cam.ip)}" loading="lazy"
                     onerror="this.style.display='none';document.getElementById('v2-ph-${safeIp}').style.display='flex'">
                <div class="v2-camera-screenshot-placeholder" id="v2-ph-${safeIp}" style="display:none">
                    <div class="v2-placeholder-inner">
                        <span>📷</span>
                        <button class="v2-capture-now-btn" onclick="v2CapturePreview('${_esc(cam.ip)}', event)">▶ Загрузить превью</button>
                    </div>
                </div>
                <button class="v2-refresh-preview-btn" onclick="v2CapturePreview('${_esc(cam.ip)}', event)" title="Обновить снимок потока">🔄 Обновить</button>
            </div>
        `;
    } else {
        previewHtml = `
            <div class="v2-preview-wrapper" id="v2-preview-box-${safeIp}">
                <div class="v2-camera-screenshot-placeholder">
                    <div class="v2-placeholder-inner">
                        <span style="font-size:1.8rem">📷</span>
                        <button class="v2-capture-now-btn" onclick="v2CapturePreview('${_esc(cam.ip)}', event)" title="Получить снимок кадра">
                            ▶ Получить превью
                        </button>
                    </div>
                </div>
            </div>
        `;
    }

    const verified = streams.some(s => s.verified);
    const verifiedBadge = verified ? '<span class="v2-verified-badge">✓ Live</span>' : '';

    const protocols = (cam.protocols || []).slice(0, 5);
    const badges = protocols.map(p => `<span class="v2-proto-badge ${_protoBadgeClass(p)}">${_protoLabel(p)}</span>`).join('');

    // Stream selector dropdown (top 15 streams + option to browse all 300+)
    let streamSelectorHtml = '';
    if (totalStreams > 0) {
        const streamOptions = streams.slice(0, 15).map((s, idx) => {
            const shortPath = _formatShortStreamUrl(s.url);
            const isSel = s.url === currentStreamUrl ? 'selected' : '';
            const ver = s.verified ? ' [✓ Live]' : '';
            return `<option value="${_esc(s.url)}" ${isSel}>#${idx + 1} ${shortPath}${ver}</option>`;
        }).join('');

        const moreOption = totalStreams > 15
            ? `<option value="__open_modal__">⚡ Показать все ${totalStreams} потоков...</option>`
            : '';

        const streamCountText = totalStreams === 1 ? '1 поток' : (totalStreams < 5 ? `${totalStreams} потока` : `${totalStreams} потоков`);

        streamSelectorHtml = `
            <div class="v2-stream-selector-row">
                <div class="v2-stream-info-header">
                    <span style="color:rgba(255,255,255,0.45)">Поток:</span>
                    <span class="v2-stream-count-badge" onclick="v2OpenStreamModal('${_esc(cam.ip)}')" title="Открыть полный список ${totalStreams} потоков">
                        🎥 ${streamCountText}
                    </span>
                </div>
                <select class="v2-stream-select" id="v2-select-${safeIp}" onchange="v2OnStreamChange('${_esc(cam.ip)}', this.value)">
                    ${streamOptions}
                    ${moreOption}
                </select>
            </div>
        `;
    }

    const inGo2rtc = cam.in_go2rtc;
    const goBtn = `<button class="v2-camera-btn go2rtc-btn ${inGo2rtc ? 'added' : ''}"
        onclick="v2AddToGo2rtc('${_esc(cam.ip)}')"
        title="Добавить текущий поток в go2rtc" id="v2-go2rtc-${safeIp}">
        ${inGo2rtc ? '✓ go2rtc' : '+ go2rtc'}
    </button>`;

    return `<div class="v2-camera-card" id="v2-cam-${safeIp}">
        ${previewHtml}
        ${verifiedBadge}
        <div class="v2-camera-body">
            <div class="v2-camera-brand">${_esc(cam.brand || 'Unknown')}</div>
            <div class="v2-camera-ip">${_esc(cam.ip)}${cam.rtsp_port ? ':' + cam.rtsp_port : ''}</div>
            <div class="v2-camera-model">${_esc(cam.model || '')}</div>
            <div class="v2-proto-badges">${badges}</div>
            ${streamSelectorHtml}
            <div class="v2-camera-actions">
                ${goBtn}
                <button class="v2-camera-btn" onclick="v2CopySelectedUrl('${_esc(cam.ip)}')" title="Скопировать выбранный URL">📋</button>
                <button class="v2-camera-btn" onclick="v2OpenStreamModal('${_esc(cam.ip)}')" title="Просмотр всех ${totalStreams} потоков">⚡ ${totalStreams}</button>
                <button class="v2-camera-btn" onclick="v2ShowDetails('${_esc(cam.ip)}')" title="Подробности">ℹ️</button>
            </div>
        </div>
    </div>`;
}

function _formatShortStreamUrl(url) {
    if (!url) return '';
    try {
        if (url.includes('://')) {
            const afterProto = url.split('://')[1];
            const slashIdx = afterProto.indexOf('/');
            if (slashIdx >= 0) return afterProto.slice(slashIdx);
        }
    } catch (e) {}
    return url.length > 35 ? url.slice(-32) + '...' : url;
}

function _protoBadgeClass(p) {
    if (p.includes('onvif')) return 'onvif';
    if (p.includes('hikvision')) return 'hikvision';
    if (p.includes('dahua')) return 'dahua';
    if (p.includes('axis')) return 'axis';
    if (p.includes('hls')) return 'hls';
    if (p.includes('mjpeg')) return 'mjpeg';
    if (p.includes('rtmp')) return 'rtmp';
    if (p.includes('rtsp')) return 'rtsp';
    return 'generic';
}

function _protoLabel(p) {
    const MAP = {
        onvif: 'ONVIF', hikvision_isapi: 'ISAPI', dahua_cgi: 'Dahua',
        axis_cgi: 'Axis', rtsp_direct: 'RTSP', rtmp: 'RTMP',
        hls: 'HLS', mjpeg: 'MJPEG', http_snapshot: 'SNAP',
        http_generic: 'HTTP', rtsp_port_open: 'RTSP?',
    };
    return MAP[p] || p.toUpperCase().slice(0, 6);
}

// ─────────────────────────────────────────────────────────────────────────────
// Stream change & Live capture actions
// ─────────────────────────────────────────────────────────────────────────────
function v2OnStreamChange(ip, streamUrl) {
    if (streamUrl === '__open_modal__') {
        v2OpenStreamModal(ip);
        // Reset select to previous value
        const sel = document.getElementById(`v2-select-${ip.replace(/\./g, '_')}`);
        if (sel && V2State.selectedStreams[ip]) sel.value = V2State.selectedStreams[ip];
        return;
    }
    V2State.selectedStreams[ip] = streamUrl;
}

async function v2CapturePreview(ip, event) {
    if (event) event.stopPropagation();
    const safeIp = ip.replace(/\./g, '_');
    const box = document.getElementById(`v2-preview-box-${safeIp}`);
    const streamUrl = V2State.selectedStreams[ip] || '';

    if (!streamUrl) {
        alert('Нет URL потока для захвата кадра');
        return;
    }

    if (box) {
        box.innerHTML = `
            <div class="v2-placeholder-inner" style="background:rgba(0,0,0,0.7)">
                <div class="v2-spinner" style="width:24px;height:24px;border-width:3px"></div>
                <span style="font-size:0.7rem;color:#6ee7b7">Захват кадра...</span>
            </div>
        `;
    }

    const cam = V2State.results.find(c => c.ip === ip);
    const user = cam?.credentials?.user || 'admin';
    const pass = cam?.credentials?.password || '';

    try {
        const previewUrl = `/api/v2/preview?ip=${encodeURIComponent(ip)}&stream_url=${encodeURIComponent(streamUrl)}&user=${encodeURIComponent(user)}&password=${encodeURIComponent(pass)}&_t=${Date.now()}`;
        const resp = await fetch(previewUrl);

        if (!resp.ok) {
            if (box) {
                box.innerHTML = `
                    <div class="v2-placeholder-inner">
                        <span style="font-size:1.6rem">⚠️</span>
                        <span style="font-size:0.65rem;color:#fca5a5">Поток не ответил</span>
                        <button class="v2-capture-now-btn" onclick="v2CapturePreview('${_esc(ip)}', event)">Повторить</button>
                    </div>
                `;
            }
            return;
        }

        // Cache update in local model
        const blob = await resp.blob();
        const objUrl = URL.createObjectURL(blob);

        if (cam) {
            for (const s of (cam.streams || [])) {
                if (s.url === streamUrl) {
                    s.verified = true;
                    s.screenshot = objUrl;
                }
            }
        }

        if (box) {
            box.innerHTML = `
                <img class="v2-camera-screenshot" src="${objUrl}" alt="${_esc(ip)}">
                <button class="v2-refresh-preview-btn" onclick="v2CapturePreview('${_esc(ip)}', event)" title="Обновить снимок потока">🔄 Обновить</button>
            `;
        }

        // Mark Live badge
        const card = document.getElementById(`v2-cam-${safeIp}`);
        if (card && !card.querySelector('.v2-verified-badge')) {
            const badge = document.createElement('span');
            badge.className = 'v2-verified-badge';
            badge.textContent = '✓ Live';
            card.appendChild(badge);
        }

    } catch (err) {
        if (box) {
            box.innerHTML = `
                <div class="v2-placeholder-inner">
                    <span style="font-size:1.6rem">❌</span>
                    <span style="font-size:0.65rem;color:#fca5a5">Ошибка соединения</span>
                    <button class="v2-capture-now-btn" onclick="v2CapturePreview('${_esc(ip)}', event)">Повторить</button>
                </div>
            `;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stream Modal Browser (Handles 300+ streams with live search)
// ─────────────────────────────────────────────────────────────────────────────
function v2OpenStreamModal(ip) {
    const cam = V2State.results.find(c => c.ip === ip);
    if (!cam) return;

    // Remove existing modal if any
    document.getElementById('v2-stream-modal-overlay')?.remove();

    const streams = cam.streams || [];
    const safeIp = cam.ip.replace(/\./g, '_');

    const overlay = document.createElement('div');
    overlay.className = 'v2-modal-overlay';
    overlay.id = 'v2-stream-modal-overlay';
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

    overlay.innerHTML = `
        <div class="v2-modal-content">
            <div class="v2-modal-header">
                <div class="v2-modal-title">
                    <span>🎥</span>
                    <span>Потоки камеры ${cam.ip} (${cam.brand || 'Unknown'})</span>
                    <span class="v2-stream-count-badge">${streams.length} потоков</span>
                </div>
                <button class="v2-modal-close" onclick="document.getElementById('v2-stream-modal-overlay').remove()">✕</button>
            </div>
            <div class="v2-modal-search">
                <input type="text" id="v2-modal-search-input" placeholder="Поиск по URL или типу потока (например: h264, ch1, main, rtsp)..."
                    oninput="v2FilterModalStreams('${_esc(cam.ip)}', this.value)">
            </div>
            <div class="v2-modal-body" id="v2-modal-stream-list">
                ${_renderModalStreamItems(cam, streams)}
            </div>
        </div>
    `;

    document.body.appendChild(overlay);
    document.getElementById('v2-modal-search-input')?.focus();
}

function _renderModalStreamItems(cam, streams) {
    if (!streams.length) {
        return '<div style="text-align:center;padding:2rem;color:rgba(255,255,255,0.4)">Потоки не найдены</div>';
    }

    return streams.map((s, idx) => {
        const type = (s.type || s.stream_type || 'rtsp').toUpperCase();
        const verBadge = s.verified ? '<span class="v2-verified-badge" style="position:static;display:inline-block;padding:0.1rem 0.35rem;font-size:0.55rem">✓ Live</span>' : '';
        const resText = s.resolution ? `<span style="color:rgba(255,255,255,0.4);font-size:0.65rem">${s.resolution}</span>` : '';

        return `
            <div class="v2-stream-item">
                <div style="display:flex;align-items:center;gap:0.5rem;flex:1;min-width:0">
                    <span style="font-size:0.7rem;color:rgba(255,255,255,0.3);min-width:28px">#${idx + 1}</span>
                    <span class="v2-proto-badge ${_protoBadgeClass(type.toLowerCase())}">${type}</span>
                    <span class="v2-stream-item-url" title="${_esc(s.url)}">${_esc(s.url)}</span>
                    ${verBadge} ${resText}
                </div>
                <div class="v2-stream-item-actions">
                    <button class="v2-btn-small" onclick="v2CopyUrl('${_esc(s.url)}')" title="Скопировать URL">📋 Копировать</button>
                    <button class="v2-btn-small v2-btn-green" onclick="v2CaptureFromModal('${_esc(cam.ip)}', '${_esc(s.url)}', this)">📸 Превью</button>
                    <button class="v2-btn-small" onclick="v2AddSpecificStreamToGo2rtc('${_esc(cam.ip)}', '${_esc(s.url)}', ${idx + 1})">+ go2rtc</button>
                </div>
            </div>
        `;
    }).join('');
}

function v2FilterModalStreams(ip, query) {
    const cam = V2State.results.find(c => c.ip === ip);
    if (!cam) return;
    const list = document.getElementById('v2-modal-stream-list');
    if (!list) return;

    const q = (query || '').toLowerCase().trim();
    const filtered = (cam.streams || []).filter(s => (s.url || '').toLowerCase().includes(q) || (s.type || s.stream_type || '').toLowerCase().includes(q));
    list.innerHTML = _renderModalStreamItems(cam, filtered);
}

async function v2CaptureFromModal(ip, streamUrl, btn) {
    const origText = btn.textContent;
    btn.textContent = '⏳...';
    btn.disabled = true;
    V2State.selectedStreams[ip] = streamUrl;
    await v2CapturePreview(ip);
    btn.textContent = '✓ Готово';
    setTimeout(() => { btn.textContent = origText; btn.disabled = false; }, 2000);
}

// ─────────────────────────────────────────────────────────────────────────────
// go2rtc integration
// ─────────────────────────────────────────────────────────────────────────────
async function v2AddToGo2rtc(ip) {
    const streamUrl = V2State.selectedStreams[ip];
    if (!streamUrl) {
        alert('Нет выбранного RTSP URL для добавления');
        return;
    }
    const safeIp = ip.replace(/\./g, '_');
    const streamName = `v2_${safeIp}_1`;
    try {
        const resp = await fetch(`/api/v2/results/${ip}/go2rtc?stream_url=${encodeURIComponent(streamUrl)}&stream_name=${encodeURIComponent(streamName)}`, {
            method: 'POST',
        });
        const data = await resp.json();
        if (data.success) {
            const btn = document.getElementById(`v2-go2rtc-${safeIp}`);
            if (btn) {
                btn.textContent = '✓ go2rtc';
                btn.classList.add('added');
            }
        } else {
            alert('Не удалось добавить в go2rtc: ' + JSON.stringify(data));
        }
    } catch (e) {
        alert('Ошибка: ' + e.message);
    }
}

async function v2AddSpecificStreamToGo2rtc(ip, streamUrl, channelIdx) {
    const safeIp = ip.replace(/\./g, '_');
    const streamName = `v2_${safeIp}_ch${channelIdx}`;
    try {
        const resp = await fetch(`/api/v2/results/${ip}/go2rtc?stream_url=${encodeURIComponent(streamUrl)}&stream_name=${encodeURIComponent(streamName)}`, {
            method: 'POST',
        });
        const data = await resp.json();
        if (data.success) {
            alert(`Поток #${channelIdx} (${streamName}) успешно добавлен в go2rtc!`);
        } else {
            alert('Ошибка добавления: ' + JSON.stringify(data));
        }
    } catch (e) {
        alert('Ошибка сети: ' + e.message);
    }
}

async function v2ExportAllToGo2rtc() {
    const cameras = V2State.results.filter(c => !c.in_go2rtc);
    if (!cameras.length) {
        alert('Все камеры уже добавлены в go2rtc или результатов нет');
        return;
    }
    if (!confirm(`Добавить ${cameras.length} камер в go2rtc?`)) return;

    let success = 0;
    for (const cam of cameras) {
        const streamUrl = V2State.selectedStreams[cam.ip] || cam.streams?.[0]?.url;
        if (streamUrl) {
            try {
                const safeIp = cam.ip.replace(/\./g, '_');
                const resp = await fetch(`/api/v2/results/${cam.ip}/go2rtc?stream_url=${encodeURIComponent(streamUrl)}&stream_name=v2_${safeIp}_1`, {
                    method: 'POST',
                });
                if ((await resp.json()).success) success++;
            } catch (e) {}
        }
    }
    alert(`Добавлено ${success} из ${cameras.length} камер`);
    v2LoadStoredResults();
}

function v2CopySelectedUrl(ip) {
    const url = V2State.selectedStreams[ip];
    if (!url) { alert('URL недоступен'); return; }
    v2CopyUrl(url);
}

function v2CopyUrl(url) {
    if (!url) { alert('URL недоступен'); return; }
    navigator.clipboard.writeText(url).then(() => {
        const toast = document.createElement('div');
        toast.textContent = 'URL скопирован в буфер';
        toast.style.cssText = 'position:fixed;bottom:2rem;right:2rem;background:#10b981;color:#fff;padding:0.55rem 1.2rem;border-radius:8px;font-size:0.8rem;font-weight:600;z-index:99999;box-shadow:0 4px 20px rgba(0,0,0,0.4);animation:v2-fade-in 0.2s ease';
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 2200);
    });
}

function v2ShowDetails(ip) {
    const cam = V2State.results.find(c => c.ip === ip);
    if (!cam) return;
    v2OpenStreamModal(ip);
}

function v2ExportJson() {
    const json = JSON.stringify(V2State.results, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `v2_cameras_${Date.now()}.json`;
    a.click();
}

async function v2ClearResults() {
    if (!confirm('Удалить все результаты v2 из базы данных?')) return;
    await fetch('/api/v2/results', { method: 'DELETE' });
    V2State.results = [];
    v2RenderResults();
    v2UpdateResultsCount();
}

// ─────────────────────────────────────────────────────────────────────────────
// Filters
// ─────────────────────────────────────────────────────────────────────────────
function v2SetFilter(type, value) {
    V2State[type === 'brand' ? 'filterBrand' : 'filterProtocol'] = value;
    const prefix = type === 'brand' ? 'v2-filter-brand-' : 'v2-filter-proto-';
    document.querySelectorAll(`.v2-filter-btn[id^="${prefix}"]`).forEach(btn => {
        btn.classList.toggle('active', btn.dataset.value === value);
    });
    v2RenderResults();
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
function _esc(str) {
    if (!str && str !== 0) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ─────────────────────────────────────────────────────────────────────────────
// Init on page load (restore version preference)
// ─────────────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    const savedVersion = localStorage.getItem('ip2domain_cam_version');
    if (savedVersion === 'v2') {
        setTimeout(() => {
            const v2Btn = document.getElementById('cam-ver-btn-v2');
            if (v2Btn && document.getElementById('cameras-view')?.classList.contains('active')) {
                switchCameraVersion('v2');
            }
        }, 100);
    }
});

function v2CheckVersionOnTabOpen() {
    const savedVersion = localStorage.getItem('ip2domain_cam_version');
    if (savedVersion === 'v2') {
        switchCameraVersion('v2');
    }
}
