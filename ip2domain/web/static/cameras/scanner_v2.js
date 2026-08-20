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
    isStarting: false,
    pollTimer: null,
    pollInterval: 2000,
    results: [],           // CameraResult[]
    selectedStreams: {},   // { [ip]: streamUrl }
    previewCache: {},      // { [ip]: blobUrl }
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
// Target counting & CIDR/Range calculation (Pure JS)
// ─────────────────────────────────────────────────────────────────────────────
const MAX_V2_TARGETS = 5000000;

function _ipToInt(ip) {
    if (!ip || typeof ip !== 'string') return null;
    const parts = ip.trim().split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
    return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function v2CountIPsFromText(text) {
    if (!text || !text.trim()) return 0;
    const tokens = text.split(/[\s,;\n\r]+/).filter(Boolean);
    let total = 0;

    for (const token of tokens) {
        let clean = token.trim();
        if (!clean || clean.startsWith('#')) continue;

        // Skip IPv6 subnets / addresses (e.g. 2a02:f800::/29)
        if (clean.includes(':') && (clean.includes('::') || clean.split(':').length > 2)) {
            continue;
        }

        // Strip port if IPv4 with port (e.g. 1.2.3.4:554)
        if (clean.includes(':')) {
            clean = clean.split(':')[0].trim();
        }

        // 1. CIDR notation (e.g. 192.168.1.0/24)
        if (clean.includes('/')) {
            const [ip, maskStr] = clean.split('/');
            const mask = parseInt(maskStr, 10);
            if (!isNaN(mask) && mask >= 0 && mask <= 32) {
                total += Math.pow(2, 32 - mask);
                continue;
            }
        }

        // 2. Range notation (e.g. 10.0.0.1-10.0.0.255 or 10.0.0.1-255)
        if (clean.includes('-')) {
            const parts = clean.split('-');
            const startStr = parts[0].trim();
            let endStr = parts[1].trim();

            const startInt = _ipToInt(startStr);
            if (startInt !== null) {
                // Short range notation like 10.0.0.1-255
                if (!endStr.includes('.') && /^\d+$/.test(endStr)) {
                    const lastOctet = parseInt(endStr, 10);
                    if (lastOctet >= 0 && lastOctet <= 255) {
                        const startParts = startStr.split('.');
                        endStr = `${startParts[0]}.${startParts[1]}.${startParts[2]}.${lastOctet}`;
                    }
                }
                const endInt = _ipToInt(endStr);
                if (endInt !== null && endInt >= startInt) {
                    total += (endInt - startInt + 1);
                    continue;
                }
            }
        }

        // 3. Single IPv4 address
        if (_ipToInt(clean) !== null) {
            total += 1;
            continue;
        }

        // Fallback: if it looks like an IP or hostname
        if (/^[a-zA-Z0-9.-]+$/.test(clean)) {
            total += 1;
        }
    }

    return total;
}

function v2CalculateTargetsCount() {
    const textarea = document.getElementById('v2-targets');
    const counter = document.getElementById('v2-targets-counter');
    if (!textarea || !counter) return;

    const count = v2CountIPsFromText(textarea.value);
    const countFormatted = count.toLocaleString('ru-RU');
    const maxFormatted = MAX_V2_TARGETS.toLocaleString('ru-RU');

    if (count === 0) {
        counter.innerHTML = `<span style="color:rgba(255,255,255,0.45)">0 IP (макс. ${maxFormatted})</span>`;
    } else if (count > MAX_V2_TARGETS) {
        counter.innerHTML = `<span style="color:#f87171;font-weight:700">⚠️ ${countFormatted} / ${maxFormatted} IP (превышен лимит 5 млн!)</span>`;
    } else {
        const pct = ((count / MAX_V2_TARGETS) * 100).toFixed(count >= 100000 ? 1 : 2);
        counter.innerHTML = `<span style="color:#6ee7b7;font-weight:600">🎯 ${countFormatted} IP</span> <span style="color:rgba(255,255,255,0.45);font-size:0.7rem">(${pct}% от 5 млн)</span>`;
    }
}
window.v2CalculateTargetsCount = v2CalculateTargetsCount;

async function loadAsnPrefixesForV2() {
    const asnInput = document.getElementById('v2-asn-input');
    const targets = document.getElementById('v2-targets');
    if (!asnInput || !targets) return;
    const rawAsn = asnInput.value.trim().toUpperCase();
    if (!rawAsn) return;
    const asn = rawAsn.startsWith('AS') ? rawAsn.slice(2) : rawAsn;
    if (!/^\d+$/.test(asn)) {
        alert('Введите корректный номер ASN, например AS12345 или 12345');
        return;
    }
    try {
        const resp = await fetch(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}`);
        if (!resp.ok) throw new Error('Ошибка RIPE API');
        const data = await resp.json();
        // Strictly filter for IPv4 prefixes (ignore IPv6)
        const prefixes = (data?.data?.prefixes || [])
            .map(p => p.prefix)
            .filter(p => p && !p.includes(':'));
        if (!prefixes.length) {
            alert(`IPv4 префиксы для AS${asn} не найдены`);
            return;
        }
        const existing = targets.value.trim();
        targets.value = existing ? `${existing}\n${prefixes.join('\n')}` : prefixes.join('\n');
        v2CalculateTargetsCount();
    } catch (e) {
        alert(`Не удалось загрузить префиксы: ${e.message}`);
    }
}
window.loadAsnPrefixesForV2 = loadAsnPrefixesForV2;



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
    v2CalculateTargetsCount();
}


async function v2CheckActiveScan() {
    let savedJobId = localStorage.getItem('ip2domain_v2_active_job');
    if (!savedJobId) {
        try {
            const resp = await fetch('/api/v2/active_job');
            if (resp.ok) {
                const data = await resp.json();
                if (data.active && data.job) {
                    savedJobId = data.job.job_id;
                    localStorage.setItem('ip2domain_v2_active_job', savedJobId);
                }
            }
        } catch (e) {}
    }
    if (!savedJobId) {
        v2SetScanState('idle');
        v2LoadStoredResults();
        return;
    }
    try {
        const resp = await fetch(`/api/v2/scan/${savedJobId}`);
        if (!resp.ok) {
            localStorage.removeItem('ip2domain_v2_active_job');
            v2SetScanState('idle');
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
            v2SetScanState('idle');
            if (job.results && job.results.length) {
                v2MergeResults(job.results);
            }
            v2LoadStoredResults();
        }
    } catch (e) {
        v2SetScanState('idle');
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

    const startBtn = document.getElementById('v2-start-btn');
    if (V2State.isStarting || V2State.currentJobId || (startBtn && startBtn.disabled)) {
        alert('Сканирование уже выполняется. Дождитесь его завершения или нажмите «Отмена».');
        return;
    }

    const targets = document.getElementById('v2-targets').value.trim();
    if (!targets) {
        alert('Укажите IP-адреса или CIDR-диапазоны для сканирования');
        return;
    }

    // Immediately lock state & UI to prevent double click
    V2State.isStarting = true;
    v2SetScanState('running');

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
            V2State.isStarting = false;
            v2SetScanState('idle');
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
        V2State.isStarting = false;
        v2SetScanState('idle');
        alert('Ошибка сети: ' + err.message);
    } finally {
        V2State.isStarting = false;
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
    let changed = false;
    const existingMap = new Map(V2State.results.map((r, i) => [r.ip, i]));
    for (const cam of incoming) {
        if (!existingMap.has(cam.ip)) {
            V2State.results.push(cam);
            existingMap.set(cam.ip, V2State.results.length - 1);
            changed = true;
        } else {
            const idx = existingMap.get(cam.ip);
            const oldCam = V2State.results[idx];
            const oldStreamsJson = JSON.stringify(oldCam.streams || []);
            const newStreamsJson = JSON.stringify(cam.streams || []);
            if (oldStreamsJson !== newStreamsJson || oldCam.brand !== cam.brand || oldCam.model !== cam.model) {
                if (V2State.previewCache[cam.ip]) {
                    for (const s of (cam.streams || [])) {
                        if (!s.screenshot) s.screenshot = V2State.previewCache[cam.ip];
                    }
                }
                V2State.results[idx] = cam;
                changed = true;
            }
        }
    }
    if (changed) {
        v2UpdateResultsCount();
        v2RenderResults();
    }
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
        const results = data.results || [];
        V2State.results = results;
        v2UpdateResultsCount();
        v2RenderResults();
        const card = document.getElementById('v2-results-card');
        if (card) {
            card.classList.add('visible');
        }
    } catch (e) {
        console.error('[v2] Error loading stored results:', e);
    }
}


function _cameraScore(cam) {
    let score = 0;
    const streams = cam.streams || [];
    if (streams.some(s => s.screenshot && String(s.screenshot).trim().length > 0)) {
        score += 1000;
    }
    if (streams.some(s => s.verified)) {
        score += 500;
    }
    if (streams.some(s => s.type === 'http_snapshot' || (s.url && (s.url.startsWith('http://') || s.url.startsWith('https://'))))) {
        score += 200;
    }
    if (cam.brand && cam.brand !== 'Unknown' && cam.brand !== 'Generic IPCam' && cam.brand !== 'Generic RTSP') {
        score += 50;
    }
    return score;
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

    // Default sorting: cameras with preview / screenshot first!
    filtered = [...filtered].sort((a, b) => _cameraScore(b) - _cameraScore(a));

    grid.innerHTML = filtered.map(cam => v2RenderCameraCard(cam)).join('');
    initV2LazyLoading();
}

let v2ImageObserver = null;
function initV2LazyLoading() {
    if (v2ImageObserver) {
        v2ImageObserver.disconnect();
    }
    const lazyImages = document.querySelectorAll('#v2-camera-grid img.v2-lazy-img[data-src]');
    if (!lazyImages.length) return;

    function loadImg(img) {
        const src = img.getAttribute('data-src');
        if (src) {
            img.src = src;
            img.removeAttribute('data-src');
            img.onload = () => img.classList.add('v2-loaded');
            img.onerror = () => {
                img.style.display = 'none';
                const ph = img.nextElementSibling;
                if (ph) ph.style.display = 'flex';
            };
        }
        if (v2ImageObserver) {
            v2ImageObserver.unobserve(img);
        }
    }

    if ('IntersectionObserver' in window) {
        v2ImageObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    loadImg(entry.target);
                }
            });
        }, {
            root: null,
            rootMargin: '350px 0px',
            threshold: 0.01
        });

        lazyImages.forEach(img => v2ImageObserver.observe(img));
    } else {
        lazyImages.forEach(img => loadImg(img));
    }
}
window.initV2LazyLoading = initV2LazyLoading;

// ─────────────────────────────────────────────────────────────────────────────
// Camera Card (Handles 300+ streams gracefully & on-demand previews)
// ─────────────────────────────────────────────────────────────────────────────
function _streamScore(s) {
    let score = 0;
    if (s.screenshot && String(s.screenshot).trim().length > 0) score += 1000;
    if (s.verified) score += 500;
    if (s.width && s.height) score += Math.min(100, Math.floor((s.width * s.height) / 20000));
    if (s.type === 'rtsp' || (s.url && s.url.startsWith('rtsp://'))) score += 50;
    return score;
}

function v2RenderCameraCard(cam) {
    const safeIp = cam.ip.replace(/\./g, '_');
    const rawStreams = cam.streams || [];
    const totalStreams = rawStreams.length;

    // Sort streams so that the stream with a guaranteed screenshot / live verification is #1
    const streams = [...rawStreams].sort((a, b) => _streamScore(b) - _streamScore(a));

    // Determine current selected stream URL for this camera (always prioritize stream with real screenshot)
    const bestStream = streams[0];
    const curSelected = V2State.selectedStreams[cam.ip];
    const curStreamObj = streams.find(s => s.url === curSelected);

    if (!curSelected || (!curStreamObj?.screenshot && bestStream?.screenshot)) {
        V2State.selectedStreams[cam.ip] = bestStream?.url || '';
    }
    const currentStreamUrl = V2State.selectedStreams[cam.ip];
    const currentStreamObj = streams.find(s => s.url === currentStreamUrl) || streams[0];

    // Find screenshot: first check selected stream, then any stream that has a screenshot, or cached preview
    const cachedBlobUrl = V2State.previewCache[cam.ip] || '';
    const streamWithScreen = (currentStreamObj?.screenshot ? currentStreamObj : null)
        || streams.find(s => s.screenshot && s.screenshot.length > 0);
    const screenshotPath = streamWithScreen?.screenshot || cachedBlobUrl;

    // Preview area HTML
    let previewHtml = '';


    let imgSrc = '';
    if (screenshotPath) {
        if (screenshotPath.startsWith('blob:') || screenshotPath.startsWith('/api/') || screenshotPath.startsWith('http')) {
            imgSrc = screenshotPath;
        } else {
            imgSrc = `/api/v2/capture?path=${encodeURIComponent(screenshotPath)}`;
        }
    }


    if (imgSrc) {
        previewHtml = `
            <div class="v2-preview-wrapper" id="v2-preview-box-${safeIp}">
                <img class="v2-camera-screenshot v2-lazy-img"
                     data-src="${imgSrc}"
                     src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 9'%3E%3Crect width='16' height='9' fill='%230b0f19'/%3E%3C/svg%3E"
                     alt="${_esc(cam.ip)}"
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

    const verified = streams.some(s => s.verified || s.screenshot);
    const verifiedBadge = verified ? '<span class="v2-verified-badge">✓ Live</span>' : '';

    const protocols = (cam.protocols || []).slice(0, 5);
    const badges = protocols.map(p => `<span class="v2-proto-badge ${_protoBadgeClass(p)}">${_protoLabel(p)}</span>`).join('');

    // Stream selector dropdown (top 15 streams sorted by quality/preview)
    let streamSelectorHtml = '';
    if (totalStreams > 0) {
        const streamOptions = streams.slice(0, 15).map((s, idx) => {
            const shortPath = _formatShortStreamUrl(s.url);
            const isSel = s.url === currentStreamUrl ? 'selected' : '';
            let tag = '';
            if (s.screenshot) tag = ' [🖼️ Кадр]';
            else if (s.verified) tag = ' [🟢 Live]';
            else if (s.type === 'http_snapshot') tag = ' [📷 Snap]';
            return `<option value="${_esc(s.url)}" ${isSel}>#${idx + 1} ${shortPath}${tag}</option>`;
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
                <button class="v2-camera-btn" onclick="v2OpenSelectedStreamPlayer('${_esc(cam.ip)}')" title="Тест видеопотока в реальном времени (WebRTC / MSE плеер)" style="background:rgba(99,102,241,0.25);color:#c4b5fd;border:1px solid rgba(99,102,241,0.45);font-weight:600">▶ Тест</button>
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
    const cam = V2State.results.find(c => c.ip === ip);
    if (cam) {
        const safeIp = ip.replace(/\./g, '_');
        const cardEl = document.getElementById(`v2-cam-${safeIp}`);
        if (cardEl) {
            const temp = document.createElement('div');
            temp.innerHTML = v2RenderCameraCard(cam);
            const newCard = temp.firstElementChild;
            if (newCard) cardEl.replaceWith(newCard);
        }
    }
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
        V2State.previewCache[ip] = objUrl;

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
                    <button class="v2-btn-small" style="background:rgba(99,102,241,0.25);color:#c4b5fd;border:1px solid rgba(99,102,241,0.5);font-weight:600" onclick="v2OpenStreamPlayer('${_esc(s.url)}', '${_esc(cam.brand || cam.ip)}', '${_esc(cam.ip)}', ${idx})" title="Тест потока в реальном времени (WebRTC / MSE плеер)">▶ Тест</button>
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
// Real-Time Live Stream Test Player Dialog
// ─────────────────────────────────────────────────────────────────────────────
function v2OpenSelectedStreamPlayer(ip) {
    const cam = V2State.results.find(c => c.ip === ip);
    if (!cam) return;
    const streamUrl = V2State.selectedStreams[ip] || (cam.streams?.[0]?.url || '');
    const idx = (cam.streams || []).findIndex(s => s.url === streamUrl);
    v2OpenStreamPlayer(streamUrl, cam.brand || cam.ip, ip, idx >= 0 ? idx : 0);
}
window.v2OpenSelectedStreamPlayer = v2OpenSelectedStreamPlayer;

async function v2OpenStreamPlayer(srcUrl, camName, ip, currentIdx = 0) {
    if (!srcUrl) return;

    const cam = V2State.results.find(c => c.ip === ip);
    const streams = cam?.streams || [];
    const totalStreams = streams.length;

    // Create or reuse modal dialog
    let dialog = document.getElementById('v2-player-dialog');
    if (!dialog) {
        dialog = document.createElement('dialog');
        dialog.id = 'v2-player-dialog';
        dialog.className = 'centra-player-dialog';
        dialog.style.maxWidth = '940px';
        dialog.style.width = '94vw';
        dialog.style.background = '#0f172a';
        dialog.style.color = '#f8fafc';
        dialog.style.borderRadius = '16px';
        dialog.style.border = '1px solid rgba(255,255,255,0.15)';
        dialog.style.padding = '0';
        dialog.style.overflow = 'hidden';
        dialog.style.boxShadow = '0 25px 50px -12px rgba(0, 0, 0, 0.7)';

        dialog.addEventListener('close', async () => {
            const tempName = dialog.dataset.tempStreamName;
            if (tempName) {
                fetch(`/api/go2rtc/streams/${encodeURIComponent(tempName)}`, { method: "DELETE" }).catch(() => {});
                delete dialog.dataset.tempStreamName;
            }
            const iframe = dialog.querySelector('iframe');
            if (iframe) iframe.src = 'about:blank';
        });
        dialog.addEventListener('click', (event) => {
            if (event.target === dialog) dialog.close();
        });
        document.body.appendChild(dialog);
    }

    // Clean up previous temp stream if switching inside open dialog
    const prevTempName = dialog.dataset.tempStreamName;
    if (prevTempName) {
        fetch(`/api/go2rtc/streams/${encodeURIComponent(prevTempName)}`, { method: "DELETE" }).catch(() => {});
    }

    const tempName = `temp_v2_${Date.now()}`;
    dialog.dataset.tempStreamName = tempName;

    // Navigation indexes
    const prevIdx = (currentIdx - 1 + totalStreams) % totalStreams;
    const nextIdx = (currentIdx + 1) % totalStreams;
    const prevStream = totalStreams > 1 ? streams[prevIdx] : null;
    const nextStream = totalStreams > 1 ? streams[nextIdx] : null;

    dialog.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; gap: 0.75rem; padding: 0.85rem 1.2rem; background: rgba(15,23,42,0.95); border-bottom: 1px solid rgba(255,255,255,0.1);">
            <div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <span style="font-size:1.1rem">🎥</span>
                    <strong style="font-size:0.95rem">Тест видеопотока · ${_esc(ip)} (${_esc(camName)})</strong>
                    ${totalStreams > 1 ? `<span style="font-size: 0.72rem; padding: 0.15rem 0.45rem; border-radius: 6px; background: rgba(99,102,241,0.25); color: #c4b5fd; font-weight: 600;">Поток ${currentIdx + 1} из ${totalStreams}</span>` : ''}
                </div>
                <small style="display: block; color: #93c5fd; font-family: monospace; font-size: 0.72rem; overflow: hidden; text-overflow: ellipsis; margin-top: 2px;">${_esc(srcUrl)}</small>
            </div>
            <div style="display: flex; align-items: center; gap: 0.4rem; flex-shrink: 0;">
                ${totalStreams > 1 ? `
                    <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.75rem; padding: 0.3rem 0.6rem; border-radius:6px; background:rgba(255,255,255,0.06); color:#cbd5e1; border:1px solid rgba(255,255,255,0.1);" title="Предыдущий поток" onclick="v2OpenStreamPlayer('${_esc(prevStream.url)}', '${_esc(camName)}', '${_esc(ip)}', ${prevIdx})">◀ Назад</button>
                    <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.75rem; padding: 0.3rem 0.6rem; border-radius:6px; background:rgba(255,255,255,0.06); color:#cbd5e1; border:1px solid rgba(255,255,255,0.1);" title="Следующий поток" onclick="v2OpenStreamPlayer('${_esc(nextStream.url)}', '${_esc(camName)}', '${_esc(ip)}', ${nextIdx})">Вперед ▶</button>
                ` : ''}
                <button type="button" class="btn btn-small" style="background: #10b981; color:#fff; font-size: 0.75rem; font-weight:600; padding:0.3rem 0.65rem; border-radius:6px; border:none; cursor:pointer;" onclick="v2AddSpecificStreamToGo2rtc('${_esc(ip)}', '${_esc(srcUrl)}', ${currentIdx+1}); this.disabled=true; this.textContent='✓ Добавлено';">+ В go2rtc</button>
                <button type="button" style="background:none; border:none; color:#94a3b8; font-size:1.4rem; cursor:pointer; padding:0 4px; line-height:1;" onclick="document.getElementById('v2-player-dialog').close()" aria-label="Закрыть">×</button>
            </div>
        </div>
        <div style="position: relative; width: 100%; aspect-ratio: 16/9; background: #000; display: flex; align-items: center; justify-content: center; overflow: hidden;">
            <div id="v2-modal-loader" style="display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 0.75rem; color: #cbd5e1;">
                <span class="v2-spinner" style="width: 32px; height: 32px; border-width:3px; border-top-color:#6366f1;"></span>
                <span style="font-size: 0.85rem; color:#a5b4fc;">Подключение к видеопотоку (WebRTC / MSE)...</span>
            </div>
            <iframe id="v2-modal-iframe" style="display: none; width: 100%; height: 100%; border: none;" allow="autoplay; fullscreen"></iframe>
            
            ${totalStreams > 1 ? `
                <button type="button" style="position: absolute; left: 12px; top: 50%; transform: translateY(-50%); width: 40px; height: 40px; border-radius: 50%; background: rgba(15,23,42,0.8); border: 1px solid rgba(255,255,255,0.25); color: #fff; display: flex; align-items: center; justify-content: center; cursor: pointer; backdrop-filter: blur(6px); transition: all 0.2s; z-index: 10; font-size:1.1rem;" onmouseover="this.style.background='rgba(99,102,241,0.9)'" onmouseout="this.style.background='rgba(15,23,42,0.8)'" onclick="v2OpenStreamPlayer('${_esc(prevStream.url)}', '${_esc(camName)}', '${_esc(ip)}', ${prevIdx})" title="Предыдущий поток (#${prevIdx+1})">◀</button>
                <button type="button" style="position: absolute; right: 12px; top: 50%; transform: translateY(-50%); width: 40px; height: 40px; border-radius: 50%; background: rgba(15,23,42,0.8); border: 1px solid rgba(255,255,255,0.25); color: #fff; display: flex; align-items: center; justify-content: center; cursor: pointer; backdrop-filter: blur(6px); transition: all 0.2s; z-index: 10; font-size:1.1rem;" onmouseover="this.style.background='rgba(99,102,241,0.9)'" onmouseout="this.style.background='rgba(15,23,42,0.8)'" onclick="v2OpenStreamPlayer('${_esc(nextStream.url)}', '${_esc(camName)}', '${_esc(ip)}', ${nextIdx})" title="Следующий поток (#${nextIdx+1})">▶</button>
            ` : ''}
        </div>
        ${totalStreams > 1 ? `
            <div style="display: flex; gap: 0.4rem; padding: 0.5rem 0.8rem; background: rgba(10, 14, 26, 0.98); overflow-x: auto; border-top: 1px solid rgba(255,255,255,0.08); align-items: center;" class="v2-modal-playlist">
                <span style="font-size: 0.72rem; color: #94a3b8; white-space: nowrap; margin-right: 0.3rem; font-weight: 600;">Каналы (${totalStreams}):</span>
                ${streams.map((st, i) => {
                    const isCur = i === currentIdx;
                    const stUrl = st.url || "";
                    const stType = (st.type || st.stream_type || 'RTSP').toUpperCase();
                    const live = st.verified ? '✓' : '';
                    return `
                        <button type="button" id="v2-stream-pill-${i}" class="v2-btn-small" style="font-size: 0.7rem; padding: 0.25rem 0.55rem; white-space: nowrap; border-radius: 6px; ${isCur ? 'background: rgba(99,102,241,0.9); color: #fff; border: 1px solid #a5b4fc; font-weight: 700; box-shadow: 0 0 10px rgba(99,102,241,0.6);' : 'background: rgba(255,255,255,0.06); color: #cbd5e1; border: 1px solid rgba(255,255,255,0.1);'}" onclick="v2OpenStreamPlayer('${_esc(stUrl)}', '${_esc(camName)}', '${_esc(ip)}', ${i})">
                            ${isCur ? '▶ ' : ''}#${i+1} · ${_esc(stType)} ${live}
                        </button>
                    `;
                }).join('')}
            </div>
        ` : ''}
    `;

    if (!dialog.open) {
        dialog.showModal();
    }

    try {
        const isHttpSnapshot = srcUrl.startsWith('http://') || srcUrl.startsWith('https://');

        if (isHttpSnapshot) {
            const iframe = document.getElementById('v2-modal-iframe');
            const loader = document.getElementById('v2-modal-loader');
            const playerContainer = iframe ? iframe.parentElement : null;
            if (playerContainer) {
                if (loader) loader.style.display = 'none';
                if (iframe) iframe.style.display = 'none';

                playerContainer.innerHTML = `
                    <div style="position: relative; width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; background: #000;">
                        <img id="v2-modal-live-img" src="/api/v2/preview?ip=${encodeURIComponent(ip)}&stream_url=${encodeURIComponent(srcUrl)}&_t=${Date.now()}" alt="Live Snapshot" style="max-width: 100%; max-height: 100%; object-fit: contain;" onerror="this.style.display='none'; const el=document.getElementById('v2-modal-live-err'); if(el) el.style.display='flex';">
                        <div id="v2-modal-live-err" style="display: none; flex-direction: column; align-items: center; justify-content: center; gap: 0.5rem; color: #ef4444; font-size: 0.85rem;">
                            <span>⚠️ Поток недоступен (камера не отвечает по HTTP)</span>
                        </div>
                        <div style="position: absolute; bottom: 12px; right: 12px; display: flex; gap: 6px; background: rgba(0,0,0,0.6); padding: 4px 8px; border-radius: 6px;">
                            <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.72rem; padding: 3px 8px; border-radius:4px; background:rgba(255,255,255,0.1); color:#fff;" onclick="const img=document.getElementById('v2-modal-live-img'); const err=document.getElementById('v2-modal-live-err'); if(img){ img.style.display=''; img.src='/api/v2/preview?ip=${encodeURIComponent(ip)}&stream_url=${encodeURIComponent(srcUrl)}&_t='+Date.now(); } if(err) err.style.display='none';">🔄 Обновить</button>
                        </div>
                    </div>
                `;
            }
            return;
        }

        // RTSP / RTMP stream via go2rtc WebRTC/MSE
        const regResp = await fetch("/api/go2rtc/streams", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name: tempName,
                url: [srcUrl, `ffmpeg:${srcUrl}#video=h264#audio=aac`]
            })
        });
        if (!regResp.ok) {
            const err = await regResp.json();
            throw new Error(err.detail || "Не удалось запустить временный поток в go2rtc");
        }

        const iframe = document.getElementById('v2-modal-iframe');
        const loader = document.getElementById('v2-modal-loader');
        if (iframe && loader) {
            iframe.src = `/api/go2rtc/player/stream.html?src=${encodeURIComponent(tempName)}`;
            iframe.onload = () => {
                loader.style.display = 'none';
                iframe.style.display = 'block';
            };
            setTimeout(() => {
                loader.style.display = 'none';
                iframe.style.display = 'block';
            }, 800);
        }

    } catch (err) {
        const loader = document.getElementById('v2-modal-loader');
        if (loader) {
            loader.innerHTML = `<span style="color:#ef4444">⚠️ Ошибка запуска плеера: ${_esc(err.message)}</span>`;
        }
    }
}
window.v2OpenStreamPlayer = v2OpenStreamPlayer;


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
    v2LoadTools();
    v2RenderCredentials();
    v2LoadStoredResults();

    const savedVersion = localStorage.getItem('ip2domain_cam_version');
    if (savedVersion === 'v2') {
        setTimeout(() => {
            const v2Btn = document.getElementById('cam-ver-btn-v2');
            if (v2Btn) {
                switchCameraVersion('v2');
            }
        }, 50);
    }
});

function v2CheckVersionOnTabOpen() {
    const savedVersion = localStorage.getItem('ip2domain_cam_version');
    if (savedVersion === 'v2') {
        switchCameraVersion('v2');
    } else {
        v2LoadStoredResults();
    }
}

