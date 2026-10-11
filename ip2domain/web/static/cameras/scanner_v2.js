/* Camera Scanner v2 Client (Auto-bundled from scanner_v2/) */
'use strict';


// ════════════════════════════════════════════════════════════════
// MODULE: scanner_v2/targets.js
// ════════════════════════════════════════════════════════════════

// ── Camera Scanner v2: Targets, CIDR Math, Tools & Credentials ─────────

const V2State = window.V2State || {
    currentJobId: null,
    isStarting: false,
    pollTimer: null,
    pollInterval: 2000,
    results: [],           // CameraResult[]
    selectedStreams: {},   // { [ip]: streamUrl }
    previewCache: {},      // { [ip]: blobUrl }
    filterBrand: 'all',
    filterCategory: 'all',
    filterProtocol: 'all',
    filterGeo: 'all',
    geoSearch: '',
    filterStatus: 'all',   // all | live | preview
    filterAuth: 'all',     // all | open | 401
    totalInDb: 0,
    visibleCount: 48,
    pageSize: 48,
    isLoadingResults: false,
    resultsLoaded: false,
    credentials: [
        { user: 'admin', password: '' },
        { user: 'admin', password: 'admin' },
        { user: 'admin', password: '12345' },
        { user: 'admin', password: '123456' },
        { user: 'admin', password: '12345admin' },
        { user: 'admin', password: 'admin123' },
        { user: 'admin', password: 'admin12345' },
        { user: 'root',  password: '' },
        { user: 'root',  password: 'root' },
        { user: 'root',  password: 'pass' },
        { user: 'root',  password: '123456' },
        { user: 'service', password: 'service' },
    ],
};
window.V2State = V2State;

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

function switchCameraVersion(version) {
    const v1Tabs   = document.querySelectorAll('.camera-tab');
    const v1Panels = document.querySelectorAll('.camera-tab-panel');
    const v2Panel  = document.getElementById('camera-v2-panel');
    const btn1 = document.getElementById('cam-ver-btn-v1');
    const btn2 = document.getElementById('cam-ver-btn-v2');

    if (version === 'v2') {
        v1Tabs.forEach(t => t.style.display = 'none');
        v1Panels.forEach(p => { p.style.display = 'none'; p.classList.remove('active'); });
        if (v2Panel) v2Panel.classList.add('v2-active');
        if (btn1) btn1.classList.remove('active');
        if (btn2) btn2.classList.add('active', 'active-v2');
        localStorage.setItem('ip2domain_cam_version', 'v2');
        v2OnActivate();
    } else {
        v1Tabs.forEach(t => t.style.display = '');
        if (v2Panel) v2Panel.classList.remove('v2-active');
        if (btn1) btn1.classList.add('active');
        if (btn2) btn2.classList.remove('active', 'active-v2');
        localStorage.setItem('ip2domain_cam_version', 'v1');
        const activeTab = document.querySelector('.camera-tab.active');
        if (activeTab) {
            const tabId = activeTab.id.replace('camera-', '').replace('-tab', '');
            if (window.switchCameraTab) switchCameraTab(tabId);
        } else {
            if (window.switchCameraTab) switchCameraTab('go2rtc');
        }
    }
}
window.switchCameraVersion = switchCameraVersion;

function v2OnActivate() {
    v2LoadTools();
    v2RenderCredentials();
    if (window.v2LoadStoredResults) v2LoadStoredResults();
    v2CheckActiveScan();
    v2CalculateTargetsCount();
}
window.v2OnActivate = v2OnActivate;

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
        if (window.v2SetScanState) v2SetScanState('idle');
        return;
    }
    try {
        const resp = await fetch(`/api/v2/scan/${savedJobId}`);
        if (!resp.ok) {
            localStorage.removeItem('ip2domain_v2_active_job');
            if (window.v2SetScanState) v2SetScanState('idle');
            return;
        }
        const job = await resp.json();
        if (['queued', 'running'].includes(job.status)) {
            V2State.currentJobId = savedJobId;
            if (window.v2ShowProgress) v2ShowProgress();
            if (window.v2SetScanState) v2SetScanState('running');
            if (window.v2UpdateProgress) v2UpdateProgress(job);
            if (window.v2MergeResults) v2MergeResults(job.results || []);
            if (window.v2StartPolling) v2StartPolling();
        } else {
            localStorage.removeItem('ip2domain_v2_active_job');
            if (window.v2SetScanState) v2SetScanState('idle');
            if (job.results && job.results.length && window.v2MergeResults) {
                v2MergeResults(job.results);
            }
        }
    } catch (e) {
        if (window.v2SetScanState) v2SetScanState('idle');
    }
}
window.v2CheckActiveScan = v2CheckActiveScan;

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
window.v2LoadTools = v2LoadTools;

function v2ToolBadge(name, ok, cls) {
    const c = cls || (ok ? 'ok' : 'missing');
    const icon = ok ? '✓' : '✗';
    return `<span class="v2-tool-badge ${c}">${icon} ${name}</span>`;
}

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
window.v2RenderCredentials = v2RenderCredentials;

function v2RemoveCred(idx) {
    V2State.credentials.splice(idx, 1);
    v2RenderCredentials();
}
window.v2RemoveCred = v2RemoveCred;

function v2AddCred() {
    V2State.credentials.push({ user: '', password: '' });
    v2RenderCredentials();
    const inputs = document.querySelectorAll('#v2-creds-list .v2-cred-row input[type="text"]');
    if (inputs.length) inputs[inputs.length - 1].focus();
}
window.v2AddCred = v2AddCred;

function v2OnRateChange(val) {
    const display = document.getElementById('v2-rate-display');
    if (display) display.textContent = Number(val).toLocaleString() + ' pps';
}
window.v2OnRateChange = v2OnRateChange;


// ════════════════════════════════════════════════════════════════
// MODULE: scanner_v2/scan.js
// ════════════════════════════════════════════════════════════════

// ── Camera Scanner v2: Scan Lifecycle, Polling, Stages & Logs ──────────

async function v2StartScan(event) {
    if (event) event.preventDefault();

    const startBtn = document.getElementById('v2-start-btn');
    if (window.V2State.isStarting || window.V2State.currentJobId || (startBtn && startBtn.disabled)) {
        alert('Сканирование уже выполняется. Дождитесь его завершения или нажмите «Отмена».');
        return;
    }

    const targets = document.getElementById('v2-targets').value.trim();
    if (!targets) {
        alert('Укажите IP-адреса или CIDR-диапазоны для сканирования');
        return;
    }

    // Immediately lock state & UI to prevent double click
    window.V2State.isStarting = true;
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
        credentials: window.V2State.credentials.filter(c => c.user),
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
            window.V2State.isStarting = false;
            v2SetScanState('idle');
            alert('Ошибка запуска: ' + (data.detail || resp.status));
            return;
        }
        window.V2State.currentJobId = data.job_id;
        localStorage.setItem('ip2domain_v2_active_job', data.job_id);
        window.V2State.results = [];

        v2ShowProgress();
        v2SetScanState('running');
        v2StartPolling();
    } catch (err) {
        window.V2State.isStarting = false;
        v2SetScanState('idle');
        alert('Ошибка сети: ' + err.message);
    } finally {
        window.V2State.isStarting = false;
    }
}
window.v2StartScan = v2StartScan;

function v2SetScanState(state) {
    const startBtn = document.getElementById('v2-start-btn');
    const cancelBtn = document.getElementById('v2-cancel-btn');
    const spinner = document.getElementById('v2-start-spinner');
    if (state === 'running') {
        if (startBtn) startBtn.disabled = true;
        if (cancelBtn) cancelBtn.classList.add('visible');
        if (spinner) spinner.style.display = 'inline-block';
    } else {
        if (startBtn) startBtn.disabled = false;
        if (cancelBtn) cancelBtn.classList.remove('visible');
        if (spinner) spinner.style.display = 'none';
    }
}
window.v2SetScanState = v2SetScanState;

async function v2CancelScan() {
    if (!window.V2State.currentJobId) return;
    const jid = window.V2State.currentJobId;
    localStorage.removeItem('ip2domain_v2_active_job');
    window.V2State.currentJobId = null;
    v2StopPolling();
    v2SetScanState('idle');
    try {
        await fetch(`/api/v2/scan/${jid}/cancel`, { method: 'POST' });
        v2AddLog('Сканирование отменено пользователем.', 'warn');
    } catch (e) {}
}
window.v2CancelScan = v2CancelScan;

function v2StartPolling() {
    v2StopPolling();
    window.V2State.pollTimer = setInterval(v2Poll, window.V2State.pollInterval);
    v2Poll();
}
window.v2StartPolling = v2StartPolling;

function v2StopPolling() {
    if (window.V2State.pollTimer) {
        clearInterval(window.V2State.pollTimer);
        window.V2State.pollTimer = null;
    }
}
window.v2StopPolling = v2StopPolling;

async function v2Poll() {
    if (!window.V2State.currentJobId) return;
    try {
        const resp = await fetch(`/api/v2/scan/${window.V2State.currentJobId}`);
        if (!resp.ok) {
            if (resp.status === 404) {
                localStorage.removeItem('ip2domain_v2_active_job');
                window.V2State.currentJobId = null;
                v2StopPolling();
                v2SetScanState('idle');
            }
            return;
        }
        const job = await resp.json();
        v2UpdateProgress(job);
        if (window.v2MergeResults) v2MergeResults(job.results || []);

        if (['completed', 'cancelled', 'error'].includes(job.status)) {
            localStorage.removeItem('ip2domain_v2_active_job');
            window.V2State.currentJobId = null;
            v2StopPolling();
            v2SetScanState('idle');
            if (job.status === 'completed') {
                v2AddLog(`✓ Сканирование завершено. Найдено ${job.results_count} камер.`, 'ok');
            } else if (job.status === 'error') {
                v2AddLog(`✗ Ошибка: ${job.error}`, 'err');
            }
            if (window.v2LoadStoredResults) v2LoadStoredResults();
        }
    } catch (e) {}
}
window.v2Poll = v2Poll;

function v2ShowProgress() {
    const pCard = document.getElementById('v2-progress-card');
    const rCard = document.getElementById('v2-results-card');
    const lPanel = document.getElementById('v2-log-panel');
    if (pCard) pCard.classList.add('visible');
    if (rCard) rCard.classList.add('visible');
    if (lPanel) lPanel.innerHTML = '';
    v2ResetStages();
}
window.v2ShowProgress = v2ShowProgress;

function v2ResetStages() {
    ['discovery', 'port_sweep', 'fingerprint', 'capture', 'geolocation'].forEach(s => {
        v2SetStageStatus(s, 'pending');
    });
    const fill = document.getElementById('v2-progress-fill');
    const pct = document.getElementById('v2-progress-pct');
    if (fill) fill.style.width = '0%';
    if (pct) pct.textContent = '0%';
}
window.v2ResetStages = v2ResetStages;

const _STAGE_IDS = {
    discovery: 'v2-stage-discovery',
    port_sweep: 'v2-stage-sweep',
    fingerprint: 'v2-stage-finger',
    capture: 'v2-stage-capture',
    geolocation: 'v2-stage-geo',
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
window.v2SetStageStatus = v2SetStageStatus;

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
    v2SetStageStatus('geolocation', stages.geolocation?.status || 'pending',
        stages.geolocation?.completed > 0 ? `${stages.geolocation.completed} гео` : '—');

    const pct = job.progress_pct || 0;
    const fill = document.getElementById('v2-progress-fill');
    const pctEl = document.getElementById('v2-progress-pct');
    if (fill) fill.style.width = pct + '%';
    if (pctEl) pctEl.textContent = pct + '%';

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
window.v2UpdateProgress = v2UpdateProgress;

function v2AddLog(msg, cls) {
    const logPanel = document.getElementById('v2-log-panel');
    if (!logPanel) return;
    const div = document.createElement('div');
    div.className = cls ? `log-${cls}` : '';
    div.textContent = msg;
    logPanel.appendChild(div);
    logPanel.scrollTop = logPanel.scrollHeight;
}
window.v2AddLog = v2AddLog;


// ════════════════════════════════════════════════════════════════
// MODULE: scanner_v2/results.js
// ════════════════════════════════════════════════════════════════

// ── Camera Scanner v2: Results, Cards, Badges & Frame Previews ─────────

function v2MergeResults(incoming) {
    if (!incoming || !incoming.length) return;
    let changed = false;
    const existingMap = new Map(window.V2State.results.map((r, i) => [r.ip, i]));
    for (const cam of incoming) {
        if (!existingMap.has(cam.ip)) {
            window.V2State.results.push(cam);
            existingMap.set(cam.ip, window.V2State.results.length - 1);
            changed = true;
        } else {
            const idx = existingMap.get(cam.ip);
            const oldCam = window.V2State.results[idx];
            if (JSON.stringify(oldCam) !== JSON.stringify(cam)) {
                window.V2State.results[idx] = cam;
                changed = true;
            }
        }
    }
    if (changed) {
        v2UpdateResultsCount();
        v2RenderResults();
    }
}
window.v2MergeResults = v2MergeResults;

function v2UpdateResultsCount(filteredCount) {
    const el = document.getElementById('v2-results-count');
    if (!el) return;
    const results = window.V2State.results || [];
    const totalLoaded = results.length;
    const totalDb = window.V2State.totalInDb || totalLoaded;
    const total = Math.max(totalLoaded, totalDb);

    let camCount = 0;
    let routerCount = 0;
    let webCount = 0;
    let sprecordCount = 0;
    let screenCount = 0;
    let verifiedCount = 0;

    for (const c of results) {
        if (_isSpRecord(c)) {
            sprecordCount++;
        } else if (_isRouterDevice(c)) {
            routerCount++;
        } else if (_isCameraDevice(c)) {
            camCount++;
        } else if (_isWebDevice(c)) {
            webCount++;
        }

        const hasScreen = (c.streams || []).some(s => s.screenshot && String(s.screenshot).trim().length > 0);
        if (hasScreen) screenCount++;
        const isVerified = (c.streams || []).some(s => s.verified || (s.screenshot && String(s.screenshot).trim().length > 0));
        if (isVerified) verifiedCount++;
    }

    const fmt = n => Number(n).toLocaleString('ru-RU');

    const details = [];
    if (camCount > 0) details.push(`🎥 ${fmt(camCount)} камер`);
    if (routerCount > 0) details.push(`🌐 ${fmt(routerCount)} роутеров`);
    if (webCount > 0) details.push(`💻 ${fmt(webCount)} веб`);
    if (sprecordCount > 0) details.push(`🎙️ ${fmt(sprecordCount)} SpRecord`);
    if (screenCount > 0) details.push(`🖼️ ${fmt(screenCount)} превью`);
    else if (verifiedCount > 0) details.push(`✓ ${fmt(verifiedCount)} подтверждено`);

    const subText = details.length ? ` <span class="v2-count-sub">(${details.join(' · ')})</span>` : '';

    if (filteredCount !== undefined && filteredCount !== total) {
        el.innerHTML = `<strong>${fmt(filteredCount)}</strong> из ${fmt(total)} устройств${subText}`;
    } else {
        el.innerHTML = `<strong>${fmt(total)}</strong> устройств${subText}`;
    }
}
window.v2UpdateResultsCount = v2UpdateResultsCount;

async function v2LoadStoredResults(force = false) {
    if (window.V2State.isLoadingResults) {
        if (force) window.V2State.reloadResultsAfterLoad = true;
        return;
    }
    if (!force && window.V2State.resultsLoaded && (window.V2State.results || []).length > 0) {
        v2RenderResults();
        return;
    }
    window.V2State.isLoadingResults = true;
    try {
        const resp = await fetch('/api/v2/results?limit=100000');
        if (!resp.ok) return;
        const data = await resp.json();
        const results = data.results || [];
        window.V2State.results = results;
        window.V2State.totalInDb = data.total_db || results.length;
        window.V2State.resultsLoaded = true;
        v2UpdateResultsCount();
        v2RenderResults();
        const card = document.getElementById('v2-results-card');
        if (card) {
            card.classList.add('visible');
        }
    } catch (e) {
        console.error('[v2] Error loading stored results:', e);
    } finally {
        window.V2State.isLoadingResults = false;
        if (window.V2State.reloadResultsAfterLoad) {
            window.V2State.reloadResultsAfterLoad = false;
            v2LoadStoredResults(true);
        }
    }
}
window.v2LoadStoredResults = v2LoadStoredResults;

const _V2_CAMERA_BRAND_PATTERNS = [
    'hikvision', 'hiwatch', 'dahua', 'axis', 'reolink', 'trassir', 'xiongmai', 'flussonic',
    'streamer', 'dnvrs', 'rvi', 'uniview', 'unv', 'tiandy', 'mobotix', 'generic nvr', 'generic dvr',
    'generic ipcam', 'generic webcam', 'generic surveillance', 'generic video server', 'generic rtsp',
    'unknown camera', 'tp-link', 'ezviz', 'hilook', 'imou', 'lorex', 'foscam', 'amcrest', 'hanwha',
    'wisenet', 'samsung', 'topsvision', 'topsee', 'jovision', 'h264', 'netip', 'netsurveillance',
    'cp plus', 'bosch', 'pelco', 'vivotek', 'grandstream', 'beward', 'activecam', 'polyvision',
    'novicam', 'ltv', 'milesight', 'tvt', 'sunell', 'avigilon', 'flir', 'ubiquiti unifi', 'tapo',
    'tl-sc', 'vstarcam', 'sricam', 'srihome', 'herospeed', 'onvif', 'unimo', 'udrocx', 'ants',
    'vvtk', 'nd8322p'
];

const _V2_CAMERA_PROTOCOLS = [
    'onvif', 'rtsp', 'rtsp_direct', 'dhip', 'sofia', 'hls', 'webrtc', 'isapi',
    'dahua_cgi', 'hikvision_isapi', 'rtmp'
];

function _isSpRecord(cam) {
    if (!cam) return false;
    const b = (cam.brand || '').toLowerCase();
    const m = (cam.model || '').toLowerCase();
    const p = cam.protocols || [];
    return b.includes('sprecord') || m.includes('sprecord') || p.includes('sprecord_audio') || p.includes('sprecord');
}
window._isSpRecord = _isSpRecord;

function _hasCategory(c, cat) {
    if (!c || !cat) return false;
    if (c.device_category === cat) return true;
    if (Array.isArray(c.categories) && c.categories.includes(cat)) return true;
    return false;
}
window._hasCategory = _hasCategory;

function _isRouterDevice(c) {
    if (!c) return false;
    if (_hasCategory(c, 'router')) return true;
    const protos = c.protocols || [];
    return protos.includes('router') || protos.includes('winbox');
}
window._isRouterDevice = _isRouterDevice;

function _isIntercomDevice(c) {
    if (!c) return false;
    return _hasCategory(c, 'intercom');
}
window._isIntercomDevice = _isIntercomDevice;

function _isIotDevice(c) {
    if (!c) return false;
    return _hasCategory(c, 'iot') || _hasCategory(c, 'industrial');
}
window._isIotDevice = _isIotDevice;

function _isServerDevice(c) {
    if (!c) return false;
    return _hasCategory(c, 'server');
}
window._isServerDevice = _isServerDevice;

function _isCameraDevice(c) {
    if (!c || _isSpRecord(c)) return false;
    if (_hasCategory(c, 'camera')) return true;
    if (_hasCategory(c, 'intercom')) return true;

    // Brand matches known camera brand
    const brand = (c.brand || '').toLowerCase();
    if (_V2_CAMERA_BRAND_PATTERNS.some(b => brand.includes(b))) return true;

    // Known camera protocols
    const protos = c.protocols || [];
    if (_V2_CAMERA_PROTOCOLS.some(p => protos.includes(p))) return true;

    // Verified stream or real screenshot
    if ((c.streams || []).some(s => s.verified || (s.screenshot && String(s.screenshot).trim().length > 0))) return true;

    // Has RTSP or video stream
    if ((c.streams || []).some(s => s.type === 'rtsp' || s.type === 'rtsps' || s.type === 'mjpeg')) return true;

    // If pure non-camera without video
    if (c.device_category === 'router' || c.device_category === 'generic_web' || c.device_category === 'device' || c.device_category === 'iot' || c.device_category === 'server') return false;

    // Has video streams and is not generic web
    if ((c.streams || []).length > 0 && !brand.includes('generic web device')) return true;

    return false;
}
window._isCameraDevice = _isCameraDevice;

function _isNetworkDevice(c) {
    if (!c || _isSpRecord(c)) return false;
    return c.device_category === 'device' || (c.protocols || []).includes('tcp');
}
window._isNetworkDevice = _isNetworkDevice;

function _isWebDevice(c) {
    if (!c || _isSpRecord(c)) return false;
    if (_hasCategory(c, 'generic_web')) return true;
    const brand = (c.brand || '').toLowerCase();
    if (brand.includes('generic web device') || brand.includes('web service')) return true;
    return false;
}
window._isWebDevice = _isWebDevice;

function _cameraScore(cam) {
    let score = 0;
    if (_isSpRecord(cam)) {
        score += 8500;
    }
    const streams = cam.streams || [];
    // Priority 1: Real preview screenshot captured and available - ALWAYS FIRST
    if (streams.some(s => s.screenshot && String(s.screenshot).trim().length > 0)) {
        score += 10000;
    }
    // Priority 2: Verified live stream
    if (streams.some(s => s.verified)) {
        score += 5000;
    }
    // Priority 3: HTTP snapshot stream
    if (streams.some(s => s.type === 'http_snapshot' || (s.url && (s.url.startsWith('http://') || s.url.startsWith('https://'))))) {
        score += 2000;
    }
    // Priority 4: RTSP stream
    if (streams.some(s => s.type === 'rtsp' || (s.url && s.url.startsWith('rtsp://')))) {
        score += 500;
    }
    if (cam.brand && cam.brand !== 'Unknown' && cam.brand !== 'Generic IPCam' && cam.brand !== 'Generic RTSP') {
        score += 50;
    }
    return score;
}

function v2UpdateGeoDropdown() {
    const select = document.getElementById('v2-filter-geo');
    if (!select) return;

    const curVal = window.V2State.filterGeo || 'all';
    const citiesMap = new Map();
    const regionsMap = new Map();
    let ruCount = 0, byCount = 0, noGeoCount = 0;

    (window.V2State.results || []).forEach(cam => {
        if (cam.city) {
            citiesMap.set(cam.city, (citiesMap.get(cam.city) || 0) + 1);
        }
        if (cam.region) {
            regionsMap.set(cam.region, (regionsMap.get(cam.region) || 0) + 1);
        }
        const cc = (cam.country_code || '').toUpperCase();
        if (cc === 'RU') ruCount++;
        else if (cc === 'BY') byCount++;

        if (!cam.city && !cam.region) noGeoCount++;
    });

    let html = '<option value="all">Все регионы и города</option>';

    if (ruCount > 0 || byCount > 0) {
        html += '<optgroup label="Страны">';
        if (ruCount > 0) html += `<option value="country:RU">🇷🇺 Россия (${ruCount})</option>`;
        if (byCount > 0) html += `<option value="country:BY">🇧🇾 Беларусь (${byCount})</option>`;
        html += '</optgroup>';
    }

    if (citiesMap.size > 0) {
        html += '<optgroup label="Города">';
        const sortedCities = Array.from(citiesMap.entries()).sort((a, b) => b[1] - a[1]);
        sortedCities.forEach(([city, count]) => {
            html += `<option value="city:${_esc(city)}">📍 ${_esc(city)} (${count})</option>`;
        });
        html += '</optgroup>';
    }

    if (regionsMap.size > 0) {
        html += '<optgroup label="Регионы / Области">';
        const sortedRegions = Array.from(regionsMap.entries()).sort((a, b) => b[1] - a[1]);
        sortedRegions.forEach(([region, count]) => {
            html += `<option value="region:${_esc(region)}">🗺️ ${_esc(region)} (${count})</option>`;
        });
        html += '</optgroup>';
    }

    if (noGeoCount > 0) {
        html += `<optgroup label="Другое"><option value="__no_geo__">Без гео-привязки (${noGeoCount})</option></optgroup>`;
    }

    select.innerHTML = html;
    select.value = curVal;
    if (select.value !== curVal && curVal !== 'all') {
        select.value = 'all';
    }
}
window.v2UpdateGeoDropdown = v2UpdateGeoDropdown;

function _isCam401(c) {
    return c.auth_required === true || (c.streams || []).some(s => s.auth_required === true);
}

window._isCam401 = _isCam401;

function v2GetFilteredResults() {
    let filtered = window.V2State.results || [];
    if (window.V2State.filterCategory && window.V2State.filterCategory !== 'all') {
        const cat = window.V2State.filterCategory;
        if (cat === 'sprecord') {
            filtered = filtered.filter(c => _isSpRecord(c));
        } else if (cat === 'camera') {
            filtered = filtered.filter(c => _isCameraDevice(c));
        } else if (cat === 'router') {
            filtered = filtered.filter(c => _isRouterDevice(c));
        } else if (cat === 'intercom') {
            filtered = filtered.filter(c => _isIntercomDevice(c));
        } else if (cat === 'iot') {
            filtered = filtered.filter(c => _isIotDevice(c));
        } else if (cat === 'server') {
            filtered = filtered.filter(c => _isServerDevice(c));
        } else if (cat === 'generic_web') {
            filtered = filtered.filter(c => _isWebDevice(c));
        } else if (cat === 'device') {
            filtered = filtered.filter(c => _isNetworkDevice(c));
        }
    }
    if (window.V2State.filterBrand && window.V2State.filterBrand !== 'all') {
        filtered = filtered.filter(c => (c.brand || '').toLowerCase().includes(window.V2State.filterBrand.toLowerCase()));
    }
    if (window.V2State.filterProtocol && window.V2State.filterProtocol !== 'all') {
        if (window.V2State.filterProtocol === 'sprecord_audio' || window.V2State.filterProtocol === 'sprecord') {
            filtered = filtered.filter(c => _isSpRecord(c));
        } else {
            filtered = filtered.filter(c => (c.protocols || []).includes(window.V2State.filterProtocol));
        }
    }
    if (window.V2State.filterStatus === 'live') {
        filtered = filtered.filter(c =>
            _isSpRecord(c) || (c.streams || []).some(s => s.verified || (s.screenshot && String(s.screenshot).trim().length > 0))
        );
    } else if (window.V2State.filterStatus === 'preview') {
        filtered = filtered.filter(c =>
            _isSpRecord(c) || (c.streams || []).some(s => s.screenshot && String(s.screenshot).trim().length > 0)
        );
    }
    if (window.V2State.filterAuth === 'open') {
        filtered = filtered.filter(c => (c.streams || []).some(s => s.verified));
    } else if (window.V2State.filterAuth === '401') {
        filtered = filtered.filter(c => _isCam401(c));
    }
    if (window.V2State.filterGeo && window.V2State.filterGeo !== 'all') {
        if (window.V2State.filterGeo === '__no_geo__') {
            filtered = filtered.filter(c => !c.city && !c.region);
        } else if (window.V2State.filterGeo.startsWith('country:')) {
            const cCode = window.V2State.filterGeo.replace('country:', '').toUpperCase();
            filtered = filtered.filter(c => (c.country_code || '').toUpperCase() === cCode);
        } else if (window.V2State.filterGeo.startsWith('region:')) {
            const reg = window.V2State.filterGeo.replace('region:', '').toLowerCase();
            filtered = filtered.filter(c => (c.region || '').toLowerCase() === reg);
        } else if (window.V2State.filterGeo.startsWith('city:')) {
            const cit = window.V2State.filterGeo.replace('city:', '').toLowerCase();
            filtered = filtered.filter(c => (c.city || '').toLowerCase() === cit);
        }
    }
    if (window.V2State.geoSearch && window.V2State.geoSearch.trim()) {
        const q = window.V2State.geoSearch.trim().toLowerCase();
        filtered = filtered.filter(c =>
            (c.city || '').toLowerCase().includes(q) ||
            (c.region || '').toLowerCase().includes(q) ||
            (c.isp || '').toLowerCase().includes(q) ||
            (c.ip || '').includes(q)
        );
    }
    return filtered;
}
window.v2GetFilteredResults = v2GetFilteredResults;

function v2RenderResults() {
    const grid = document.getElementById('v2-camera-grid');
    if (!grid) return;

    let filtered = v2GetFilteredResults();
    v2UpdateResultsCount(filtered.length);
    v2UpdateGeoDropdown();

    const paginationContainer = document.getElementById('v2-pagination-container');

    if (!filtered.length) {
        grid.innerHTML = `<div class="v2-empty-state" style="grid-column:1/-1">
            <div class="v2-empty-icon">🌐</div>
            <p>Устройства не найдены по выбранным фильтрам.</p>
            ${window.V2State.filterGeo !== 'all' || window.V2State.geoSearch ? `<button type="button" class="v2-btn-small" onclick="v2ClearGeoFilter()" style="margin-top:0.5rem">Сбросить гео-фильтр</button>` : ''}
        </div>`;
        if (paginationContainer) paginationContainer.style.display = 'none';
        return;
    }

    // Default sorting: cameras with preview / screenshot first!
    filtered = [...filtered].sort((a, b) => _cameraScore(b) - _cameraScore(a));

    const pageSize = window.V2State.pageSize || 48;
    const visibleCount = Math.min(window.V2State.visibleCount || pageSize, filtered.length);
    const visibleCams = filtered.slice(0, visibleCount);

    grid.innerHTML = visibleCams.map(cam => v2RenderCameraCard(cam)).join('');
    initV2LazyLoading();
    v2RenderPagination(visibleCount, filtered.length);
}
window.v2RenderResults = v2RenderResults;

function v2RenderPagination(visibleCount, totalCount) {
    let container = document.getElementById('v2-pagination-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'v2-pagination-container';
        container.className = 'v2-pagination-bar';
        const card = document.getElementById('v2-results-card');
        if (card) {
            card.appendChild(container);
        }
    }
    if (!container) return;

    const pageSize = window.V2State.pageSize || 48;
    if (visibleCount >= totalCount) {
        container.innerHTML = totalCount > pageSize ? `
            <div class="v2-pagination-info">✓ Показаны все ${totalCount} камер</div>
        ` : '';
        container.style.display = totalCount > pageSize ? 'flex' : 'none';
        return;
    }

    const remaining = totalCount - visibleCount;
    const nextBatch = Math.min(pageSize, remaining);
    container.style.display = 'flex';
    container.innerHTML = `
        <div class="v2-pagination-info">Показано <strong>${visibleCount}</strong> из <strong>${totalCount}</strong> камер</div>
        <div class="v2-pagination-actions">
            <button type="button" class="v2-btn-load-more" onclick="v2LoadMoreResults()">
                ⬇ Загрузить ещё ${nextBatch}
            </button>
            <button type="button" class="v2-btn-show-all" onclick="v2ShowAllResults()">
                Показать все (${totalCount})
            </button>
        </div>
    `;
}
window.v2RenderPagination = v2RenderPagination;

function v2LoadMoreResults() {
    const step = window.V2State.pageSize || 48;
    window.V2State.visibleCount = (window.V2State.visibleCount || step) + step;
    v2RenderResults();
}
window.v2LoadMoreResults = v2LoadMoreResults;

function v2ShowAllResults() {
    window.V2State.visibleCount = (window.V2State.results || []).length;
    v2RenderResults();
}
window.v2ShowAllResults = v2ShowAllResults;

function _sanitizeV2ImageUrl(url) {
    if (!url || typeof url !== 'string') return '';
    const trimmed = url.trim();
    if (trimmed.startsWith('/') || trimmed.startsWith('data:image/') || trimmed.startsWith('blob:') || /^https?:\/\//i.test(trimmed)) {
        return trimmed;
    }
    return '';
}

function initV2LazyLoading() {
    // Native loading="lazy" handled by browser
}
window.initV2LazyLoading = initV2LazyLoading;

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
    const isAudioDevice = _isSpRecord(cam);
    const isRouter = _isRouterDevice(cam);
    const isCamera = _isCameraDevice(cam);
    const isWebDevice = !isCamera && _isWebDevice(cam);
    const isNetworkDevice = !isCamera && !isRouter && !isWebDevice && _isNetworkDevice(cam);
    const isNonCamera = isRouter || isWebDevice || isNetworkDevice;

    const webPort = cam.http_port || (cam.open_ports && cam.open_ports.find(p => [80, 443, 8080, 8443, 8081, 8888, 8181, 9443, 10443, 8000, 8008, 7547].includes(p))) || 80;
    const isHttps = [443, 8443, 9443, 10443].includes(webPort) || String(webPort).includes('443');
    const targetHost = cam.domain || cam.ip;
    const webUrl = cam.web_url || `${isHttps ? 'https' : 'http'}://${targetHost}:${webPort}/`;

    const rawStreams = cam.streams || [];
    const totalStreams = rawStreams.length;

    // Sort streams so that the stream with a guaranteed screenshot / live verification is #1
    const streams = [...rawStreams].sort((a, b) => _streamScore(b) - _streamScore(a));

    // Determine current selected stream URL for this camera (always prioritize stream with real screenshot)
    const bestStream = streams[0];
    const curSelected = window.V2State.selectedStreams[cam.ip];
    const curStreamObj = streams.find(s => s.url === curSelected);

    if (!curSelected || !curStreamObj) {
        window.V2State.selectedStreams[cam.ip] = bestStream?.url || (isNonCamera ? webUrl : '');
    }
    const currentStreamUrl = window.V2State.selectedStreams[cam.ip];
    const currentStreamObj = streams.find(s => s.url === currentStreamUrl) || streams[0];
    const endpoint = (cam.endpoints || []).find(e => e.port === currentStreamObj?.source_port);
    const displayBrand = endpoint?.brand || cam.brand || 'Unknown';
    const displayModel = endpoint?.model || cam.model || '';
    const endpointPorts = [...new Set((cam.endpoints || []).map(e => e.port).filter(Boolean))];

    // A frame belongs to exactly one URL, including its port and channel.
    const previewKey = JSON.stringify([cam.ip, currentStreamUrl]);
    const cachedBlobUrl = window.V2State.previewCache[previewKey] || '';
    const screenshotPath = cam.web_screenshot || currentStreamObj?.screenshot || cachedBlobUrl;

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

    if (isAudioDevice) {
        const recordCountMatch = (cam.model || '').match(/\(([^)]+)\)/);
        const recordCountStr = recordCountMatch ? recordCountMatch[1] : `${cam.total_records || '132 300+'} записей`;
        previewHtml = `
            <div class="v2-sprecord-preview-wrapper" id="v2-preview-box-${safeIp}">
                <div class="v2-sprecord-eq-container">
                    <span class="v2-sprecord-eq-bar"></span>
                    <span class="v2-sprecord-eq-bar"></span>
                    <span class="v2-sprecord-eq-bar"></span>
                    <span class="v2-sprecord-eq-bar"></span>
                    <span class="v2-sprecord-eq-bar"></span>
                    <span class="v2-sprecord-eq-bar"></span>
                    <span class="v2-sprecord-eq-bar"></span>
                </div>
                <div class="v2-sprecord-banner-title">🎙️ SpRecord Audio Server</div>
                <div class="v2-sprecord-banner-count">${_esc(recordCountStr)}</div>
                <button class="v2-sprecord-card-listen-btn" onclick="v2OpenSpRecordPlayer('${_esc(cam.ip)}')">
                    ▶ Слушать записи
                </button>
            </div>
        `;
    } else if (imgSrc) {
        previewHtml = `
            <div class="v2-preview-wrapper" id="v2-preview-box-${safeIp}">
                <img class="v2-camera-screenshot"
                     src="${_esc(imgSrc)}"
                     loading="lazy"
                     alt="${_esc(cam.ip)}"
                     onload="this.classList.add('v2-loaded')"
                     onerror="this.style.display='none';const ph=document.getElementById('v2-ph-${safeIp}');if(ph)ph.style.display='flex'">
                <div class="v2-camera-screenshot-placeholder" id="v2-ph-${safeIp}" style="display:none">
                    <div class="v2-placeholder-inner">
                        <span>📷</span>
                        <button class="v2-capture-now-btn" onclick="v2CapturePreview('${_esc(cam.ip)}', event)">▶ Загрузить превью</button>
                    </div>
                </div>
                <button class="v2-refresh-preview-btn" onclick="v2CapturePreview('${_esc(cam.ip)}', event)" title="Обновить снимок">🔄 Обновить</button>
            </div>
        `;
    } else if (isNonCamera) {
        const icon = isRouter ? '🌐' : (isWebDevice ? '💻' : '🖥️');
        const defaultTitle = isRouter ? 'Роутер / Сетевой шлюз' : (isWebDevice ? 'Веб-сервер / Сервис' : 'Сетевое устройство');
        previewHtml = `
            <div class="v2-preview-wrapper" id="v2-preview-box-${safeIp}">
                <div class="v2-camera-screenshot-placeholder" style="background: radial-gradient(circle at 50% 30%, rgba(30, 41, 59, 0.8), rgba(15, 23, 42, 0.95))">
                    <div class="v2-placeholder-inner">
                        <span style="font-size:2rem">${icon}</span>
                        <div style="font-size:0.75rem;color:#94a3b8;margin-bottom:8px;font-weight:600;max-width:90%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${_esc(cam.web_title || defaultTitle)}">${_esc(cam.web_title || defaultTitle)}</div>
                        <button class="v2-capture-now-btn" onclick="v2CapturePreview('${_esc(cam.ip)}', event)" title="Сделать скриншот веб-страницы">
                            ▶ Скриншот страницы
                        </button>
                    </div>
                </div>
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

    const verified = streams.some(s => s.verified) || Boolean(cam.web_screenshot);
    let verifiedBadge = '';
    let authBadge = '';

    if (isAudioDevice) {
        verifiedBadge = '<span class="v2-verified-badge" style="background:#059669">🎙️ Аудиосервер</span>';
        authBadge = '<span class="v2-auth-badge auth-open">🔓 admin: без пароля</span>';
    } else if (isRouter) {
        verifiedBadge = '<span class="v2-verified-badge" style="background:#0284c7">🌐 Роутер</span>';
        authBadge = cam.auth_required
            ? '<span class="v2-auth-badge auth-locked" title="Требуется авторизация">🔒 Доступ по паролю</span>'
            : '<span class="v2-auth-badge auth-open">✓ Веб-панель активна</span>';
    } else if (isWebDevice) {
        verifiedBadge = '<span class="v2-verified-badge" style="background:#475569">💻 Веб-сервис</span>';
        authBadge = cam.auth_required
            ? '<span class="v2-auth-badge auth-locked" title="Требуется авторизация">🔒 Доступ по паролю</span>'
            : '<span class="v2-auth-badge auth-open">✓ Сервис онлайн</span>';
    } else if (isNetworkDevice) {
        verifiedBadge = '<span class="v2-verified-badge" style="background:#334155">🖥️ Сетевой хост</span>';
        authBadge = '<span class="v2-auth-badge auth-open">✓ Порты открыты</span>';
    } else {
        verifiedBadge = verified ? '<span class="v2-verified-badge">✓ Live</span>' : '';
        const is401 = _isCam401(cam);
        authBadge = is401
            ? '<span class="v2-auth-badge auth-locked" title="Один или несколько сервисов требуют авторизацию">🔒 Требуется авторизация</span>'
            : (verified
                ? '<span class="v2-auth-badge auth-open">✓ Видео подтверждено</span>'
                : '<span class="v2-auth-badge">○ Видео не подтверждено</span>');
    }

    let credsBadge = '';
    if (cam.credentials && cam.credentials.user) {
        const pw = cam.credentials.password ? `:${_esc(cam.credentials.password)}` : '';
        credsBadge = `<span style="font-size:0.7rem;color:#34d399;margin-left:6px;background:rgba(16,185,129,0.15);padding:1px 5px;border-radius:3px;font-weight:600">🔑 ${_esc(cam.credentials.user)}${pw}</span>`;
    }

    const protocols = (cam.protocols || []).slice(0, 5);
    const badges = protocols.map(p => `<span class="v2-proto-badge ${_protoBadgeClass(p)}">${_protoLabel(p)}</span>`).join('');

    // Stream selector dropdown (top 15 streams sorted by quality/preview)
    const hasMediaStreams = streams.some(s => s.stream_type === 'rtsp' || s.stream_type === 'rtmp' || s.stream_type === 'hls');
    let streamSelectorHtml = '';
    if (isAudioDevice) {
        const recordCountMatch = (cam.model || '').match(/\(([^)]+)\)/);
        const recordCountStr = recordCountMatch ? recordCountMatch[1] : `${cam.total_records || '132 300+'} записей`;
        streamSelectorHtml = `
            <div class="v2-stream-selector-row">
                <div class="v2-stream-info-header">
                    <span style="color:rgba(255,255,255,0.45)">Сервер разговоров:</span>
                    <span class="v2-stream-count-badge" onclick="v2OpenSpRecordPlayer('${_esc(cam.ip)}')" title="Открыть аудиоплеер звонков" style="background:rgba(16,185,129,0.2);color:#34d399;border-color:rgba(16,185,129,0.4);cursor:pointer">
                        🎙️ ${_esc(recordCountStr)}
                    </span>
                </div>
                <div style="font-size:0.75rem;color:#94a3b8;margin-top:4px;display:flex;align-items:center;justify-content:space-between">
                    <span>🌐 Портал: <strong style="color:#e2e8f0">${_esc(cam.ip)}:${cam.http_port || 8002}</strong></span>
                    <button type="button" class="v2-btn-small" onclick="v2OpenSpRecordPlayer('${_esc(cam.ip)}')" style="padding:2px 8px;font-size:0.75rem;background:rgba(16,185,129,0.25);color:#34d399;border:1px solid rgba(16,185,129,0.4)">▶ Записи</button>
                </div>
            </div>
        `;
    } else if (isNonCamera && !hasMediaStreams) {
        const titleText = cam.web_title || (isRouter ? 'Панель управления' : (isWebDevice ? 'Веб-сервис' : 'Сетевой узел'));
        streamSelectorHtml = `
            <div class="v2-stream-selector-row">
                <div class="v2-stream-info-header">
                    <span style="color:rgba(255,255,255,0.45)">Веб-интерфейс:</span>
                    <span class="v2-stream-count-badge" onclick="window.open('${_esc(webUrl)}', '_blank')" title="Открыть веб-интерфейс в новой вкладке" style="background:rgba(2,132,199,0.2);color:#38bdf8;border-color:rgba(2,132,199,0.4);cursor:pointer">
                        🌐 ${_esc(titleText)}
                    </span>
                </div>
                <div style="font-size:0.75rem;color:#94a3b8;margin-top:4px;display:flex;align-items:center;justify-content:space-between;gap:6px">
                    <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${_esc(webUrl)}">
                        🔗 <a href="${_esc(webUrl)}" target="_blank" rel="noopener noreferrer" style="color:#38bdf8;text-decoration:none">${_esc(webUrl)}</a>
                    </span>
                    <button type="button" class="v2-btn-small" onclick="window.open('${_esc(webUrl)}', '_blank')" style="padding:2px 8px;font-size:0.75rem;background:rgba(2,132,199,0.25);color:#38bdf8;border:1px solid rgba(2,132,199,0.4);white-space:nowrap">↗ Открыть</button>
                </div>
            </div>
        `;
    } else if (totalStreams > 0) {
        const streamOptions = streams.map((s, idx) => {
            const shortPath = _esc(s.url);
            const isSel = s.url === currentStreamUrl ? 'selected' : '';
            let tag = '';
            if (s.screenshot) tag = ' [🖼️ Кадр]';
            else if (s.verified) tag = ' [🟢 Live]';
            else tag = s.verification_status === 'failed' ? ' [нет кадра]' : ' [не проверен]';
            return `<option value="${_esc(s.url)}" ${isSel}>#${idx + 1} ${shortPath}${tag}</option>`;
        }).join('');

        const moreOption = '';

        const confirmedStreams = streams.filter(s => s.verified).length;
        const streamCountText = `${confirmedStreams} подтверждено · ${totalStreams} URL`;

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

    let locationHtml = '';
    if (cam.city || cam.region || cam.country_code) {
        const flag = cam.country_code === 'BY' ? '🇧🇾' : cam.country_code === 'RU' ? '🇷🇺' : '';
        const country = cam.country_code === 'RU' ? 'Россия' : cam.country_code === 'BY' ? 'Беларусь' : cam.country_code;
        const label = cam.city || `${cam.region || country} · город не определён`;
        const filter = cam.city ? `city:${cam.city}` : cam.region ? `region:${cam.region}` : `country:${cam.country_code}`;
        const accuracy = cam.geo_accuracy_radius_km != null ? ` · радиус оценки ${cam.geo_accuracy_radius_km} км` : '';
        const title = `Оценка местоположения по IP${accuracy}${cam.geo_database_date ? ' · база от ' + cam.geo_database_date : ''}`;
        locationHtml = `<div class="v2-camera-location" onclick="v2SetGeoFilter('${_esc(filter)}')" title="${_esc(title)}">
            <span class="v2-geo-pin">📍</span><strong class="v2-geo-city">${flag} ${_esc(label)}</strong>
            ${cam.city && cam.region && cam.region !== cam.city ? `<span class="v2-geo-region">${_esc(cam.region)}</span>` : ''}
            <span class="v2-geo-region">GeoIP${_esc(accuracy)}</span>
        </div>`;
    }

    let actionsHtml = '';
    if (isAudioDevice) {
        actionsHtml = `
            <div class="v2-camera-actions">
                <button class="v2-camera-btn" onclick="v2OpenSpRecordPlayer('${_esc(cam.ip)}')" title="Открыть аудиоплеер разговоров" style="background:rgba(16,185,129,0.25);color:#6ee7b7;border:1px solid rgba(16,185,129,0.5);font-weight:700">▶ Слушать записи</button>
                <button class="v2-camera-btn" onclick="window.open('http://${_esc(cam.ip)}:${cam.http_port || 8002}/', '_blank')" title="Открыть веб-интерфейс SpRecord Web" style="background:rgba(59,130,246,0.2);color:#93c5fd;border:1px solid rgba(59,130,246,0.4)">🌐 SpRecord Web</button>
                <button class="v2-camera-btn" onclick="v2ShowDetails('${_esc(cam.ip)}')" title="Подробности">ℹ️</button>
            </div>
        `;
    } else if (isNonCamera && !hasMediaStreams) {
        actionsHtml = `
            <div class="v2-camera-actions">
                <button class="v2-camera-btn" onclick="window.open('${_esc(webUrl)}', '_blank')" title="Открыть веб-интерфейс в новой вкладке" style="background:rgba(2,132,199,0.25);color:#38bdf8;border:1px solid rgba(2,132,199,0.45);font-weight:600">🌐 Открыть веб</button>
                <button class="v2-camera-btn" onclick="v2CapturePreview('${_esc(cam.ip)}', event)" title="Снять скриншот веб-страницы" style="background:rgba(59,130,246,0.2);color:#93c5fd;border:1px solid rgba(59,130,246,0.4)">📷 Скриншот</button>
                <button class="v2-camera-btn" onclick="navigator.clipboard.writeText('${_esc(webUrl)}');alert('Скопировано: ${_esc(webUrl)}')" title="Скопировать URL веб-интерфейса">📋</button>
                <button class="v2-camera-btn" onclick="v2ShowDetails('${_esc(cam.ip)}')" title="Подробности">ℹ️</button>
            </div>
        `;
    } else {
        const hasWebInterface = Boolean(cam.http_port || (cam.open_ports && cam.open_ports.some(p => [80, 443, 8080, 8443, 8081, 8888, 8181, 9443, 10443, 8000, 8008, 7547, 8001].includes(p))));
        const webBtn = hasWebInterface ? `<button class="v2-camera-btn" onclick="window.open('${_esc(webUrl)}', '_blank')" title="Открыть веб-интерфейс (${_esc(webUrl)})" style="background:rgba(2,132,199,0.2);color:#38bdf8;border:1px solid rgba(2,132,199,0.4)">🌐 Веб</button>` : '';
        actionsHtml = `
            <div class="v2-camera-actions">
                <button class="v2-camera-btn" onclick="v2OpenSelectedStreamPlayer('${_esc(cam.ip)}')" title="Тест видеопотока в реальном времени (WebRTC / MSE плеер)" style="background:rgba(99,102,241,0.25);color:#c4b5fd;border:1px solid rgba(99,102,241,0.45);font-weight:600">▶ Тест</button>
                ${goBtn}
                ${webBtn}
                <button class="v2-camera-btn" onclick="v2CopySelectedUrl('${_esc(cam.ip)}')" title="Скопировать выбранный URL">📋</button>
                <button class="v2-camera-btn" onclick="v2OpenStreamModal('${_esc(cam.ip)}')" title="Просмотр всех ${totalStreams} потоков">⚡ ${totalStreams}</button>
                <button class="v2-camera-btn" onclick="v2ShowDetails('${_esc(cam.ip)}')" title="Подробности">ℹ️</button>
            </div>
        `;
    }

    return `<div class="v2-camera-card" id="v2-cam-${safeIp}">
        ${previewHtml}
        <div style="position:absolute;top:8px;left:8px;display:flex;gap:5px;z-index:3">
            ${verifiedBadge}
            ${authBadge}
        </div>
        <div class="v2-camera-body">
            <div class="v2-camera-brand">${_esc(displayBrand)}</div>
            <div class="v2-camera-ip">${_esc(cam.ip)}${endpoint?.port ? ':' + endpoint.port : (cam.rtsp_port ? ':' + cam.rtsp_port : '')}${credsBadge}</div>
            ${cam.domain ? `<div style="font-size:0.75rem;color:#38bdf8;font-weight:600;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${_esc(cam.domain)}">🌐 ${_esc(cam.domain)}</div>` : ''}
            ${locationHtml}
            <div class="v2-camera-model">${_esc(displayModel)}</div>
            ${endpointPorts.length > 1 ? `<div class="v2-camera-model">Порты: ${endpointPorts.join(', ')}</div>` : ''}
            <div class="v2-proto-badges">${badges}</div>
            ${streamSelectorHtml}
            ${actionsHtml}
        </div>
    </div>`;
}
window.v2RenderCameraCard = v2RenderCameraCard;

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
    if (p.includes('sofia')) return 'sofia';
    if (p.includes('dhip')) return 'dhip';
    return 'generic';
}

function _protoLabel(p) {
    const MAP = {
        onvif: 'ONVIF', hikvision_isapi: 'ISAPI', dahua_cgi: 'Dahua',
        axis_cgi: 'Axis', rtsp_direct: 'RTSP', rtmp: 'RTMP',
        hls: 'HLS', mjpeg: 'MJPEG', http_snapshot: 'SNAP',
        http_generic: 'HTTP', rtsp_port_open: 'RTSP?',
        xiongmai_sofia: 'SOFIA:34567', dahua_dhip: 'DHIP:37777',
        embed: 'EMBED',
    };
    return MAP[p] || p.toUpperCase().slice(0, 11);
}

function v2OnStreamChange(ip, streamUrl) {
    if (streamUrl === '__open_modal__') {
        v2OpenStreamModal(ip);
        const sel = document.getElementById(`v2-select-${ip.replace(/\./g, '_')}`);
        if (sel && window.V2State.selectedStreams[ip]) sel.value = window.V2State.selectedStreams[ip];
        return;
    }
    window.V2State.selectedStreams[ip] = streamUrl;
    const cam = (window.V2State.results || []).find(c => c.ip === ip);
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
window.v2OnStreamChange = v2OnStreamChange;

async function v2CapturePreview(ip, event) {
    if (event) event.stopPropagation();
    const safeIp = ip.replace(/\./g, '_');
    let box = document.getElementById(`v2-preview-box-${safeIp}`);
    const cam = (window.V2State.results || []).find(c => c.ip === ip);
    const isRouter = _isRouterDevice(cam);
    const isCamera = _isCameraDevice(cam);
    const isWebDevice = !isCamera && _isWebDevice(cam);
    const isNetworkDevice = !isCamera && !isRouter && !isWebDevice && _isNetworkDevice(cam);
    const isNonCamera = isRouter || isWebDevice || isNetworkDevice;

    let streamUrl = window.V2State.selectedStreams[ip] || '';
    if (!streamUrl && cam) {
        streamUrl = cam.web_url || (cam.streams && cam.streams[0]?.url) || '';
        if (!streamUrl && isNonCamera) {
            const p = cam.http_port || (cam.open_ports && cam.open_ports[0]) || 80;
            const scheme = [443, 8443, 9443, 10443].includes(p) ? 'https' : 'http';
            streamUrl = `${scheme}://${ip}:${p}/`;
        }
    }

    if (!streamUrl) {
        alert('Нет URL потока или веб-адреса для захвата кадра');
        return false;
    }

    if (box) {
        box.innerHTML = `
            <div class="v2-placeholder-inner" style="background:rgba(0,0,0,0.7)">
                <div class="v2-spinner" style="width:24px;height:24px;border-width:3px"></div>
                <span style="font-size:0.7rem;color:#6ee7b7">${isNonCamera ? 'Захват веб-скриншота...' : 'Захват кадра...'}</span>
            </div>
        `;
    }

    const selected = (cam?.streams || []).find(s => s.url === streamUrl);
    const credentials = selected?.credentials ?? cam?.credentials ?? {};
    const user = credentials.user || '';
    const pass = credentials.password || '';

    try {
        const previewUrl = `/api/v2/preview?ip=${encodeURIComponent(ip)}&stream_url=${encodeURIComponent(streamUrl)}&user=${encodeURIComponent(user)}&password=${encodeURIComponent(pass)}&_t=${Date.now()}`;
        const resp = await fetch(previewUrl);

        if (!resp.ok) {
            if (selected) {
                selected.verified = false;
                selected.screenshot = '';
                selected.verification_status = 'failed';
            }
            const failedKey = JSON.stringify([ip, streamUrl]);
            if (window.V2State.previewCache[failedKey]) URL.revokeObjectURL(window.V2State.previewCache[failedKey]);
            delete window.V2State.previewCache[failedKey];
            if (window.V2State.selectedStreams[ip] === streamUrl) {
                v2OnStreamChange(ip, streamUrl);
                box = document.getElementById(`v2-preview-box-${safeIp}`);
            }
            v2UpdateResultsCount();
            if (box && window.V2State.selectedStreams[ip] === streamUrl) {
                box.innerHTML = `
                    <div class="v2-placeholder-inner">
                        <span style="font-size:1.6rem">⚠️</span>
                        <span style="font-size:0.65rem;color:#fca5a5">${isNonCamera ? 'Скриншот недоступен' : 'Поток не ответил'}</span>
                        <button class="v2-capture-now-btn" onclick="v2CapturePreview('${_esc(ip)}', event)">Повторить</button>
                    </div>
                `;
            }
            return false;
        }

        const blob = await resp.blob();
        const objUrl = URL.createObjectURL(blob);
        const previewKey = JSON.stringify([ip, streamUrl]);
        const previousBlob = window.V2State.previewCache[previewKey];
        if (previousBlob) URL.revokeObjectURL(previousBlob);
        window.V2State.previewCache[previewKey] = objUrl;

        if (cam) {
            cam.web_screenshot = objUrl;
            for (const s of (cam.streams || [])) {
                if (s.url === streamUrl || s.type === 'web_panel') {
                    s.verified = true;
                    s.verification_status = 'verified';
                    s.auth_required = false;
                    s.screenshot = objUrl;
                }
            }
        }

        if (box) {
            box.innerHTML = `
                <img class="v2-camera-screenshot" src="${objUrl}" alt="${_esc(ip)}">
                <button class="v2-refresh-preview-btn" onclick="v2CapturePreview('${_esc(ip)}', event)" title="Обновить снимок">🔄 Обновить</button>
            `;
        }

        const card = document.getElementById(`v2-cam-${safeIp}`);
        if (card && !card.querySelector('.v2-verified-badge')) {
            const badge = document.createElement('span');
            badge.className = 'v2-verified-badge';
            badge.textContent = isNonCamera ? (isRouter ? '🌐 Роутер' : '💻 Веб-сервис') : '✓ Live';
            card.appendChild(badge);
        }

        const camObj = (window.V2State.results || []).find(c => c.ip === ip);
        if (camObj && !camObj.geo_source) {
            fetch(`/api/geo/lookup?ip=${encodeURIComponent(ip)}`)
                .then(r => r.json())
                .then(j => {
                    if (j.found && j.data) {
                        camObj.city = j.data.city || '';
                        camObj.region = j.data.region || '';
                        camObj.country_code = j.data.country_code || '';
                        camObj.isp = j.data.isp || '';
                        camObj.geo_source = j.data.source || j.source || '';
                        camObj.geo_precision = j.data.precision || 'unknown';
                        camObj.geo_accuracy_radius_km = j.data.accuracy_radius_km;
                        camObj.geo_database_date = j.data.database_date || '';
                        v2RenderResults();
                    }
                }).catch(() => {});
        }

        return true;
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
        return false;
    }
}
window.v2CapturePreview = v2CapturePreview;


// ════════════════════════════════════════════════════════════════
// MODULE: scanner_v2/player.js
// ════════════════════════════════════════════════════════════════

// ── Camera Scanner v2: Stream Modal & Video Player Dialog ──────────────

if (typeof window._esc !== 'function') {
    window._esc = function(str) {
        if (str == null) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    };
}
if (typeof window._protoBadgeClass !== 'function') {
    window._protoBadgeClass = function(p) {
        if (!p) return 'generic';
        p = p.toLowerCase();
        if (p.includes('onvif')) return 'onvif';
        if (p.includes('hikvision')) return 'hikvision';
        if (p.includes('dahua')) return 'dahua';
        if (p.includes('axis')) return 'axis';
        if (p.includes('hls')) return 'hls';
        if (p.includes('mjpeg')) return 'mjpeg';
        if (p.includes('rtmp')) return 'rtmp';
        if (p.includes('rtsp')) return 'rtsp';
        return 'generic';
    };
}
if (typeof window.v2CopyUrl !== 'function') {
    window.v2CopyUrl = function(url) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(url).then(() => {
                _showStreamToast('✓ URL потока скопирован');
            }).catch(() => _fallbackCopy(url));
        } else {
            _fallbackCopy(url);
        }
        function _fallbackCopy(text) {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            ta.remove();
            _showStreamToast('✓ URL скопирован');
        }
        function _showStreamToast(msg) {
            const toast = document.createElement('div');
            toast.textContent = msg;
            toast.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:rgba(16,185,129,0.95);color:#fff;padding:8px 16px;border-radius:8px;font-size:13px;z-index:999999;box-shadow:0 4px 12px rgba(0,0,0,0.3);';
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 2500);
        }
    };
}
if (typeof window.v2AddSpecificStreamToGo2rtc !== 'function') {
    window.v2AddSpecificStreamToGo2rtc = async function(ip, streamUrl, channelIdx) {
        const safeIp = ip.replace(/\./g, '_');
        const streamName = `v2_${safeIp}_ch${channelIdx}`;
        try {
            const isHttp = streamUrl.startsWith('http://') || streamUrl.startsWith('https://');
            const urls = isHttp ? [streamUrl] : [streamUrl, `ffmpeg:${streamUrl}#video=copy`];
            const resp = await fetch("/api/go2rtc/streams", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    name: streamName,
                    url: urls
                })
            });
            if (resp.ok) {
                alert(`Поток #${channelIdx} (${streamName}) успешно добавлен в go2rtc!`);
            } else {
                const data = await resp.json().catch(() => ({}));
                alert('Ошибка добавления: ' + (data.detail || resp.statusText));
            }
        } catch (e) {
            alert('Ошибка сети: ' + e.message);
        }
    };
}

window._v2LiveSnapshotTimer = null;

function v2ToggleLiveSnapshot(ip, streamUrl) {
    const badge = document.getElementById('v2-modal-live-badge');
    const toggleBtn = document.getElementById('v2-modal-live-toggle');
    if (window._v2LiveSnapshotTimer) {
        clearInterval(window._v2LiveSnapshotTimer);
        window._v2LiveSnapshotTimer = null;
        if (badge) {
            badge.style.color = '#94a3b8';
            badge.innerHTML = '⏸ На паузе';
        }
        if (toggleBtn) {
            toggleBtn.style.borderColor = 'rgba(255,255,255,0.2)';
            toggleBtn.style.background = 'rgba(255,255,255,0.08)';
            toggleBtn.textContent = '▶ Запуск';
        }
    } else {
        if (badge) {
            badge.style.color = '#10b981';
            badge.innerHTML = '🟢 Realtime Live';
        }
        if (toggleBtn) {
            toggleBtn.style.borderColor = '#10b981';
            toggleBtn.style.background = 'rgba(16,185,129,0.2)';
            toggleBtn.textContent = '⏸ Пауза';
        }
        v2RefreshSingleSnapshot(ip, streamUrl);
        window._v2LiveSnapshotTimer = setInterval(() => {
            v2RefreshSingleSnapshot(ip, streamUrl);
        }, 1200);
    }
}
window.v2ToggleLiveSnapshot = v2ToggleLiveSnapshot;

function v2RefreshSingleSnapshot(ip, streamUrl) {
    const img = document.getElementById('v2-modal-live-img');
    const err = document.getElementById('v2-modal-live-err');
    if (img) {
        const userInput = document.getElementById('v2-player-user-input')?.value.trim();
        const passInput = document.getElementById('v2-player-pass-input')?.value;
        const cam = (window.V2State.results || []).find(c => c.ip === ip);
        const u = (userInput !== undefined && userInput !== '') ? userInput : (cam?.credentials?.user || '');
        const p = (passInput !== undefined && passInput !== '') ? passInput : (cam?.credentials?.password ?? '');
        let nextUrl = `/api/v2/preview?ip=${encodeURIComponent(ip)}&stream_url=${encodeURIComponent(streamUrl)}&_t=${Date.now()}`;
        if (u) {
            nextUrl += `&user=${encodeURIComponent(u)}&password=${encodeURIComponent(p)}`;
        }
        const testImg = new Image();
        testImg.onload = () => {
            img.src = nextUrl;
            img.style.display = '';
            if (err) err.style.display = 'none';
        };
        testImg.onerror = () => {
            if (err && !img.complete) err.style.display = 'flex';
        };
        testImg.src = nextUrl;
    }
}
window.v2RefreshSingleSnapshot = v2RefreshSingleSnapshot;

function v2OpenStreamModal(ip) {
    const cam = (window.V2State.results || []).find(c => c.ip === ip);
    if (!cam) return;

    document.getElementById('v2-stream-modal-overlay')?.remove();

    const streams = cam.streams || [];
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
                    <span class="v2-stream-count-badge">${streams.filter(s => s.verified).length} подтверждено · ${streams.length} URL</span>
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
window.v2OpenStreamModal = v2OpenStreamModal;

function _renderModalStreamItems(cam, streams) {
    if (!streams.length) {
        return '<div style="text-align:center;padding:2rem;color:rgba(255,255,255,0.4)">Потоки не найдены</div>';
    }

    return streams.map((s, idx) => {
        const type = (s.type || s.stream_type || 'rtsp').toUpperCase();
        const verBadge = s.verified ? '<span class="v2-verified-badge" style="position:static;display:inline-block;padding:0.1rem 0.35rem;font-size:0.55rem">✓ Live</span>' : '';
        const source = (cam.endpoints || []).find(e => e.port === s.source_port);
        const sourceLabel = source ? `${source.brand || ''} ${source.model || ''} · порт ${source.port}` : '';
        const resText = s.resolution ? `<span style="color:rgba(255,255,255,0.4);font-size:0.65rem">${s.resolution}</span>` : '';

        return `
            <div class="v2-stream-item">
                <div style="display:flex;align-items:center;gap:0.5rem;flex:1;min-width:0">
                    <span style="font-size:0.7rem;color:rgba(255,255,255,0.3);min-width:28px">#${idx + 1}</span>
                    <span class="v2-proto-badge ${_protoBadgeClass(type.toLowerCase())}">${type}</span>
                    ${s.screenshot ? `<img loading="lazy" width="96" height="54" style="object-fit:contain" src="${_esc(s.screenshot.startsWith('blob:') ? s.screenshot : '/api/v2/capture?path=' + encodeURIComponent(s.screenshot))}" alt="Кадр потока ${idx + 1}">` : ''}
                    <span class="v2-stream-item-url" title="${_esc(s.url)}">${_esc(s.url)}</span>
                    ${verBadge} ${resText}
                    ${sourceLabel ? `<small>${_esc(sourceLabel)}</small>` : ''}
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
    const cam = (window.V2State.results || []).find(c => c.ip === ip);
    if (!cam) return;
    const list = document.getElementById('v2-modal-stream-list');
    if (!list) return;

    const q = (query || '').toLowerCase().trim();
    const filtered = (cam.streams || []).filter(s => (s.url || '').toLowerCase().includes(q) || (s.type || s.stream_type || '').toLowerCase().includes(q));
    list.innerHTML = _renderModalStreamItems(cam, filtered);
}
window.v2FilterModalStreams = v2FilterModalStreams;

async function v2CaptureFromModal(ip, streamUrl, btn) {
    const origText = btn.textContent;
    btn.textContent = '⏳...';
    btn.disabled = true;
    window.V2State.selectedStreams[ip] = streamUrl;
    const ok = window.v2CapturePreview ? await v2CapturePreview(ip) : false;
    btn.textContent = ok ? '✓ Кадр получен' : 'Нет кадра';
    setTimeout(() => { btn.textContent = origText; btn.disabled = false; }, 2000);
}
window.v2CaptureFromModal = v2CaptureFromModal;

function v2OpenSelectedStreamPlayer(ip) {
    const cam = (window.V2State.results || []).find(c => c.ip === ip);
    if (!cam) return;
    if (_isSpRecord(cam)) {
        v2OpenSpRecordPlayer(ip);
        return;
    }
    if (!cam.streams || !cam.streams.length) return;
    let streamUrl = window.V2State.selectedStreams[ip] || '';
    if (!streamUrl || streamUrl.startsWith('ws://') || streamUrl.includes('.jpg') || streamUrl.includes('.jpeg') || streamUrl.includes('snapshot')) {
        const playable = cam.streams.find(s => (s.url || '').startsWith('rtsp://') || (s.url || '').startsWith('rtmp://') || (s.url || '').includes('.mjpg') || (s.url || '').includes('video.cgi') || (s.url || '').includes('.m3u8'));
        if (playable) {
            streamUrl = playable.url;
        } else {
            streamUrl = cam.streams[0].url;
        }
    }
    const idx = (cam.streams || []).findIndex(s => s.url === streamUrl);
    v2OpenStreamPlayer(streamUrl, cam.brand || cam.ip, ip, idx >= 0 ? idx : 0);
}
window.v2OpenSelectedStreamPlayer = v2OpenSelectedStreamPlayer;

async function v2OpenStreamPlayer(srcUrl, camName, ip, currentIdx = 0) {
    if (!srcUrl) return;

    const cam = (window.V2State.results || []).find(c => c.ip === ip);
    const streams = cam?.streams || [];
    const totalStreams = streams.length;

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
            if (window._v2LiveSnapshotTimer) {
                clearInterval(window._v2LiveSnapshotTimer);
                window._v2LiveSnapshotTimer = null;
            }
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

    const prevTempName = dialog.dataset.tempStreamName;
    if (prevTempName) {
        fetch(`/api/go2rtc/streams/${encodeURIComponent(prevTempName)}`, { method: "DELETE" }).catch(() => {});
    }

    const tempName = `temp_v2_${Date.now()}`;
    dialog.dataset.tempStreamName = tempName;

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
        <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; padding: 0.4rem 1.2rem; background: rgba(10,14,26,0.9); border-bottom: 1px solid rgba(255,255,255,0.06); font-size: 0.75rem;">
            <div style="display: flex; align-items: center; gap: 0.4rem;">
                <span style="color: #94a3b8;">🔒 Авторизация потока:</span>
                <input type="text" id="v2-player-user-input" placeholder="Логин (admin)" value="${_esc(cam?.credentials?.user || '')}" style="background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.15); color: #fff; padding: 3px 8px; border-radius: 4px; font-size: 0.72rem; width: 100px;">
                <input type="password" id="v2-player-pass-input" placeholder="Пароль" value="${_esc(cam?.credentials?.password || '')}" style="background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.15); color: #fff; padding: 3px 8px; border-radius: 4px; font-size: 0.72rem; width: 110px;">
                <button type="button" class="btn btn-small" style="font-size: 0.72rem; padding: 3px 10px; background: rgba(99,102,241,0.7); color: #fff; border: 1px solid #818cf8; border-radius: 4px; cursor: pointer; font-weight: 600;" onclick="v2ApplyCredentialsAndReload('${_esc(ip)}', '${_esc(srcUrl)}', '${_esc(camName)}', ${currentIdx})">▶ Воспроизвести с паролем</button>
            </div>
            <span style="color: #64748b; font-size: 0.7rem;">(Для Hikvision/HiWatch логин обычно admin)</span>
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

                const u = cam?.credentials?.user || '';
                const p = cam?.credentials?.password ?? '';
                let initialSnapUrl = `/api/v2/preview?ip=${encodeURIComponent(ip)}&stream_url=${encodeURIComponent(srcUrl)}&_t=${Date.now()}`;
                if (u) {
                    initialSnapUrl += `&user=${encodeURIComponent(u)}&password=${encodeURIComponent(p)}`;
                }

                playerContainer.innerHTML = `
                    <div style="position: relative; width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; background: #000;">
                        <img id="v2-modal-live-img" src="${initialSnapUrl}" alt="Live Snapshot" style="max-width: 100%; max-height: 100%; object-fit: contain;" onerror="this.style.display='none'; const el=document.getElementById('v2-modal-live-err'); if(el) el.style.display='flex';">
                        <div id="v2-modal-live-err" style="display: none; flex-direction: column; align-items: center; justify-content: center; gap: 0.5rem; color: #ef4444; font-size: 0.85rem;">
                            <span>⚠️ Поток недоступен (камера не отвечает по HTTP)</span>
                        </div>
                        <div style="position: absolute; bottom: 12px; right: 12px; display: flex; gap: 6px; background: rgba(0,0,0,0.65); padding: 4px 10px; border-radius: 6px; align-items: center; z-index: 20; backdrop-filter: blur(4px);">
                            <span id="v2-modal-live-badge" style="font-size: 0.72rem; color: #10b981; font-weight: 600; display: flex; align-items: center; gap: 4px;">🟢 Realtime Live</span>
                            <button type="button" id="v2-modal-live-toggle" class="btn btn-ghost btn-small" style="font-size: 0.72rem; padding: 3px 8px; border-radius:4px; background:rgba(16,185,129,0.2); border:1px solid #10b981; color:#fff;" onclick="v2ToggleLiveSnapshot('${_esc(ip)}', '${_esc(srcUrl)}')">⏸ Пауза</button>
                            <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.72rem; padding: 3px 8px; border-radius:4px; background:rgba(255,255,255,0.1); color:#fff;" onclick="v2RefreshSingleSnapshot('${_esc(ip)}', '${_esc(srcUrl)}')">🔄 Обновить</button>
                        </div>
                    </div>
                `;
                if (window._v2LiveSnapshotTimer) clearInterval(window._v2LiveSnapshotTimer);
                window._v2LiveSnapshotTimer = setInterval(() => {
                    v2RefreshSingleSnapshot(ip, srcUrl);
                }, 1200);
            }
            return;
        }

        let actualSrcUrl = srcUrl;
        const u = cam?.credentials?.user || '';
        const p = cam?.credentials?.password ?? '';

        if (actualSrcUrl.startsWith('ws://') || actualSrcUrl.startsWith('wss://')) {
            const credsPart = u ? `${encodeURIComponent(u)}:${encodeURIComponent(p)}@` : '';
            if (actualSrcUrl.includes('rtsp-over-websocket')) {
                actualSrcUrl = `rtsp://${credsPart}${ip}:554/axis-media/media.amp`;
            } else {
                const rtspStream = (cam?.streams || []).find(s => (s.url || '').startsWith('rtsp://'));
                if (rtspStream) actualSrcUrl = rtspStream.url;
            }
        }

        if (actualSrcUrl.startsWith('rtsp://') || actualSrcUrl.startsWith('rtsps://')) {
            if (u) {
                const credsPart = `${encodeURIComponent(u)}:${encodeURIComponent(p)}@`;
                if (actualSrcUrl.includes(':***@')) {
                    actualSrcUrl = actualSrcUrl.replace(/:[^\/@]+@/, `:${encodeURIComponent(p)}@`);
                } else {
                    const hostPart = actualSrcUrl.split('://')[1]?.split('/')[0] || '';
                    if (!hostPart.includes('@')) {
                        actualSrcUrl = actualSrcUrl.replace('://', `://${credsPart}`);
                    }
                }
            }
        }

        const mainUrl = (actualSrcUrl.startsWith('rtsp://') || actualSrcUrl.startsWith('rtsps://'))
            ? (actualSrcUrl.includes('#') ? actualSrcUrl : `${actualSrcUrl}#transport=tcp#backchannel=0`)
            : actualSrcUrl;
        const ffUrl = `ffmpeg:${actualSrcUrl}#video=copy`;

        const regResp = await fetch("/api/go2rtc/streams", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name: tempName,
                url: [mainUrl, ffUrl]
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

function v2ApplyCredentialsAndReload(ip, srcUrl, camName, currentIdx) {
    const u = document.getElementById('v2-player-user-input')?.value.trim() || '';
    const p = document.getElementById('v2-player-pass-input')?.value || '';
    const cam = (window.V2State.results || []).find(c => c.ip === ip);
    if (cam) {
        cam.credentials = { user: u, password: p };
        (cam.streams || []).forEach(s => {
            s.credentials = { user: u, password: p };
        });
    }
    const isHttpSnapshot = srcUrl.startsWith('http://') || srcUrl.startsWith('https://');
    if (isHttpSnapshot) {
        const img = document.getElementById('v2-modal-live-img');
        const err = document.getElementById('v2-modal-live-err');
        if (err) err.style.display = 'none';
        if (img) img.style.display = '';
        v2RefreshSingleSnapshot(ip, srcUrl);
        return;
    }
    v2OpenStreamPlayer(srcUrl, camName, ip, currentIdx);
}
window.v2ApplyCredentialsAndReload = v2ApplyCredentialsAndReload;

// ── SpRecord Audio Player Dialog & Dynamic Recordings ─────────────────────

window.V2SpRecordState = {
    ip: '',
    offset: 0,
    limit: 25,
    total: 0,
    currentRecord: null,
    records: [],
};

function v2OpenSpRecordPlayer(ip) {
    const cam = (window.V2State.results || []).find(c => c.ip === ip) || { ip: ip };
    window.V2SpRecordState = {
        ip: ip,
        offset: 0,
        limit: 25,
        total: 0,
        currentRecord: null,
        records: [],
    };

    let dialog = document.getElementById('v2-sprecord-dialog');
    if (!dialog) {
        dialog = document.createElement('dialog');
        dialog.id = 'v2-sprecord-dialog';
        dialog.className = 'v2-sprecord-modal';
        dialog.addEventListener('click', (e) => {
            if (e.target === dialog) dialog.close();
        });
        dialog.addEventListener('close', () => {
            const audio = dialog.querySelector('audio');
            if (audio) {
                audio.pause();
                audio.src = '';
            }
        });
        document.body.appendChild(dialog);
    }

    const recordCountMatch = (cam.model || '').match(/\(([^)]+)\)/);
    const recordSubtitle = recordCountMatch ? recordCountMatch[1] : `${cam.total_records || '132 300+'} записей`;

    dialog.innerHTML = `
        <div class="v2-sprecord-modal-header">
            <div style="display:flex;align-items:center;gap:10px">
                <span style="font-size:1.6rem">🎙️</span>
                <div>
                    <h3 style="margin:0;font-size:1.05rem;color:#ecfdf5">SpRecord · Система записи разговоров</h3>
                    <div style="font-size:0.75rem;color:#6ee7b7;margin-top:2px">
                        ${_esc(ip)}:${cam.http_port || 8002} • ${_esc(recordSubtitle)} • admin (без пароля)
                    </div>
                </div>
            </div>
            <div style="display:flex;align-items:center;gap:8px">
                <a href="http://${_esc(ip)}:${cam.http_port || 8002}/" target="_blank" class="v2-btn-small" style="text-decoration:none;background:rgba(59,130,246,0.25);color:#93c5fd;border:1px solid rgba(59,130,246,0.5);font-size:0.78rem;padding:4px 10px;font-weight:600">
                    🌐 SpRecord Web
                </a>
                <button type="button" class="btn btn-ghost" style="font-size:1.2rem;color:#94a3b8;cursor:pointer;padding:2px 8px" onclick="document.getElementById('v2-sprecord-dialog').close()">✕</button>
            </div>
        </div>
        <div class="v2-sprecord-now-playing">
            <div style="display:flex;justify-content:space-between;align-items:center">
                <div>
                    <span style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.05em;color:#10b981;font-weight:700">Сейчас играет</span>
                    <h4 id="v2-sprecord-cur-title" style="margin:3px 0 0 0;font-size:0.95rem;color:#f8fafc">
                        Загрузка записей разговоров с сервера...
                    </h4>
                </div>
                <a id="v2-sprecord-download-link" href="#" target="_blank" download class="v2-btn-small" style="display:none;text-decoration:none;background:rgba(16,185,129,0.25);color:#6ee7b7;border:1px solid rgba(16,185,129,0.4);font-size:0.78rem;padding:4px 10px;font-weight:600">
                    ⬇ Скачать MP3
                </a>
            </div>
            <audio id="v2-sprecord-audio-elem" controls class="v2-sprecord-audio-ctrl" src="">
                Ваш браузер не поддерживает воспроизведение MP3 аудио.
            </audio>
        </div>
        <div style="padding:0 1.2rem 1.2rem 1.2rem;max-height:360px;overflow-y:auto">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;gap:10px;flex-wrap:wrap">
                <span id="v2-sprecord-page-info" style="font-size:0.8rem;font-weight:700;color:#94a3b8">
                    Подключение к SpRecord...
                </span>
                <div style="display:flex;align-items:center;gap:6px">
                    <button id="v2-sprecord-prev-btn" class="v2-btn-small" style="font-size:0.75rem;padding:3px 8px" onclick="v2LoadSpRecordPage('${_esc(ip)}', Math.max(0, window.V2SpRecordState.offset - 25))" disabled>◀ Назад</button>
                    <button id="v2-sprecord-next-btn" class="v2-btn-small" style="font-size:0.75rem;padding:3px 8px" onclick="v2LoadSpRecordPage('${_esc(ip)}', window.V2SpRecordState.offset + 25)" disabled>Вперед ▶</button>
                    <button class="v2-btn-small" style="font-size:0.75rem;padding:3px 8px" onclick="v2LoadSpRecordPage('${_esc(ip)}', window.V2SpRecordState.offset)">🔄</button>
                </div>
            </div>
            <table class="v2-sprecord-calls-table">
                <thead>
                    <tr>
                        <th style="width:35px">#</th>
                        <th>Время записи</th>
                        <th>Канал</th>
                        <th>Длительность</th>
                        <th>Файл</th>
                        <th style="text-align:right">Действия</th>
                    </tr>
                </thead>
                <tbody id="v2-sprecord-tbody">
                    <tr><td colspan="6" style="text-align:center;padding:2rem;color:#94a3b8"><span class="v2-spinner" style="width:20px;height:20px;border-width:2px;border-top-color:#10b981;display:inline-block;vertical-align:middle;margin-right:8px"></span>Загрузка разговоров с сервера...</td></tr>
                </tbody>
            </table>
        </div>
    `;

    dialog.showModal();
    v2LoadSpRecordPage(ip, 0);
}
window.v2OpenSpRecordPlayer = v2OpenSpRecordPlayer;

async function v2LoadSpRecordPage(ip, offset) {
    const tbody = document.getElementById('v2-sprecord-tbody');
    const pageInfo = document.getElementById('v2-sprecord-page-info');
    const prevBtn = document.getElementById('v2-sprecord-prev-btn');
    const nextBtn = document.getElementById('v2-sprecord-next-btn');

    if (tbody) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:2rem;color:#94a3b8"><span class="v2-spinner" style="width:20px;height:20px;border-width:2px;border-top-color:#10b981;display:inline-block;vertical-align:middle;margin-right:8px"></span>Загрузка записей разговоров...</td></tr>`;
    }

    try {
        const res = await fetch(`/api/v2/sprecord/records?ip=${encodeURIComponent(ip)}&offset=${offset}&limit=25`);
        const data = await res.json();
        if (data.code !== 200) {
            if (tbody) tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:1.5rem;color:#f87171">Ошибка: ${data.error || 'Не удалось получить записи'}</td></tr>`;
            return;
        }

        window.V2SpRecordState.offset = offset;
        window.V2SpRecordState.total = data.total;
        window.V2SpRecordState.records = data.records || [];

        const curStart = data.records.length > 0 ? offset + 1 : 0;
        const curEnd = offset + data.records.length;
        if (pageInfo) {
            pageInfo.innerHTML = `Записи <strong>${curStart}–${curEnd}</strong> из <strong>${Number(data.total).toLocaleString('ru-RU')}</strong>`;
        }
        if (prevBtn) prevBtn.disabled = offset <= 0;
        if (nextBtn) nextBtn.disabled = curEnd >= data.total;

        if (!data.records.length) {
            if (tbody) tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:1.5rem;color:#94a3b8">Записей нет</td></tr>`;
            return;
        }

        const activeId = window.V2SpRecordState.currentRecord?.id || data.records[0].id;

        tbody.innerHTML = data.records.map((r, idx) => {
            const isCur = r.id === activeId;
            return `
                <tr id="v2-sp-row-${r.id}" style="${isCur ? 'background:rgba(16,185,129,0.15);font-weight:600' : ''}">
                    <td style="color:${isCur ? '#34d399' : '#94a3b8'}">${isCur ? '▶ ' : ''}${offset + idx + 1}</td>
                    <td><strong style="color:#e2e8f0">${_esc(r.time || '–')}</strong></td>
                    <td><span style="color:#6ee7b7;background:rgba(16,185,129,0.12);padding:2px 6px;border-radius:4px;font-size:0.75rem">${_esc(r.channel || 'Канал')}</span></td>
                    <td><span style="font-family:monospace;color:#f1f5f9">${_esc(r.duration || '00:00:00')}</span></td>
                    <td><span style="font-family:monospace;font-size:0.72rem;color:#64748b">${_esc(r.filename || '')}</span></td>
                    <td style="text-align:right">
                        <button class="v2-btn-small" style="padding:2px 8px;font-size:0.75rem;background:rgba(16,185,129,0.25);color:#34d399;border:1px solid rgba(16,185,129,0.4)" onclick="v2PlaySpRecordById('${_esc(ip)}', ${r.id})">▶ Слушать</button>
                        <a href="${_esc(r.download_url)}" target="_blank" download class="v2-btn-small" style="padding:2px 8px;font-size:0.75rem;background:rgba(255,255,255,0.08);color:#cbd5e1;border:1px solid rgba(255,255,255,0.15);text-decoration:none;margin-left:4px">⬇ MP3</a>
                    </td>
                </tr>
            `;
        }).join('');

        if (!window.V2SpRecordState.currentRecord && data.records.length > 0) {
            v2SetSpRecordTrack(ip, data.records[0], false);
        }
    } catch (err) {
        if (tbody) tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:1.5rem;color:#f87171">Сетевая ошибка: ${err.message}</td></tr>`;
    }
}
window.v2LoadSpRecordPage = v2LoadSpRecordPage;

function v2PlaySpRecordById(ip, recordId) {
    const rec = (window.V2SpRecordState.records || []).find(r => r.id === recordId) || {
        id: recordId,
        audio_url: `/api/v2/sprecord/audio?ip=${encodeURIComponent(ip)}&record_id=${recordId}`,
        download_url: `/api/v2/sprecord/audio?ip=${encodeURIComponent(ip)}&record_id=${recordId}&download=1`,
        channel: 'Запись #' + recordId,
        time: '',
        duration: '',
    };
    v2SetSpRecordTrack(ip, rec, true);
}
window.v2PlaySpRecordById = v2PlaySpRecordById;

function v2SetSpRecordTrack(ip, rec, autoplay = true) {
    window.V2SpRecordState.currentRecord = rec;
    const audio = document.getElementById('v2-sprecord-audio-elem');
    const titleElem = document.getElementById('v2-sprecord-cur-title');
    const downLink = document.getElementById('v2-sprecord-download-link');
    const title = rec.channel ? `${rec.channel} · ${rec.time} (${rec.duration})` : `Запись #${rec.id}`;

    if (titleElem) titleElem.textContent = title;
    if (downLink) {
        downLink.href = rec.download_url;
        downLink.style.display = 'inline-block';
    }
    if (audio) {
        audio.src = rec.audio_url;
        if (autoplay) {
            audio.play().catch(() => {});
        }
    }

    // Highlight active row in table
    const tbody = document.getElementById('v2-sprecord-tbody');
    if (tbody) {
        tbody.querySelectorAll('tr').forEach(tr => {
            const isMatch = tr.id === `v2-sp-row-${rec.id}`;
            tr.style.background = isMatch ? 'rgba(16,185,129,0.15)' : '';
            tr.style.fontWeight = isMatch ? '600' : '';
        });
    }
}
window.v2SetSpRecordTrack = v2SetSpRecordTrack;


// ════════════════════════════════════════════════════════════════
// MODULE: scanner_v2/export.js
// ════════════════════════════════════════════════════════════════

// ── Camera Scanner v2: Export, Go2rtc Sync, Filtering & Helpers ────────

async function v2AddToGo2rtc(ip) {
    const streamUrl = window.V2State.selectedStreams[ip];
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
window.v2AddToGo2rtc = v2AddToGo2rtc;

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
window.v2AddSpecificStreamToGo2rtc = v2AddSpecificStreamToGo2rtc;

async function v2ExportAllToGo2rtc() {
    const cameras = (window.V2State.results || []).filter(c => !c.in_go2rtc);
    if (!cameras.length) {
        alert('Все камеры уже добавлены в go2rtc или результатов нет');
        return;
    }
    if (!confirm(`Добавить ${cameras.length} камер в go2rtc?`)) return;

    let success = 0;
    for (const cam of cameras) {
        const streamUrl = window.V2State.selectedStreams[cam.ip] || cam.streams?.[0]?.url;
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
    if (window.v2LoadStoredResults) v2LoadStoredResults();
}
window.v2ExportAllToGo2rtc = v2ExportAllToGo2rtc;

function v2CopySelectedUrl(ip) {
    const url = window.V2State.selectedStreams[ip];
    if (!url) { alert('URL недоступен'); return; }
    v2CopyUrl(url);
}
window.v2CopySelectedUrl = v2CopySelectedUrl;

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
window.v2CopyUrl = v2CopyUrl;

function v2ShowDetails(ip) {
    const cam = (window.V2State.results || []).find(c => c.ip === ip);
    if (!cam) return;
    if (window.v2OpenStreamModal) v2OpenStreamModal(ip);
}
window.v2ShowDetails = v2ShowDetails;

function v2ExportJson() {
    const json = JSON.stringify(window.V2State.results, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `v2_cameras_${Date.now()}.json`;
    a.click();
}
window.v2ExportJson = v2ExportJson;

function v2Export401() {
    window.open('/api/v2/export/401?format=txt', '_blank');
}
window.v2Export401 = v2Export401;

function v2GetActiveFilterSummary() {
    const parts = [];
    if (window.V2State.filterCategory && window.V2State.filterCategory !== 'all') {
        const catMap = {
            'camera': 'Камеры',
            'router': 'Роутеры и шлюзы',
            'generic_web': 'Веб-сервисы',
            'sprecord': 'SpRecord Аудио',
            'device': 'Сетевые узлы'
        };
        parts.push(`Тип: ${catMap[window.V2State.filterCategory] || window.V2State.filterCategory}`);
    }
    if (window.V2State.filterBrand && window.V2State.filterBrand !== 'all') {
        parts.push(`Бренд: ${window.V2State.filterBrand}`);
    }
    if (window.V2State.filterProtocol && window.V2State.filterProtocol !== 'all') {
        parts.push(`Протокол: ${window.V2State.filterProtocol}`);
    }
    if (window.V2State.filterStatus && window.V2State.filterStatus !== 'all') {
        parts.push(window.V2State.filterStatus === 'live' ? 'Только Live' : 'С превью');
    }
    if (window.V2State.filterAuth === '401') {
        parts.push('Требуют авторизацию (401)');
    } else if (window.V2State.filterAuth === 'open') {
        parts.push('Без авторизации');
    }
    if (window.V2State.filterGeo && window.V2State.filterGeo !== 'all') {
        parts.push(`Гео: ${window.V2State.filterGeo}`);
    }
    if (window.V2State.geoSearch && window.V2State.geoSearch.trim()) {
        parts.push(`Поиск: "${window.V2State.geoSearch.trim()}"`);
    }
    return parts.length ? parts.join(' · ') : 'Все устройства (без фильтрации)';
}
window.v2GetActiveFilterSummary = v2GetActiveFilterSummary;

function v2GetFilteredIpsList() {
    const filtered = (typeof window.v2GetFilteredResults === 'function')
        ? window.v2GetFilteredResults()
        : (window.V2State.results || []);

    const seen = new Set();
    const ips = [];
    for (const c of filtered) {
        let ip = (c.ip || '').trim();
        if (ip.startsWith('http://') || ip.startsWith('https://')) {
            ip = ip.split('//')[1].split('/')[0];
        }
        if (ip.includes(':') && !ip.startsWith('[')) {
            ip = ip.split(':')[0];
        }
        if (ip && !seen.has(ip)) {
            seen.add(ip);
            ips.push(ip);
        }
    }
    return ips;
}
window.v2GetFilteredIpsList = v2GetFilteredIpsList;

function v2OpenExportIpsModal() {
    document.getElementById('v2-export-ips-modal-overlay')?.remove();

    const ips = v2GetFilteredIpsList();
    const filterDesc = v2GetActiveFilterSummary();
    const ipText = ips.join('\n');

    const overlay = document.createElement('div');
    overlay.className = 'v2-modal-overlay';
    overlay.id = 'v2-export-ips-modal-overlay';
    overlay.onclick = (e) => { if (e.target === overlay) v2CloseExportIpsModal(); };

    overlay.innerHTML = `
        <div class="v2-modal-content" style="max-width:620px">
            <div class="v2-modal-header">
                <div class="v2-modal-title">
                    <span>📄</span>
                    <span>Экспорт списка IP-адресов</span>
                </div>
                <button class="v2-modal-close" onclick="v2CloseExportIpsModal()">✕</button>
            </div>
            <div class="v2-modal-body" style="padding:1.2rem;display:flex;flex-direction:column;gap:0.85rem;">
                <div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:0.75rem 1rem;font-size:0.8rem;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                        <span style="color:#94a3b8;">Активные фильтры выборки:</span>
                        <strong style="color:#60a5fa;font-size:0.88rem;">${ips.length} уникальных IP</strong>
                    </div>
                    <div style="color:#cbd5e1;font-size:0.75rem;line-height:1.4;">${_esc(filterDesc)}</div>
                </div>

                <div style="display:flex;flex-direction:column;gap:0.35rem;">
                    <div style="display:flex;justify-content:space-between;align-items:center;">
                        <label style="font-size:0.75rem;color:#94a3b8;font-weight:600;">Список IP (без портов, готов к сканированию):</label>
                        <span style="font-size:0.7rem;color:#64748b;">${ips.length ? `${ips.length} строк` : 'Пусто'}</span>
                    </div>
                    <textarea id="v2-export-ips-textarea" readonly rows="12"
                        style="width:100%;font-family:monospace;font-size:0.8rem;background:rgba(0,0,0,0.5);border:1px solid rgba(255,255,255,0.12);color:#e2e8f0;border-radius:6px;padding:0.6rem;resize:vertical;line-height:1.45;"
                        placeholder="Нет IP для выгрузки">${_esc(ipText)}</textarea>
                </div>

                <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-top:0.25rem;">
                    <div style="display:flex;gap:6px;">
                        <button type="button" class="v2-btn-small" style="background:#2563eb;color:#fff;border:none;padding:0.45rem 0.9rem;font-weight:600;" onclick="v2DownloadFilteredIps()">
                            ⬇ Скачать .txt
                        </button>
                        <button type="button" id="v2-btn-copy-ips" class="v2-btn-small" style="background:rgba(255,255,255,0.1);color:#fff;border:1px solid rgba(255,255,255,0.2);padding:0.45rem 0.9rem;font-weight:600;" onclick="v2CopyIpsToClipboard()">
                            📋 Скопировать
                        </button>
                    </div>
                    <div style="display:flex;gap:6px;">
                        <button type="button" class="v2-btn-small" style="background:rgba(16,185,129,0.2);border:1px solid rgba(16,185,129,0.5);color:#34d399;padding:0.45rem 0.9rem;font-weight:600;" onclick="v2InsertIpsIntoScannerTargets()">
                            📥 Вставить в цели сканера
                        </button>
                        <button type="button" class="v2-btn-small" style="background:transparent;border:1px solid rgba(255,255,255,0.1);color:#94a3b8;padding:0.45rem 0.75rem;" onclick="v2CloseExportIpsModal()">
                            Закрыть
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);
}
window.v2OpenExportIpsModal = v2OpenExportIpsModal;

function v2CloseExportIpsModal() {
    document.getElementById('v2-export-ips-modal-overlay')?.remove();
}
window.v2CloseExportIpsModal = v2CloseExportIpsModal;

function v2DownloadFilteredIps() {
    const ips = v2GetFilteredIpsList();
    if (!ips.length) {
        alert('Нет IP-адресов для скачивания по текущим фильтрам');
        return;
    }
    const textContent = ips.join('\n') + '\n';
    const parts = ['ips'];
    if (window.V2State.filterCategory && window.V2State.filterCategory !== 'all') {
        parts.push(window.V2State.filterCategory);
    }
    if (window.V2State.filterBrand && window.V2State.filterBrand !== 'all') {
        parts.push(window.V2State.filterBrand.toLowerCase().replace(/[^a-z0-9_-]/g, ''));
    }
    if (window.V2State.filterStatus && window.V2State.filterStatus !== 'all') {
        parts.push(window.V2State.filterStatus);
    }
    const filename = `${parts.join('_')}_${ips.length}_${new Date().toISOString().slice(0, 10)}.txt`;
    const blob = new Blob([textContent], { type: 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
}
window.v2DownloadFilteredIps = v2DownloadFilteredIps;

async function v2CopyIpsToClipboard() {
    const ips = v2GetFilteredIpsList();
    if (!ips.length) {
        alert('Нет IP-адресов для копирования');
        return;
    }
    const textContent = ips.join('\n');
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(textContent);
        } else {
            const ta = document.getElementById('v2-export-ips-textarea');
            if (ta) {
                ta.select();
                document.execCommand('copy');
            }
        }
        const btn = document.getElementById('v2-btn-copy-ips');
        if (btn) {
            const oldText = btn.textContent;
            btn.textContent = '✓ Скопировано!';
            btn.style.color = '#34d399';
            setTimeout(() => {
                btn.textContent = oldText;
                btn.style.color = '#fff';
            }, 1800);
        }
    } catch (e) {
        alert('Не удалось скопировать: ' + e.message);
    }
}
window.v2CopyIpsToClipboard = v2CopyIpsToClipboard;

function v2InsertIpsIntoScannerTargets() {
    const ips = v2GetFilteredIpsList();
    if (!ips.length) {
        alert('Нет IP-адресов для вставки');
        return;
    }
    const targetArea = document.getElementById('v2-targets');
    if (targetArea) {
        targetArea.value = ips.join('\n');
        if (typeof v2CalculateTargetsCount === 'function') {
            v2CalculateTargetsCount();
        }
        targetArea.scrollIntoView({ behavior: 'smooth', block: 'center' });
        targetArea.focus();
        v2CloseExportIpsModal();
    }
}
window.v2InsertIpsIntoScannerTargets = v2InsertIpsIntoScannerTargets;


// ── RTSP Brute Force Modal & Real-time Runner ───────────────────────
let _v2BruterPollTimer = null;

function v2OpenBruterModal() {
    document.getElementById('v2-bruter-modal-overlay')?.remove();

    const cameras401 = (window.V2State.results || []).filter(window._isCam401 || (c => c.auth_required));
    const count401 = cameras401.length;

    const overlay = document.createElement('div');
    overlay.className = 'v2-modal-overlay';
    overlay.id = 'v2-bruter-modal-overlay';
    overlay.onclick = (e) => { if (e.target === overlay) v2CloseBruterModal(); };

    const defaultUsers = 'admin\nroot\nservice\nuser\noperator\nviewer';
    const defaultPass = '\nadmin\n12345\n123456\n12345678\nadmin123\nadmin12345\n12345admin\nroot\npass\npassword\nservice\n1111\n666666';

    overlay.innerHTML = `
        <div class="v2-modal-content" style="max-width:760px">
            <div class="v2-modal-header">
                <div class="v2-modal-title">
                    <span>🔨</span>
                    <span>RTSP Brute Force (/root/rtspBruter)</span>
                </div>
                <button class="v2-modal-close" onclick="v2CloseBruterModal()">✕</button>
            </div>
            <div class="v2-modal-body" style="padding:1.25rem;display:flex;flex-direction:column;gap:1rem;overflow-y:auto;max-height:calc(85vh - 70px);">
                <!-- Target Summary -->
                <div style="background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.35);padding:10px 14px;border-radius:8px;font-size:0.85rem;color:#fde68a;display:flex;align-items:center;justify-content:space-between">
                    <div>
                        <strong>🎯 Камеры для подбора:</strong>
                        <span>${count401 > 0 ? `${count401} камер с 401 в результатах` : 'Все камеры с ошибкой 401 из базы'}</span>
                    </div>
                    <button class="v2-btn-small" onclick="v2Export401()" title="Скачать targets.txt для ручного запуска">⬇ Скачать targets.txt</button>
                </div>

                <!-- Wordlists and Settings -->
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
                    <div>
                        <label style="display:block;font-size:0.75rem;font-weight:600;color:#94a3b8;margin-bottom:4px">Логины (один на строку):</label>
                        <textarea id="v2-brute-users" style="width:100%;height:100px;background:#020617;border:1px solid rgba(255,255,255,0.12);border-radius:6px;color:#e2e8f0;font-size:0.75rem;font-family:monospace;padding:6px;resize:none">${defaultUsers}</textarea>
                    </div>
                    <div>
                        <label style="display:block;font-size:0.75rem;font-weight:600;color:#94a3b8;margin-bottom:4px">Пароли (первая пустая = без пароля):</label>
                        <textarea id="v2-brute-passwords" style="width:100%;height:100px;background:#020617;border:1px solid rgba(255,255,255,0.12);border-radius:6px;color:#e2e8f0;font-size:0.75rem;font-family:monospace;padding:6px;resize:none">${defaultPass}</textarea>
                    </div>
                </div>

                <!-- Threads & Options -->
                <div style="display:flex;align-items:center;gap:16px;font-size:0.8rem;color:#cbd5e1">
                    <div style="display:flex;align-items:center;gap:8px">
                        <span>Потоков (Threads):</span>
                        <input type="number" id="v2-brute-threads" value="50" min="1" max="200" style="width:70px;background:#020617;border:1px solid rgba(255,255,255,0.12);color:#e2e8f0;padding:4px 8px;border-radius:4px;font-size:0.8rem">
                    </div>
                    <div style="color:rgba(255,255,255,0.45);font-size:0.75rem">
                        ✓ При успехе пароль сохраняется в базу и автоматически захватывается превью!
                    </div>
                </div>

                <!-- Action buttons -->
                <div style="display:flex;align-items:center;gap:10px;margin-top:4px">
                    <button class="v2-btn-small" id="v2-btn-start-brute" style="background:linear-gradient(135deg, #10b981, #059669);color:#fff;font-weight:600;padding:6px 14px" onclick="v2StartBruter()">▶ Запустить брутфорс</button>
                    <button class="v2-btn-small v2-btn-danger" id="v2-btn-stop-brute" style="display:none;padding:6px 14px" onclick="v2StopBruter()">⏹ Остановить</button>
                    <span id="v2-brute-status-indicator" style="font-size:0.8rem;color:#94a3b8;margin-left:auto">Готов к запуску</span>
                </div>

                <!-- Terminal / Console Log -->
                <div>
                    <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                        <span style="font-size:0.75rem;font-weight:600;color:#94a3b8">Лог работы rtspBrute:</span>
                        <span id="v2-brute-cracked-stats" style="font-size:0.75rem;color:#4ade80;font-weight:600">✓ Подобрано: 0</span>
                    </div>
                    <div class="v2-bruter-console" id="v2-bruter-log">Ожидание запуска задачи...</div>
                </div>

                <!-- Cracked cameras list -->
                <div id="v2-bruter-cracked-section" style="display:none">
                    <div style="font-size:0.75rem;font-weight:700;color:#4ade80;margin-bottom:6px">Успешно подобраны пароли:</div>
                    <div id="v2-bruter-cracked-list" style="display:flex;flex-direction:column;gap:6px;max-height:140px;overflow-y:auto"></div>
                </div>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);
    v2CheckBruterStatusOnOpen();
}
window.v2OpenBruterModal = v2OpenBruterModal;

function v2CloseBruterModal() {
    if (_v2BruterPollTimer) {
        clearInterval(_v2BruterPollTimer);
        _v2BruterPollTimer = null;
    }
    document.getElementById('v2-bruter-modal-overlay')?.remove();
}
window.v2CloseBruterModal = v2CloseBruterModal;

async function v2CheckBruterStatusOnOpen() {
    try {
        const resp = await fetch('/api/v2/bruter/status');
        if (!resp.ok) return;
        const data = await resp.json();
        v2UpdateBruterUI(data);
        if (data.is_running) {
            _v2StartBruterPolling();
        }
    } catch (e) {}
}

function _v2StartBruterPolling() {
    if (_v2BruterPollTimer) clearInterval(_v2BruterPollTimer);
    _v2BruterPollTimer = setInterval(async () => {
        try {
            const resp = await fetch('/api/v2/bruter/status');
            if (!resp.ok) return;
            const data = await resp.json();
            v2UpdateBruterUI(data);
            if (!data.is_running) {
                clearInterval(_v2BruterPollTimer);
                _v2BruterPollTimer = null;
                // Reload stored results to show updated cracked cameras
                if (window.v2LoadStoredResults) v2LoadStoredResults(true);
            }
        } catch (e) {}
    }, 1500);
}

function v2UpdateBruterUI(data) {
    const startBtn = document.getElementById('v2-btn-start-brute');
    const stopBtn = document.getElementById('v2-btn-stop-brute');
    const indicator = document.getElementById('v2-brute-status-indicator');
    const logBox = document.getElementById('v2-bruter-log');
    const crackedStats = document.getElementById('v2-brute-cracked-stats');
    const crackedSec = document.getElementById('v2-bruter-cracked-section');
    const crackedList = document.getElementById('v2-bruter-cracked-list');

    if (startBtn && stopBtn) {
        startBtn.style.display = data.is_running ? 'none' : 'inline-block';
        stopBtn.style.display = data.is_running ? 'inline-block' : 'none';
    }

    if (indicator) {
        if (data.is_running) {
            indicator.innerHTML = `<span style="color:#34d399;font-weight:600">⚡ Выполняется... (${data.elapsed_seconds || 0}с, целей: ${data.total_targets})</span>`;
        } else if (data.status === 'finished') {
            indicator.innerHTML = `<span style="color:#4ade80;font-weight:600">✓ Завершено (Взломано: ${data.cracked_count})</span>`;
        } else if (data.status === 'stopped') {
            indicator.innerHTML = `<span style="color:#f87171">⏹ Остановлено</span>`;
        } else if (data.status === 'error') {
            indicator.innerHTML = `<span style="color:#f87171">⚠️ Ошибка: ${_esc(data.error || 'unknown')}</span>`;
        }
    }

    if (crackedStats) {
        crackedStats.textContent = `✓ Подобрано: ${data.cracked_count || 0}`;
    }

    if (logBox && data.logs && data.logs.length) {
        logBox.textContent = data.logs.join('\n');
        logBox.scrollTop = logBox.scrollHeight;
    }

    if (crackedSec && crackedList && data.cracked_cameras && data.cracked_cameras.length) {
        crackedSec.style.display = 'block';
        crackedList.innerHTML = data.cracked_cameras.map(c => `
            <div style="background:rgba(16,185,129,0.15);border:1px solid rgba(16,185,129,0.3);padding:6px 10px;border-radius:6px;display:flex;align-items:center;justify-content:space-between;font-size:0.75rem">
                <div>
                    <strong style="color:#e2e8f0">${_esc(c.ip)}:${c.port}</strong>
                    <span style="color:#34d399;margin-left:8px;font-weight:600">🔑 ${_esc(c.user || 'none')}:${_esc(c.password || '')}</span>
                </div>
                <button class="v2-btn-small" onclick="v2CloseBruterModal();v2OpenSelectedStreamPlayer('${_esc(c.ip)}')" style="padding:2px 8px;font-size:0.7rem">▶ Просмотр</button>
            </div>
        `).join('');
    }
}

async function v2StartBruter() {
    const usersTxt = document.getElementById('v2-brute-users')?.value || '';
    const passTxt = document.getElementById('v2-brute-passwords')?.value || '';
    const threads = parseInt(document.getElementById('v2-brute-threads')?.value || '50', 10);

    const usernames = usersTxt.split('\n').map(u => u.trim()).filter(Boolean);
    const passwords = passTxt.split('\n');

    try {
        const resp = await fetch('/api/v2/bruter/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                usernames: usernames,
                passwords: passwords,
                threads: threads,
            }),
        });
        const data = await resp.json();
        if (data.started) {
            _showV2Toast(`Запущен подбор паролей для ${data.total_targets} камер!`);
            _v2StartBruterPolling();
        } else {
            alert(data.message || 'Не удалось запустить брутфорс');
        }
    } catch (e) {
        alert('Ошибка запуска: ' + e.message);
    }
}
window.v2StartBruter = v2StartBruter;

async function v2StopBruter() {
    try {
        await fetch('/api/v2/bruter/stop', { method: 'POST' });
        _showV2Toast('Остановка процесса брутфорса...');
    } catch (e) {}
}
window.v2StopBruter = v2StopBruter;

async function v2ClearResults() {
    if (!confirm('Удалить все результаты v2 из базы данных?')) return;
    await fetch('/api/v2/results', { method: 'DELETE' });
    window.V2State.results = [];
    if (window.v2RenderResults) v2RenderResults();
    if (window.v2UpdateResultsCount) v2UpdateResultsCount();
}
window.v2ClearResults = v2ClearResults;

async function v2ResolveAllGeo(btn) {
    const origText = btn?.textContent || '';
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Определение...'; }
    try {
        const resp = await fetch('/api/v2/resolve_geo', { method: 'POST' });
        if (!resp.ok) throw new Error('Не удалось обновить геопозицию');
        const data = await resp.json();
        if (!data.success) throw new Error('Ошибка определения геопозиции');
        window.V2State.results = data.results || [];
        window.v2RenderResults?.();
        window.v2UpdateResultsCount?.();
        const counts = data.precision_counts || {};
        _showV2Toast(`Город определён: ${counts.city || 0}; только регион: ${counts.region || 0}; только страна: ${counts.country || 0}; нет данных: ${counts.unknown || 0}`);
    } catch (error) {
        _showV2Toast(error.message);
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = origText; }
    }
}
window.v2ResolveAllGeo = v2ResolveAllGeo;

let _bulkCaptureTimer = null;
let _bulkCapturePending = false;
let _bulkCapturePollVersion = 0;

function _resetBulkCaptureButton(btn) {
    const b = btn || document.getElementById('v2-btn-bulk-capture');
    if (!b) return;
    b.disabled = false;
    b.textContent = '📸 Получить все превью';
    b.style.color = '#34d399';
    b.style.borderColor = 'rgba(16,185,129,0.45)';
    b.style.background = 'rgba(16,185,129,0.2)';
}

async function v2ToggleBulkCapture(btn) {
    if (_bulkCapturePending) return;
    try {
        const resp = await fetch('/api/v2/bulk_capture/status');
        if (!resp.ok) throw new Error('Статус проверки недоступен');
        const status = await resp.json();
        if (status.is_running) { await v2StopBulkCapture(); return; }
        if (confirm('Получить недостающие превью всех потоков из базы? Уже сохранённые проверенные кадры будут пропущены. Одновременно обрабатываются не более двух потоков.')) {
            await v2StartBulkCapture(btn);
        }
    } catch (error) { _showV2Toast(error.message); }
}
window.v2ToggleBulkCapture = v2ToggleBulkCapture;

async function v2StartBulkCapture(btn) {
    if (_bulkCapturePending) return;
    _bulkCapturePending = true;
    const b = btn || document.getElementById('v2-btn-bulk-capture');
    if (b) { b.disabled = true; b.textContent = '⏳ Запуск...'; }
    try {
        const resp = await fetch('/api/v2/bulk_capture/start', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({concurrency: 2, only_unverified: true, max_streams_per_cam: 0})
        });
        if (!resp.ok) throw new Error(`Ошибка запуска (${resp.status})`);
        const data = await resp.json();
        if (!data.success && !data.status?.is_running) throw new Error(data.message || 'Захват превью не запущен');
        _showV2Toast(data.message || 'Фоновый захват превью запущен');
        _startBulkCapturePolling();
    } catch (error) {
        _resetBulkCaptureButton(b);
        _showV2Toast(error.message);
    } finally {
        _bulkCapturePending = false;
        if (b) b.disabled = false;
    }
}
window.v2StartBulkCapture = v2StartBulkCapture;

async function v2StopBulkCapture() {
    try {
        const resp = await fetch('/api/v2/bulk_capture/stop', { method: 'POST' });
        if (!resp.ok) throw new Error('Не удалось остановить проверку');
        _showV2Toast('Остановка после текущего потока...');
        _startBulkCapturePolling();
    } catch (error) { _showV2Toast(error.message); }
}
window.v2StopBulkCapture = v2StopBulkCapture;

function _startBulkCapturePolling() {
    if (_bulkCaptureTimer) clearInterval(_bulkCaptureTimer);
    const version = ++_bulkCapturePollVersion;
    let lastProcessed = -1;
    let pending = false;
    const poll = async () => {
        if (pending) return;
        pending = true;
        try {
            const resp = await fetch('/api/v2/bulk_capture/status');
            if (!resp.ok) throw new Error('Не удалось получить статус проверки');
            const s = await resp.json();
            if (version !== _bulkCapturePollVersion) return;
            const bar = document.getElementById('v2-bulk-capture-status');
            const text = document.getElementById('v2-bulk-capture-text');
            const stats = document.getElementById('v2-bulk-capture-stats');
            const btn = document.getElementById('v2-btn-bulk-capture');
            if (bar) bar.style.display = 'flex';
            if (stats) stats.textContent = `✓ ${s.verified_streams || 0} с кадром · ${s.failed_streams || 0} без кадра · ${s.unsupported_streams || 0} не поддерживаются`;
            if (s.is_running) {
                if (btn) btn.textContent = s.stop_requested ? '⏳ Остановка...' : `⏹ Остановить (${s.processed_streams}/${s.total_streams})`;
                if (text) text.textContent = `IP: ${s.processed_cameras}/${s.total_cameras}; потоки: ${s.processed_streams}/${s.total_streams}`;
            } else {
                clearInterval(_bulkCaptureTimer);
                _bulkCaptureTimer = null;
                _resetBulkCaptureButton(btn);
                const message = s.error || s.status === 'error'
                    ? `Ошибка проверки: ${s.error || 'неизвестная ошибка'}`
                    : s.stop_requested || s.status === 'cancelled'
                        ? `Проверка остановлена: ${s.processed_streams}/${s.total_streams} потоков`
                        : s.total_streams === 0
                            ? 'Нет потоков с недостающими превью'
                            : `Проверка завершена: ${s.processed_streams}/${s.total_streams} потоков, кадров: ${s.verified_streams}`;
                if (text) text.textContent = message;
                _showV2Toast(message);
            }
            if (s.processed_streams !== lastProcessed || !s.is_running) {
                lastProcessed = s.processed_streams;
                await window.v2LoadStoredResults?.(true);
            }
        } catch (error) {
            const text = document.getElementById('v2-bulk-capture-text');
            if (text) text.textContent = error.message;
        } finally { pending = false; }
    };
    _bulkCaptureTimer = setInterval(poll, 2000);
    poll();
}

// Check on page load if bulk capture was already running in background
function v2CheckBulkCaptureOnLoad() {
    fetch('/api/v2/bulk_capture/status')
        .then(r => r.json())
        .then(s => {
            if (s && s.is_running) {
                _startBulkCapturePolling();
            }
        })
        .catch(() => {});
}
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', v2CheckBulkCaptureOnLoad);
} else {
    v2CheckBulkCaptureOnLoad();
}


function _showV2Toast(msg) {
    const toast = document.createElement('div');
    toast.textContent = msg;
    toast.style.cssText = 'position:fixed;bottom:2rem;right:2rem;background:linear-gradient(135deg, #0ea5e9, #0284c7);color:#fff;padding:0.6rem 1.3rem;border-radius:8px;font-size:0.85rem;font-weight:600;z-index:99999;box-shadow:0 6px 25px rgba(0,0,0,0.5);animation:v2-fade-in 0.2s ease';
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

function v2SetFilter(type, value) {
    window.V2State.visibleCount = window.V2State.pageSize || 48;
    if (type === 'category') {
        const cur = window.V2State.filterCategory || 'all';
        window.V2State.filterCategory = (cur === value && value !== 'all') ? 'all' : value;
        const activeCat = window.V2State.filterCategory;
        document.querySelectorAll('.v2-filter-btn-cat').forEach(btn => btn.classList.remove('active'));
        const targetBtn = document.getElementById(`v2-filter-cat-${activeCat}`);
        if (targetBtn) {
            targetBtn.classList.add('active');
        } else {
            document.getElementById('v2-filter-cat-all')?.classList.add('active');
        }
    } else if (type === 'status') {
        const cur = window.V2State.filterStatus || 'all';
        window.V2State.filterStatus = (cur === value) ? 'all' : value;
        const activeVal = window.V2State.filterStatus;
        document.getElementById('v2-filter-status-live')?.classList.toggle('active', activeVal === 'live');
        document.getElementById('v2-filter-status-preview')?.classList.toggle('active', activeVal === 'preview');
    } else if (type === 'auth') {
        const cur = window.V2State.filterAuth || 'all';
        window.V2State.filterAuth = (cur === value) ? 'all' : value;
        const activeVal = window.V2State.filterAuth;
        document.getElementById('v2-filter-auth-open')?.classList.toggle('active', activeVal === 'open');
        document.getElementById('v2-filter-auth-401')?.classList.toggle('active', activeVal === '401');
    } else if (type === 'brand') {
        window.V2State.filterBrand = value;
        if (value === 'all') {
            window.V2State.filterProtocol = 'all';
            window.V2State.filterCategory = 'all';
            window.V2State.filterStatus = 'all';
            window.V2State.filterAuth = 'all';
            document.querySelectorAll('.v2-filter-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById('v2-filter-brand-all')?.classList.add('active');
            document.getElementById('v2-filter-cat-all')?.classList.add('active');
            document.getElementById('v2-filter-auth-open')?.classList.remove('active');
            document.getElementById('v2-filter-auth-401')?.classList.remove('active');
        } else {
            document.querySelectorAll('.v2-filter-btn[id^="v2-filter-brand-"]').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.value === value);
            });
        }
    } else if (type === 'protocol') {
        window.V2State.filterProtocol = value;
        document.querySelectorAll('.v2-filter-btn[id^="v2-filter-proto-"]').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.value === value);
        });
    }

    const isAll = window.V2State.filterBrand === 'all' &&
                  window.V2State.filterProtocol === 'all' &&
                  (!window.V2State.filterCategory || window.V2State.filterCategory === 'all') &&
                  (!window.V2State.filterStatus || window.V2State.filterStatus === 'all') &&
                  (!window.V2State.filterAuth || window.V2State.filterAuth === 'all');
    document.getElementById('v2-filter-brand-all')?.classList.toggle('active', isAll);

    if (window.v2RenderResults) v2RenderResults();
}
window.v2SetFilter = v2SetFilter;

function v2SetGeoFilter(val) {
    window.V2State.visibleCount = window.V2State.pageSize || 48;
    window.V2State.filterGeo = val;
    const select = document.getElementById('v2-filter-geo');
    if (select && select.value !== val) {
        select.value = val;
    }
    _updateGeoClearBtn();
    if (window.v2RenderResults) v2RenderResults();
}
window.v2SetGeoFilter = v2SetGeoFilter;

function v2SetGeoSearch(val) {
    window.V2State.visibleCount = window.V2State.pageSize || 48;
    window.V2State.geoSearch = val;
    _updateGeoClearBtn();
    if (window.v2RenderResults) v2RenderResults();
}
window.v2SetGeoSearch = v2SetGeoSearch;

function v2ClearGeoFilter() {
    window.V2State.visibleCount = window.V2State.pageSize || 48;
    window.V2State.filterGeo = 'all';
    window.V2State.geoSearch = '';
    const select = document.getElementById('v2-filter-geo');
    if (select) select.value = 'all';
    const searchInput = document.getElementById('v2-geo-search-input');
    if (searchInput) searchInput.value = '';
    _updateGeoClearBtn();
    if (window.v2RenderResults) v2RenderResults();
}
window.v2ClearGeoFilter = v2ClearGeoFilter;

function _updateGeoClearBtn() {
    const btn = document.getElementById('v2-geo-clear-btn');
    if (!btn) return;
    const hasActive = (window.V2State.filterGeo && window.V2State.filterGeo !== 'all') || (window.V2State.geoSearch && window.V2State.geoSearch.trim().length > 0);
    btn.style.display = hasActive ? 'block' : 'none';
}

function _esc(str) {
    if (!str && str !== 0) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
window._esc = _esc;

if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
        if (window.v2LoadTools) v2LoadTools();
        if (window.v2RenderCredentials) v2RenderCredentials();

        const savedVersion = localStorage.getItem('ip2domain_cam_version');
        if (savedVersion === 'v2') {
            setTimeout(() => {
                const v2Btn = document.getElementById('cam-ver-btn-v2');
                if (v2Btn && window.switchCameraVersion) {
                    switchCameraVersion('v2');
                }
            }, 50);
        }
    });
}

function v2CheckVersionOnTabOpen() {
    const savedVersion = localStorage.getItem('ip2domain_cam_version');
    if (savedVersion === 'v2') {
        if (window.switchCameraVersion) switchCameraVersion('v2');
    } else {
        if (window.v2LoadStoredResults) v2LoadStoredResults();
    }
}
window.v2CheckVersionOnTabOpen = v2CheckVersionOnTabOpen;
