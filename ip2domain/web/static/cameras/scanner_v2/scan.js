'use strict';
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
    ['discovery', 'port_sweep', 'fingerprint', 'capture'].forEach(s => {
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
