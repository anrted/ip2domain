'use strict';
// ── Strix Scanner: Scan Execution, ETA Tracker, and Polling ─────

let activeStrixJobId = null;

async function startStrixScan(event) {
    event.preventDefault();
    const targets = document.getElementById('strix-target').value.trim();
    const preset = document.getElementById('strix-preset').value;
    const user = document.getElementById('strix-user').value.trim();
    const password = document.getElementById('strix-pass').value;
    const scanBtn = document.getElementById('strix-scan-button');
    const cancelBtn = document.getElementById('strix-cancel-button');
    const progress = document.getElementById('strix-progress');

    if (!targets) return;

    scanBtn.disabled = true;
    cancelBtn.style.display = '';
    progress.style.display = 'block';
    document.getElementById('strix-progress-stage').textContent = 'Инициализация последовательной проверки...';
    document.getElementById('strix-progress-pct').textContent = '0%';
    document.getElementById('strix-progress-fill').style.width = '0%';
    document.getElementById('strix-log-box').innerHTML = '<div style="color:#93c5fd">Запуск задания сканирования...</div>';

    const skipExisting = Boolean(document.getElementById('strix-skip-existing')?.checked);
    const skipCidrs = Boolean(document.getElementById('strix-skip-cidrs')?.checked);
    const strictVideoOnly = Boolean(document.getElementById('strix-strict-video')?.checked !== false);
    const concurrency = parseInt(document.getElementById('strix-concurrency')?.value || '10', 10);

    try {
        const response = await fetch('/api/strix/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                targets,
                ids: preset,
                user,
                password,
                skip_existing: skipExisting,
                skip_cidrs: skipCidrs,
                strict_video_only: strictVideoOnly,
                concurrency
            })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось запустить сканирование Strix');
        
        activeStrixJobId = data.job_id;
        localStorage.setItem('ip2domain_strix_job', data.job_id);
        pollStrixScan(data.job_id);
    } catch (err) {
        alert(err.message);
        scanBtn.disabled = false;
        cancelBtn.style.display = 'none';
        progress.style.display = 'none';
    }
}
window.startStrixScan = startStrixScan;

async function pollStrixScan(jobId) {
    if (!jobId || jobId !== activeStrixJobId) return;
    const scanBtn = document.getElementById('strix-scan-button');
    const cancelBtn = document.getElementById('strix-cancel-button');
    const progress = document.getElementById('strix-progress');

    if (scanBtn) scanBtn.disabled = true;
    if (cancelBtn) cancelBtn.style.display = '';
    if (progress) progress.style.display = 'block';

    try {
        const response = await fetch(`/api/strix/scan/${encodeURIComponent(jobId)}`);
        if (!response.ok) {
            localStorage.removeItem('ip2domain_strix_job');
            if (scanBtn) scanBtn.disabled = false;
            if (cancelBtn) cancelBtn.style.display = 'none';
            return;
        }
        const job = await response.json();

        const pct = job.progress_pct || 0;
        const stageEl = document.getElementById('strix-progress-stage');
        const pctEl = document.getElementById('strix-progress-pct');
        const fillEl = document.getElementById('strix-progress-fill');
        
        // Calculate ETA (Estimated Time Remaining) dynamically using rolling window
        const now = Date.now();
        if (!window._strixProgressTracker || window._strixProgressTracker.jobId !== jobId) {
            window._strixProgressTracker = {
                jobId: jobId,
                samples: [] // [{time, index}]
            };
        }
        
        const tracker = window._strixProgressTracker;
        const currentIndex = job.current_index || 0;
        const totalTargets = job.total_targets || 1;
        const remainingTargets = Math.max(0, totalTargets - currentIndex);
        
        // Add current sample and keep samples within last 60 seconds
        tracker.samples.push({ time: now, index: currentIndex });
        while (tracker.samples.length > 2 && (now - tracker.samples[0].time) > 60000) {
            tracker.samples.shift();
        }
        
        let etaText = "";
        const oldestSample = tracker.samples[0];
        const elapsedSec = (now - oldestSample.time) / 1000;
        const processedInWindow = currentIndex - oldestSample.index;
        
        if (processedInWindow > 10 && elapsedSec > 4 && remainingTargets > 0) {
            const ipsPerSec = processedInWindow / elapsedSec;
            if (ipsPerSec > 0) {
                const remainingSec = Math.round(remainingTargets / ipsPerSec);
                const hrs = Math.floor(remainingSec / 3600);
                const mins = Math.floor((remainingSec % 3600) / 60);
                const secs = remainingSec % 60;
                
                const speedFormatted = ipsPerSec >= 10 ? Math.round(ipsPerSec) : ipsPerSec.toFixed(1);
                
                if (hrs > 0) {
                    etaText = ` · осталось ~${hrs}ч ${mins}м (${speedFormatted} IP/с)`;
                } else if (mins > 0) {
                    etaText = ` · осталось ~${mins}м ${secs}с (${speedFormatted} IP/с)`;
                } else {
                    etaText = ` · осталось ~${secs}с (${speedFormatted} IP/с)`;
                }
            }
        }
        
        let stageText = job.stage || 'Выполнение...';
        if (etaText && !stageText.includes('осталось')) {
            stageText += etaText;
        }

        if (stageEl) stageEl.textContent = stageText;
        if (pctEl) pctEl.textContent = `${pct}%`;
        if (fillEl) fillEl.style.width = `${pct}%`;

        const logBox = document.getElementById('strix-log-box');
        if (logBox && job.logs) {
            logBox.innerHTML = job.logs.map(l => `<div>${_esc(l)}</div>`).join('');
            logBox.scrollTop = logBox.scrollHeight;
        }

        if (job.results && job.results.length) {
            const currentTotal = job.results.reduce((sum, item) => sum + (item.streams ? item.streams.length : 0), 0);
            if (window._strixLastRenderedCount !== currentTotal || window._strixLastResultsLen !== job.results.length) {
                window._strixLastRenderedCount = currentTotal;
                window._strixLastResultsLen = job.results.length;
                if (window.renderStrixResults) renderStrixResults(job.results);
            }
        }

        if (job.status === 'completed' || job.status === 'cancelled') {
            if (scanBtn) scanBtn.disabled = false;
            if (cancelBtn) cancelBtn.style.display = 'none';
            activeStrixJobId = null;
            localStorage.removeItem('ip2domain_strix_job');
            loadStrixResults();
            return;
        }

        setTimeout(() => pollStrixScan(jobId), 1500);
    } catch (err) {
        console.error('Strix poll error:', err);
        setTimeout(() => pollStrixScan(jobId), 3000);
    }
}

async function cancelStrixScan() {
    if (!activeStrixJobId) return;
    try {
        await fetch(`/api/strix/scan/${encodeURIComponent(activeStrixJobId)}/cancel`, {method: 'POST'});
        const stageEl = document.getElementById('strix-progress-stage');
        if (stageEl) stageEl.textContent = 'Остановка задания...';
    } catch (_) {}
}
window.cancelStrixScan = cancelStrixScan;

async function restoreStrixScan() {
    const savedJobId = localStorage.getItem('ip2domain_strix_job');
    if (!savedJobId) return;
    try {
        const response = await fetch(`/api/strix/scan/${encodeURIComponent(savedJobId)}`);
        if (!response.ok) {
            localStorage.removeItem('ip2domain_strix_job');
            return;
        }
        const job = await response.json();
        if (job.status === 'running' || job.status === 'queued') {
            activeStrixJobId = savedJobId;
            pollStrixScan(savedJobId);
        } else {
            localStorage.removeItem('ip2domain_strix_job');
            if (job.results && job.results.length && window.renderStrixResults) {
                renderStrixResults(job.results);
            }
        }
    } catch (_) {}
}
window.restoreStrixScan = restoreStrixScan;

async function refreshStrixGo2rtcState() {
    try {
        const response = await fetch('/api/go2rtc/streams');
        if (response.ok) {
            const data = await response.json();
            const streams = data.streams || {};
            window.strixActiveGo2rtcStreams = new Set(Object.keys(streams));
            window.strixActiveGo2rtcUrls = new Set();
            window.strixActiveGo2rtcIps = new Set();
            for (const name in streams) {
                const s = streams[name] || {};
                const prods = s.producers || [];
                prods.forEach(p => {
                    if (p.url) {
                        const cleanUrl = p.url.trim().toLowerCase();
                        window.strixActiveGo2rtcUrls.add(cleanUrl);
                        const match = cleanUrl.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
                        if (match) window.strixActiveGo2rtcIps.add(match[0]);
                    }
                });
                const nameMatch = name.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
                if (nameMatch) window.strixActiveGo2rtcIps.add(nameMatch[0]);
            }
        }
    } catch (_) {}
}
window.refreshStrixGo2rtcState = refreshStrixGo2rtcState;

async function loadStrixResults() {
    const container = document.getElementById('strix-results');
    if (!container) return;
    try {
        await refreshStrixGo2rtcState();
        const response = await fetch('/api/strix/results');
        if (!response.ok) return;
        const data = await response.json();
        window.strixCachedItems = data.results || [];
        if (window.renderStrixResults) renderStrixResults(window.strixCachedItems);
        if (window.updateStrixDbCounts) updateStrixDbCounts();
    } catch (_) {}
}
window.loadStrixResults = loadStrixResults;

async function clearStrixResults() {
    if (!confirm('Очистить сохранённые результаты Strix?')) return;
    try {
        await fetch('/api/strix/results', {method: 'DELETE'});
        window.strixCachedItems = [];
        loadStrixResults();
    } catch (_) {}
}
window.clearStrixResults = clearStrixResults;
