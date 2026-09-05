'use strict';

let activeCentraJobId = null;
window.activeCentraJobId = activeCentraJobId;

function updateCentraTypeFields() {
    const selection = document.getElementById('centra-camera-type').value;
    const customGroup = document.getElementById('centra-custom-type-group');
    const customInput = document.getElementById('centra-custom-type');
    document.getElementById('centra-discovery-form').classList.toggle('custom-type-active', selection === 'custom');
    customGroup.style.display = selection === 'custom' ? '' : 'none';
    customInput.required = selection === 'custom';
    const type = selection === 'custom' ? customInput.value.trim().toUpperCase() : selection;
    const server = document.getElementById('centra-base-url');
    const color = document.getElementById('centra-pin-color');
    const entranceEnd = document.getElementById('centra-entrance-end');
    if (type === 'ALL' || type === 'ALL_LETTERS') {
        server.value = '';
        color.value = 'red';
        if (entranceEnd) entranceEnd.value = '10';
    } else if (type === 'I') { server.value = ''; color.value = 'red'; if (entranceEnd) entranceEnd.value = '15'; }
    else if (type === 'G') { server.value = ''; color.value = 'blue'; if (entranceEnd) entranceEnd.value = '2'; }
    else if (type === 'H') { server.value = ''; color.value = 'green'; if (entranceEnd) entranceEnd.value = '10'; }
    else if (type === 'T') { server.value = ''; color.value = 'orange'; if (entranceEnd) entranceEnd.value = '6'; }
    else if (type === 'A') { server.value = ''; color.value = 'violet'; if (entranceEnd) entranceEnd.value = '1'; }
    else if (type === 'P') { server.value = ''; color.value = 'pink'; if (entranceEnd) entranceEnd.value = '3'; }
    else if (centraTypePinColors[type]) color.value = centraTypePinColors[type];
    server.placeholder = 'https://flus6.mycentra.ru';
    server.required = false;
    updateCentraColorOptions();
}
window.updateCentraTypeFields = updateCentraTypeFields;
document.addEventListener('DOMContentLoaded', () => {
    updateCentraTypeFields();
    if (window.restoreCentraScan) restoreCentraScan();
});

function updateCentraColorOptions() {
    const selection = document.getElementById('centra-camera-type')?.value;
    const type = selection === 'custom' ? document.getElementById('centra-custom-type').value.trim().toUpperCase() : selection;
    const select = document.getElementById('centra-pin-color');
    if (!select) return;
    const fixedColor = type?.length === 1 ? centraTypePinColors[type] : null;
    if (fixedColor) select.value = fixedColor;
    [...select.options].forEach((option) => {
        const owner = centraUsedPinColors[option.value];
        const sharedHP = owner === 'H/P' && ['H', 'P'].includes(type);
        const assignedToCurrentType = option.value === fixedColor;
        option.disabled = Boolean(owner && owner !== type && !sharedHP && !assignedToCurrentType);
        option.title = option.disabled ? `Используется типом ${owner}` : '';
    });
    if (select.selectedOptions[0]?.disabled) {
        const available = [...select.options].find((option) => !option.disabled);
        if (available) select.value = available.value;
    }
    select.disabled = ['ALL', 'ALL_LETTERS', 'I', 'G', 'H', 'P', 'T', 'A'].includes(type) || Boolean(fixedColor);
}

function selectedCentraCameraType() {
    const selection = document.getElementById('centra-camera-type').value;
    return selection === 'custom' ? document.getElementById('centra-custom-type').value.trim().toUpperCase() : selection;
}

function formatCentraEta(seconds) {
    if (!Number.isFinite(seconds) || seconds < 0) return 'расчёт времени…';
    if (seconds < 60) return 'меньше минуты';
    const minutes = Math.ceil(seconds / 60);
    if (minutes < 60) return `≈ ${minutes} мин`;
    const hours = Math.floor(minutes / 60);
    const rest = minutes % 60;
    return `≈ ${hours} ч${rest ? ` ${rest} мин` : ''}`;
}

async function startCentraDiscovery(event) {
    event.preventDefault();
    const button = document.getElementById('centra-discovery-button');
    const progress = document.getElementById('centra-discovery-progress');
    const serverInput = document.getElementById('centra-base-url');
    serverInput.setCustomValidity('');
    const serverValue = serverInput.value.trim();
    if (serverValue && !/^https:\/\/[a-z0-9-]+\.mycentra\.ru\/?$/i.test(serverValue)) {
        serverInput.setCustomValidity('Формат: https://flus6.mycentra.ru — без пути, параметров и порта');
        serverInput.reportValidity();
        serverInput.focus();
        return;
    }
    const body = {
        camera_type: selectedCentraCameraType(),
        base_url: serverValue || null,
        pin_color: document.getElementById('centra-pin-color').value,
        start_id: Number(document.getElementById('centra-start-id').value),
        end_id: Number(document.getElementById('centra-end-id').value),
        entrance_start: Number(document.getElementById('centra-entrance-start').value),
        entrance_end: Number(document.getElementById('centra-entrance-end').value),
        concurrency: Number(document.getElementById('centra-concurrency').value),
        skip_existing: document.getElementById('centra-skip-existing').checked
    };
    try {
        button.disabled = true;
        progress.style.display = 'block';
        progress.textContent = 'Запуск поиска...';
        const response = await fetch('/api/cameras/centra/discover', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось запустить поиск');
        const activeResponse = await fetch('/api/cameras/centra/discover/active');
        const activeData = activeResponse.ok ? await activeResponse.json() : {jobs: []};
        const jobIds = (activeData.jobs || []).map((job) => job.job_id);
        if (!jobIds.length) jobIds.push(...(data.job_ids || [data.job_id]));
        localStorage.setItem('ip2domain_centra_job', JSON.stringify(jobIds));
        activeCentraJobId = jobIds;
        window.activeCentraJobId = jobIds;
        const cancelButton = document.getElementById('centra-cancel-button');
        if (cancelButton) {
            cancelButton.disabled = false;
            cancelButton.textContent = '■ Остановить';
            cancelButton.style.display = '';
        }
        pollCentraDiscovery(jobIds, true);
    } catch (error) {
        button.disabled = false;
        progress.innerHTML = `<span style="color:#f87171">${_esc(error.message)}</span>`;
    }
}
window.startCentraDiscovery = startCentraDiscovery;

function pollCentraDiscovery(jobIds, immediate = false) {
    jobIds = Array.isArray(jobIds) ? jobIds : [jobIds];
    activeCentraJobId = jobIds;
    window.activeCentraJobId = jobIds;
    if (window._centraPoller) {
        clearInterval(window._centraPoller);
        window._centraPoller = null;
    }
    const button = document.getElementById('centra-discovery-button');
    const cancelButton = document.getElementById('centra-cancel-button');
    const progress = document.getElementById('centra-discovery-progress');

    const tick = async () => {
        try {
            const responses = await Promise.all(jobIds.map((id) => fetch(`/api/cameras/centra/discover/${encodeURIComponent(id)}`)));
            if (responses.some((response) => response.status === 404)) {
                const activeRes = await fetch('/api/cameras/centra/discover/active');
                if (activeRes.ok) {
                    const activeData = await activeRes.json();
                    const currentActive = (activeData.jobs || []).map((j) => j.job_id);
                    if (currentActive.length) {
                        jobIds = currentActive;
                        activeCentraJobId = jobIds;
                        window.activeCentraJobId = jobIds;
                        localStorage.setItem('ip2domain_centra_job', JSON.stringify(jobIds));
                        return;
                    }
                }
                clearInterval(window._centraPoller);
                window._centraPoller = null;
                localStorage.removeItem('ip2domain_centra_job');
                activeCentraJobId = null;
                window.activeCentraJobId = null;
                if (button) button.disabled = false;
                if (cancelButton) cancelButton.style.display = 'none';
                if (progress) progress.innerHTML = '<span style="color:var(--text-muted, #94a3b8)">Сканирование завершено</span>';
                return;
            }
            if (responses.some((response) => !response.ok)) throw new Error('Ошибка получения статуса задания');
            const jobs = await Promise.all(responses.map((response) => response.json()));
            const total = jobs.reduce((sum, job) => sum + (job.total || 0), 0);
            const checked = jobs.reduce((sum, job) => sum + (job.checked || 0), 0);
            const found = jobs.reduce((sum, job) => sum + (job.found || 0), 0);
            const pct = total ? Math.min(100, Math.floor(checked * 100 / total)) : 100;
            const active = jobs.filter((job) => ['queued', 'running', 'cancelling'].includes(job.status));
            const measuredSpeed = jobs.reduce((sum, job) => sum + (Number(job.speed) || 0), 0);
            const remaining = jobs.reduce((sum, job) => sum + Math.max(0, (job.total || 0) - (job.checked || 0)), 0);
            const overallEta = measuredSpeed > 0 ? remaining / measuredSpeed : NaN;
            const rows = jobs.map((job) => {
                const jobPct = job.total ? Math.min(100, Math.floor((job.checked || 0) * 100 / job.total)) : (job.progress_pct || 0);
                const etaValue = job.eta_seconds == null ? NaN : Number(job.eta_seconds);
                const eta = job.status === 'queued' ? 'в очереди' : (job.status === 'completed' ? 'завершено' : (job.status === 'cancelled' ? 'отменено' : `${formatCentraEta(etaValue)} осталось`));
                let actionHtml = '';
                if (['queued', 'running'].includes(job.status)) {
                    actionHtml = `<button type="button" class="centra-job-cancel-btn" onclick="cancelSingleCentraJob('${_esc(job.job_id)}', this, event)" title="Отменить это сканирование">Отменить</button>`;
                } else if (job.status === 'cancelling') {
                    actionHtml = `<span class="centra-job-status-pill cancelling">Отменяется...</span>`;
                } else if (job.status === 'completed') {
                    actionHtml = `<span class="centra-job-status-pill completed">Готово</span>`;
                } else if (job.status === 'cancelled') {
                    actionHtml = `<span class="centra-job-status-pill cancelled">Отменено</span>`;
                }
                return `<div class="centra-job-row" data-job-id="${_esc(job.job_id)}">` +
                       `<span>${_esc(job.stage || job.target || job.job_id)} <small>${_esc(eta)}</small></span>` +
                       `<strong>${jobPct}%</strong>` +
                       `<div class="centra-job-actions">${actionHtml}</div>` +
                       `</div>`;
            }).join('');
            if (progress) {
                progress.style.display = 'block';
                progress.innerHTML = `<div class="progress-header"><span>Активные сканирования: ${active.length} · проверено ${checked.toLocaleString()} · найдено ${found} · ${formatCentraEta(overallEta)} осталось</span><span>${pct}%</span></div><div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div><div class="centra-job-list">${rows}</div>`;
            }
            if (jobs.every((job) => job.status === 'completed')) {
                clearInterval(window._centraPoller);
                window._centraPoller = null;
                window._centraPollerTick = null;
                if (button) button.disabled = false;
                activeCentraJobId = null;
                window.activeCentraJobId = null;
                localStorage.removeItem('ip2domain_centra_job');
                if (cancelButton) cancelButton.style.display = 'none';
                centraCameras = [];
                if (window.loadCentraCameras) await loadCentraCameras();
            } else if (jobs.every((job) => ['completed', 'cancelled'].includes(job.status))) {
                clearInterval(window._centraPoller);
                window._centraPoller = null;
                window._centraPollerTick = null;
                if (button) button.disabled = false;
                activeCentraJobId = null;
                window.activeCentraJobId = null;
                localStorage.removeItem('ip2domain_centra_job');
                if (cancelButton) cancelButton.style.display = 'none';
                centraCameras = [];
                if (window.loadCentraCameras) await loadCentraCameras();
            } else if (jobs.some((job) => job.status === 'error' || job.status === 'interrupted')) {
                clearInterval(window._centraPoller);
                window._centraPoller = null;
                window._centraPollerTick = null;
                if (button) button.disabled = false;
                activeCentraJobId = null;
                window.activeCentraJobId = null;
                localStorage.removeItem('ip2domain_centra_job');
                if (cancelButton) cancelButton.style.display = 'none';
                throw new Error(jobs.find((job) => job.error)?.error || 'Поиск прерван');
            }
        } catch (error) {
            clearInterval(window._centraPoller);
            window._centraPoller = null;
            window._centraPollerTick = null;
            if (button) button.disabled = false;
            if (cancelButton) cancelButton.style.display = 'none';
            if (progress) progress.innerHTML = `<span style="color:#f87171">${_esc(error.message)}</span>`;
        }
    };

    window._centraPollerTick = tick;
    if (immediate) {
        tick();
    }
    window._centraPoller = setInterval(tick, 2000);
}

async function cancelSingleCentraJob(jobId, btn, event) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    if (!jobId) return;
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Остановка...';
    }
    try {
        const response = await fetch(`/api/cameras/centra/discover/${encodeURIComponent(jobId)}/cancel`, {method:'POST'});
        if (!response.ok) {
            const data = await response.json().catch(() => ({}));
            throw new Error(data.detail || 'Не удалось остановить задание');
        }
        if (window._centraPollerTick) {
            window._centraPollerTick();
        }
    } catch (err) {
        console.error('Cancel single job error:', err);
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Отменить';
        }
    }
}
window.cancelSingleCentraJob = cancelSingleCentraJob;

async function cancelCentraDiscovery() {
    let jobIds = activeCentraJobId;
    if (!jobIds) { try { jobIds = JSON.parse(localStorage.getItem('ip2domain_centra_job')); } catch (_) {} }
    if (!jobIds) return;
    jobIds = Array.isArray(jobIds) ? jobIds : [jobIds];
    const cancelButton = document.getElementById('centra-cancel-button');
    if (cancelButton) {
        cancelButton.disabled = true;
        cancelButton.textContent = 'Остановка...';
    }
    try {
        const responses = await Promise.all(jobIds.map((id) => fetch(`/api/cameras/centra/discover/${encodeURIComponent(id)}/cancel`, {method:'POST'})));
        if (responses.some((response) => !response.ok)) throw new Error('Не удалось остановить поиск');
        const progress = document.getElementById('centra-discovery-progress');
        if (progress) progress.style.display = 'block';
    } catch (error) {
        if (cancelButton) {
            cancelButton.disabled = false;
            cancelButton.textContent = '■ Остановить';
        }
    }
}
window.cancelCentraDiscovery = cancelCentraDiscovery;

async function restoreCentraScan() {
    try {
        let jobIds = [];
        const activeResponse = await fetch('/api/cameras/centra/discover/active');
        if (activeResponse.ok) {
            const activeData = await activeResponse.json();
            jobIds = (activeData.jobs || []).map((j) => j.job_id);
        }
        if (!jobIds.length) {
            try {
                const stored = JSON.parse(localStorage.getItem('ip2domain_centra_job') || '[]');
                if (Array.isArray(stored) && stored.length) {
                    const checks = await Promise.all(stored.map((id) => fetch(`/api/cameras/centra/discover/${encodeURIComponent(id)}`)));
                    const stillActive = [];
                    for (let i = 0; i < checks.length; i++) {
                        if (checks[i].ok) {
                            const job = await checks[i].json();
                            if (['queued', 'running', 'cancelling'].includes(job.status)) {
                                stillActive.push(stored[i]);
                            }
                        }
                    }
                    if (stillActive.length) {
                        jobIds = stillActive;
                    } else {
                        localStorage.removeItem('ip2domain_centra_job');
                    }
                }
            } catch (_) {}
        }
        if (jobIds.length) {
            localStorage.setItem('ip2domain_centra_job', JSON.stringify(jobIds));
            activeCentraJobId = jobIds;
            window.activeCentraJobId = jobIds;
            const button = document.getElementById('centra-discovery-button');
            const cancelButton = document.getElementById('centra-cancel-button');
            const progress = document.getElementById('centra-discovery-progress');
            if (button) button.disabled = true;
            if (cancelButton) {
                cancelButton.disabled = false;
                cancelButton.textContent = '■ Остановить';
                cancelButton.style.display = '';
            }
            if (progress) {
                progress.style.display = 'block';
                progress.innerHTML = '<div class="progress-header"><span>Восстановление активных сканирований...</span></div>';
            }
            pollCentraDiscovery(jobIds, true);
        }
    } catch (e) {
        console.warn('Failed to restore centra scan:', e);
    }
}
window.restoreCentraScan = restoreCentraScan;
