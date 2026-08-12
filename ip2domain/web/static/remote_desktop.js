'use strict';

async function clearRemoteDesktopResults() {
    const response = await fetch('/api/remote-desktop/results', {method: 'DELETE'});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || 'Не удалось очистить результаты');
    document.getElementById('remote-results').innerHTML = '<div class="empty-state">Результаты очищены</div>';
}

function refreshRemoteTargets() {
    const list = document.getElementById('remote-graph-targets');
    if (!list) return;
    const ips = new Set();
    ((typeof currentGraphData !== 'undefined' && currentGraphData?.nodes) || []).forEach((node) => {
        if (node.group === 'ip') ips.add(String(node.label || node.id || '').replace(/^ip:/, ''));
    });
    list.innerHTML = [...ips].sort().slice(0, 20).map((ip) => `<button type="button" class="text-button" onclick="addRemoteTarget('${_esc(ip)}')">${_esc(ip)}</button>`).join('');
}
window.refreshRemoteTargets = refreshRemoteTargets;

function addRemoteTarget(ip) {
    const input = document.getElementById('remote-target');
    const existing = input.value.split(/\s+/).filter(Boolean);
    if (!existing.includes(ip)) input.value = [...existing, ip].join('\n');
}

function _remotePorts(value) {
    const ports = new Set();
    for (const token of value.replace(/\s/g, '').split(',').filter(Boolean)) {
        if (/^\d+$/.test(token)) ports.add(Number(token));
        else if (/^\d+-\d+$/.test(token)) {
            const [start, end] = token.split('-').map(Number);
            if (start > end || end - start > 100) throw new Error(`Некорректный диапазон: ${token}`);
            for (let port = start; port <= end; port++) ports.add(port);
        } else throw new Error(`Некорректный порт: ${token}`);
    }
    if ([...ports].some((port) => port < 1 || port > 65535)) throw new Error('Порт должен быть от 1 до 65535');
    return [...ports];
}

async function startRemoteDesktopScan(event) {
    event.preventDefault();
    const button = document.getElementById('remote-scan-button');
    const progress = document.getElementById('remote-progress');
    try {
        const body = {
            targets: document.getElementById('remote-target').value.trim(),
            scan_rdp: document.getElementById('remote-rdp').checked,
            scan_vnc: document.getElementById('remote-vnc').checked,
            rdp_ports: _remotePorts(document.getElementById('remote-rdp-ports').value),
            vnc_ports: _remotePorts(document.getElementById('remote-vnc-ports').value),
        };
        button.disabled = true;
        button.innerHTML = '<span class="spinner" style="width:14px;height:14px;"></span> Запуск...';
        progress.style.display = 'block';
        progress.innerHTML = 'Подготовка проверки...';
        const response = await fetch('/api/remote-desktop/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось запустить проверку');
        localStorage.setItem('ip2domain_remote_job', data.job_id);
        pollRemoteDesktopScan(data.job_id);
    } catch (error) {
        button.disabled = false;
        button.textContent = '▶ Запустить проверку';
        progress.style.display = 'block';
        progress.innerHTML = `<span style="color:#f87171">${_esc(error.message)}</span>`;
    }
}

function pollRemoteDesktopScan(jobId) {
    if (window._remoteDesktopPoller) clearInterval(window._remoteDesktopPoller);
    const timer = setInterval(async () => {
        const button = document.getElementById('remote-scan-button');
        const progress = document.getElementById('remote-progress');
        try {
            const response = await fetch(`/api/remote-desktop/scan/${jobId}`);
            const job = await response.json();
            if (!response.ok) throw new Error(job.detail || 'Задание не найдено');
            progress.innerHTML = `<div class="progress-header"><span>${_esc(job.stage || 'Проверка...')}</span><span>${job.progress_pct || 0}%</span></div><div class="progress-track"><div class="progress-fill" style="width:${job.progress_pct || 0}%"></div></div>`;
            button.innerHTML = `<span class="spinner" style="width:14px;height:14px;"></span> Проверка... ${job.progress_pct || 0}%`;
            if (job.status === 'completed') {
                clearInterval(timer);
                button.disabled = false;
                button.textContent = '↻ Запустить повторно';
                renderRemoteDesktopResults(job.results || {});
            } else if (job.status === 'error' || job.status === 'interrupted') {
                clearInterval(timer);
                button.disabled = false;
                button.textContent = '▶ Запустить проверку';
                progress.innerHTML = `<span style="color:#f87171">${_esc(job.error || 'Проверка прервана')}</span>`;
            }
        } catch (error) {
            clearInterval(timer);
            button.disabled = false;
            button.textContent = '▶ Запустить проверку';
            progress.innerHTML = `<span style="color:#f87171">${_esc(error.message)}</span>`;
        }
    }, 2000);
    window._remoteDesktopPoller = timer;
}

async function restoreRemoteDesktopScan() {
    try {
        const savedResponse = await fetch('/api/remote-desktop/results');
        if (savedResponse.ok) renderRemoteDesktopResults(await savedResponse.json());
    } catch (_) {}
    const jobId = localStorage.getItem('ip2domain_remote_job');
    if (!jobId) return;
    try {
        const response = await fetch(`/api/remote-desktop/scan/${jobId}`);
        if (!response.ok) return;
        const job = await response.json();
        const progress = document.getElementById('remote-progress');
        if (job.status === 'completed' && job.results) {
            progress.style.display = 'block';
            progress.textContent = `Завершено · проверено ${job.total_targets || job.results.target_count || 0} IP`;
            renderRemoteDesktopResults(job.results);
        } else if (job.status === 'queued' || job.status === 'running') {
            document.getElementById('remote-scan-button').disabled = true;
            progress.style.display = 'block';
            pollRemoteDesktopScan(jobId);
        }
    } catch (_) {}
}

function renderRemoteDesktopResults(result) {
    const container = document.getElementById('remote-results');
    const services = result.services || [];
    if (!services.length) {
        container.innerHTML = '<div class="empty-state">Открытые RDP/VNC-сервисы не обнаружены</div>';
        return;
    }
    container.innerHTML = services.map((service) => {
        const protocol = service.protocol_type === 'vnc' ? 'VNC' : 'RDP';
        const scripts = (service.scripts || []).map((script) => `<details><summary>${_esc(script.id)}</summary><pre>${_esc(script.output)}</pre></details>`).join('');
        const capture = service.capture_id
            ? `<a class="remote-capture" href="/api/remote-desktop/capture/${service.capture_id}" target="_blank"><img src="/api/remote-desktop/capture/${service.capture_id}" alt="VNC ${_esc(service.target)}:${service.port}"><span>Открыть снимок полностью</span></a>`
            : service.protocol_type === 'vnc' ? `<div class="remote-capture-state">${_esc(service.capture_message || 'Снимок недоступен')}</div>` : '';
        return `<article class="remote-service-card"><div class="remote-service-head"><span class="remote-protocol ${service.protocol_type}">${protocol}</span><div><b>${_esc(service.target)}:${service.port}</b><small>${_esc(service.product || service.service || 'Версия не определена')}</small></div></div>${capture}<div class="remote-script-list">${scripts}</div></article>`;
    }).join('');
}

document.addEventListener('DOMContentLoaded', restoreRemoteDesktopScan);
