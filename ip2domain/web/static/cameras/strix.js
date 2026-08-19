'use strict';
// ── Strix Scanner Client Implementation ───────────────────────
let activeStrixJobId = null;
let strixPresetsLoaded = false;

function refreshStrixGraphTargets() {
    const container = document.getElementById('strix-graph-targets');
    if (!container) return;
    const ips = window.getGraphUniqueIPs ? window.getGraphUniqueIPs() : [];
    if (!ips.length) {
        container.innerHTML = '';
        return;
    }
    container.innerHTML = `<span style="font-size:0.7rem; color:var(--text-muted); width:100%;">Цели из текущего графа (${ips.length}):</span>` +
        ips.slice(0, 10).map((ip) => `<button type="button" class="btn btn-ghost btn-small" onclick="appendStrixTarget('${_esc(ip)}')">+ ${_esc(ip)}</button>`).join('') +
        (ips.length > 10 ? `<button type="button" class="btn btn-ghost btn-small" onclick="appendAllStrixTargets()">+ Добавить все (${ips.length})</button>` : '');
}
window.refreshStrixGraphTargets = refreshStrixGraphTargets;

function appendStrixTarget(ip) {
    const area = document.getElementById('strix-target');
    if (!area) return;
    const lines = area.value.split('\n').map(l => l.trim()).filter(Boolean);
    if (!lines.includes(ip)) {
        lines.push(ip);
        area.value = lines.join('\n');
    }
}
window.appendStrixTarget = appendStrixTarget;

function appendAllStrixTargets() {
    const area = document.getElementById('strix-target');
    if (!area) return;
    const ips = window.getGraphUniqueIPs ? window.getGraphUniqueIPs() : [];
    const lines = new Set(area.value.split('\n').map(l => l.trim()).filter(Boolean));
    ips.forEach(ip => lines.add(ip));
    area.value = Array.from(lines).join('\n');
}
window.appendAllStrixTargets = appendAllStrixTargets;

async function loadAsnPrefixesForStrix() {
    const input = document.getElementById('strix-asn-input');
    const btn = document.getElementById('strix-asn-btn');
    const status = document.getElementById('strix-asn-status');
    const area = document.getElementById('strix-target');
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
window.loadAsnPrefixesForStrix = loadAsnPrefixesForStrix;

let _strixDbTargetsCache = null;

async function updateStrixDbCounts() {
    try {
        const resp = await fetch('/api/strix/targets/db_ips');
        if (!resp.ok) return;
        const data = await resp.json();
        _strixDbTargetsCache = data;

        const countNotGo2rtc = document.getElementById('count-not-go2rtc');
        const countAllDb = document.getElementById('count-all-db');

        if (countNotGo2rtc) countNotGo2rtc.textContent = data.counts?.not_in_go2rtc ?? 0;
        if (countAllDb) countAllDb.textContent = data.counts?.total_saved ?? 0;
    } catch (e) {
        console.debug('Failed to fetch DB targets count:', e);
    }
}
window.updateStrixDbCounts = updateStrixDbCounts;

async function insertStrixDbTargets(type = 'not_in_go2rtc') {
    const area = document.getElementById('strix-target');
    const status = document.getElementById('strix-asn-status');
    if (!area) return;

    try {
        let data = _strixDbTargetsCache;
        if (!data) {
            if (status) {
                status.style.color = '#93c5fd';
                status.textContent = 'Загрузка списка IP из базы...';
            }
            const resp = await fetch('/api/strix/targets/db_ips');
            if (!resp.ok) throw new Error('Ошибка получения списка IP из базы');
            data = await resp.json();
            _strixDbTargetsCache = data;
        }

        const ipList = type === 'not_in_go2rtc' ? (data.not_in_go2rtc || []) : (data.all_ips || []);
        if (!ipList.length) {
            if (status) {
                status.style.color = '#eab308';
                status.textContent = type === 'not_in_go2rtc'
                    ? 'Все найденные камеры из базы уже добавлены в go2rtc!'
                    : 'В базе пока нет сохраненных камер';
            }
            return;
        }

        area.value = ipList.join('\n');
        if (status) {
            status.style.color = '#4ade80';
            status.textContent = type === 'not_in_go2rtc'
                ? `✓ Подставлено ${ipList.length} IP (не добавленных в go2rtc)`
                : `✓ Подставлено ${ipList.length} всех IP из базы`;
            setTimeout(() => { if (status.textContent.startsWith('✓')) status.textContent = ''; }, 6000);
        }
    } catch (err) {
        if (status) {
            status.style.color = '#ef4444';
            status.textContent = err.message;
        }
    }
}
window.insertStrixDbTargets = insertStrixDbTargets;

async function loadStrixPresets() {
    if (strixPresetsLoaded) return;
    const select = document.getElementById('strix-preset');
    if (!select) return;
    try {
        const response = await fetch('/api/strix/presets');
        if (!response.ok) return;
        const data = await response.json();
        const results = data.results || [];
        if (results.length) {
            const presets = results.filter(r => r.type === 'preset');
            const brands = results.filter(r => r.type === 'brand');
            
            let html = '<optgroup label="Пресеты потоков">';
            presets.forEach(p => {
                const selected = p.id === 'p:top-150' ? 'selected' : '';
                html += `<option value="${_esc(p.id)}" ${selected}>${_esc(p.name)}</option>`;
            });
            html += '</optgroup>';
            
            if (brands.length) {
                html += '<optgroup label="Бренды и производители">';
                brands.forEach(b => {
                    html += `<option value="${_esc(b.id)}">${_esc(b.name)}</option>`;
                });
                html += '</optgroup>';
            }
            select.innerHTML = html;
            strixPresetsLoaded = true;
        }
    } catch (_) {}
}
window.loadStrixPresets = loadStrixPresets;

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
                renderStrixResults(job.results);
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
            if (job.results && job.results.length) {
                renderStrixResults(job.results);
            }
        }
    } catch (_) {}
}
window.restoreStrixScan = restoreStrixScan;

let strixCachedItems = [];
let strixActiveGo2rtcStreams = new Set();
let strixActiveGo2rtcUrls = new Set();
let strixActiveGo2rtcIps = new Set();

async function refreshStrixGo2rtcState() {
    try {
        const response = await fetch('/api/go2rtc/streams');
        if (response.ok) {
            const data = await response.json();
            const streams = data.streams || {};
            strixActiveGo2rtcStreams = new Set(Object.keys(streams));
            strixActiveGo2rtcUrls = new Set();
            strixActiveGo2rtcIps = new Set();
            for (const name in streams) {
                const s = streams[name] || {};
                const prods = s.producers || [];
                prods.forEach(p => {
                    if (p.url) {
                        const cleanUrl = p.url.trim().toLowerCase();
                        strixActiveGo2rtcUrls.add(cleanUrl);
                        const match = cleanUrl.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
                        if (match) strixActiveGo2rtcIps.add(match[0]);
                    }
                });
                const nameMatch = name.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
                if (nameMatch) strixActiveGo2rtcIps.add(nameMatch[0]);
            }
        }
    } catch (_) {}
}

async function loadStrixResults() {
    const container = document.getElementById('strix-results');
    if (!container) return;
    try {
        await refreshStrixGo2rtcState();
        const response = await fetch('/api/strix/results');
        if (!response.ok) return;
        const data = await response.json();
        strixCachedItems = data.results || [];
        renderStrixResults(strixCachedItems);
        updateStrixDbCounts();
    } catch (_) {}
}
window.loadStrixResults = loadStrixResults;

async function clearStrixResults() {
    if (!confirm('Очистить сохранённые результаты Strix?')) return;
    try {
        await fetch('/api/strix/results', {method: 'DELETE'});
        strixCachedItems = [];
        loadStrixResults();
    } catch (_) {}
}
window.clearStrixResults = clearStrixResults;

let strixResultsSearchQuery = '';
let strixStatusFilter = 'all'; // 'all', 'in_go2rtc', 'not_in_go2rtc', 'garbage'
let strixHideGarbage = true;   // by default hide junk cameras unless 'garbage' or 'all_with_garbage' selected

function filterStrixResultsBySearch(query) {
    strixResultsSearchQuery = (query || '').toLowerCase().trim();
    renderStrixResults(strixCachedItems);
}
window.filterStrixResultsBySearch = filterStrixResultsBySearch;

function setStrixStatusFilter(filter) {
    strixStatusFilter = filter;
    renderStrixResults(strixCachedItems);
}
window.setStrixStatusFilter = setStrixStatusFilter;

function toggleStrixHideGarbage(hide) {
    strixHideGarbage = hide;
    renderStrixResults(strixCachedItems);
}
window.toggleStrixHideGarbage = toggleStrixHideGarbage;

async function toggleStrixGarbage(ip, isCurrentlyGarbage) {
    const newStatus = !isCurrentlyGarbage;
    // Optimistic UI update
    const item = strixCachedItems.find(i => i.ip === ip);
    if (item) {
        item.is_garbage = newStatus;
    }
    renderStrixResults(strixCachedItems);

    try {
        const resp = await fetch(`/api/strix/results/${encodeURIComponent(ip)}/garbage`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ is_garbage: newStatus })
        });
        if (!resp.ok) {
            const err = await resp.json();
            throw new Error(err.detail || 'Ошибка сохранения статуса');
        }
    } catch (err) {
        alert(`Не удалось изменить статус для ${ip}: ${err.message}`);
        if (item) {
            item.is_garbage = isCurrentlyGarbage;
            renderStrixResults(strixCachedItems);
        }
    }
}
window.toggleStrixGarbage = toggleStrixGarbage;

function isStreamInGo2rtc(srcUrl, camName) {
    if (!srcUrl) return false;
    const cleanUrl = srcUrl.trim().toLowerCase();
    if (strixActiveGo2rtcUrls.has(cleanUrl)) return true;
    const noAuthUrl = cleanUrl.replace(/:\/\/[^@]+@/, '://');
    if (strixActiveGo2rtcUrls.has(noAuthUrl)) return true;
    if (camName && strixActiveGo2rtcStreams.has(camName)) return true;
    return false;
}

function renderStrixResults(items) {
    const container = document.getElementById('strix-results');
    if (!container) return;
    
    // Merge items into strixCachedItems without duplicates
    if (items && items.length) {
        items.forEach(newItem => {
            const existingIdx = strixCachedItems.findIndex(ci => ci.ip === newItem.ip);
            if (existingIdx >= 0) {
                strixCachedItems[existingIdx] = {
                    ...newItem,
                    is_garbage: newItem.is_garbage !== undefined ? newItem.is_garbage : strixCachedItems[existingIdx].is_garbage
                };
            } else {
                strixCachedItems.unshift(newItem);
            }
        });
    }

    const allItems = strixCachedItems.length ? strixCachedItems : (items || []);
    if (!allItems || !allItems.length) {
        container.innerHTML = '<div class="empty-state">Нет обнаруженных камер или потоков</div>';
        return;
    }

    // Group items by IP
    const ipGroups = new Map();
    allItems.forEach((item) => {
        const ip = item.ip;
        if (!ipGroups.has(ip)) {
            ipGroups.set(ip, {
                ip: ip,
                probe: item.probe || {},
                session_id: item.session_id || '',
                streams: [],
                is_garbage: Boolean(item.is_garbage),
                timestamp: item.timestamp || ''
            });
        }
        const group = ipGroups.get(ip);
        if (item.is_garbage !== undefined) group.is_garbage = Boolean(item.is_garbage);
        if (item.session_id && !group.session_id) group.session_id = item.session_id;
        (item.streams || []).forEach((st) => {
            if (!group.streams.some(existing => existing.source === st.source)) {
                group.streams.push(st);
            }
        });
    });

    // Compute stats for all groups
    let countTotalIps = ipGroups.size;
    let countInGo2rtc = 0;
    let countNotInGo2rtc = 0;
    let countGarbage = 0;

    ipGroups.forEach((group, ip) => {
        let hasGo2rtc = strixActiveGo2rtcIps.has(ip);
        if (!hasGo2rtc) {
            hasGo2rtc = (group.streams || []).some((st, idx) => {
                const camName = `strix_${ip.replace(/[^a-zA-Z0-9]/g, '_')}_${idx+1}`;
                return isStreamInGo2rtc(st.source, camName);
            });
        }
        group.hasAddedStreams = hasGo2rtc;
        if (hasGo2rtc) countInGo2rtc++;
        else countNotInGo2rtc++;
        if (group.is_garbage) countGarbage++;
    });

    let totalStreamsCount = 0;
    let filteredGroupsCount = 0;
    let html = '';

    // Search and Filters toolbar at top of results
    html += `
    <div style="grid-column: 1 / -1; display: flex; flex-direction: column; gap: 0.75rem; margin-bottom: 0.75rem; background: rgba(15,23,42,0.6); padding: 0.85rem 1rem; border-radius: 10px; border: 1px solid var(--card-border); box-shadow: 0 4px 20px rgba(0,0,0,0.2);">
        
        <!-- Upper Row: Stats and Search & Expand -->
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.75rem;">
            <div style="font-size: 0.85rem; color: #cbd5e1; display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;">
                <span>Всего IP: <strong style="color: #fff;">${countTotalIps}</strong></span>
                <span style="color: #64748b;">•</span>
                <span>Потоков в выдаче: <strong id="strix-total-streams-badge" style="color: #4ade80;">...</strong></span>
            </div>
            <div style="display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap;">
                <input type="search" placeholder="Поиск по IP, протоколу, URL..." value="${_esc(strixResultsSearchQuery)}" oninput="filterStrixResultsBySearch(this.value)" style="padding: 0.35rem 0.65rem; font-size: 0.78rem; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.15); border-radius: 6px; color: #fff; min-width: 220px;">
                <button type="button" class="btn btn-ghost btn-small" onclick="toggleAllStrixGroups(true)" style="font-size: 0.72rem; padding: 0.25rem 0.5rem;">Развернуть все</button>
                <button type="button" class="btn btn-ghost btn-small" onclick="toggleAllStrixGroups(false)" style="font-size: 0.72rem; padding: 0.25rem 0.5rem;">Свернуть все</button>
            </div>
        </div>

        <!-- Lower Row: Filter Tabs & Garbage Toggle -->
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.6rem; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 0.6rem;">
            <div style="display: flex; gap: 0.4rem; align-items: center; flex-wrap: wrap;">
                <button type="button" class="btn btn-small ${strixStatusFilter === 'all' ? 'btn-primary' : 'btn-ghost'}" onclick="setStrixStatusFilter('all')" style="font-size: 0.75rem; padding: 0.25rem 0.6rem;">
                    Все (${countTotalIps})
                </button>
                <button type="button" class="btn btn-small ${strixStatusFilter === 'in_go2rtc' ? 'btn-primary' : 'btn-ghost'}" onclick="setStrixStatusFilter('in_go2rtc')" style="font-size: 0.75rem; padding: 0.25rem 0.6rem; ${strixStatusFilter === 'in_go2rtc' ? 'background: #16a34a; border-color: #22c55e;' : ''}">
                    ✓ В go2rtc (${countInGo2rtc})
                </button>
                <button type="button" class="btn btn-small ${strixStatusFilter === 'not_in_go2rtc' ? 'btn-primary' : 'btn-ghost'}" onclick="setStrixStatusFilter('not_in_go2rtc')" style="font-size: 0.75rem; padding: 0.25rem 0.6rem; ${strixStatusFilter === 'not_in_go2rtc' ? 'background: #6366f1;' : ''}">
                    + Не в go2rtc (${countNotInGo2rtc})
                </button>
                <button type="button" class="btn btn-small ${strixStatusFilter === 'garbage' ? 'btn-primary' : 'btn-ghost'}" onclick="setStrixStatusFilter('garbage')" style="font-size: 0.75rem; padding: 0.25rem 0.6rem; ${strixStatusFilter === 'garbage' ? 'background: #dc2626; border-color: #ef4444;' : 'color: #f87171;'}">
                    🗑 Мусорные (${countGarbage})
                </button>
            </div>

            <!-- Hide garbage checkbox when not specifically viewing garbage tab -->
            ${strixStatusFilter !== 'garbage' ? `
            <label style="display: flex; align-items: center; gap: 0.45rem; font-size: 0.78rem; color: #cbd5e1; cursor: pointer; user-select: none; background: rgba(0,0,0,0.25); padding: 0.25rem 0.55rem; border-radius: 6px; border: 1px solid rgba(255,255,255,0.08);">
                <input type="checkbox" ${strixHideGarbage ? 'checked' : ''} onchange="toggleStrixHideGarbage(this.checked)" style="cursor: pointer;">
                <span>Скрыть мусорные (${countGarbage})</span>
            </label>
            ` : ''}
        </div>
    </div>`;

    // Preserve user open/collapsed states of details elements
    const openedGroupIds = new Set();
    document.querySelectorAll('#strix-results details[open]').forEach(d => {
        if (d.id) openedGroupIds.add(d.id);
    });

    ipGroups.forEach((group, ip) => {
        const isGarbage = Boolean(group.is_garbage);
        const hasAddedStreamsInGroup = Boolean(group.hasAddedStreams);

        // Filter by Status Tab
        if (strixStatusFilter === 'in_go2rtc' && !hasAddedStreamsInGroup) return;
        if (strixStatusFilter === 'not_in_go2rtc' && hasAddedStreamsInGroup) return;
        if (strixStatusFilter === 'garbage' && !isGarbage) return;

        // Hide garbage toggle filter (when not on garbage tab)
        if (strixStatusFilter !== 'garbage' && strixHideGarbage && isGarbage) {
            return;
        }

        let streams = group.streams || [];
        if (strixResultsSearchQuery) {
            streams = streams.filter(st => {
                const src = (st.source || '').toLowerCase();
                const codecs = ((st.codecs || []).join(' ')).toLowerCase();
                return ip.includes(strixResultsSearchQuery) || src.includes(strixResultsSearchQuery) || codecs.includes(strixResultsSearchQuery);
            });
            if (!streams.length && !ip.includes(strixResultsSearchQuery)) {
                return;
            }
        }

        totalStreamsCount += streams.length;
        filteredGroupsCount++;

        const probe = group.probe || {};
        const probeType = (probe.type || (probe.reachable ? 'active' : 'camera')).toUpperCase();
        const sessionId = group.session_id || '';
        const groupDomId = `strix_group_${ip.replace(/[^a-zA-Z0-9]/g, '_')}`;
        const isDetailsOpen = openedGroupIds.has(groupDomId) || (openedGroupIds.size === 0 && ipGroups.size <= 2);

        // Count how many streams from this IP are added to go2rtc
        let groupAddedStreamsCount = 0;
        streams.forEach((st, idx) => {
            const camName = `strix_${ip.replace(/[^a-zA-Z0-9]/g, '_')}_${idx+1}`;
            if (isStreamInGo2rtc(st.source, camName)) {
                groupAddedStreamsCount++;
            }
        });
        if (groupAddedStreamsCount === 0 && hasAddedStreamsInGroup) {
            groupAddedStreamsCount = 1;
        }

        // Styling based on status (Garbage / In go2rtc / Normal)
        let groupBorderColor = 'rgba(255,255,255,0.1)';
        let groupBoxShadow = 'none';
        let groupBg = 'rgba(15,23,42,0.65)';
        let summaryBg = 'rgba(255,255,255,0.03)';
        let summaryBorderBottom = 'rgba(255,255,255,0.06)';

        if (isGarbage) {
            groupBorderColor = 'rgba(239, 68, 68, 0.35)';
            groupBg = 'rgba(30, 15, 20, 0.45)';
            summaryBg = 'rgba(239, 68, 68, 0.08)';
            summaryBorderBottom = 'rgba(239, 68, 68, 0.15)';
        } else if (hasAddedStreamsInGroup) {
            groupBorderColor = 'rgba(34, 197, 94, 0.45)';
            groupBoxShadow = '0 0 16px rgba(34, 197, 94, 0.12)';
            summaryBg = 'rgba(34, 197, 94, 0.05)';
            summaryBorderBottom = 'rgba(34, 197, 94, 0.2)';
        }

        html += `
        <div class="glass-card" style="grid-column: 1 / -1; margin-bottom: 0.75rem; border: 1px solid ${groupBorderColor}; border-radius: 10px; overflow: hidden; background: ${groupBg}; box-shadow: ${groupBoxShadow}; opacity: ${isGarbage ? '0.75' : '1'}; transition: border-color 0.2s, box-shadow 0.2s, opacity 0.2s;">
            <details id="${groupDomId}" ${isDetailsOpen ? 'open' : ''} style="width: 100%;">
                <summary style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 1rem; cursor: pointer; background: ${summaryBg}; border-bottom: 1px solid ${summaryBorderBottom}; user-select: none; gap: 0.5rem; flex-wrap: wrap;">
                    <div style="display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;">
                        <span style="font-size: 1.1rem; color: ${isGarbage ? '#f87171' : (hasAddedStreamsInGroup ? '#4ade80' : '#a5b4fc')};">
                            ${isGarbage ? '🗑️' : '📹'}
                        </span>
                        <div style="display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap;">
                            <strong style="font-size: 0.95rem; color: #fff; letter-spacing: 0.3px; ${isGarbage ? 'text-decoration: line-through; opacity: 0.8;' : ''}">${_esc(ip)}</strong>
                            <span style="font-size: 0.72rem; padding: 0.15rem 0.45rem; border-radius: 4px; background: rgba(99,102,241,0.2); color: #c7d2fe;">${_esc(probeType)}</span>
                            ${hasAddedStreamsInGroup ? `<span style="font-size: 0.68rem; padding: 0.15rem 0.45rem; border-radius: 4px; background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.4);">✓ В go2rtc (${groupAddedStreamsCount})</span>` : ''}
                            ${isGarbage ? `<span style="font-size: 0.68rem; padding: 0.15rem 0.45rem; border-radius: 4px; background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4);">🗑 Мусорная / Нерабочая</span>` : ''}
                        </div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.6rem;">
                        <button type="button" class="btn btn-small" onclick="event.stopPropagation(); toggleStrixGarbage('${_esc(ip)}', ${isGarbage})" style="font-size: 0.68rem; padding: 0.2rem 0.5rem; ${isGarbage ? 'background: rgba(34, 197, 94, 0.25); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.4);' : 'background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3);'}" title="${isGarbage ? 'Снять метку мусорной камеры' : 'Пометить камеру как нерабочую/мусорную'}">
                            ${isGarbage ? '✓ Восстановить' : '🗑 В мусорные'}
                        </button>
                        <span style="font-size: 0.75rem; color: #a1a1aa;">Потоков: <strong style="color: #4ade80;">${streams.length}</strong></span>
                        <span class="btn btn-ghost btn-small" style="font-size: 0.7rem; padding: 0.1rem 0.4rem;">▾</span>
                    </div>
                </summary>

                <div style="padding: 1rem; display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1rem; background: rgba(0,0,0,0.2);">
                    ${streams.map((st, idx) => {
                        const src = st.source || '';
                        const scheme = (src.split('://')[0] || 'rtsp').toUpperCase();
                        const width = st.width || 0;
                        const height = st.height || 0;
                        const resText = (width && height) ? `${width}x${height}` : 'SD';
                        const codecs = (st.codecs || []).join(', ') || 'H264';
                        const screenshotUrl = src ? `/api/strix/preview?url=${encodeURIComponent(src)}` : (sessionId ? `/api/strix/screenshot/${encodeURIComponent(sessionId)}/${idx}` : '');
                        const camName = `strix_${ip.replace(/[^a-zA-Z0-9]/g, '_')}_${idx+1}`;
                        const isAdded = isStreamInGo2rtc(src, camName);

                        let cardBorder = isAdded ? '1px solid rgba(34, 197, 94, 0.6)' : '1px solid rgba(255,255,255,0.08)';
                        let cardShadow = isAdded ? '0 0 14px rgba(34, 197, 94, 0.18)' : 'none';
                        let cardBg = isAdded ? 'rgba(15, 30, 24, 0.75)' : 'rgba(20,20,32,0.7)';

                        if (isGarbage) {
                            cardBorder = '1px solid rgba(239, 68, 68, 0.25)';
                            cardBg = 'rgba(25, 18, 22, 0.7)';
                        }

                        return `
                        <div class="glass-card" style="display: flex; flex-direction: column; overflow: hidden; border: ${cardBorder}; border-radius: 8px; background: ${cardBg}; box-shadow: ${cardShadow}; transition: all 0.2s;">
                            <div style="padding: 0.4rem 0.65rem; border-bottom: 1px solid ${isAdded ? 'rgba(34, 197, 94, 0.25)' : 'rgba(255,255,255,0.05)'}; display: flex; justify-content: space-between; align-items: center; background: ${isAdded ? 'rgba(34, 197, 94, 0.1)' : 'rgba(255,255,255,0.02)'}; font-size: 0.75rem;">
                                <span style="font-weight: 600; color: ${isAdded ? '#86efac' : '#e2e8f0'}; display: flex; align-items: center; gap: 0.35rem;">
                                    ${isAdded ? '<span style="color: #22c55e;">●</span>' : ''} #${idx+1} · ${_esc(resText)}
                                </span>
                                <div style="display: flex; gap: 0.35rem; align-items: center;">
                                    ${isAdded ? '<span style="padding: 0.1rem 0.35rem; border-radius: 4px; font-size: 0.62rem; font-weight: 700; background: rgba(34, 197, 94, 0.25); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.4);">В go2rtc</span>' : ''}
                                    <span style="padding: 0.1rem 0.35rem; border-radius: 4px; font-size: 0.65rem; font-weight: 700; background: rgba(139,92,246,0.25); color: #c4b5fd;">${_esc(scheme)}</span>
                                </div>
                            </div>

                            <div style="position: relative; width: 100%; aspect-ratio: 16/9; background: #080b12; display: flex; align-items: center; justify-content: center; overflow: hidden; cursor: pointer;" onclick="openStrixStreamPlayer('${_esc(src)}', '${_esc(camName)}', '${_esc(ip)}', ${idx})">
                                ${screenshotUrl ? `
                                    <img class="strix-lazy-img" data-src="${screenshotUrl}" alt="Снимок" style="width: 100%; height: 100%; object-fit: contain; opacity: 0; transition: opacity 0.3s;" onload="this.style.opacity='1'" onerror="this.style.display='none'; if(this.nextElementSibling) this.nextElementSibling.style.display='flex';">
                                    <div style="display:none; color:#71717a; font-size:0.7rem; align-items:center; justify-content:center; width:100%; height:100%;">Снимок недоступен</div>
                                ` : `
                                    <div style="color:#71717a; font-size:0.7rem;">Поток обнаружен</div>
                                `}
                                <div style="position: absolute; inset: 0; background: rgba(0,0,0,0.3); display: flex; flex-direction: column; align-items: center; justify-content: center; opacity: 0; transition: opacity 0.2s;" onmouseover="this.style.opacity='1'" onmouseout="this.style.opacity='0'">
                                    <div style="width: 42px; height: 42px; border-radius: 50%; background: ${isAdded ? 'rgba(34, 197, 94, 0.85)' : 'rgba(99,102,241,0.85)'}; display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 15px rgba(0,0,0,0.5);">
                                        <span style="color: #fff; font-size: 1.1rem; margin-left: 2px;">▶</span>
                                    </div>
                                    <span style="font-size: 0.68rem; color: #f1f5f9; margin-top: 0.4rem; font-weight: 500; text-shadow: 0 1px 3px rgba(0,0,0,0.8);">Тест потока</span>
                                </div>
                            </div>

                            <div style="padding: 0.5rem 0.65rem; display: flex; flex-direction: column; gap: 0.35rem; background: rgba(0,0,0,0.3); font-size: 0.72rem;">
                                <div style="font-family: monospace; font-size: 0.68rem; color: ${isAdded ? '#86efac' : '#93c5fd'}; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${_esc(src)}">
                                    🔗 ${_esc(src)}
                                </div>
                                <div style="color: #a1a1aa; font-size: 0.68rem;">Кодеки: ${_esc(codecs)}</div>
                                <div style="display: flex; justify-content: space-between; align-items: center; gap: 0.35rem; margin-top: 0.2rem;">
                                    <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.65rem; padding: 0.15rem 0.35rem;" onclick="copyToClipboard('${_esc(src)}')">📋 Скопировать</button>
                                    ${isAdded ? `
                                        <button type="button" class="btn btn-small" style="font-size: 0.65rem; padding: 0.15rem 0.45rem; background: rgba(34, 197, 94, 0.35); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.4);" disabled>✓ Добавлена</button>
                                    ` : `
                                        <button type="button" class="btn btn-small" style="font-size: 0.65rem; padding: 0.15rem 0.45rem; background: rgba(99,102,241,0.4);" onclick="quickAddGo2rtc('${_esc(camName)}', '${_esc(src)}')">+ go2rtc</button>
                                    `}
                                </div>
                            </div>
                        </div>`;
                    }).join('')}
                </div>
            </details>
        </div>`;
    });

    if (filteredGroupsCount === 0) {
        let msg = 'Нет результатов';
        if (strixStatusFilter === 'in_go2rtc') msg = 'Нет камер, добавленных в go2rtc';
        else if (strixStatusFilter === 'not_in_go2rtc') msg = 'Все камеры уже добавлены в go2rtc';
        else if (strixStatusFilter === 'garbage') msg = 'Нет камер, помеченных как мусорные / нерабочие';
        else if (strixResultsSearchQuery) msg = `Нет результатов по запросу "${_esc(strixResultsSearchQuery)}"`;

        container.innerHTML = `<div class="empty-state">${msg}</div>`;
        return;
    }

    container.innerHTML = html;
    const badge = document.getElementById('strix-total-streams-badge');
    if (badge) badge.textContent = totalStreamsCount;

    // Attach IntersectionObserver for lazy loading images viewport-only
    initStrixLazyLoading();
}

let strixImageObserver = null;
function initStrixLazyLoading() {
    if (strixImageObserver) {
        strixImageObserver.disconnect();
    }
    const lazyImages = document.querySelectorAll('#strix-results img.strix-lazy-img[data-src]');
    if (!lazyImages.length) return;

    function loadImg(img) {
        const src = img.getAttribute('data-src');
        if (src) {
            img.src = src;
            img.removeAttribute('data-src');
        }
        if (strixImageObserver) {
            strixImageObserver.unobserve(img);
        }
    }

    if ('IntersectionObserver' in window) {
        strixImageObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    loadImg(entry.target);
                }
            });
        }, {
            root: null,
            rootMargin: '250px 0px',
            threshold: 0.01
        });

        lazyImages.forEach(img => strixImageObserver.observe(img));
    } else {
        lazyImages.forEach(img => loadImg(img));
    }

    // Re-observe images when a details group is opened
    document.querySelectorAll('#strix-results details').forEach(d => {
        d.addEventListener('toggle', () => {
            if (d.open && strixImageObserver) {
                d.querySelectorAll('img.strix-lazy-img[data-src]').forEach(img => {
                    strixImageObserver.observe(img);
                });
            }
        });
    });
}

function toggleAllStrixGroups(open) {
    document.querySelectorAll('#strix-results details').forEach(d => d.open = open);
}
window.toggleAllStrixGroups = toggleAllStrixGroups;

function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text);
        alert('URL скопирован в буфер обмена!');
    } else {
        prompt('Скопируйте URL:', text);
    }
}
window.copyToClipboard = copyToClipboard;

async function quickAddGo2rtc(name, url) {
    try {
        const response = await fetch("/api/go2rtc/streams", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({name, url})
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Ошибка добавления в go2rtc");
        if (name) strixActiveGo2rtcStreams.add(name);
        if (url) strixActiveGo2rtcUrls.add(url.trim().toLowerCase());
        alert(`Камера "${name}" успешно добавлена в go2rtc!`);
        if (window.loadGo2rtcStreams) loadGo2rtcStreams();
        renderStrixResults(strixCachedItems);
    } catch (err) {
        alert(err.message);
    }
}
window.quickAddGo2rtc = quickAddGo2rtc;

async function openStrixStreamPlayer(srcUrl, camName, ip, currentIdx = 0) {
    if (!srcUrl) return;
    
    // Find all streams for this IP group to enable switching
    let ipGroupStreams = [];
    const ipItem = strixCachedItems.find(item => item.ip === ip);
    if (ipItem && ipItem.streams && ipItem.streams.length > 0) {
        ipGroupStreams = ipItem.streams;
    }
    const totalStreams = ipGroupStreams.length;

    // Create or reuse modal dialog
    let dialog = document.getElementById('strix-player-dialog');
    if (!dialog) {
        dialog = document.createElement('dialog');
        dialog.id = 'strix-player-dialog';
        dialog.className = 'centra-player-dialog';
        dialog.style.maxWidth = '920px';
        dialog.style.width = '92vw';
        dialog.addEventListener('close', async () => {
            const tempName = dialog.dataset.tempStreamName;
            if (tempName) {
                // Remove temporary test stream from go2rtc
                fetch(`/api/go2rtc/streams/${encodeURIComponent(tempName)}`, {method: "DELETE"}).catch(() => {});
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
        fetch(`/api/go2rtc/streams/${encodeURIComponent(prevTempName)}`, {method: "DELETE"}).catch(() => {});
    }

    const tempName = `temp_test_${Date.now()}`;
    dialog.dataset.tempStreamName = tempName;

    // Navigation indexes
    const prevIdx = (currentIdx - 1 + totalStreams) % totalStreams;
    const nextIdx = (currentIdx + 1) % totalStreams;
    const prevStream = totalStreams > 1 ? ipGroupStreams[prevIdx] : null;
    const nextStream = totalStreams > 1 ? ipGroupStreams[nextIdx] : null;

    const isIpGarbage = Boolean(ipItem && ipItem.is_garbage);

    dialog.innerHTML = `
        <div class="centra-player-head" style="display: flex; justify-content: space-between; align-items: center; gap: 0.75rem;">
            <div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <strong>Тест видеопотока · ${_esc(ip)}</strong>
                    ${isIpGarbage ? `<span style="font-size: 0.68rem; padding: 0.1rem 0.4rem; border-radius: 4px; background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4);">🗑 Мусорная</span>` : ''}
                    ${totalStreams > 1 ? `<span style="font-size: 0.72rem; padding: 0.1rem 0.4rem; border-radius: 4px; background: rgba(99,102,241,0.25); color: #c4b5fd; font-weight: 600;">Поток ${currentIdx + 1} из ${totalStreams}</span>` : ''}
                </div>
                <small style="display: block; color: #93c5fd; font-family: monospace; font-size: 0.72rem; overflow: hidden; text-overflow: ellipsis;">${_esc(srcUrl)}</small>
            </div>
            <div style="display: flex; align-items: center; gap: 0.4rem; flex-shrink: 0;">
                <button type="button" id="strix-modal-garbage-btn" class="btn btn-small" style="font-size: 0.72rem; padding: 0.25rem 0.5rem; ${isIpGarbage ? 'background: rgba(34, 197, 94, 0.25); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.4);' : 'background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4);'}" onclick="toggleStrixGarbage('${_esc(ip)}', ${isIpGarbage}); document.getElementById('strix-player-dialog').close();">
                    ${isIpGarbage ? '✓ Снять метку мусора' : '🗑 В мусорные'}
                </button>
                ${totalStreams > 1 ? `
                    <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.75rem; padding: 0.25rem 0.55rem;" title="Предыдущий поток" onclick="openStrixStreamPlayer('${_esc(prevStream.source)}', '${_esc(ip)}_stream${prevIdx+1}', '${_esc(ip)}', ${prevIdx})">◀ Назад</button>
                    <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.75rem; padding: 0.25rem 0.55rem;" title="Следующий поток" onclick="openStrixStreamPlayer('${_esc(nextStream.source)}', '${_esc(ip)}_stream${nextIdx+1}', '${_esc(ip)}', ${nextIdx})">Вперед ▶</button>
                ` : ''}
                <button type="button" class="btn btn-small" style="background: rgba(99,102,241,0.5); font-size: 0.75rem;" onclick="quickAddGo2rtc('${_esc(camName)}', '${_esc(srcUrl)}'); this.disabled=true; this.textContent='Добавлено';">+ В go2rtc</button>
                <button class="centra-player-close" type="button" onclick="document.getElementById('strix-player-dialog').close()" aria-label="Закрыть">×</button>
            </div>
        </div>
        <div style="position: relative; width: 100%; aspect-ratio: 16/9; background: #000; display: flex; align-items: center; justify-content: center; overflow: hidden;">
            <div id="strix-modal-loader" style="display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 0.75rem; color: #cbd5e1;">
                <span class="spinner" style="width: 24px; height: 24px;"></span>
                <span style="font-size: 0.85rem;">Инициализация WebRTC/MSE трансляции...</span>
            </div>
            <iframe id="strix-modal-iframe" style="display: none; width: 100%; height: 100%; border: none;" allow="autoplay; fullscreen"></iframe>
            
            ${totalStreams > 1 ? `
                <button type="button" style="position: absolute; left: 10px; top: 50%; transform: translateY(-50%); width: 36px; height: 36px; border-radius: 50%; background: rgba(15,23,42,0.75); border: 1px solid rgba(255,255,255,0.2); color: #fff; display: flex; align-items: center; justify-content: center; cursor: pointer; backdrop-filter: blur(4px); transition: all 0.2s; z-index: 10;" onmouseover="this.style.background='rgba(99,102,241,0.85)'" onmouseout="this.style.background='rgba(15,23,42,0.75)'" onclick="openStrixStreamPlayer('${_esc(prevStream.source)}', '${_esc(ip)}_stream${prevIdx+1}', '${_esc(ip)}', ${prevIdx})" title="Предыдущий поток (#${prevIdx+1})">◀</button>
                <button type="button" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); width: 36px; height: 36px; border-radius: 50%; background: rgba(15,23,42,0.75); border: 1px solid rgba(255,255,255,0.2); color: #fff; display: flex; align-items: center; justify-content: center; cursor: pointer; backdrop-filter: blur(4px); transition: all 0.2s; z-index: 10;" onmouseover="this.style.background='rgba(99,102,241,0.85)'" onmouseout="this.style.background='rgba(15,23,42,0.75)'" onclick="openStrixStreamPlayer('${_esc(nextStream.source)}', '${_esc(ip)}_stream${nextIdx+1}', '${_esc(ip)}', ${nextIdx})" title="Следующий поток (#${nextIdx+1})">▶</button>
            ` : ''}

            <!-- Floating PTZ Overlay Controller -->
            <div id="strix-ptz-overlay" style="display: none; position: absolute; right: 16px; bottom: 16px; background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(255,255,255,0.2); border-radius: 12px; padding: 8px; backdrop-filter: blur(8px); box-shadow: 0 8px 32px rgba(0,0,0,0.6); z-index: 20; flex-direction: column; gap: 6px; align-items: center;">
                <div style="display: flex; justify-content: space-between; width: 100%; align-items: center; font-size: 0.7rem; color: #a5b4fc; font-weight: 600; padding: 0 2px;">
                    <span>🕹️ PTZ / Patrol</span>
                    <button type="button" style="background: none; border: none; color: #94a3b8; cursor: pointer; font-size: 0.8rem;" onclick="document.getElementById('strix-ptz-overlay').style.display='none'">✕</button>
                </div>
                <!-- 3x3 Direction Pad -->
                <div style="display: grid; grid-template-columns: repeat(3, 28px); grid-template-rows: repeat(3, 28px); gap: 3px;">
                    <button type="button" class="btn btn-ghost" style="padding:0; font-size:0.75rem;" onmousedown="sendPTZ('${_esc(ip)}', 'upleft')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')">↖</button>
                    <button type="button" class="btn btn-ghost" style="padding:0; font-size:0.75rem;" onmousedown="sendPTZ('${_esc(ip)}', 'up')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')">▲</button>
                    <button type="button" class="btn btn-ghost" style="padding:0; font-size:0.75rem;" onmousedown="sendPTZ('${_esc(ip)}', 'upright')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')">↗</button>
                    <button type="button" class="btn btn-ghost" style="padding:0; font-size:0.75rem;" onmousedown="sendPTZ('${_esc(ip)}', 'left')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')">◀</button>
                    <button type="button" class="btn btn-ghost" style="padding:0; font-size:0.65rem; color:#ef4444;" onclick="sendPTZ('${_esc(ip)}', 'stop')">■</button>
                    <button type="button" class="btn btn-ghost" style="padding:0; font-size:0.75rem;" onmousedown="sendPTZ('${_esc(ip)}', 'right')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')">▶</button>
                    <button type="button" class="btn btn-ghost" style="padding:0; font-size:0.75rem;" onmousedown="sendPTZ('${_esc(ip)}', 'downleft')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')">↙</button>
                    <button type="button" class="btn btn-ghost" style="padding:0; font-size:0.75rem;" onmousedown="sendPTZ('${_esc(ip)}', 'down')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')">▼</button>
                    <button type="button" class="btn btn-ghost" style="padding:0; font-size:0.75rem;" onmousedown="sendPTZ('${_esc(ip)}', 'downright')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')">↘</button>
                </div>
                <!-- Zoom & Patrol actions -->
                <div style="display: flex; gap: 4px; width: 100%; justify-content: center; margin-top: 2px;">
                    <button type="button" class="btn btn-small" style="font-size:0.65rem; padding: 2px 6px;" onmousedown="sendPTZ('${_esc(ip)}', 'zoom_in')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')" title="Приблизить">🔍 +</button>
                    <button type="button" class="btn btn-small" style="font-size:0.65rem; padding: 2px 6px;" onmousedown="sendPTZ('${_esc(ip)}', 'zoom_out')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')" title="Отдалить">🔍 -</button>
                </div>
                <div style="display: flex; gap: 4px; width: 100%; justify-content: center; margin-top: 2px;">
                    <button type="button" class="btn btn-small btn-ghost" style="font-size:0.62rem; padding: 2px 5px;" onclick="sendPTZ('${_esc(ip)}', 'goto_preset', '1')">Поз.1</button>
                    <button type="button" class="btn btn-small btn-ghost" style="font-size:0.62rem; padding: 2px 5px;" onclick="sendPTZ('${_esc(ip)}', 'goto_preset', '2')">Поз.2</button>
                    <button type="button" class="btn btn-small" style="font-size:0.62rem; padding: 2px 5px; background: rgba(139,92,246,0.6);" onclick="sendPTZ('${_esc(ip)}', 'start_patrol', '1')" title="Запустить тур патрулирования">⚡ Тур</button>
                </div>
            </div>
            
            <!-- PTZ Toggle Button -->
            <button type="button" id="strix-ptz-toggle-btn" style="position: absolute; right: 12px; bottom: 12px; background: rgba(15,23,42,0.8); border: 1px solid rgba(255,255,255,0.25); border-radius: 6px; padding: 4px 8px; color: #fff; font-size: 0.72rem; cursor: pointer; backdrop-filter: blur(4px); z-index: 15; display: flex; align-items: center; gap: 4px;" onclick="const ov = document.getElementById('strix-ptz-overlay'); if (ov) ov.style.display = (ov.style.display === 'none' ? 'flex' : 'none');">
                🕹️ <span>PTZ / Патруль</span>
            </button>
        </div>
        ${totalStreams > 1 ? `
            <div style="display: flex; gap: 0.35rem; padding: 0.4rem 0.6rem; background: rgba(10, 14, 26, 0.95); overflow-x: auto; border-top: 1px solid rgba(255,255,255,0.08); align-items: center; scrollbar-width: thin; scrollbar-color: rgba(99,102,241,0.4) transparent;" class="strix-modal-playlist">
                <span style="font-size: 0.68rem; color: #94a3b8; white-space: nowrap; margin-right: 0.2rem; font-weight: 500;">Каналы (${totalStreams}):</span>
                ${ipGroupStreams.map((st, i) => {
                    const isCur = i === currentIdx;
                    const stSrc = st.source || "";
                    const stRes = (st.width && st.height) ? `${st.width}p` : '';
                    const stCodecs = Array.isArray(st.codecs) ? st.codecs[0] : (st.codecs || 'RTSP');
                    const badge = stRes ? `${stRes}` : stCodecs;
                    return `
                        <button type="button" id="strix-stream-pill-${i}" class="btn btn-small" style="font-size: 0.65rem; padding: 0.18rem 0.45rem; white-space: nowrap; border-radius: 4px; ${isCur ? 'background: rgba(99,102,241,0.8); color: #fff; border: 1px solid #a5b4fc; font-weight: 700; box-shadow: 0 0 8px rgba(99,102,241,0.5);' : 'background: rgba(255,255,255,0.05); color: #cbd5e1; border: 1px solid rgba(255,255,255,0.1); font-weight: 400;'}" onclick="openStrixStreamPlayer('${_esc(stSrc)}', '${_esc(ip)}_stream${i+1}', '${_esc(ip)}', ${i})">
                            ${isCur ? '▶ ' : ''}#${i+1} · ${_esc(badge)}
                        </button>
                    `;
                }).join('')}
            </div>
        ` : ''}
    `;

    if (!dialog.open) {
        dialog.showModal();
    }

    // Auto-scroll active pill into view smoothly
    setTimeout(() => {
        const activePill = document.getElementById(`strix-stream-pill-${currentIdx}`);
        if (activePill) {
            activePill.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
        }
    }, 50);

    try {
        const isHttpSnapshot = srcUrl.startsWith('http://') || srcUrl.startsWith('https://');
        
        if (isHttpSnapshot) {
            // For HTTP JPEG/MJPEG snapshots or endpoints, show direct live player or frame with auto-refresh
            const iframe = document.getElementById('strix-modal-iframe');
            const loader = document.getElementById('strix-modal-loader');
            const playerContainer = iframe ? iframe.parentElement : null;
            if (playerContainer) {
                if (loader) loader.style.display = 'none';
                if (iframe) iframe.style.display = 'none';
                
                // Render live snapshot player with refresh capability
                playerContainer.innerHTML = `
                    <div style="position: relative; width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; background: #000;">
                        <img id="strix-modal-live-img" src="/api/strix/preview?url=${encodeURIComponent(srcUrl)}&t=${Date.now()}" alt="Live Snapshot" style="max-width: 100%; max-height: 100%; object-fit: contain;" onerror="this.style.display='none'; const el=document.getElementById('strix-modal-live-err'); if(el) el.style.display='flex';">
                        <div id="strix-modal-live-err" style="display: none; flex-direction: column; align-items: center; justify-content: center; gap: 0.5rem; color: #ef4444; font-size: 0.85rem;">
                            <span>⚠️ Поток недоступен (камера не отвечает по HTTP/MJPEG)</span>
                        </div>
                        <div style="position: absolute; bottom: 10px; right: 10px; display: flex; gap: 6px; background: rgba(0,0,0,0.6); padding: 4px 8px; border-radius: 6px;">
                            <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.7rem; padding: 2px 6px;" onclick="const img=document.getElementById('strix-modal-live-img'); const err=document.getElementById('strix-modal-live-err'); if(img){ img.style.display=''; img.src='/api/strix/preview?url=${encodeURIComponent(srcUrl)}&t='+Date.now(); } if(err) err.style.display='none';">🔄 Повторить</button>
                        </div>
                    </div>
                `;
            }
            return;
        }

        // Register temporary RTSP stream in go2rtc (with auto-transcode fallback for MPEG4/MJPEG)
        const response = await fetch("/api/go2rtc/streams", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                name: tempName,
                url: [srcUrl, `ffmpeg:${srcUrl}#video=h264#audio=aac`]
            })
        });
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || "Не удалось запустить временный поток в go2rtc");
        }

        const iframe = document.getElementById('strix-modal-iframe');
        const loader = document.getElementById('strix-modal-loader');
        if (iframe && loader) {
            iframe.src = `/api/go2rtc/player/stream.html?src=${encodeURIComponent(tempName)}`;
            iframe.onload = () => {
                loader.style.display = 'none';
                iframe.style.display = 'block';
            };
            // Fallback show iframe
            setTimeout(() => {
                loader.style.display = 'none';
                iframe.style.display = 'block';
            }, 800);
        }
    } catch (error) {
        const loader = document.getElementById('strix-modal-loader');
        if (loader) {
            loader.innerHTML = `<span style="color: #ef4444; font-size: 0.85rem;">Ошибка запуска: ${_esc(error.message)}</span>`;
        }
    }
}
window.openStrixStreamPlayer = openStrixStreamPlayer;

async function sendPTZ(ip, command, preset = '1') {
    try {
        await fetch('/api/go2rtc/ptz/control', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                ip: ip,
                command: command,
                preset_token: preset,
                speed: 0.5
            })
        });
    } catch (_) {}
}
window.sendPTZ = sendPTZ;

// Initialize presets and database target counts on load
if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            updateStrixDbCounts();
        });
    } else {
        updateStrixDbCounts();
    }
}

