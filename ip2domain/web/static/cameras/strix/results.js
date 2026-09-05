'use strict';
// ── Strix Scanner: Results Rendering, Filtering, and Garbage Tagging ────

window.strixCachedItems = window.strixCachedItems || [];
window.strixActiveGo2rtcStreams = window.strixActiveGo2rtcStreams || new Set();
window.strixActiveGo2rtcUrls = window.strixActiveGo2rtcUrls || new Set();
window.strixActiveGo2rtcIps = window.strixActiveGo2rtcIps || new Set();

let strixResultsSearchQuery = '';
let strixStatusFilter = 'all'; // 'all', 'in_go2rtc', 'not_in_go2rtc', 'garbage'
let strixHideGarbage = true;   // by default hide junk cameras unless 'garbage' or 'all_with_garbage' selected

function filterStrixResultsBySearch(query) {
    strixResultsSearchQuery = (query || '').toLowerCase().trim();
    renderStrixResults(window.strixCachedItems);
}
window.filterStrixResultsBySearch = filterStrixResultsBySearch;

function setStrixStatusFilter(filter) {
    strixStatusFilter = filter;
    renderStrixResults(window.strixCachedItems);
}
window.setStrixStatusFilter = setStrixStatusFilter;

function toggleStrixHideGarbage(hide) {
    strixHideGarbage = hide;
    renderStrixResults(window.strixCachedItems);
}
window.toggleStrixHideGarbage = toggleStrixHideGarbage;

async function toggleStrixGarbage(ip, isCurrentlyGarbage) {
    const newStatus = !isCurrentlyGarbage;
    // Optimistic UI update
    const item = window.strixCachedItems.find(i => i.ip === ip);
    if (item) {
        item.is_garbage = newStatus;
    }
    renderStrixResults(window.strixCachedItems);

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
            renderStrixResults(window.strixCachedItems);
        }
    }
}
window.toggleStrixGarbage = toggleStrixGarbage;

function isStreamInGo2rtc(srcUrl, camName) {
    if (!srcUrl) return false;
    const cleanUrl = srcUrl.trim().toLowerCase();
    if (window.strixActiveGo2rtcUrls && window.strixActiveGo2rtcUrls.has(cleanUrl)) return true;
    const noAuthUrl = cleanUrl.replace(/:\/\/[^@]+@/, '://');
    if (window.strixActiveGo2rtcUrls && window.strixActiveGo2rtcUrls.has(noAuthUrl)) return true;
    if (camName && window.strixActiveGo2rtcStreams && window.strixActiveGo2rtcStreams.has(camName)) return true;
    return false;
}
window.isStreamInGo2rtc = isStreamInGo2rtc;

function renderStrixResults(items) {
    const container = document.getElementById('strix-results');
    if (!container) return;
    
    // Merge items into window.strixCachedItems without duplicates
    if (items && items.length) {
        items.forEach(newItem => {
            const existingIdx = window.strixCachedItems.findIndex(ci => ci.ip === newItem.ip);
            if (existingIdx >= 0) {
                window.strixCachedItems[existingIdx] = {
                    ...newItem,
                    is_garbage: newItem.is_garbage !== undefined ? newItem.is_garbage : window.strixCachedItems[existingIdx].is_garbage
                };
            } else {
                window.strixCachedItems.unshift(newItem);
            }
        });
    }

    const allItems = window.strixCachedItems.length ? window.strixCachedItems : (items || []);
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
        let hasGo2rtc = window.strixActiveGo2rtcIps && window.strixActiveGo2rtcIps.has(ip);
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
                                    <img class="strix-lazy-img" src="${_esc(screenshotUrl)}" loading="lazy" alt="Снимок" style="width: 100%; height: 100%; object-fit: contain;" onerror="this.style.display='none'; if(this.nextElementSibling) this.nextElementSibling.style.display='flex';">
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
window.renderStrixResults = renderStrixResults;

function _sanitizeStrixImageUrl(url) {
    if (!url || typeof url !== 'string') return '';
    const trimmed = url.trim();
    if (trimmed.startsWith('/') || trimmed.startsWith('data:image/') || trimmed.startsWith('blob:') || /^https?:\/\//i.test(trimmed)) {
        return trimmed;
    }
    return '';
}

function initStrixLazyLoading() {
    // Native loading="lazy" handled by browser
}
window.initStrixLazyLoading = initStrixLazyLoading;

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
