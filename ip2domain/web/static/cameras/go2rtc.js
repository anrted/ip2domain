'use strict';
// --- go2rtc integration with IP Grouping, Tagging & Filtering ---

let go2rtcStreamsData = {};
let go2rtcMetaData = { cameras: {}, groups: {} };
let go2rtcCurrentFilterTag = "all";
let go2rtcSearchQuery = "";
let go2rtcCurrentViewMode = "groups"; // "groups" or "flat"
const PRESET_TAGS = [
    { id: "ПВЗ", label: "🏬 ПВЗ", color: "#f59e0b" },
    { id: "Магазин", label: "🛒 Магазин", color: "#3b82f6" },
    { id: "Офис", label: "🏢 Офис", color: "#8b5cf6" },
    { id: "Склад", label: "🏭 Склад", color: "#ec4899" },
    { id: "Дом", label: "🏠 Дом", color: "#10b981" },
    { id: "Парковка", label: "🚗 Парковка", color: "#64748b" },
    { id: "Избранное", label: "⭐ Избранное", color: "#eab308" },
];

function _esc(s) {
    if (!s) return "";
    return String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function extractIpFromUrl(url) {
    if (!url) return "unknown";
    try {
        const clean = url.replace(/^[a-zA-Z]+:\/\//, "");
        const hostPart = clean.split("/")[0].split("@").pop();
        const ip = hostPart.split(":")[0];
        return ip || "unknown";
    } catch {
        return "unknown";
    }
}

async function loadGo2rtcStreams() {
    const container = document.getElementById("go2rtc-streams-container");
    if (!container) return;
    container.innerHTML = '<div class="empty-state"><span class="spinner"></span> Загрузка камер go2rtc...</div>';
    
    try {
        const response = await fetch("/api/go2rtc/streams");
        const data = await response.json();
        if (data.error) {
            container.innerHTML = `<div class="empty-state" style="color: #ef4444;">Ошибка go2rtc: ${_esc(data.error)}</div>`;
            return;
        }
        
        go2rtcStreamsData = data.streams || {};
        go2rtcMetaData = data.meta || { cameras: {}, groups: {} };
        
        renderGo2rtcTagPills();
        renderGo2rtcStreams();
    } catch (err) {
        container.innerHTML = `<div class="empty-state" style="color: #ef4444;">Не удалось подключиться к go2rtc: ${_esc(err.message)}</div>`;
    }
}
window.loadGo2rtcStreams = loadGo2rtcStreams;

function setGo2rtcViewMode(mode) {
    go2rtcCurrentViewMode = mode;
    const grpBtn = document.getElementById("go2rtc-view-groups-btn");
    const flatBtn = document.getElementById("go2rtc-view-grid-btn");
    if (grpBtn && flatBtn) {
        if (mode === "groups") {
            grpBtn.classList.add("active");
            flatBtn.classList.remove("active");
        } else {
            flatBtn.classList.add("active");
            grpBtn.classList.remove("active");
        }
    }
    renderGo2rtcStreams();
}
window.setGo2rtcViewMode = setGo2rtcViewMode;

function onGo2rtcSearchChange(query) {
    go2rtcSearchQuery = (query || "").trim().toLowerCase();
    renderGo2rtcStreams();
}
window.onGo2rtcSearchChange = onGo2rtcSearchChange;

function setGo2rtcFilterTag(tag) {
    go2rtcCurrentFilterTag = tag;
    renderGo2rtcTagPills();
    renderGo2rtcStreams();
}
window.setGo2rtcFilterTag = setGo2rtcFilterTag;

function renderGo2rtcTagPills() {
    const pillsContainer = document.getElementById("go2rtc-tag-pills");
    if (!pillsContainer) return;
    
    // Count tags across all streams
    const tagCounts = { all: Object.keys(go2rtcStreamsData).length };
    const metaCams = go2rtcMetaData.cameras || {};
    
    for (const name of Object.keys(go2rtcStreamsData)) {
        const camMeta = metaCams[name] || {};
        const tags = camMeta.tags || [];
        for (const t of tags) {
            tagCounts[t] = (tagCounts[t] || 0) + 1;
        }
    }
    
    let pillsHtml = `
        <button type="button" class="btn btn-small ${go2rtcCurrentFilterTag === 'all' ? 'btn-primary' : 'btn-ghost'}" 
                onclick="setGo2rtcFilterTag('all')" 
                style="font-size: 0.72rem; padding: 0.2rem 0.6rem; border-radius: 9999px;">
            Все (${tagCounts.all})
        </button>
    `;
    
    for (const p of PRESET_TAGS) {
        const count = tagCounts[p.id] || 0;
        if (count > 0 || go2rtcCurrentFilterTag === p.id) {
            const isActive = go2rtcCurrentFilterTag === p.id;
            pillsHtml += `
                <button type="button" class="btn btn-small ${isActive ? 'btn-primary' : 'btn-ghost'}" 
                        onclick="setGo2rtcFilterTag('${_esc(p.id)}')" 
                        style="font-size: 0.72rem; padding: 0.2rem 0.6rem; border-radius: 9999px; ${isActive ? '' : `border: 1px solid ${p.color}40; color: ${p.color};`}">
                    ${p.label} (${count})
                </button>
            `;
        }
    }
    
    pillsContainer.innerHTML = pillsHtml;
}

function renderGo2rtcStreams() {
    const container = document.getElementById("go2rtc-streams-container");
    if (!container) return;
    
    const streamKeys = Object.keys(go2rtcStreamsData).sort((a, b) => a.localeCompare(b, undefined, {numeric: true, sensitivity: 'base'}));
    if (!streamKeys.length) {
        container.innerHTML = '<div class="empty-state">Нет активных камер в go2rtc. Добавьте первую камеру через форму выше.</div>';
        return;
    }
    
    const metaCams = go2rtcMetaData.cameras || {};
    const metaGroups = go2rtcMetaData.groups || {};
    
    // 1. Group streams by IP / host
    const groups = {};
    for (const name of streamKeys) {
        const stream = go2rtcStreamsData[name] || {};
        const producers = stream.producers || [];
        const srcUrl = producers.length ? (producers[0].url || "") : "";
        const ip = extractIpFromUrl(srcUrl);
        
        const camMeta = metaCams[name] || {};
        const tags = camMeta.tags || [];
        const title = camMeta.custom_title || name;
        
        // Filter by Tag
        if (go2rtcCurrentFilterTag !== "all" && !tags.includes(go2rtcCurrentFilterTag)) {
            continue;
        }
        
        // Filter by Search Query
        if (go2rtcSearchQuery) {
            const matchesName = name.toLowerCase().includes(go2rtcSearchQuery);
            const matchesTitle = title.toLowerCase().includes(go2rtcSearchQuery);
            const matchesUrl = srcUrl.toLowerCase().includes(go2rtcSearchQuery);
            const matchesIp = ip.toLowerCase().includes(go2rtcSearchQuery);
            const matchesTags = tags.some(t => t.toLowerCase().includes(go2rtcSearchQuery));
            if (!matchesName && !matchesTitle && !matchesUrl && !matchesIp && !matchesTags) {
                continue;
            }
        }
        
        if (!groups[ip]) {
            groups[ip] = [];
        }
        groups[ip].push({ name, stream, srcUrl, camMeta, tags, title, ip });
    }
    
    const groupIps = Object.keys(groups).sort();
    if (!groupIps.length) {
        container.innerHTML = '<div class="empty-state">По вашему запросу камер не найдено.</div>';
        return;
    }
    
    let html = "";
    
    if (go2rtcCurrentViewMode === "flat") {
        // Flat Grid View
        html += '<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 1.25rem; width: 100%;">';
        for (const ip of groupIps) {
            for (const item of groups[ip]) {
                html += renderCameraCard(item);
            }
        }
        html += '</div>';
    } else {
        // Grouped by IP / Location View - Responsive Multi-Column Masonry Grid
        html += '<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 1.25rem; width: 100%; align-items: start;">';
        for (const ip of groupIps) {
            const camList = groups[ip];
            const grpMeta = metaGroups[ip] || {};
            const groupDisplayName = grpMeta.custom_name || `Локация: ${ip}`;
            const groupTags = grpMeta.tags || [];

            // Group tag badges
            let groupTagBadges = "";
            for (const t of groupTags) {
                const preset = PRESET_TAGS.find(p => p.id === t);
                const color = preset ? preset.color : "#94a3b8";
                groupTagBadges += `<span style="font-size: 0.65rem; padding: 0.1rem 0.4rem; border-radius: 4px; background: ${color}20; color: ${color}; border: 1px solid ${color}40; font-weight: 600;">${_esc(t)}</span>`;
            }

            // Calculate grid span: 1 cam = 1 column, 2-3 cams = 2 cols, 4+ cams = full width (3-4 cols)
            let colSpanStyle = "grid-column: span 1;";
            if (camList.length === 2) {
                colSpanStyle = "grid-column: span min(2, auto);";
            } else if (camList.length >= 3) {
                colSpanStyle = "grid-column: 1 / -1;";
            }
            
            html += `
            <div class="glass-card" style="background: rgba(15, 23, 42, 0.5); border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; overflow: hidden; width: 100%; box-sizing: border-box; padding: 0; ${colSpanStyle}">
                <div style="padding: 0.4rem 0.65rem; background: rgba(30, 41, 59, 0.55); border-bottom: 1px solid rgba(255,255,255,0.06); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.35rem;">
                    <div style="display: flex; align-items: center; gap: 0.35rem; flex-wrap: wrap; flex: 1; min-width: 140px;">
                        <span style="font-size: 0.9rem;">📍</span>
                        <div style="font-weight: 700; font-size: 0.82rem; color: #f8fafc;">
                            <span id="grp-title-${_esc(ip)}">${_esc(groupDisplayName)}</span>
                            <span style="font-family: monospace; font-size: 0.68rem; color: #94a3b8; font-weight: normal; margin-left: 0.25rem;">(${_esc(ip)})</span>
                        </div>
                        <button type="button" class="btn btn-ghost btn-small" onclick="promptEditGroupName('${_esc(ip)}')" style="font-size: 0.62rem; padding: 0.05rem 0.25rem; color: #94a3b8;" title="Переименовать объект">✏️</button>
                        <button type="button" class="btn btn-ghost btn-small" onclick="promptEditGroupTags('${_esc(ip)}')" style="font-size: 0.62rem; padding: 0.05rem 0.3rem; color: #a5b4fc; border: 1px dashed rgba(99,102,241,0.4);" title="Управление тегами объекта">🏷️ Тег</button>
                        ${groupTagBadges}
                        <span style="font-size: 0.65rem; padding: 0.08rem 0.4rem; border-radius: 9999px; background: rgba(99, 102, 241, 0.2); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.3); font-weight: 600;">
                            ${camList.length} ${camList.length === 1 ? 'камера' : (camList.length < 5 ? 'камеры' : 'камер')}
                        </span>
                    </div>
                    
                    <div style="display: flex; gap: 0.3rem; align-items: center; flex-wrap: wrap;">
                        <button type="button" class="btn btn-ghost btn-small" onclick="openAddStreamToGroupModal('${_esc(ip)}')" style="font-size: 0.65rem; padding: 0.12rem 0.4rem; background: rgba(99,102,241,0.2); color: #c7d2fe; border: 1px solid rgba(99,102,241,0.4);">+ Поток</button>
                        <button type="button" class="btn btn-ghost btn-small" onclick="playAllInGroup('${_esc(ip)}')" style="font-size: 0.65rem; padding: 0.12rem 0.4rem; background: rgba(16,185,129,0.15); color: #34d399; border: 1px solid rgba(16,185,129,0.3);">▶ Все</button>
                        <button type="button" class="btn btn-ghost btn-small" onclick="stopAllInGroup('${_esc(ip)}')" style="font-size: 0.65rem; padding: 0.12rem 0.4rem; background: rgba(239,68,68,0.15); color: #f87171; border: 1px solid rgba(239,68,68,0.3);">■</button>
                    </div>
                </div>
                
                <div style="padding: 0.45rem;">
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 0.5rem; width: 100%;">
                        ${camList.map(item => renderCameraCard(item)).join("")}
                    </div>
                </div>
            </div>`;
        }
        html += '</div>';
    }
    
    container.innerHTML = html;
    initLazyImages(container);
}

function renderCameraCard({ name, stream, srcUrl, camMeta, tags, title, ip }) {
    const consumersCount = stream.consumers ? stream.consumers.length : 0;
    const containerId = `go2rtc-player-${name.replace(/[^a-zA-Z0-9_-]/g, '_')}`;
    const frameUrl = `/api/go2rtc/frame/${encodeURIComponent(name)}`;
    
    // Tag badges
    let tagBadges = "";
    for (const t of tags) {
        const preset = PRESET_TAGS.find(p => p.id === t);
        const color = preset ? preset.color : "#94a3b8";
        tagBadges += `<span style="font-size: 0.62rem; padding: 0.08rem 0.35rem; border-radius: 4px; background: ${color}20; color: ${color}; border: 1px solid ${color}40; font-weight: 600;">${_esc(t)}</span>`;
    }
    
    return `
    <div class="glass-card" style="background: rgba(20,20,30,0.65); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; overflow: hidden; display: flex; flex-direction: column; width: 100%; box-sizing: border-box; padding: 0;">
        <div style="padding: 0.35rem 0.6rem; border-bottom: 1px solid rgba(255,255,255,0.06); display: flex; justify-content: space-between; align-items: center; background: rgba(255,255,255,0.02);">
            <div style="display: flex; align-items: center; gap: 0.35rem; overflow: hidden; flex: 1;">
                <span style="font-size: 0.75rem;">📹</span>
                <span style="font-weight: 600; font-size: 0.78rem; color: #fff; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;" title="${_esc(title)}">${_esc(title)}</span>
                <button type="button" class="btn btn-ghost btn-small" onclick="promptEditCamera('${_esc(name)}')" style="font-size: 0.6rem; padding: 0.05rem 0.2rem; color: #94a3b8;" title="Редактировать название и теги">✏️</button>
            </div>
            <button type="button" class="btn btn-ghost btn-small" onclick="deleteGo2rtcStream('${_esc(name)}')" style="color: #ef4444; padding: 0.1rem 0.35rem; font-size: 0.7rem;" title="Удалить камеру">✕</button>
        </div>
        
        <div id="${containerId}" data-stream-name="${_esc(name)}" data-group-ip="${_esc(ip)}" style="position: relative; width: 100%; aspect-ratio: 16/9; background: #080b12; display: flex; align-items: center; justify-content: center; overflow: hidden; cursor: pointer;" onclick="playGo2rtcStream('${containerId}', '${_esc(name)}')">
            <img class="go2rtc-lazy-img" src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 9'%3E%3C/svg%3E" data-src="${frameUrl}" alt="Превью камеры" style="width: 100%; height: 100%; object-fit: contain; opacity: 0; transition: opacity 0.3s;" onload="this.style.opacity='1'; if(this.nextElementSibling) this.nextElementSibling.style.display='none';" onerror="handleGo2rtcFrameError(this, '${_esc(name)}')">
            <div class="go2rtc-frame-placeholder" style="display: none; width: 100%; height: 100%; position: absolute; inset: 0; align-items: center; justify-content: center; flex-direction: column; gap: 0.35rem; background: #0b0f19; color: #64748b; font-size: 0.7rem; z-index: 2;">
                <span>Кадр формируется...</span>
                <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.62rem; padding: 0.08rem 0.35rem;" onclick="event.stopPropagation(); retryGo2rtcFrame(this, '${_esc(name)}')">🔄 Обновить</button>
            </div>
            <div style="position: absolute; inset: 0; background: rgba(0,0,0,0.35); display: flex; flex-direction: column; align-items: center; justify-content: center; transition: background 0.2s;" onmouseover="this.style.background='rgba(0,0,0,0.15)'" onmouseout="this.style.background='rgba(0,0,0,0.35)'">
                <div style="width: 36px; height: 36px; border-radius: 50%; background: rgba(99,102,241,0.85); display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 12px rgba(0,0,0,0.5);">
                    <span style="color: #fff; font-size: 1rem; margin-left: 2px;">▶</span>
                </div>
                <span style="font-size: 0.65rem; color: #f1f5f9; margin-top: 0.3rem; font-weight: 500; text-shadow: 0 1px 3px rgba(0,0,0,0.8);">Запустить видео</span>
            </div>
        </div>
        
        <div style="padding: 0.4rem 0.6rem; font-size: 0.68rem; color: #a1a1aa; background: rgba(0,0,0,0.2); border-top: 1px solid rgba(255,255,255,0.05); display: flex; flex-direction: column; gap: 0.25rem;">
            <div style="display: flex; gap: 0.25rem; flex-wrap: wrap; align-items: center;">
                ${tagBadges}
                <button type="button" class="btn btn-ghost btn-small" onclick="promptAddTag('${_esc(name)}')" style="font-size: 0.58rem; padding: 0.04rem 0.25rem; border-radius: 4px; border: 1px dashed rgba(255,255,255,0.2); color: #94a3b8;">+ Тег</button>
            </div>
            <div style="font-family: monospace; font-size: 0.68rem; text-overflow: ellipsis; overflow: hidden; white-space: nowrap; color: #93c5fd;" title="${_esc(srcUrl)}">
                🔗 ${_esc(srcUrl || 'Источник настроен')}
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 0.1rem;">
                <span style="font-size: 0.65rem; color: #94a3b8;">Зрители: <strong style="color: #f8fafc;">${consumersCount}</strong></span>
                <div style="display: flex; gap: 0.25rem;">
                    <a href="/api/go2rtc/player/webrtc.html?src=${encodeURIComponent(name)}" target="_blank" class="btn btn-ghost btn-small" style="font-size: 0.62rem; padding: 0.1rem 0.35rem;">WebRTC ↗</a>
                    <a href="/api/go2rtc/player/stream.html?src=${encodeURIComponent(name)}" target="_blank" class="btn btn-ghost btn-small" style="font-size: 0.62rem; padding: 0.1rem 0.35rem;">Плеер ↗</a>
                </div>
            </div>
        </div>
    </div>`;
}

function initLazyImages(container) {
    const lazyImgs = container.querySelectorAll('img.go2rtc-lazy-img[data-src]');
    if ('IntersectionObserver' in window) {
        const observer = new IntersectionObserver((entries, obs) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    const src = img.getAttribute('data-src');
                    if (src) {
                        img.src = src;
                        img.removeAttribute('data-src');
                    }
                    obs.unobserve(img);
                }
            });
        }, { rootMargin: '200px 0px' });
        lazyImgs.forEach(img => observer.observe(img));
    } else {
        lazyImgs.forEach(img => {
            img.src = img.getAttribute('data-src');
            img.removeAttribute('data-src');
        });
    }
}

function playGo2rtcStream(containerId, name) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.onclick = null;
    container.style.cursor = 'default';
    container.innerHTML = `
        <iframe src="/api/go2rtc/player/stream.html?src=${encodeURIComponent(name)}" 
                style="width: 100%; height: 100%; border: none;" 
                allow="autoplay; fullscreen" 
                loading="lazy">
        </iframe>
        <button type="button" class="btn btn-ghost btn-small" onclick="event.stopPropagation(); stopGo2rtcStream('${containerId}', '${_esc(name)}')" style="position: absolute; top: 8px; right: 8px; font-size: 0.65rem; padding: 0.15rem 0.35rem; background: rgba(0,0,0,0.7); z-index: 10;" title="Остановить плеер">■ Стоп</button>
    `;
}
window.playGo2rtcStream = playGo2rtcStream;

function stopGo2rtcStream(containerId, name) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const frameUrl = `/api/go2rtc/frame/${encodeURIComponent(name)}?t=${Date.now()}`;
    container.style.cursor = 'pointer';
    container.onclick = () => playGo2rtcStream(containerId, name);
    container.innerHTML = `
        <img src="${frameUrl}" alt="Превью камеры" style="width: 100%; height: 100%; object-fit: contain;" onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';">
        <div style="display: none; width: 100%; height: 100%; position: absolute; inset: 0; align-items: center; justify-content: center; background: #0b0f19; color: #64748b; font-size: 0.75rem;">
            Превью формируется...
        </div>
        <div style="position: absolute; inset: 0; background: rgba(0,0,0,0.35); display: flex; flex-direction: column; align-items: center; justify-content: center; transition: background 0.2s;" onmouseover="this.style.background='rgba(0,0,0,0.15)'" onmouseout="this.style.background='rgba(0,0,0,0.35)'">
            <div style="width: 44px; height: 44px; border-radius: 50%; background: rgba(99,102,241,0.85); display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 15px rgba(0,0,0,0.5);">
                <span style="color: #fff; font-size: 1.2rem; margin-left: 3px;">▶</span>
            </div>
            <span style="font-size: 0.7rem; color: #f1f5f9; margin-top: 0.4rem; font-weight: 500; text-shadow: 0 1px 3px rgba(0,0,0,0.8);">Запустить видео</span>
        </div>
    `;
}
window.stopGo2rtcStream = stopGo2rtcStream;

function playAllInGroup(ip) {
    const players = document.querySelectorAll(`[data-group-ip="${ip}"]`);
    players.forEach(p => {
        const streamName = p.getAttribute("data-stream-name");
        if (streamName && p.id && !p.querySelector("iframe")) {
            playGo2rtcStream(p.id, streamName);
        }
    });
}
window.playAllInGroup = playAllInGroup;

function stopAllInGroup(ip) {
    const players = document.querySelectorAll(`[data-group-ip="${ip}"]`);
    players.forEach(p => {
        const streamName = p.getAttribute("data-stream-name");
        if (streamName && p.id && p.querySelector("iframe")) {
            stopGo2rtcStream(p.id, streamName);
        }
    });
}
window.stopAllInGroup = stopAllInGroup;

function renderTagSelectorHtml(currentTags, onSelectFnName) {
    let html = '<div style="display: flex; gap: 0.35rem; flex-wrap: wrap; margin-bottom: 0.75rem;">';
    for (const p of PRESET_TAGS) {
        const isSelected = currentTags.includes(p.id);
        html += `
            <button type="button" class="btn btn-small" 
                    onclick="${onSelectFnName}('${_esc(p.id)}')" 
                    style="font-size: 0.75rem; padding: 0.25rem 0.6rem; border-radius: 6px; 
                           background: ${isSelected ? p.color : 'rgba(255,255,255,0.06)'}; 
                           color: ${isSelected ? '#fff' : p.color}; 
                           border: 1px solid ${p.color}${isSelected ? 'ff' : '40'};">
                ${p.label} ${isSelected ? '✓' : '+'}
            </button>
        `;
    }
    html += '</div>';
    return html;
}

function openTagModal(title, initialTags, onSaveCallback) {
    let activeTags = [...initialTags];
    
    // Remove existing modal if any
    const existing = document.getElementById("go2rtc-tag-modal");
    if (existing) existing.remove();
    
    const modal = document.createElement("div");
    modal.id = "go2rtc-tag-modal";
    modal.style.cssText = "position: fixed; inset: 0; background: rgba(0,0,0,0.75); display: flex; align-items: center; justify-content: center; z-index: 9999; backdrop-filter: blur(4px);";
    
    function renderModalContent() {
        modal.innerHTML = `
            <div class="glass-card" style="background: #0f172a; border: 1px solid rgba(255,255,255,0.15); border-radius: 12px; padding: 1.25rem; width: 92%; max-width: 460px; box-shadow: 0 20px 40px rgba(0,0,0,0.8);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 0.5rem;">
                    <div style="font-weight: 700; font-size: 1rem; color: #f8fafc;">🏷️ ${_esc(title)}</div>
                    <button type="button" class="btn btn-ghost btn-small" onclick="document.getElementById('go2rtc-tag-modal').remove()" style="color: #94a3b8; font-size: 1rem;">✕</button>
                </div>
                
                <div style="font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.4rem;">Выберите предустановленный тег:</div>
                <div style="display: flex; gap: 0.4rem; flex-wrap: wrap; margin-bottom: 1rem;">
                    ${PRESET_TAGS.map(p => {
                        const sel = activeTags.includes(p.id);
                        return `
                            <button type="button" class="btn btn-small" 
                                    onclick="window._toggleModalTag('${_esc(p.id)}')" 
                                    style="font-size: 0.75rem; padding: 0.3rem 0.65rem; border-radius: 6px; 
                                           background: ${sel ? p.color : 'rgba(255,255,255,0.05)'}; 
                                           color: ${sel ? '#fff' : p.color}; 
                                           border: 1px solid ${p.color}${sel ? 'ff' : '40'}; font-weight: 600;">
                                ${p.label} ${sel ? '✓' : '+'}
                            </button>
                        `;
                    }).join("")}
                </div>
                
                <div style="font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.4rem;">Или введите кастомные теги через запятую:</div>
                <input type="text" id="go2rtc-modal-tags-input" value="${_esc(activeTags.join(', '))}" 
                       placeholder="напр. ПВЗ, Касса, Вход" 
                       style="width: 100%; padding: 0.5rem 0.75rem; background: rgba(0,0,0,0.4); border: 1px solid rgba(255,255,255,0.15); border-radius: 6px; color: #fff; font-size: 0.85rem; margin-bottom: 1.25rem;">
                
                <div style="display: flex; justify-content: flex-end; gap: 0.5rem;">
                    <button type="button" class="btn btn-ghost btn-small" onclick="document.getElementById('go2rtc-tag-modal').remove()">Отмена</button>
                    <button type="button" class="btn btn-primary btn-small" id="go2rtc-modal-save-btn">Сохранить теги</button>
                </div>
            </div>
        `;
        
        modal.querySelector("#go2rtc-modal-save-btn").onclick = () => {
            const inputVal = modal.querySelector("#go2rtc-modal-tags-input").value;
            const finalTags = inputVal.split(",").map(t => t.trim()).filter(Boolean);
            modal.remove();
            onSaveCallback(finalTags);
        };
    }
    
    window._toggleModalTag = (tagId) => {
        if (activeTags.includes(tagId)) {
            activeTags = activeTags.filter(t => t !== tagId);
        } else {
            activeTags.push(tagId);
        }
        renderModalContent();
    };
    
    renderModalContent();
    document.body.appendChild(modal);
}

async function promptEditGroupTags(ip) {
    const metaGroups = go2rtcMetaData.groups || {};
    const grpMeta = metaGroups[ip] || {};
    const curTags = grpMeta.tags || [];
    const grpName = grpMeta.custom_name || ip;
    
    openTagModal(`Теги для объекта: ${grpName}`, curTags, async (newTags) => {
        try {
            await fetch(`/api/go2rtc/meta/group/${encodeURIComponent(ip)}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ tags: newTags }),
            });
            
            // Also optionally apply tag to all cameras inside this group
            for (const name of Object.keys(go2rtcStreamsData)) {
                const stream = go2rtcStreamsData[name] || {};
                const src = (stream.producers && stream.producers[0] && stream.producers[0].url) || "";
                if (extractIpFromUrl(src) === ip) {
                    const camMeta = (go2rtcMetaData.cameras && go2rtcMetaData.cameras[name]) || {};
                    const mergedCamTags = Array.from(new Set([...(camMeta.tags || []), ...newTags]));
                    await fetch(`/api/go2rtc/meta/camera/${encodeURIComponent(name)}`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ tags: mergedCamTags, group_ip: ip }),
                    });
                }
            }
            await loadGo2rtcStreams();
        } catch (err) {
            alert(`Ошибка сохранения тегов: ${err.message}`);
        }
    });
}
window.promptEditGroupTags = promptEditGroupTags;

async function promptEditGroupName(ip) {
    const current = (go2rtcMetaData.groups && go2rtcMetaData.groups[ip] && go2rtcMetaData.groups[ip].custom_name) || "";
    const newName = prompt(`Введите название для объекта (IP ${ip}):`, current || `ПВЗ / Магазин (${ip})`);
    if (newName === null) return;
    
    try {
        await fetch(`/api/go2rtc/meta/group/${encodeURIComponent(ip)}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ custom_name: newName.trim() }),
        });
        await loadGo2rtcStreams();
    } catch (err) {
        alert(`Ошибка сохранения: ${err.message}`);
    }
}
window.promptEditGroupName = promptEditGroupName;

async function promptEditCamera(name) {
    const camMeta = (go2rtcMetaData.cameras && go2rtcMetaData.cameras[name]) || {};
    const curTitle = camMeta.custom_title || name;
    const curTags = camMeta.tags || [];
    
    const newTitle = prompt(`Название камеры:`, curTitle);
    if (newTitle === null) return;
    
    openTagModal(`Теги камеры: ${newTitle || name}`, curTags, async (newTags) => {
        try {
            await fetch(`/api/go2rtc/meta/camera/${encodeURIComponent(name)}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ custom_title: newTitle.trim(), tags: newTags }),
            });
            await loadGo2rtcStreams();
        } catch (err) {
            alert(`Ошибка сохранения: ${err.message}`);
        }
    });
}
window.promptEditCamera = promptEditCamera;

async function promptAddTag(name) {
    const camMeta = (go2rtcMetaData.cameras && go2rtcMetaData.cameras[name]) || {};
    const curTags = camMeta.tags || [];
    
    openTagModal(`Теги для камеры: ${camMeta.custom_title || name}`, curTags, async (newTags) => {
        try {
            await fetch(`/api/go2rtc/meta/camera/${encodeURIComponent(name)}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ tags: newTags }),
            });
            await loadGo2rtcStreams();
        } catch (err) {
            alert(`Ошибка сохранения тега: ${err.message}`);
        }
    });
}
window.promptAddTag = promptAddTag;
window.promptAddTag = promptAddTag;

async function addGo2rtcStream(event) {
    event.preventDefault();
    const nameInput = document.getElementById("go2rtc-stream-name");
    const urlInput = document.getElementById("go2rtc-stream-url");
    const tagInput = document.getElementById("go2rtc-stream-tag");
    const status = document.getElementById("go2rtc-add-status");
    const btn = document.getElementById("go2rtc-add-btn");
    
    const name = nameInput.value.trim();
    const url = urlInput.value.trim();
    const selectedTag = tagInput ? tagInput.value : "";
    if (!name || !url) return;
    
    btn.disabled = true;
    status.style.color = "#93c5fd";
    status.textContent = "Добавление потока в go2rtc...";
    
    try {
        const payload = { name, url };
        if (selectedTag) {
            payload.tags = [selectedTag];
        }
        const response = await fetch("/api/go2rtc/streams", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(payload)
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Ошибка добавления потока");
        
        status.style.color = "#4ade80";
        status.textContent = `Камера "${name}" успешно добавлена!`;
        nameInput.value = "";
        urlInput.value = "";
        setTimeout(() => { status.textContent = ""; }, 3500);
        loadGo2rtcStreams();
    } catch (err) {
        status.style.color = "#ef4444";
        status.textContent = err.message;
    } finally {
        btn.disabled = false;
    }
}
window.addGo2rtcStream = addGo2rtcStream;

async function deleteGo2rtcStream(name) {
    if (!confirm(`Удалить камеру "${name}" из go2rtc?`)) return;
    try {
        const response = await fetch(`/api/go2rtc/streams/${encodeURIComponent(name)}`, {method: "DELETE"});
        if (!response.ok) throw new Error("Не удалось удалить камеру");
        loadGo2rtcStreams();
    } catch (err) {
        alert(err.message);
    }
}
window.deleteGo2rtcStream = deleteGo2rtcStream;

function handleGo2rtcFrameError(img, name) {
    img.style.display = 'none';
    const placeholder = img.nextElementSibling;
    if (placeholder) {
        placeholder.style.display = 'flex';
    }
}
window.handleGo2rtcFrameError = handleGo2rtcFrameError;

function retryGo2rtcFrame(btn, name) {
    const parent = btn.closest('[id^="go2rtc-player-"]');
    if (!parent) return;
    const img = parent.querySelector('img.go2rtc-lazy-img');
    const placeholder = parent.querySelector('.go2rtc-frame-placeholder');
    if (img) {
        img.style.display = 'block';
        img.style.opacity = '0';
        img.src = `/api/go2rtc/frame/${encodeURIComponent(name)}?t=${Date.now()}`;
        if (placeholder) {
            placeholder.style.display = 'none';
        }
    }
}
window.retryGo2rtcFrame = retryGo2rtcFrame;

async function openAddStreamToGroupModal(ip) {
    const metaGroups = go2rtcMetaData.groups || {};
    const grpMeta = metaGroups[ip] || {};
    const grpName = grpMeta.custom_name || `Локация: ${ip}`;
    const grpTags = grpMeta.tags || [];

    // Remove existing modal if any
    const existing = document.getElementById("go2rtc-add-stream-modal");
    if (existing) existing.remove();

    const modal = document.createElement("div");
    modal.id = "go2rtc-add-stream-modal";
    modal.style.cssText = "position: fixed; inset: 0; background: rgba(0,0,0,0.8); display: flex; align-items: center; justify-content: center; z-index: 9999; backdrop-filter: blur(5px);";

    modal.innerHTML = `
        <div class="glass-card" style="background: #0f172a; border: 1px solid rgba(255,255,255,0.15); border-radius: 12px; padding: 1.25rem; width: 92%; max-width: 620px; max-height: 88vh; overflow-y: auto; box-shadow: 0 25px 50px rgba(0,0,0,0.9);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 0.5rem;">
                <div>
                    <div style="font-weight: 700; font-size: 1.05rem; color: #f8fafc;">➕ Добавить поток для: ${_esc(grpName)}</div>
                    <div style="font-size: 0.75rem; color: #94a3b8; font-family: monospace;">IP: ${_esc(ip)}</div>
                </div>
                <button type="button" class="btn btn-ghost btn-small" onclick="document.getElementById('go2rtc-add-stream-modal').remove()" style="color: #94a3b8; font-size: 1.1rem;">✕</button>
            </div>

            <!-- Manual Add Section -->
            <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.07); border-radius: 8px; padding: 0.85rem; margin-bottom: 1.25rem;">
                <div style="font-size: 0.82rem; font-weight: 600; color: #e2e8f0; margin-bottom: 0.6rem;">Ручной ввод потока:</div>
                <div style="display: flex; gap: 0.6rem; flex-wrap: wrap; margin-bottom: 0.5rem;">
                    <div style="flex: 1; min-width: 140px;">
                        <label style="font-size: 0.72rem; color: #94a3b8; display: block; margin-bottom: 0.2rem;">Имя камеры / Канал</label>
                        <input type="text" id="modal-stream-name" placeholder="напр. cam_${ip}_ch2" value="cam_${ip.replace(/[^0-9]/g, '_')}_ch" style="width: 100%; padding: 0.4rem 0.6rem; background: rgba(0,0,0,0.4); border: 1px solid rgba(255,255,255,0.15); border-radius: 6px; color: #fff; font-size: 0.8rem;">
                    </div>
                    <div style="flex: 2; min-width: 200px;">
                        <label style="font-size: 0.72rem; color: #94a3b8; display: block; margin-bottom: 0.2rem;">RTSP URL</label>
                        <input type="text" id="modal-stream-url" placeholder="rtsp://admin:pass@${ip}:554/ch1_0" style="width: 100%; padding: 0.4rem 0.6rem; background: rgba(0,0,0,0.4); border: 1px solid rgba(255,255,255,0.15); border-radius: 6px; color: #fff; font-size: 0.8rem;">
                    </div>
                </div>
                <div style="display: flex; justify-content: flex-end;">
                    <button type="button" class="btn btn-primary btn-small" onclick="submitModalAddStream('${_esc(ip)}')">+ Добавить в go2rtc</button>
                </div>
            </div>

            <!-- Strix Suggestions Section -->
            <div style="border-top: 1px solid rgba(255,255,255,0.08); padding-top: 0.85rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
                    <div style="font-size: 0.85rem; font-weight: 600; color: #f8fafc;">🔍 Потоки, найденные в Strix для этого IP:</div>
                    <button type="button" class="btn btn-ghost btn-small" onclick="quickReScanStrixIp('${_esc(ip)}')" style="font-size: 0.72rem; padding: 0.2rem 0.5rem; background: rgba(99,102,241,0.25); color: #c7d2fe; border: 1px solid rgba(99,102,241,0.4);">⚡ Пересканировать IP в Strix</button>
                </div>
                <div id="modal-strix-streams-list" style="display: flex; flex-direction: column; gap: 0.5rem;">
                    <div style="color: #94a3b8; font-size: 0.78rem; text-align: center; padding: 1rem;">Загрузка сохраненных результатов Strix...</div>
                </div>
            </div>
        </div>
    `;

    document.body.appendChild(modal);

    // Fetch and populate Strix results for this IP
    try {
        const response = await fetch("/api/strix/results");
        const data = await response.json();
        const results = data.results || [];
        const ipRecord = results.find(r => r.ip === ip);
        const streams = (ipRecord && ipRecord.streams) || [];
        
        const listDiv = document.getElementById("modal-strix-streams-list");
        if (!streams.length) {
            listDiv.innerHTML = `
                <div style="background: rgba(255,255,255,0.02); border: 1px dashed rgba(255,255,255,0.15); border-radius: 8px; padding: 1rem; text-align: center; font-size: 0.8rem; color: #94a3b8;">
                    В базе Strix пока нет сохраненных потоков для IP ${ip}.<br>
                    <button type="button" class="btn btn-small" onclick="quickReScanStrixIp('${_esc(ip)}')" style="margin-top: 0.6rem; background: rgba(99,102,241,0.3); color: #fff;">Запустить сканирование Strix сейчас</button>
                </div>
            `;
            return;
        }

        // Render available streams with "Add to go2rtc" quick button
        const activeUrls = new Set();
        for (const s of Object.values(go2rtcStreamsData)) {
            if (s.producers && s.producers[0] && s.producers[0].url) {
                activeUrls.add(s.producers[0].url.trim().toLowerCase());
            }
        }

        let streamsHtml = "";
        streams.forEach((st, idx) => {
            const src = st.source || "";
            const isAlreadyAdded = activeUrls.has(src.trim().toLowerCase());
            const probeInfo = st.title || st.details || `Канал ${idx + 1}`;
            const camSuggestName = `cam_${ip.replace(/[^0-9]/g, '_')}_ch${idx + 1}`;
            const previewUrl = `/api/strix/preview?url=${encodeURIComponent(src)}`;
            
            streamsHtml += `
            <div style="background: rgba(30,41,59,0.55); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 0.65rem 0.8rem; display: flex; align-items: center; gap: 0.85rem; flex-wrap: wrap;">
                <!-- Mini Preview Thumbnail -->
                <div style="width: 120px; aspect-ratio: 16/9; background: #090d16; border-radius: 6px; overflow: hidden; position: relative; flex-shrink: 0; display: flex; align-items: center; justify-content: center; border: 1px solid rgba(255,255,255,0.1);">
                    <img src="${previewUrl}" alt="Кадр потока" loading="lazy" style="width: 100%; height: 100%; object-fit: cover;" onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';">
                    <div style="display: none; width: 100%; height: 100%; position: absolute; inset: 0; align-items: center; justify-content: center; background: #0f172a; color: #64748b; font-size: 0.62rem; text-align: center; padding: 2px;">
                        Нет кадра
                    </div>
                </div>

                <div style="flex: 1; min-width: 200px;">
                    <div style="font-weight: 600; font-size: 0.82rem; color: #e2e8f0;">📹 ${probeInfo}</div>
                    <div style="font-family: monospace; font-size: 0.72rem; color: #93c5fd; text-overflow: ellipsis; overflow: hidden; white-space: nowrap; max-width: 320px; margin-top: 0.2rem;" title="${_esc(src)}">
                        🔗 ${_esc(src)}
                    </div>
                </div>

                <div style="flex-shrink: 0;">
                    ${isAlreadyAdded ? `
                        <span style="font-size: 0.72rem; padding: 0.25rem 0.55rem; border-radius: 4px; background: rgba(34,197,94,0.2); color: #4ade80; border: 1px solid rgba(34,197,94,0.4); font-weight: 600;">✓ Уже в go2rtc</span>
                    ` : `
                        <button type="button" class="btn btn-small" onclick="quickAddSuggestedStream('${_esc(camSuggestName)}', '${_esc(src)}', '${_esc(ip)}', this)" style="font-size: 0.72rem; padding: 0.25rem 0.6rem; background: rgba(99,102,241,0.4); color: #fff;">+ Добавить этот поток</button>
                    `}
                </div>
            </div>`;
        });

        listDiv.innerHTML = streamsHtml;
    } catch (err) {
        document.getElementById("modal-strix-streams-list").innerHTML = `<div style="color: #ef4444; font-size: 0.8rem;">Ошибка загрузки: ${err.message}</div>`;
    }
}
window.openAddStreamToGroupModal = openAddStreamToGroupModal;

async function submitModalAddStream(ip) {
    const name = document.getElementById("modal-stream-name").value.trim();
    const url = document.getElementById("modal-stream-url").value.trim();
    if (!name || !url) {
        alert("Укажите имя и RTSP URL камеры");
        return;
    }

    try {
        const response = await fetch("/api/go2rtc/streams", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, url, group_ip: ip })
        });
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || "Ошибка добавления");
        }
        document.getElementById("go2rtc-add-stream-modal")?.remove();
        await loadGo2rtcStreams();
    } catch (e) {
        alert(e.message);
    }
}
window.submitModalAddStream = submitModalAddStream;

async function quickAddSuggestedStream(suggestedName, srcUrl, ip, btn) {
    if (btn) btn.disabled = true;
    try {
        const response = await fetch("/api/go2rtc/streams", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: suggestedName, url: srcUrl, group_ip: ip })
        });
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || "Ошибка добавления");
        }
        if (btn) {
            btn.textContent = "✓ Добавлено";
            btn.style.background = "rgba(34,197,94,0.3)";
            btn.style.color = "#4ade80";
        }
        await loadGo2rtcStreams();
    } catch (e) {
        alert(e.message);
        if (btn) btn.disabled = false;
    }
}
window.quickAddSuggestedStream = quickAddSuggestedStream;

function quickReScanStrixIp(ip) {
    document.getElementById("go2rtc-add-stream-modal")?.remove();
    // Switch to Strix Tab and fill IP
    if (window.switchCameraTab) {
        window.switchCameraTab('strix');
    }
    const targetInput = document.getElementById('strix-target');
    if (targetInput) {
        targetInput.value = ip;
    }
    const form = document.getElementById('strix-scan-form');
    if (form) {
        form.scrollIntoView({ behavior: 'smooth' });
    }
}
window.quickReScanStrixIp = quickReScanStrixIp;

document.addEventListener("DOMContentLoaded", () => {
    const camerasView = document.getElementById("cameras-view");
    const go2rtcPanel = document.getElementById("camera-go2rtc-panel");
    if (camerasView && camerasView.classList.contains("active") && go2rtcPanel && go2rtcPanel.classList.contains("active")) {
        loadGo2rtcStreams();
    }
});

