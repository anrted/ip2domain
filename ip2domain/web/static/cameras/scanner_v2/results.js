'use strict';
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
            const oldStreamsJson = JSON.stringify(oldCam.streams || []);
            const newStreamsJson = JSON.stringify(cam.streams || []);
            if (oldStreamsJson !== newStreamsJson || oldCam.brand !== cam.brand || oldCam.model !== cam.model) {
                if (window.V2State.previewCache[cam.ip]) {
                    for (const s of (cam.streams || [])) {
                        if (!s.screenshot) s.screenshot = window.V2State.previewCache[cam.ip];
                    }
                }
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
    const total = (window.V2State.results || []).length;
    if (filteredCount !== undefined && filteredCount !== total) {
        el.textContent = `${filteredCount} из ${total} камер`;
    } else {
        el.textContent = `${total} камер`;
    }
}
window.v2UpdateResultsCount = v2UpdateResultsCount;

async function v2LoadStoredResults() {
    try {
        const resp = await fetch('/api/v2/results?limit=5000');
        if (!resp.ok) return;
        const data = await resp.json();
        const results = data.results || [];
        window.V2State.results = results;
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
window.v2LoadStoredResults = v2LoadStoredResults;

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
        if (cam.country_code === 'RU') ruCount++;
        else if (cam.country_code === 'BY') byCount++;
        if (!cam.city && !cam.region) noGeoCount++;
    });

    let html = '<option value="all">📍 Все регионы и города</option>';

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

function v2RenderResults() {
    const grid = document.getElementById('v2-camera-grid');
    if (!grid) return;

    let filtered = window.V2State.results;
    if (window.V2State.filterBrand !== 'all') {
        filtered = filtered.filter(c => (c.brand || '').toLowerCase().includes(window.V2State.filterBrand.toLowerCase()));
    }
    if (window.V2State.filterProtocol !== 'all') {
        filtered = filtered.filter(c => (c.protocols || []).includes(window.V2State.filterProtocol));
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

    v2UpdateResultsCount(filtered.length);
    v2UpdateGeoDropdown();

    if (!filtered.length) {
        grid.innerHTML = `<div class="v2-empty-state" style="grid-column:1/-1">
            <div class="v2-empty-icon">📷</div>
            <p>Камеры не найдены по выбранным фильтрам.</p>
            ${window.V2State.filterGeo !== 'all' || window.V2State.geoSearch ? `<button type="button" class="v2-btn-small" onclick="v2ClearGeoFilter()" style="margin-top:0.5rem">Сбросить гео-фильтр</button>` : ''}
        </div>`;
        return;
    }

    // Default sorting: cameras with preview / screenshot first!
    filtered = [...filtered].sort((a, b) => _cameraScore(b) - _cameraScore(a));

    grid.innerHTML = filtered.map(cam => v2RenderCameraCard(cam)).join('');
    initV2LazyLoading();
}
window.v2RenderResults = v2RenderResults;

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
    const curSelected = window.V2State.selectedStreams[cam.ip];
    const curStreamObj = streams.find(s => s.url === curSelected);

    if (!curSelected || (!curStreamObj?.screenshot && bestStream?.screenshot)) {
        window.V2State.selectedStreams[cam.ip] = bestStream?.url || '';
    }
    const currentStreamUrl = window.V2State.selectedStreams[cam.ip];
    const currentStreamObj = streams.find(s => s.url === currentStreamUrl) || streams[0];

    // Find screenshot: first check selected stream, then any stream that has a screenshot, or cached preview
    const cachedBlobUrl = window.V2State.previewCache[cam.ip] || '';
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

    let locationHtml = '';
    if (cam.city) {
        const flag = cam.country_code === 'BY' ? '🇧🇾' : '🇷🇺';
        locationHtml = `<div class="v2-camera-location" onclick="v2SetGeoFilter('city:${_esc(cam.city)}')" title="Фильтровать по городу ${_esc(cam.city)}${cam.region ? ' • ' + _esc(cam.region) : ''}${cam.isp ? ' • ' + _esc(cam.isp) : ''}">
            <span class="v2-geo-pin">📍</span>
            <strong class="v2-geo-city">${flag} ${_esc(cam.city)}</strong>
            ${cam.region && cam.region !== cam.city ? `<span class="v2-geo-region">${_esc(cam.region)}</span>` : ''}
        </div>`;
    }

    return `<div class="v2-camera-card" id="v2-cam-${safeIp}">
        ${previewHtml}
        ${verifiedBadge}
        <div class="v2-camera-body">
            <div class="v2-camera-brand">${_esc(cam.brand || 'Unknown')}</div>
            <div class="v2-camera-ip">${_esc(cam.ip)}${cam.rtsp_port ? ':' + cam.rtsp_port : ''}</div>
            ${locationHtml}
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
    const box = document.getElementById(`v2-preview-box-${safeIp}`);
    const streamUrl = window.V2State.selectedStreams[ip] || '';

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

    const cam = (window.V2State.results || []).find(c => c.ip === ip);
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

        const blob = await resp.blob();
        const objUrl = URL.createObjectURL(blob);
        window.V2State.previewCache[ip] = objUrl;

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

        const card = document.getElementById(`v2-cam-${safeIp}`);
        if (card && !card.querySelector('.v2-verified-badge')) {
            const badge = document.createElement('span');
            badge.className = 'v2-verified-badge';
            badge.textContent = '✓ Live';
            card.appendChild(badge);
        }

        const camObj = (window.V2State.results || []).find(c => c.ip === ip);
        if (camObj && !camObj.city) {
            fetch(`/api/geo/lookup?ip=${encodeURIComponent(ip)}`)
                .then(r => r.json())
                .then(j => {
                    if (j.found && j.data && j.data.city) {
                        camObj.city = j.data.city;
                        camObj.region = j.data.region || '';
                        camObj.country_code = j.data.country_code || '';
                        camObj.isp = j.data.isp || '';
                        v2RenderResults();
                    }
                }).catch(() => {});
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
window.v2CapturePreview = v2CapturePreview;
