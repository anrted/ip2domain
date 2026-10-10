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
    'tl-sc', 'vstarcam', 'sricam', 'srihome', 'herospeed', 'onvif'
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

function _isRouterDevice(c) {
    if (!c) return false;
    if (c.device_category === 'router') return true;
    const protos = c.protocols || [];
    return protos.includes('router') || protos.includes('winbox');
}
window._isRouterDevice = _isRouterDevice;

function _isCameraDevice(c) {
    if (!c || _isSpRecord(c)) return false;
    if (_isRouterDevice(c)) return false;

    // Explicit camera category
    if (c.device_category === 'camera') return true;

    // Brand matches known camera brand
    const brand = (c.brand || '').toLowerCase();
    if (_V2_CAMERA_BRAND_PATTERNS.some(b => brand.includes(b))) return true;

    // Known camera protocols
    const protos = c.protocols || [];
    if (_V2_CAMERA_PROTOCOLS.some(p => protos.includes(p))) return true;

    // Verified stream or real screenshot
    if ((c.streams || []).some(s => s.verified || (s.screenshot && String(s.screenshot).trim().length > 0))) return true;

    // If explicitly marked as generic_web or device, not a camera
    if (c.device_category === 'generic_web' || c.device_category === 'device') return false;

    // Has video streams and is not generic web
    if ((c.streams || []).length > 0 && !brand.includes('generic web device')) return true;

    return false;
}
window._isCameraDevice = _isCameraDevice;

function _isNetworkDevice(c) {
    if (!c || _isSpRecord(c) || _isRouterDevice(c) || _isCameraDevice(c)) return false;
    return c.device_category === 'device' || (c.protocols || []).includes('tcp');
}
window._isNetworkDevice = _isNetworkDevice;

function _isWebDevice(c) {
    if (!c || _isSpRecord(c) || _isRouterDevice(c) || _isCameraDevice(c)) return false;
    if (c.device_category === 'generic_web') return true;
    const brand = (c.brand || '').toLowerCase();
    if (brand.includes('generic web device') || brand.includes('web service')) return true;
    return true;
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
    const webUrl = cam.web_url || `${isHttps ? 'https' : 'http'}://${cam.ip}:${webPort}/`;

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
        actionsHtml = `
            <div class="v2-camera-actions">
                <button class="v2-camera-btn" onclick="v2OpenSelectedStreamPlayer('${_esc(cam.ip)}')" title="Тест видеопотока в реальном времени (WebRTC / MSE плеер)" style="background:rgba(99,102,241,0.25);color:#c4b5fd;border:1px solid rgba(99,102,241,0.45);font-weight:600">▶ Тест</button>
                ${goBtn}
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
