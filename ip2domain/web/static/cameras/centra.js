'use strict';

let centraMap = null;
let centraCameras = [];
let centraUsedPinColors = {};
let centraTypePinColors = {I: 'red', G: 'blue', H: 'green', P: 'green'};
let centraListFilter = 'all';
let centraOpenAddressGroups = new Set();
let activeCentraJobId = null;
let centraScreensOffset = 0;
let centraScreenCameras = [];
let centraScreensLoading = false;
let centraScreensHasMore = true;
let centraScreensLoaded = false;
let centraScreenObserver = null;
let centraScreenSearchTimer = null;
let centraPeoplePoller = null;
let activeCentraPeopleJobId = null;
let centraPeopleShowingAllResults = false;
let centraScreensMode = 'all';
let centraLastClusterAction = 0;
let cameraCatalogLoaded = false;
let cameraCatalogSearchTimer = null;
let activeCameraScanJobId = null;
let cameraDevicesVersion = -1;
let cameraConnectionFilter = 'all';
let ipCameraPreviewTimer = null;
let activeIPCameraConnectionId = null;

function centraCameraNumber(camera) {
    return String(camera?.id || '').replace(/^[A-Z]-/i, '');
}

function centraEntrance(camera) {
    const value = Number(camera?.entrance || String(camera?.id || '').match(/-(\d+)$/)?.[1]);
    if (!Number.isInteger(value) || value < 1) return centraCameraNumber(camera);
    return String(camera?.camera_type || camera?.id || '').toUpperCase().startsWith('I')
        ? `Подъезд ${value}` : `Камера ${value}`;
}

function centraCameraType(camera) {
    const type = String(camera?.camera_type || camera?.id || '').toUpperCase().replace(/-.*/, '');
    if (type === 'I') return 'Домофон';
    if (type === 'G') return 'Городская камера';
    if (type === 'H' || type === 'P') return 'Камера на доме';
    return `Камера типа ${type}`;
}

function centraPlacemarkPreset(camera) {
    const color = centraPinColor(camera);
    return `islands#${color}StretchyIcon`;
}

function centraPinColor(camera) {
    return camera?.pin_color || (centraCameraType(camera) === 'Городская камера' ? 'blue' : 'violet');
}

function centraCameraOrder(camera) {
    const match = String(camera?.id || '').match(/^[A-Z]-(\d+)-(\d+)$/i);
    return match ? [Number(match[1]), Number(match[2])] : [Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER];
}

function centraSidebarAddress(address) {
    return String(address || '').replace(/^Россия,\s*(?:Кемеровская область(?:\s*-\s*Кузбасс)?),\s*/i, '').trim();
}

function centraClusterGradient(geoObjects) {
    const palette = {red:'#ef4444', blue:'#3b82f6', green:'#22c55e', violet:'#8b5cf6',
        orange:'#f97316', yellow:'#eab308', pink:'#ec4899', gray:'#6b7280'};
    const counts = new Map();
    geoObjects.forEach((object) => {
        const color = object.properties.get('pinColor') || 'gray';
        counts.set(color, (counts.get(color) || 0) + 1);
    });
    let cursor = 0;
    const total = Math.max(1, geoObjects.length);
    const stops = [...counts.entries()].map(([color, count]) => {
        const start = cursor;
        cursor += count * 100 / total;
        return `${palette[color] || palette.gray} ${start}% ${cursor}%`;
    });
    return `conic-gradient(${stops.join(',')})`;
}

function centraClusterLayout(ymaps) {
    const Layout = ymaps.templateLayoutFactory.createClass(
        '<div class="centra-cluster-pie"><span></span></div>', {
            build() {
                Layout.superclass.build.call(this);
                const objects = this.getData().properties.get('geoObjects') || [];
                const node = this.getParentElement().querySelector('.centra-cluster-pie');
                if (!node) return;
                this._node = node;
                this._onClick = (event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    handleCentraClusterClick(objects);
                };
                node.addEventListener('click', this._onClick);
                node.style.background = centraClusterGradient(objects);
                node.querySelector('span').textContent = objects.length;
            },
            clear() {
                if (this._node && this._onClick) this._node.removeEventListener('click', this._onClick);
                this._node = null;
                this._onClick = null;
                Layout.superclass.clear.call(this);
            }
        }
    );
    return Layout;
}

function handleCentraClusterClick(objects) {
    const now = Date.now();
    if (now - centraLastClusterAction < 150) return;
    centraLastClusterAction = now;
    const cameraIndexes = objects.map((object) => Number(object.properties.get('centraIndex')))
        .filter((index) => Number.isInteger(index) && centraCameras[index]);
    if (!cameraIndexes.length || !centraMap) return;
    if (centraMap.getZoom() >= 12) {
        openCentraClusterList(cameraIndexes);
        return;
    }
    const coordinates = cameraIndexes.map((index) => centraCameras[index].coordinates);
    const unique = new Set(coordinates.map((point) => point.map((value) => Number(value).toFixed(7)).join(',')));
    if (unique.size === 1) {
        centraMap.setCenter(coordinates[0], 12, {duration: 250});
        return;
    }
    const bounds = coordinates.reduce((result, point) => {
        if (!result) return [point.slice(), point.slice()];
        result[0][0] = Math.min(result[0][0], point[0]);
        result[0][1] = Math.min(result[0][1], point[1]);
        result[1][0] = Math.max(result[1][0], point[0]);
        result[1][1] = Math.max(result[1][1], point[1]);
        return result;
    }, null);
    centraMap.setBounds(bounds, {checkZoomRange: true, zoomMargin: 55});
}

function openCentraClusterList(cameraIndexes) {
    let dialog = document.getElementById('centra-cluster-dialog');
    if (!dialog) {
        dialog = document.createElement('dialog');
        dialog.id = 'centra-cluster-dialog';
        dialog.className = 'centra-cluster-dialog';
        dialog.addEventListener('click', (event) => { if (event.target === dialog) dialog.close(); });
        document.body.appendChild(dialog);
    }
    const ordered = [...new Set(cameraIndexes)].sort((left, right) =>
        String(centraCameras[left]?.title || '').localeCompare(String(centraCameras[right]?.title || ''), 'ru', {numeric:true}));
    dialog.innerHTML = `<div class="centra-player-head"><strong>Камеры в кластере · ${ordered.length}</strong><button class="centra-player-close" type="button" onclick="document.getElementById('centra-cluster-dialog').close()" aria-label="Закрыть">×</button></div><div class="centra-cluster-camera-list">${ordered.map((index) => {
        const camera = centraCameras[index];
        return `<button type="button" onclick="openCentraClusterCamera(${index})"><span class="centra-cluster-dot" style="background:${_esc(centraClusterCssColor(centraPinColor(camera)))}"></span><strong>${_esc(camera.title || camera.id)}</strong><small>${_esc(camera.id)} · ${_esc(centraCameraType(camera))} · ${_esc(camera.address || '')}</small></button>`;
    }).join('')}</div>`;
    dialog.showModal();
}

function centraClusterCssColor(color) {
    return ({red:'#ef4444', blue:'#3b82f6', green:'#22c55e', violet:'#8b5cf6', orange:'#f97316',
        yellow:'#eab308', pink:'#ec4899', gray:'#6b7280'})[color] || '#6b7280';
}

function openCentraClusterCamera(index) {
    openCentraCamera(index);
}
window.openCentraClusterCamera = openCentraClusterCamera;

function switchCameraTab(tab) {
    ['go2rtc', 'strix', 'scanner', 'catalog', 'centra', 'screens'].forEach((name) => {
        const active = name === tab;
        const tabEl = document.getElementById(`camera-${name}-tab`);
        const panelEl = document.getElementById(`camera-${name}-panel`);
        if (tabEl) {
            tabEl.classList.toggle('active', active);
            tabEl.setAttribute('aria-selected', String(active));
        }
        if (panelEl) {
            panelEl.classList.toggle('active', active);
        }
    });
    if (tab === 'go2rtc') loadGo2rtcStreams();
    if (tab === 'strix') {
        loadStrixPresets();
        loadStrixResults();
        if (!activeStrixJobId) {
            restoreStrixScan();
        }
        refreshStrixGraphTargets();
    }
    if (tab === 'scanner') {
        restoreCameraScan();
        refreshCameraTargets();
    }
    if (tab === 'catalog' && !cameraCatalogLoaded) loadCameraCatalogProviders();
    if (tab === 'centra') {
        if (!centraCameras.length) loadCentraCameras();
        setTimeout(resizeCentraMap, 80);
    }
    if (tab === 'screens') {
        if (!centraScreensLoaded) resetCentraScreens();
        else loadSavedCentraPeopleCount();
    }
}
window.switchCameraTab = switchCameraTab;

async function loadCameraCatalogProviders() {
    const select = document.getElementById('camera-catalog-provider');
    try {
        const response = await fetch('/api/camera-providers');
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось загрузить провайдеры');
        select.innerHTML = '<option value="">Все провайдеры</option>' + (data.providers || []).map((provider) =>
            `<option value="${_esc(provider.id)}">${_esc(provider.name)}</option>`).join('');
        await loadCameraCatalog();
    } catch (error) {
        document.getElementById('camera-catalog-results').innerHTML = `<div class="empty-state">${_esc(error.message)}</div>`;
    }
}

async function loadCameraCatalog() {
    const provider = document.getElementById('camera-catalog-provider')?.value || '';
    const search = document.getElementById('camera-catalog-search')?.value.trim() || '';
    const params = new URLSearchParams({offset:'0', limit:'500', provider_id:provider, search});
    const results = document.getElementById('camera-catalog-results');
    try {
        const response = await fetch(`/api/camera-catalog?${params}`);
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось загрузить каталог');
        cameraCatalogLoaded = true;
        document.getElementById('camera-catalog-count').textContent = `${Number(data.total || 0).toLocaleString()} камер`;
        results.innerHTML = (data.cameras || []).length ? data.cameras.map((camera) => {
            const snapshot = `/api/camera-catalog/${encodeURIComponent(camera.provider_id)}/${encodeURIComponent(camera.external_id)}/snapshot.jpg`;
            return `<div class="remote-result-card"><div><strong>${_esc(camera.title || camera.external_id)}</strong><small>${_esc(camera.provider_id)} · ${_esc(camera.external_id)} · ${_esc(camera.address || '')}</small></div><a class="btn btn-ghost btn-small" href="${snapshot}" target="_blank" rel="noopener">Кадр</a></div>`;
        }).join('') : '<div class="empty-state">Камеры не найдены</div>';
    } catch (error) {
        results.innerHTML = `<div class="empty-state">${_esc(error.message)}</div>`;
    }
}
window.loadCameraCatalog = loadCameraCatalog;

function scheduleCameraCatalogSearch() {
    clearTimeout(cameraCatalogSearchTimer);
    cameraCatalogSearchTimer = setTimeout(loadCameraCatalog, 300);
}
window.scheduleCameraCatalogSearch = scheduleCameraCatalogSearch;

function loadYandexMaps(apiKey) {
    if (window.ymaps) return Promise.resolve(window.ymaps);
    if (window._centraYmapsPromise) return window._centraYmapsPromise;
    window._centraYmapsPromise = new Promise((resolve, reject) => {
        const script = document.createElement('script');
        const key = apiKey ? `&apikey=${encodeURIComponent(apiKey)}` : '';
        script.src = `https://api-maps.yandex.ru/2.1/?lang=ru_RU${key}`;
        script.onload = () => window.ymaps.ready(() => resolve(window.ymaps));
        script.onerror = () => reject(new Error('Не удалось загрузить API Яндекс.Карт'));
        document.head.appendChild(script);
    });
    return window._centraYmapsPromise;
}

async function loadCentraCameras() {
    const mapNode = document.getElementById('centra-map');
    try {
        const response = await fetch('/api/cameras/centra', {cache: 'no-store'});
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось загрузить камеры Centra');
        centraCameras = (data.cameras || []).sort((left, right) => {
            const a = centraCameraOrder(left), b = centraCameraOrder(right);
            return a[0] - b[0] || a[1] - b[1];
        });
        centraUsedPinColors = data.used_pin_colors || {};
        centraTypePinColors = data.type_pin_colors || {I: 'red', G: 'blue', H: 'green', P: 'green'};
        updateCentraColorOptions();
        document.getElementById('centra-count').textContent = `${centraCameras.length} камер`;
        renderCentraList();
        if (!centraCameras.length) {
            mapNode.innerHTML = '<div class="empty-state">Камеры не настроены</div>';
            return;
        }
        const ymaps = await loadYandexMaps(data.yandex_maps_api_key || '');
        const missingByAddress = new Map();
        centraCameras.forEach((camera) => {
            if (!Array.isArray(camera.coordinates) && camera.address) missingByAddress.set(camera.address, camera);
        });
        const geocodeQueue = [...missingByAddress.keys()].slice(0, Number(data.geocode_batch_limit ?? 25));
        for (const address of geocodeQueue) {
            let coordinates = null;
            try {
                const result = await ymaps.geocode(address, {results: 1, boundedBy: [[53.3, 86.4], [54.2, 87.8]], strictBounds: true});
                coordinates = result.geoObjects.get(0)?.geometry.getCoordinates();
            } catch (_) {}
            if (!Array.isArray(coordinates)) {
                try {
                    const fallback = await fetch('/api/cameras/centra/geocode', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({address})});
                    if (fallback.ok) coordinates = (await fallback.json()).coordinates;
                } catch (_) {}
            }
            if (!Array.isArray(coordinates)) continue;
            centraCameras.filter((camera) => camera.address === address).forEach((camera) => { camera.coordinates = coordinates; });
            await fetch('/api/cameras/centra/coordinates', {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify({address, coordinates})});
        }
        const mappedCameras = centraCameras.filter((camera) => Array.isArray(camera.coordinates));
        if (!mappedCameras.length) {
            mapNode.innerHTML = '<div class="empty-state">Камеры найдены, но их адреса не удалось разместить на карте</div>';
            return;
        }
        mapNode.innerHTML = '';
        centraMap = new ymaps.Map('centra-map', {center: mappedCameras[0].coordinates, zoom: 14, controls: ['zoomControl', 'fullscreenControl']});
        const clusterer = new ymaps.Clusterer({
            clusterIconLayout: centraClusterLayout(ymaps),
            clusterIconShape: {type: 'Rectangle', coordinates: [[0, 0], [48, 48]]},
            clusterDisableClickZoom: true,
            clusterOpenBalloonOnClick: false,
            groupByCoordinates: false,
            gridSize: 48,
            minClusterSize: 2
        });
        clusterer.events.add('click', (event) => {
            const cluster = event.get('target');
            handleCentraClusterClick(cluster?.properties?.get('geoObjects') || []);
        });
        centraCameras.forEach((camera, index) => {
            if (!Array.isArray(camera.coordinates)) return;
            const color = centraPinColor(camera);
            const placemark = new ymaps.Placemark(camera.coordinates, {
                pinColor: color,
                centraIndex: index,
                iconContent: centraEntrance(camera),
                hintContent: `${centraCameraType(camera)} · ${centraEntrance(camera)} · ${camera.title}`,
                balloonContentHeader: `${_esc(centraCameraType(camera))} · ${_esc(centraEntrance(camera))} · ${_esc(camera.title)}`,
                balloonContentBody: `${_esc(camera.address || '')}<br><button class="btn btn-small" type="button" onclick="openCentraCamera(${index})">Открыть трансляцию</button>`
            }, {preset: centraPlacemarkPreset(camera)});
            placemark.events.add('click', () => selectCentraCamera(index, false));
            clusterer.add(placemark);
        });
        centraMap.geoObjects.add(clusterer);
        if (mappedCameras.length > 1) centraMap.setBounds(centraMap.geoObjects.getBounds(), {checkZoomRange: true, zoomMargin: 45});
    } catch (error) {
        mapNode.innerHTML = `<div class="empty-state" style="color:#f87171">${_esc(error.message)}</div>`;
    }
}
window.loadCentraCameras = loadCentraCameras;

function ensureCentraScreenObserver() {
    if (centraScreenObserver) return;
    centraScreenObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach((entry) => {
            if (!entry.isIntersecting) return;
            const img = entry.target;
            observer.unobserve(img);
            img.src = img.dataset.src;
            img.onload = () => {
                img.parentElement.querySelector('.centra-screen-placeholder')?.remove();
                if (img.dataset.refresh === 'true') {
                    img.dataset.refresh = 'false';
                    img.src = `${img.dataset.src}?refresh=true&v=${Date.now()}`;
                }
            };
            img.onerror = () => {
                const placeholder = img.parentElement.querySelector('.centra-screen-placeholder');
                if (placeholder) placeholder.textContent = 'Кадр временно недоступен';
            };
        });
    }, {rootMargin: '300px 0px'});
}

async function resetCentraScreens() {
    centraScreensOffset = 0;
    centraScreenCameras = [];
    centraScreensHasMore = true;
    centraScreensLoaded = true;
    document.getElementById('centra-screens-grid').innerHTML = '';
    updateCentraScreensModeButtons();
    loadSavedCentraPeopleCount();
    await loadMoreCentraScreens();
}
window.resetCentraScreens = resetCentraScreens;

function scheduleCentraScreensSearch() {
    clearTimeout(centraScreenSearchTimer);
    centraScreenSearchTimer = setTimeout(resetCentraScreens, 350);
}
window.scheduleCentraScreensSearch = scheduleCentraScreensSearch;

async function loadMoreCentraScreens() {
    if (centraScreensLoading || !centraScreensHasMore) return;
    centraScreensLoading = true;
    const sentinel = document.getElementById('centra-screens-sentinel');
    sentinel.style.display = 'flex';
    try {
        const type = document.getElementById('centra-screen-type').value;
        const search = document.getElementById('centra-screen-search').value.trim();
        const personSearch = /^person-\d+$/i.test(search);
        const endpoint = personSearch ? '/api/cameras/centra/people-identities/search'
            : centraScreensMode === 'people' ? '/api/cameras/centra/people/results' : '/api/cameras/centra/screens';
        const query = personSearch
            ? `person_id=${encodeURIComponent(search)}&camera_type=${encodeURIComponent(type)}`
            : `offset=${centraScreensOffset}&limit=100&camera_type=${encodeURIComponent(type)}&search=${encodeURIComponent(search)}`;
        const response = await fetch(`${endpoint}?${query}`);
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось загрузить камеры');
        const select = document.getElementById('centra-screen-type');
        if (select.options.length === 1) {
            (data.types || []).forEach((item) => select.add(new Option(`${item.type} · ${item.count}`, item.type)));
            select.value = type;
        }
        document.getElementById('centra-screens-count').textContent = personSearch
            ? `${data.total} совпадений ${search.toLowerCase()}`
            : centraScreensMode === 'people' ? `${data.total} камер с людьми` : `${data.total} камер`;
        document.getElementById('centra-screen-status').textContent = data.ffmpeg_available
            ? 'Preview · резервный FFmpeg' : 'Preview камер';
        const grid = document.getElementById('centra-screens-grid');
        const start = centraScreensOffset;
        grid.insertAdjacentHTML('beforeend', (data.cameras || []).map((camera) => {
            const screenIndex = centraScreenCameras.push(camera) - 1;
            const detected = camera.detected_at ? ` · найдено ${camera.detected_at}` : '';
            const badge = camera.person_search_id
                ? `<span class="centra-people-count">${_esc(camera.person_search_id)} · ${Math.round((camera.person_similarity || 0) * 100)}%</span>`
                : camera.people_count ? `<span class="centra-people-count">Людей: ${camera.people_count}</span>` : '';
            return `<button type="button" class="centra-screen-card${camera.people_count ? ' person-detected' : ''}" data-camera-id="${_esc(camera.id)}" data-people-count="${Number(camera.people_count || 0)}" onclick="openCentraScreenCamera(${screenIndex})" aria-label="Открыть камеру ${_esc(camera.title || camera.id)}"><div class="centra-screen-frame"><div class="centra-screen-placeholder"><span class="spinner"></span></div><img alt="${_esc(camera.title || camera.id)}" data-src="${_esc(camera.screenshot_url)}" data-refresh="${camera.screenshot_stale ? 'true' : 'false'}" loading="lazy">${badge}</div><div class="centra-screen-info"><strong>${_esc(camera.title || camera.id)}</strong><small>${_esc(camera.id)} · ${_esc(centraCameraType(camera))} · ${_esc(camera.address || '')}${_esc(detected)}</small></div></button>`;
        }).join(''));
        ensureCentraScreenObserver();
        [...grid.querySelectorAll('img[data-src]')].slice(start).forEach((img) => centraScreenObserver.observe(img));
        centraScreensOffset += (data.cameras || []).length;
        centraScreensHasMore = Boolean(data.has_more);
    } catch (error) {
        sentinel.textContent = error.message;
    } finally {
        centraScreensLoading = false;
        sentinel.style.display = centraScreensHasMore ? 'flex' : 'none';
    }
}

async function loadSavedCentraPeopleCount() {
    const button = document.getElementById('centra-people-saved-button');
    if (!button) return;
    const type = document.getElementById('centra-screen-type')?.value || '';
    try {
        const response = await fetch(`/api/cameras/centra/people/results?offset=0&limit=1&camera_type=${encodeURIComponent(type)}`);
        const data = await response.json();
        if (response.ok) button.textContent = `С людьми: ${Number(data.total || 0).toLocaleString()}`;
    } catch (_) {}
}

async function showSavedCentraPeople() {
    centraScreensMode = 'people';
    centraPeopleShowingAllResults = false;
    document.getElementById('centra-people-filters').style.display = 'flex';
    await resetCentraScreens();
}
window.showSavedCentraPeople = showSavedCentraPeople;

function updateCentraScreensModeButtons() {
    document.getElementById('centra-screens-all-button')?.classList.toggle('active', centraScreensMode === 'all');
    document.getElementById('centra-people-saved-button')?.classList.toggle('active', centraScreensMode === 'people');
}

const centraScreensSentinelObserver = new IntersectionObserver((entries) => {
    if (entries.some((entry) => entry.isIntersecting)) loadMoreCentraScreens();
}, {rootMargin: '600px 0px'});
document.addEventListener('DOMContentLoaded', () => {
    const sentinel = document.getElementById('centra-screens-sentinel');
    if (sentinel) centraScreensSentinelObserver.observe(sentinel);
    const search = document.getElementById('centra-screen-search');
    if (search) search.placeholder = 'Название, адрес, камера или person-2';
});

function renderCentraPeopleMatches(result, replaceGrid) {
    const resultMatches = result.matches || [];
    if (replaceGrid) {
        centraScreensMode = 'people';
        updateCentraScreensModeButtons();
        centraPeopleShowingAllResults = true;
        centraScreenCameras = resultMatches;
        centraScreensHasMore = false;
        centraScreensOffset = resultMatches.length;
        const grid = document.getElementById('centra-screens-grid');
        grid.innerHTML = resultMatches.length ? resultMatches.map((camera, index) =>
            `<button type="button" class="centra-screen-card" data-camera-id="${_esc(camera.camera_id)}" onclick="openCentraScreenCamera(${index})" aria-label="Открыть камеру ${_esc(camera.title || camera.camera_id)}"><div class="centra-screen-frame"><div class="centra-screen-placeholder"><span class="spinner"></span></div><img alt="${_esc(camera.title || camera.camera_id)}" data-src="${_esc(camera.screenshot_url)}" loading="lazy"></div><div class="centra-screen-info"><strong>${_esc(camera.title || camera.camera_id)}</strong><small>${_esc(camera.camera_id)} · ${_esc(centraCameraType(camera))} · ${_esc(camera.address || '')}</small></div></button>`
        ).join('') : '<div class="empty-state">Люди на проверенных камерах не обнаружены</div>';
        document.getElementById('centra-screens-sentinel').style.display = 'none';
        ensureCentraScreenObserver();
        grid.querySelectorAll('img[data-src]').forEach((img) => centraScreenObserver.observe(img));
    }
    const matches = new Map(resultMatches.map((match) => [match.camera_id, match]));
    document.querySelectorAll('.centra-screen-card').forEach((card) => {
        const match = matches.get(card.dataset.cameraId);
        card.dataset.peopleCount = match ? String(match.people_count || 1) : '0';
        card.classList.toggle('person-detected', Boolean(match));
        card.querySelector('.centra-people-count')?.remove();
        card.querySelector('.centra-person-ids')?.remove();
        if (match) card.querySelector('.centra-screen-frame').insertAdjacentHTML(
            'beforeend', `<span class="centra-people-count">Людей: ${match.people_count || 1}</span>`);
        if (match?.people?.length) {
            const labels = match.people.map((person) => person.matched
                ? `${person.person_id} · ${Math.round((person.similarity || 0) * 100)}%`
                : `${person.person_id} · новый`);
            card.querySelector('.centra-screen-info').insertAdjacentHTML(
                'beforeend', `<small class="centra-person-ids">${labels.map(_esc).join(' · ')}</small>`);
        }
    });
}

async function startCentraPeoplePolling(jobId, allCameras, replaceGrid = allCameras) {
    const liveMatches = new Map();
    let matchesCursor = 0;
    const button = document.getElementById('centra-people-button');
    const allButton = document.getElementById('centra-people-all-button');
    const cancelButton = document.getElementById('centra-people-cancel');
    const progress = document.getElementById('centra-people-progress');
    activeCentraPeopleJobId = jobId;
    button.disabled = true;
    allButton.disabled = true;
    cancelButton.disabled = false;
    cancelButton.style.display = '';
    progress.style.display = 'block';
    if (replaceGrid) renderCentraPeopleMatches({matches: []}, true);
    clearInterval(centraPeoplePoller);

    const pollOnce = async () => {
        try {
            const resultResponse = await fetch(`/api/cameras/centra/people/${jobId}?matches_from=${matchesCursor}`);
            const result = await resultResponse.json();
            if (!resultResponse.ok) throw new Error(result.detail || 'Анализ не найден');
            const newMatches = result.matches || [];
            newMatches.forEach((match) => liveMatches.set(match.camera_id, match));
            matchesCursor = Number(result.matches_total || liveMatches.size);
            if (newMatches.length) {
                renderCentraPeopleMatches({matches:[...liveMatches.values()]}, replaceGrid);
                document.getElementById('centra-people-filters').style.display = 'flex';
                loadSavedCentraPeopleCount();
            }
            const eta = result.eta_seconds == null ? '' : ` · ${formatCentraEta(result.eta_seconds)} осталось`;
            const lastFailure = (result.failure_details || []).at(-1);
            const failureText = lastFailure ? ` · последняя ошибка ${lastFailure.camera_id}: ${lastFailure.error}` : '';
            progress.textContent = `${result.stage}${eta} · показано ${liveMatches.size} · ошибки ${result.failed || 0}${failureText}`;
            if (['completed', 'cancelled'].includes(result.status)) {
                clearInterval(centraPeoplePoller);
                activeCentraPeopleJobId = null;
                button.disabled = false;
                allButton.disabled = false;
                cancelButton.disabled = false;
                cancelButton.style.display = 'none';
                renderCentraPeopleMatches({matches:[...liveMatches.values()]}, Boolean(result.all_cameras) || replaceGrid);
                document.getElementById('centra-people-filters').style.display = 'flex';
                filterCentraScreensByPeople('all');
                const failedIds = (result.failure_details || []).map((item) => item.camera_id).join(', ');
                progress.textContent = `${result.status === 'cancelled' ? 'Остановлено' : 'Готово'} · камеры с людьми: ${liveMatches.size} из ${result.total} · ошибки ${result.failed || 0}${failedIds ? ` (${failedIds})` : ''}`;
                return true;
            }
        } catch (error) {
            clearInterval(centraPeoplePoller);
            activeCentraPeopleJobId = null;
            button.disabled = false;
            allButton.disabled = false;
            cancelButton.style.display = 'none';
            progress.textContent = error.message;
            return true;
        }
        return false;
    };
    if (!await pollOnce()) centraPeoplePoller = setInterval(pollOnce, 1000);
}

async function analyzeCentraScreenPeople(allCameras = false) {
    const cameras = centraScreenCameras.slice(-100);
    const cameraType = document.getElementById('centra-screen-type').value;
    if (!allCameras && !cameras.length) return;
    const progress = document.getElementById('centra-people-progress');
    progress.style.display = 'block';
    progress.textContent = allCameras
        ? `Подготовка анализа всех доступных камер${cameraType ? ` типа ${cameraType}` : ''}…`
        : `Запуск анализа ${cameras.length} камер…`;
    try {
        const response = await fetch('/api/cameras/centra/people', {method:'POST', headers:{'Content-Type':'application/json'},
            body:JSON.stringify({camera_ids:allCameras ? [] : cameras.map((camera) => camera.id), all_cameras:allCameras,
                camera_type:cameraType, confidence:.45})});
        const job = await response.json();
        if (!response.ok) throw new Error(job.detail || 'Не удалось запустить анализ');
        await startCentraPeoplePolling(job.job_id, allCameras);
    } catch (error) {
        document.getElementById('centra-people-button').disabled = false;
        document.getElementById('centra-people-all-button').disabled = false;
        document.getElementById('centra-people-cancel').style.display = 'none';
        progress.textContent = error.message;
    }
}
window.analyzeCentraScreenPeople = analyzeCentraScreenPeople;

async function restoreCentraPeopleAnalysis() {
    try {
        const response = await fetch('/api/cameras/centra/people/active');
        const data = await response.json();
        if (response.ok && data.job?.job_id) {
            await startCentraPeoplePolling(data.job.job_id, Boolean(data.job.all_cameras), true);
        }
    } catch (_) {}
}
document.addEventListener('DOMContentLoaded', restoreCentraPeopleAnalysis);

async function cancelCentraPeopleAnalysis() {
    if (!activeCentraPeopleJobId) return;
    const button = document.getElementById('centra-people-cancel');
    button.disabled = true;
    await fetch(`/api/cameras/centra/people/${activeCentraPeopleJobId}/cancel`, {method:'POST'});
    document.getElementById('centra-people-progress').textContent = 'Остановка после текущей камеры…';
}
window.cancelCentraPeopleAnalysis = cancelCentraPeopleAnalysis;

function filterCentraScreensByPeople(range) {
    document.querySelectorAll('#centra-people-filters [data-people-filter]').forEach((button) => {
        button.classList.toggle('active', button.dataset.peopleFilter === range);
    });
    document.querySelectorAll('.centra-screen-card').forEach((card) => {
        const count = Number(card.dataset.peopleCount || 0);
        card.hidden = range === 'all' ? count < 1
            : range === '1+' ? count < 1
            : range === '2-4' ? count < 2 || count > 4
            : count < 5;
    });
}
window.filterCentraScreensByPeople = filterCentraScreensByPeople;

async function resetCentraPersonIdentities() {
    const response = await fetch('/api/cameras/centra/people-identities/reset', {method:'POST'});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || 'Не удалось сбросить временные ID');
    showAllCentraScreens();
    const progress = document.getElementById('centra-people-progress');
    progress.style.display = 'block';
    progress.textContent = 'Временные ID удалены';
}
window.resetCentraPersonIdentities = resetCentraPersonIdentities;

function showAllCentraScreens() {
    if (centraScreensMode === 'people') {
        centraScreensMode = 'all';
        document.getElementById('centra-people-filters').style.display = 'none';
        resetCentraScreens();
        return;
    }
    if (centraPeopleShowingAllResults) {
        centraScreensMode = 'all';
        centraPeopleShowingAllResults = false;
        document.getElementById('centra-people-filters').style.display = 'none';
        resetCentraScreens();
        return;
    }
    document.querySelectorAll('.centra-screen-card').forEach((card) => {
        card.hidden = false;
        card.classList.remove('person-detected');
        delete card.dataset.peopleCount;
        card.querySelector('.centra-people-count')?.remove();
        card.querySelector('.centra-person-ids')?.remove();
    });
    document.getElementById('centra-people-filters').style.display = 'none';
}
window.showAllCentraScreens = showAllCentraScreens;

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
    if (type === 'I') { server.value = ''; color.value = 'red'; }
    else if (type === 'G') { server.value = ''; color.value = 'blue'; }
    else if (type === 'H' || type === 'P') { server.value = ''; color.value = 'green'; }
    else if (centraTypePinColors[type]) color.value = centraTypePinColors[type];
    server.placeholder = 'https://flus6.mycentra.ru';
    server.required = false;
    updateCentraColorOptions();
}
window.updateCentraTypeFields = updateCentraTypeFields;

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
    select.disabled = ['I', 'G', 'H', 'P'].includes(type) || Boolean(fixedColor);
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
        const cancelButton = document.getElementById('centra-cancel-button');
        cancelButton.disabled = false;
        cancelButton.textContent = '■ Остановить';
        cancelButton.style.display = '';
        pollCentraDiscovery(jobIds);
    } catch (error) {
        button.disabled = false;
        progress.innerHTML = `<span style="color:#f87171">${_esc(error.message)}</span>`;
    }
}
window.startCentraDiscovery = startCentraDiscovery;

function pollCentraDiscovery(jobIds) {
    jobIds = Array.isArray(jobIds) ? jobIds : [jobIds];
    activeCentraJobId = jobIds;
    if (window._centraPoller) clearInterval(window._centraPoller);
    const timer = setInterval(async () => {
        const button = document.getElementById('centra-discovery-button');
        const progress = document.getElementById('centra-discovery-progress');
        try {
            const responses = await Promise.all(jobIds.map((id) => fetch(`/api/cameras/centra/discover/${id}`)));
            const jobs = await Promise.all(responses.map((response) => response.json()));
            if (responses.some((response) => !response.ok)) throw new Error('Задание не найдено');
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
                const eta = job.status === 'queued' ? 'в очереди' : `${formatCentraEta(etaValue)} осталось`;
                return `<div class="centra-job-row"><span>${_esc(job.stage || job.target || job.job_id)} <small>${_esc(eta)}</small></span><strong>${jobPct}%</strong></div>`;
            }).join('');
            progress.innerHTML = `<div class="progress-header"><span>Активные сканирования: ${active.length} · проверено ${checked.toLocaleString()} · найдено ${found} · ${formatCentraEta(overallEta)} осталось</span><span>${pct}%</span></div><div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div><div class="centra-job-list">${rows}</div>`;
            if (jobs.every((job) => job.status === 'completed')) {
                clearInterval(timer); button.disabled = false; activeCentraJobId = null;
                document.getElementById('centra-cancel-button').style.display = 'none';
                centraCameras = []; await loadCentraCameras();
            } else if (jobs.every((job) => ['completed', 'cancelled'].includes(job.status))) {
                clearInterval(timer); button.disabled = false; activeCentraJobId = null;
                document.getElementById('centra-cancel-button').style.display = 'none';
                centraCameras = []; await loadCentraCameras();
            } else if (jobs.some((job) => job.status === 'error' || job.status === 'interrupted')) {
                throw new Error(jobs.find((job) => job.error)?.error || 'Поиск прерван');
            }
        } catch (error) {
            clearInterval(timer); button.disabled = false;
            progress.innerHTML = `<span style="color:#f87171">${_esc(error.message)}</span>`;
        }
    }, 2000);
    window._centraPoller = timer;
}

async function cancelCentraDiscovery() {
    let jobIds = activeCentraJobId;
    if (!jobIds) { try { jobIds = JSON.parse(localStorage.getItem('ip2domain_centra_job')); } catch (_) {} }
    if (!jobIds) return;
    jobIds = Array.isArray(jobIds) ? jobIds : [jobIds];
    const cancelButton = document.getElementById('centra-cancel-button');
    cancelButton.disabled = true;
    cancelButton.textContent = 'Остановка...';
    try {
        const responses = await Promise.all(jobIds.map((id) => fetch(`/api/cameras/centra/discover/${id}/cancel`, {method:'POST'})));
        if (responses.some((response) => !response.ok)) throw new Error('Не удалось остановить поиск');
        document.getElementById('centra-discovery-progress').style.display = 'block';
        document.getElementById('centra-discovery-progress').textContent = 'Остановка поиска...';
    } catch (error) {
        cancelButton.disabled = false;
        cancelButton.textContent = '■ Остановить';
    }
}
window.cancelCentraDiscovery = cancelCentraDiscovery;

function renderCentraList() {
    const typeOf = (camera) => String(camera.camera_type || camera.id || '').split('-', 1)[0].toUpperCase();
    const counts = {
        all: centraCameras.length,
        I: centraCameras.filter((camera) => typeOf(camera) === 'I').length,
        G: centraCameras.filter((camera) => typeOf(camera) === 'G').length,
        custom: centraCameras.filter((camera) => !['I', 'G'].includes(typeOf(camera))).length
    };
    const filters = [['all', 'Все'], ['I', 'Домофоны'], ['G', 'Городские'], ['custom', 'Другие']];
    document.getElementById('centra-list-filters').innerHTML = filters.map(([value, label]) =>
        `<button type="button" class="centra-list-filter ${centraListFilter === value ? 'active' : ''}" onclick="setCentraListFilter('${value}')">${label}<small>${counts[value]}</small></button>`
    ).join('');
    const visible = centraCameras.map((camera, index) => ({camera, index})).filter(({camera}) => {
        const type = typeOf(camera);
        return centraListFilter === 'all' || type === centraListFilter ||
            (centraListFilter === 'custom' && !['I', 'G'].includes(type));
    });
    const groups = new Map();
    visible.forEach((item) => {
        const label = String(item.camera.address || item.camera.title || item.camera.id).trim();
        const key = label.toLocaleLowerCase('ru');
        if (!groups.has(key)) groups.set(key, {label, items: []});
        groups.get(key).items.push(item);
    });
    const itemHtml = ({camera, index}) =>
        `<button type="button" class="centra-camera-item" data-centra-index="${index}" onclick="selectCentraCamera(${index}, true)"><span class="centra-camera-number ${centraCameraType(camera) === 'Городская камера' ? 'city' : 'intercom'}">${_esc(centraEntrance(camera))}</span><strong>${_esc(camera.title || camera.id)}</strong><small>${_esc(centraCameraType(camera))} ${_esc(centraCameraNumber(camera))}</small></button>`;
    document.getElementById('centra-camera-list').innerHTML = [...groups.entries()].map(([key, group]) => {
        group.items.sort((left, right) => {
            const a = centraCameraOrder(left.camera), b = centraCameraOrder(right.camera);
            return a[0] - b[0] || a[1] - b[1];
        });
        return `<details class="centra-address-group" data-address-key="${_esc(key)}" ${centraOpenAddressGroups.has(key) ? 'open' : ''} ontoggle="rememberCentraAddressGroup(this)"><summary><span title="${_esc(group.label)}">${_esc(centraSidebarAddress(group.label) || group.label)}</span><small>${group.items.length}</small></summary><div class="centra-address-cameras">${group.items.map(itemHtml).join('')}</div></details>`;
    }).join('') || '<div class="empty-state">Камер этого типа нет</div>';
}

function rememberCentraAddressGroup(details) {
    const key = details.dataset.addressKey;
    if (details.open) centraOpenAddressGroups.add(key);
    else centraOpenAddressGroups.delete(key);
}
window.rememberCentraAddressGroup = rememberCentraAddressGroup;

function setCentraListFilter(filter) {
    centraListFilter = filter;
    renderCentraList();
}
window.setCentraListFilter = setCentraListFilter;

function selectCentraCamera(index, openPlayer) {
    const camera = centraCameras[index];
    if (!camera) return;
    const item = document.querySelector(`.centra-camera-item[data-centra-index="${index}"]`);
    if (item?.closest('details')) item.closest('details').open = true;
    document.querySelectorAll('.centra-camera-item').forEach((item) => item.classList.toggle('active', Number(item.dataset.centraIndex) === index));
    if (centraMap && Array.isArray(camera.coordinates)) { centraMap.setCenter(camera.coordinates, Math.max(centraMap.getZoom(), 16), {duration: 250}); }
    if (openPlayer) openCentraCamera(index);
}
window.selectCentraCamera = selectCentraCamera;

function openCentraCamera(index) {
    const camera = centraCameras[index];
    openCentraCameraPlayer(camera);
}

function openCentraScreenCamera(index) {
    openCentraCameraPlayer(centraScreenCameras[index]);
}
window.openCentraScreenCamera = openCentraScreenCamera;

function centraWebrtcEmbedUrl(embedUrl) {
    try {
        const url = new URL(embedUrl, window.location.origin);
        url.searchParams.set('proto', 'webrtc');
        url.searchParams.set('autoplay', 'true');
        url.searchParams.set('muted', 'false');
        return url.toString();
    } catch (_) {
        const separator = String(embedUrl).includes('?') ? '&' : '?';
        return `${embedUrl}${separator}proto=webrtc&autoplay=true&muted=false`;
    }
}

function centraPlainEmbedUrl(embedUrl) {
    try {
        const url = new URL(embedUrl, window.location.origin);
        url.searchParams.delete('proto');
        return url.toString();
    } catch (_) {
        return String(embedUrl).replace(/([?&])proto=[^&]*&?/i, '$1').replace(/[?&]$/, '');
    }
}

function setCentraPlayerMode(mode) {
    const dialog = document.getElementById('centra-player-dialog');
    const iframe = dialog?.querySelector('iframe');
    if (!dialog || !iframe) return;
    const baseUrl = dialog.dataset.embedUrl;
    iframe.src = mode === 'webrtc' ? centraWebrtcEmbedUrl(baseUrl) : centraPlainEmbedUrl(baseUrl);
    dialog.querySelectorAll('.centra-player-mode button').forEach((button) =>
        button.classList.toggle('active', button.dataset.mode === mode));
}
window.setCentraPlayerMode = setCentraPlayerMode;

function openCentraCameraPlayer(camera) {
    if (!camera?.embed_url) return;
    let dialog = document.getElementById('centra-player-dialog');
    if (!dialog) {
        dialog = document.createElement('dialog');
        dialog.id = 'centra-player-dialog';
        dialog.className = 'centra-player-dialog';
        dialog.addEventListener('close', () => { dialog.querySelector('iframe').src = 'about:blank'; });
        dialog.addEventListener('click', (event) => {
            if (event.target === dialog) dialog.close();
        });
        document.body.appendChild(dialog);
    }
    const type = String(camera.camera_type || camera.id || '').split('-', 1)[0].toUpperCase();
    const defaultMode = ['I', 'A', 'H'].includes(type) ? 'webrtc' : 'plain';
    const playerUrl = defaultMode === 'webrtc' ? centraWebrtcEmbedUrl(camera.embed_url) : centraPlainEmbedUrl(camera.embed_url);
    dialog.dataset.embedUrl = camera.embed_url;
    dialog.innerHTML = `<div class="centra-player-head"><strong>${_esc(centraCameraType(camera))} · ${_esc(centraEntrance(camera))} · ${_esc(camera.title || camera.id)} <small>(${_esc(centraCameraNumber(camera))})</small></strong><div class="centra-player-controls"><div class="centra-player-mode" aria-label="Режим трансляции"><button type="button" data-mode="plain" class="${defaultMode === 'plain' ? 'active' : ''}" onclick="setCentraPlayerMode('plain')">Обычный</button><button type="button" data-mode="webrtc" class="${defaultMode === 'webrtc' ? 'active' : ''}" onclick="setCentraPlayerMode('webrtc')">WebRTC</button></div><button class="centra-player-close" type="button" onclick="document.getElementById('centra-player-dialog').close()" aria-label="Закрыть">×</button></div></div><iframe class="centra-player" src="${_esc(playerUrl)}" title="${_esc(camera.title || 'Камера Centra')}" allow="autoplay; fullscreen; encrypted-media" allowfullscreen referrerpolicy="no-referrer"></iframe>`;
    dialog.showModal();
}
window.openCentraCamera = openCentraCamera;

function resizeCentraMap() { if (centraMap?.container) centraMap.container.fitToViewport(); }
window.resizeCentraMap = resizeCentraMap;

