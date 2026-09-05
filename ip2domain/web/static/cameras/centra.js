/* Centra Cameras Client (Auto-bundled from centra/) */
'use strict';


// ════════════════════════════════════════════════════════════════
// MODULE: centra/map.js
// ════════════════════════════════════════════════════════════════

// Map & Core State
let centraMap = null;
let centraCameras = [];
let centraUsedPinColors = {};
let centraTypePinColors = {I: 'red', G: 'blue', H: 'green', P: 'green', T: 'orange', A: 'violet', ORION: 'yellow', A42: 'pink'};
let centraListFilter = 'all';
let centraOpenAddressGroups = new Set();
let centraLastClusterAction = 0;

function centraCameraNumber(camera) {
    if (camera?.provider_id === 'orion') return `Орион #${camera.external_id || camera.id}`;
    if (camera?.provider_id === 'a42') return `A42 #${camera.external_id || camera.id}`;
    return String(camera?.id || '').replace(/^[A-Z]-/i, '');
}

function centraEntrance(camera) {
    if (camera?.provider_id === 'orion') return `Орион #${camera.external_id || camera.id}`;
    if (camera?.provider_id === 'a42') return `A42 #${camera.external_id || camera.id}`;
    const value = Number(camera?.entrance || String(camera?.id || '').match(/-(\d+)$/)?.[1]);
    if (!Number.isInteger(value) || value < 1) return centraCameraNumber(camera);
    const type = String(camera?.camera_type || camera?.id || '').toUpperCase().replace(/-.*/, '');
    if (type === 'I') return `Подъезд ${value}`;
    if (type === 'A') return `Калитка ${value}`;
    if (type === 'T') return `Территория ${value}`;
    if (type === 'P') return `Парковка ${value}`;
    if (type === 'G') return `Ракурс ${value}`;
    return `Камера ${value}`;
}

function centraCameraType(camera) {
    const type = String(camera?.camera_type || camera?.id || '').toUpperCase().replace(/-.*/, '');
    if (type === 'ORION') return 'Орион Телеком';
    if (type === 'A42') return 'Goodline Дорожная';
    if (type === 'I') return 'Домофон';
    if (type === 'G') return 'Городская камера';
    if (type === 'H') return 'Камера на доме';
    if (type === 'T') return 'Двор / территория';
    if (type === 'A') return 'Калитка / проходная';
    if (type === 'P') return 'Парковка / периметр';
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

function loadYandexMaps(apiKey) {
    if (window.ymaps) return Promise.resolve(window.ymaps);
    if (window._centraYmapsPromise) return window._centraYmapsPromise;
    window._centraYmapsPromise = new Promise((resolve, reject) => {
        const script = document.createElement('script');
        const keyParam = apiKey ? `&apikey=${encodeURIComponent(apiKey)}` : '';
        script.src = `https://api-maps.yandex.ru/2.1/?lang=ru_RU${keyParam}`;
        script.onload = () => window.ymaps.ready(() => resolve(window.ymaps));
        script.onerror = () => reject(new Error('Не удалось загрузить скрипт Яндекс Карт'));
        document.head.appendChild(script);
    });
    return window._centraYmapsPromise;
}

let currentCentraMapSource = 'all';

async function changeCentraMapSource(source) {
    currentCentraMapSource = source || 'all';
    await loadCentraCameras();
}
window.changeCentraMapSource = changeCentraMapSource;

async function loadCentraCameras() {
    const mapNode = document.getElementById('centra-map');
    try {
        const source = currentCentraMapSource || 'all';
        const response = await fetch(`/api/cameras/centra?source=${encodeURIComponent(source)}`, {cache: 'no-store'});
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось загрузить камеры');
        centraCameras = (data.cameras || []).sort((left, right) => {
            const a = centraCameraOrder(left), b = centraCameraOrder(right);
            return a[0] - b[0] || a[1] - b[1];
        });
        centraUsedPinColors = data.used_pin_colors || {};
        centraTypePinColors = data.type_pin_colors || {I: 'red', G: 'blue', H: 'green', P: 'green', ORION: 'yellow', A42: 'pink'};
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
        if (geocodeQueue.length) {
            await Promise.all(geocodeQueue.map(async (address) => {
                let coordinates = null;
                try {
                    const result = await ymaps.geocode(address, {results: 1});
                    coordinates = result.geoObjects.get(0)?.geometry?.getCoordinates() || null;
                } catch (_) {}
                if (!coordinates) {
                    const fallback = await fetch('/api/cameras/centra/geocode', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({address})});
                    if (fallback.ok) {
                        const fallbackData = await fallback.json();
                        coordinates = fallbackData.coordinates || null;
                    }
                }
                if (Array.isArray(coordinates)) {
                    await fetch('/api/cameras/centra/coordinates', {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify({address, coordinates})});
                    centraCameras.forEach((camera) => {
                        if (camera.address === address) camera.coordinates = coordinates;
                    });
                }
            }));
        }
        mapNode.innerHTML = '';
        centraMap = new ymaps.Map('centra-map', {center: [53.7557, 87.1099], zoom: 11, controls: ['zoomControl', 'fullscreenControl']});
        const clusterer = new ymaps.Clusterer({
            clusterIconLayout: centraClusterLayout(ymaps),
            clusterIconShape: {type: 'Rectangle', coordinates: [[0, 0], [48, 48]]},
            groupByCoordinates: false,
            clusterDisableClickZoom: true,
            gridSize: 48,
            maxZoom: 17
        });
        clusterer.events.add('click', (event) => {
            const target = event.get('target');
            const objects = target?.properties?.get('geoObjects') || [];
            if (objects.length) handleCentraClusterClick(objects);
        });
        const placemarks = [];
        centraCameras.forEach((camera, index) => {
            if (!Array.isArray(camera.coordinates)) return;
            const caption = centraEntrance(camera);
            const placemark = new ymaps.Placemark(camera.coordinates, {
                iconContent: caption,
                balloonContentHeader: `<strong>${_esc(camera.title || camera.id)}</strong>`,
                balloonContentBody: `<p>${_esc(camera.address || '')}</p><p><small>${_esc(camera.id)} · ${_esc(centraCameraType(camera))}</small></p>`,
                balloonContentFooter: `<button class="btn btn-small" type="button" onclick="openCentraCamera(${index})">Смотреть</button>`,
                centraIndex: index,
                pinColor: centraPinColor(camera)
            }, {preset: centraPlacemarkPreset(camera)});
            placemarks.push(placemark);
        });
        clusterer.add(placemarks);
        centraMap.geoObjects.add(clusterer);
        if (placemarks.length) {
            centraMap.setBounds(clusterer.getBounds(), {checkZoomRange: true, zoomMargin: 35});
        }
    } catch (error) {
        mapNode.innerHTML = `<div class="empty-state">${_esc(error.message)}</div>`;
    }
}
window.loadCentraCameras = loadCentraCameras;

function renderCentraList() {
    const list = document.getElementById('centra-camera-list');
    const filters = document.getElementById('centra-list-filters');
    if (!list) return;
    const types = [...new Set(centraCameras.map((camera) => String(camera.camera_type || camera.id || '').replace(/-.*/, '').toUpperCase()))];
    filters.innerHTML = `<button type="button" class="btn btn-ghost btn-small ${centraListFilter === 'all' ? 'active' : ''}" onclick="setCentraListFilter('all')">Все (${centraCameras.length})</button>` +
        types.map((type) => {
            const count = centraCameras.filter((camera) => String(camera.camera_type || camera.id || '').toUpperCase().startsWith(type)).length;
            return `<button type="button" class="btn btn-ghost btn-small ${centraListFilter === type ? 'active' : ''}" onclick="setCentraListFilter('${type}')">${type} (${count})</button>`;
        }).join('');
    filterCentraSidebarList();
}

function filterCentraSidebarList() {
    const list = document.getElementById('centra-camera-list');
    if (!list) return;
    const search = document.getElementById('centra-sidebar-search')?.value.trim().toLowerCase() || '';
    const filtered = centraCameras.map((camera, index) => ({camera, index})).filter(({camera}) => {
        const type = String(camera.camera_type || camera.id || '').toUpperCase().replace(/-.*/, '');
        const matchesFilter = centraListFilter === 'all' || type === centraListFilter;
        const text = `${camera.title || ''} ${camera.address || ''} ${camera.id || ''}`.toLowerCase();
        return matchesFilter && (!search || text.includes(search));
    });
    const groups = new Map();
    filtered.forEach(({camera, index}) => {
        const key = camera.address || 'Без адреса';
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push({camera, index});
    });
    if (!groups.size) {
        list.innerHTML = '<div class="empty-state">Камеры не найдены</div>';
        return;
    }
    list.innerHTML = [...groups.entries()].map(([address, items]) => {
        const isOpen = centraOpenAddressGroups.has(address) || groups.size <= 4;
        return `<details class="centra-address-group" ${isOpen ? 'open' : ''} ontoggle="rememberCentraAddressGroup(this)"><summary><span class="centra-address-title">${_esc(centraSidebarAddress(address))}</span><span class="centra-address-count">${items.length}</span></summary><div class="centra-address-cameras">${items.map(({camera, index}) =>
            `<button type="button" class="centra-camera-item" onclick="selectCentraCamera(${index}, event.detail > 1)"><span class="centra-camera-item-title">${_esc(centraEntrance(camera))}</span><small>${_esc(camera.id)} · ${_esc(centraCameraType(camera))}</small></button>`).join('')}</div></details>`;
    }).join('');
}
window.filterCentraSidebarList = filterCentraSidebarList;

function rememberCentraAddressGroup(details) {
    const title = details.querySelector('.centra-address-title')?.textContent?.trim();
    if (!title) return;
    const full = [...centraOpenAddressGroups].find((item) => item.includes(title)) || title;
    if (details.open) centraOpenAddressGroups.add(full);
    else centraOpenAddressGroups.delete(full);
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
    if (centraMap && Array.isArray(camera.coordinates)) {
        centraMap.setCenter(camera.coordinates, 16, {duration: 250});
    }
    if (openPlayer) openCentraCamera(index);
}
window.selectCentraCamera = selectCentraCamera;

function openCentraCamera(index) {
    const camera = centraCameras[index];
    openCentraCameraPlayer(camera);
}
window.openCentraCamera = openCentraCamera;

function resizeCentraMap() { if (centraMap?.container) centraMap.container.fitToViewport(); }
window.resizeCentraMap = resizeCentraMap;


// ════════════════════════════════════════════════════════════════
// MODULE: centra/discovery.js
// ════════════════════════════════════════════════════════════════

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
    } catch (error) {
        cancelButton.disabled = false;
        cancelButton.textContent = '■ Остановить';
    }
}
window.cancelCentraDiscovery = cancelCentraDiscovery;


// ════════════════════════════════════════════════════════════════
// MODULE: centra/player.js
// ════════════════════════════════════════════════════════════════

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
window.centraWebrtcEmbedUrl = centraWebrtcEmbedUrl;

function centraPlainEmbedUrl(embedUrl) {
    try {
        const url = new URL(embedUrl, window.location.origin);
        url.searchParams.delete('proto');
        url.searchParams.delete('dvr');
        url.searchParams.delete('ago');
        url.searchParams.delete('from');
        url.searchParams.delete('to');
        return url.toString();
    } catch (_) {
        return String(embedUrl).replace(/([?&])(proto|dvr|ago|from|to)=[^&]*&?/gi, '$1').replace(/[?&]$/, '');
    }
}
window.centraPlainEmbedUrl = centraPlainEmbedUrl;

function centraDvrEmbedUrl(embedUrl, options = {}) {
    try {
        const url = new URL(embedUrl, window.location.origin);
        url.searchParams.set('dvr', 'true');
        url.searchParams.delete('proto');
        url.searchParams.delete('ago');
        url.searchParams.delete('from');
        url.searchParams.delete('to');
        if (options && options.ago !== undefined && options.ago !== null && options.ago !== '') {
            url.searchParams.set('ago', String(options.ago));
        } else if (options && options.from) {
            url.searchParams.set('from', String(options.from));
            if (options.to) {
                url.searchParams.set('to', String(options.to));
            }
        }
        return url.toString();
    } catch (_) {
        const separator = String(embedUrl).includes('?') ? '&' : '?';
        let extra = 'dvr=true';
        if (options && options.ago) extra += `&ago=${options.ago}`;
        else if (options && options.from) extra += `&from=${options.from}`;
        return `${embedUrl}${separator}${extra}`;
    }
}
window.centraDvrEmbedUrl = centraDvrEmbedUrl;

function setCentraPlayerMode(mode, options = {}) {
    const dialog = document.getElementById('centra-player-dialog');
    const iframe = dialog?.querySelector('iframe');
    if (!dialog || !iframe) return;
    const baseUrl = dialog.dataset.embedUrl;
    if (mode === 'webrtc') {
        iframe.src = centraWebrtcEmbedUrl(baseUrl);
    } else if (mode === 'dvr') {
        iframe.src = centraDvrEmbedUrl(baseUrl, options);
    } else {
        iframe.src = centraPlainEmbedUrl(baseUrl);
    }
    dialog.querySelectorAll('.centra-player-mode button').forEach((button) =>
        button.classList.toggle('active', button.dataset.mode === mode));

    const dvrBar = dialog.querySelector('.centra-player-dvr-bar');
    if (dvrBar) {
        dvrBar.classList.toggle('dvr-active', mode === 'dvr');
    }
    dialog.querySelectorAll('.centra-dvr-presets button').forEach((btn) => {
        const btnAgo = btn.dataset.ago;
        if (mode === 'dvr' && options.ago !== undefined && btnAgo === String(options.ago)) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });
}
window.setCentraPlayerMode = setCentraPlayerMode;

function seekCentraDvrAgo(seconds) {
    setCentraPlayerMode('dvr', { ago: seconds });
}
window.seekCentraDvrAgo = seekCentraDvrAgo;

function seekCentraDvrDatetime() {
    const input = document.getElementById('centra-dvr-datetime');
    if (!input || !input.value) return;
    const selectedDate = new Date(input.value);
    const ts = Math.floor(selectedDate.getTime() / 1000);
    if (!isNaN(ts) && ts > 0) {
        setCentraPlayerMode('dvr', { from: ts });
    }
}
window.seekCentraDvrDatetime = seekCentraDvrDatetime;

function downloadCentraDvrClip() {
    const dialog = document.getElementById('centra-player-dialog');
    if (!dialog) return;
    const baseUrl = dialog.dataset.embedUrl;
    if (!baseUrl) return;
    try {
        const urlObj = new URL(baseUrl, window.location.origin);
        const pathParts = urlObj.pathname.split('/').filter(Boolean);
        const cameraId = pathParts[0];
        const durationPrompt = prompt('Длительность фрагмента в минутах для скачивания (например: 5, 15, 30, 60):', '15');
        if (!durationPrompt) return;
        const durationMin = parseInt(durationPrompt, 10);
        if (isNaN(durationMin) || durationMin <= 0) {
            alert('Укажите корректное количество минут');
            return;
        }
        const durationSec = durationMin * 60;
        const input = document.getElementById('centra-dvr-datetime');
        let fromTs;
        if (input && input.value) {
            const selectedDate = new Date(input.value);
            const ts = Math.floor(selectedDate.getTime() / 1000);
            if (!isNaN(ts) && ts > 0) fromTs = ts;
        }
        if (!fromTs) {
            fromTs = Math.floor(Date.now() / 1000) - durationSec;
        }
        const clipUrl = `${urlObj.origin}/${encodeURIComponent(cameraId)}/archive-${fromTs}-${durationSec}.mp4`;
        const a = document.createElement('a');
        a.href = clipUrl;
        a.target = '_blank';
        a.download = `${cameraId}_${fromTs}_${durationSec}.mp4`;
        document.body.appendChild(a);
        a.click();
        a.remove();
    } catch (e) {
        alert('Ошибка формирования ссылки на скачивание архива: ' + e.message);
    }
}
window.downloadCentraDvrClip = downloadCentraDvrClip;

async function loadCentraDvrInfo(camera) {
    const infoEl = document.getElementById('centra-dvr-info');
    const dtInput = document.getElementById('centra-dvr-datetime');
    if (!infoEl || !camera?.embed_url) return;
    try {
        const urlObj = new URL(camera.embed_url, window.location.origin);
        const pathParts = urlObj.pathname.split('/').filter(Boolean);
        const cameraId = pathParts[0];
        const statusUrl = `${urlObj.origin}/${encodeURIComponent(cameraId)}/recording_status.json`;
        const resp = await fetch(statusUrl, { mode: 'cors', cache: 'no-store' });
        if (!resp.ok) throw new Error('Status ' + resp.status);
        const data = await resp.json();
        const camData = data[cameraId] || Object.values(data)[0];
        if (camData && camData.from && camData.to) {
            const fromSec = Number(camData.from);
            const toSec = Number(camData.to);
            const totalHours = ((toSec - fromSec) / 3600).toFixed(1);
            const fromDate = new Date(fromSec * 1000);
            const fromStr = fromDate.toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
            infoEl.textContent = `Архив: ~${totalHours} ч (с ${fromStr})`;
            infoEl.title = `Доступный интервал записи: ${new Date(fromSec * 1000).toLocaleString()} — ${new Date(toSec * 1000).toLocaleString()}`;
            if (dtInput) {
                const toIsoLocal = (d) => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
                dtInput.min = toIsoLocal(fromDate);
                dtInput.max = toIsoLocal(new Date(toSec * 1000));
                if (!dtInput.value) {
                    dtInput.value = toIsoLocal(new Date(Math.max(fromSec, toSec - 3600) * 1000));
                }
            }
        } else {
            infoEl.textContent = 'Архив DVR';
        }
    } catch (_) {
        infoEl.textContent = 'Архив DVR';
    }
}

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
    const isA42 = camera.provider_id === 'a42' || camera.camera_type === 'A42';
    const isOrion = camera.provider_id === 'orion' || camera.camera_type === 'ORION';
    const type = String(camera.camera_type || camera.id || '').split('-', 1)[0].toUpperCase();

    if (isA42) {
        dialog.dataset.embedUrl = camera.embed_url;
        dialog.innerHTML = `<div class="centra-player-head"><strong>${_esc(centraCameraType(camera))} · ${_esc(camera.title || camera.id)}</strong><div class="centra-player-controls"><a class="btn btn-ghost btn-small" href="${_esc(camera.embed_url)}" target="_blank" rel="noopener" style="text-decoration:none;">Открыть на A42 ↗</a><button class="centra-player-close" type="button" onclick="document.getElementById('centra-player-dialog').close()" aria-label="Закрыть">×</button></div></div><iframe class="centra-player" src="${_esc(camera.embed_url)}" title="${_esc(camera.title || 'Дорожная камера')}" allow="autoplay; fullscreen; encrypted-media" allowfullscreen referrerpolicy="no-referrer" style="width:100%; height:550px; border:none;"></iframe>`;
        dialog.showModal();
        return;
    }

    const defaultMode = ['I', 'A', 'H'].includes(type) ? 'webrtc' : 'plain';
    const playerUrl = defaultMode === 'webrtc' ? centraWebrtcEmbedUrl(camera.embed_url) : centraPlainEmbedUrl(camera.embed_url);
    dialog.dataset.embedUrl = camera.embed_url;
    dialog.innerHTML = `<div class="centra-player-head"><strong>${_esc(centraCameraType(camera))} · ${_esc(centraEntrance(camera))} · ${_esc(camera.title || camera.id)} <small>(${_esc(centraCameraNumber(camera))})</small></strong><div class="centra-player-controls"><div class="centra-player-mode" aria-label="Режим трансляции"><button type="button" data-mode="plain" class="${defaultMode === 'plain' ? 'active' : ''}" onclick="setCentraPlayerMode('plain')">Обычный</button><button type="button" data-mode="webrtc" class="${defaultMode === 'webrtc' ? 'active' : ''}" onclick="setCentraPlayerMode('webrtc')">WebRTC</button><button type="button" data-mode="dvr" class="${defaultMode === 'dvr' ? 'active' : ''}" onclick="setCentraPlayerMode('dvr')">Архив (DVR)</button></div><button class="centra-player-close" type="button" onclick="document.getElementById('centra-player-dialog').close()" aria-label="Закрыть">×</button></div></div><div class="centra-player-dvr-bar ${defaultMode === 'dvr' ? 'dvr-active' : ''}"><div class="centra-dvr-presets"><span class="centra-dvr-label">Перемотка:</span><button type="button" data-ago="900" onclick="seekCentraDvrAgo(900)" title="15 минут назад">-15м</button><button type="button" data-ago="1800" onclick="seekCentraDvrAgo(1800)" title="30 минут назад">-30м</button><button type="button" data-ago="3600" onclick="seekCentraDvrAgo(3600)" title="1 час назад">-1ч</button><button type="button" data-ago="10800" onclick="seekCentraDvrAgo(10800)" title="3 часа назад">-3ч</button><button type="button" data-ago="43200" onclick="seekCentraDvrAgo(43200)" title="12 часов назад">-12ч</button><button type="button" data-ago="86400" onclick="seekCentraDvrAgo(86400)" title="24 часа назад">-24ч</button><button type="button" data-ago="259200" onclick="seekCentraDvrAgo(259200)" title="3 дня назад">-3д</button><button type="button" class="centra-dvr-live-btn" onclick="setCentraPlayerMode('plain')" title="Вернуться к прямой трансляции">● Live</button></div><div class="centra-dvr-jump"><input type="datetime-local" class="centra-dvr-datetime" id="centra-dvr-datetime" title="Дата и время в архиве"><button type="button" class="centra-dvr-jump-btn" onclick="seekCentraDvrDatetime()">Перейти</button></div><div class="centra-dvr-extra"><span class="centra-dvr-info" id="centra-dvr-info">Архив DVR</span><button type="button" class="centra-dvr-download" onclick="downloadCentraDvrClip()" title="Скачать отрезок архива в формате MP4">Скачать MP4</button></div></div><iframe class="centra-player" src="${_esc(playerUrl)}" title="${_esc(camera.title || 'Камера Centra')}" allow="autoplay; fullscreen; encrypted-media" allowfullscreen referrerpolicy="no-referrer"></iframe>`;
    dialog.showModal();
    loadCentraDvrInfo(camera);
}
window.openCentraCameraPlayer = openCentraCameraPlayer;


// ════════════════════════════════════════════════════════════════
// MODULE: centra/screens.js
// ════════════════════════════════════════════════════════════════

let centraScreensOffset = 0;
let centraScreenCameras = [];
let centraScreensLoading = false;
let centraScreensHasMore = true;
let centraScreensLoaded = false;
let centraScreenObserver = null;
let centraScreenSearchTimer = null;
let cameraCatalogLoaded = false;
let cameraCatalogSearchTimer = null;

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
    if (tab === 'go2rtc' && window.loadGo2rtcStreams) loadGo2rtcStreams();
    if (tab === 'strix') {
        if (window.loadStrixPresets) loadStrixPresets();
        if (window.loadStrixResults) loadStrixResults();
        if (window.activeStrixJobId === null && window.restoreStrixScan) {
            restoreStrixScan();
        }
        if (window.refreshStrixGraphTargets) refreshStrixGraphTargets();
    }
    if (tab === 'scanner') {
        if (window.restoreCameraScan) restoreCameraScan();
        if (window.refreshCameraTargets) refreshCameraTargets();
    }
    if (tab === 'catalog' && !cameraCatalogLoaded) loadCameraCatalogProviders();
    if (tab === 'centra') {
        if (!centraCameras.length && window.loadCentraCameras) loadCentraCameras();
        setTimeout(resizeCentraMap, 80);
    }
    if (tab === 'screens') {
        if (!centraScreensLoaded) resetCentraScreens();
        else if (window.loadSavedCentraPeopleCount) loadSavedCentraPeopleCount();
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

function ensureCentraScreenObserver() {
    if (centraScreenObserver || !('IntersectionObserver' in window)) return;
    centraScreenObserver = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (!entry.isIntersecting) return;
            const img = entry.target;
            const src = img.dataset.src;
            if (src) {
                img.src = src;
                img.removeAttribute('data-src');
            }
            centraScreenObserver.unobserve(img);
        });
    }, {rootMargin: '250px 0px'});
}

async function resetCentraScreens() {
    centraScreensOffset = 0;
    centraScreenCameras = [];
    centraScreensHasMore = true;
    const grid = document.getElementById('centra-screens-grid');
    if (grid) grid.innerHTML = '';
    const errorNode = document.getElementById('centra-screens-error');
    if (errorNode) errorNode.textContent = '';
    centraScreensLoaded = true;
    await loadMoreCentraScreens();
}
window.resetCentraScreens = resetCentraScreens;

function scheduleCentraScreensSearch() {
    clearTimeout(centraScreenSearchTimer);
    centraScreenSearchTimer = setTimeout(() => {
        resetCentraScreens();
    }, 300);
}
window.scheduleCentraScreensSearch = scheduleCentraScreensSearch;

async function loadMoreCentraScreens() {
    if (centraScreensLoading || !centraScreensHasMore) return;
    centraScreensLoading = true;
    const status = document.getElementById('centra-screen-status');
    const sentinel = document.getElementById('centra-screens-sentinel');
    const type = document.getElementById('centra-screens-type')?.value || '';
    const search = document.getElementById('centra-screens-search')?.value.trim() || '';
    const personSearch = (document.getElementById('centra-people-id-search')?.value.trim() || '').toLowerCase();
    const endpoint = personSearch ? '/api/cameras/centra/people-identities/search'
        : window.centraScreensMode === 'people' ? '/api/cameras/centra/people/results' : '/api/cameras/centra/screens';
    const params = personSearch
        ? new URLSearchParams({person_id: personSearch, camera_type: type})
        : new URLSearchParams({offset: String(centraScreensOffset), limit: '100', camera_type: type, search});
    if (status) status.textContent = 'Загрузка кадров...';
    try {
        const response = await fetch(`${endpoint}?${params}`);
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось загрузить кадры');
        const countNode = document.getElementById('centra-screens-count');
        if (countNode) countNode.textContent = `${Number(data.total || 0).toLocaleString()} камер`;
        centraScreensHasMore = Boolean(data.has_more);
        const startIndex = centraScreenCameras.length;
        centraScreenCameras.push(...(data.cameras || []));
        centraScreensOffset += (data.cameras || []).length;
        renderCentraScreens(data.cameras || [], startIndex);
        if (status) status.textContent = centraScreensHasMore ? '' : `Показано ${centraScreenCameras.length} камер`;
        if (sentinel) sentinel.style.display = centraScreensHasMore ? '' : 'none';
        if (data.ffmpeg_available === false) {
            const errorNode = document.getElementById('centra-screens-error');
            if (errorNode) errorNode.textContent = 'FFmpeg не установлен: используются только статические кадры preview.jpg';
        }
    } catch (error) {
        if (status) status.textContent = error.message;
    } finally {
        centraScreensLoading = false;
    }
}
window.loadMoreCentraScreens = loadMoreCentraScreens;

function renderCentraScreens(cameras, startIndex) {
    const grid = document.getElementById('centra-screens-grid');
    if (!grid) return;
    ensureCentraScreenObserver();
    const fragment = document.createDocumentFragment();
    cameras.forEach((camera, offset) => {
        const index = startIndex + offset;
        const card = document.createElement('div');
        card.className = 'centra-screen-card';
        const img = document.createElement('img');
        img.className = 'centra-screen-image';
        img.alt = camera.title || camera.id;
        img.dataset.src = camera.screenshot_url;
        if (camera.screenshot_stale) {
            img.dataset.refresh = 'true';
            img.setAttribute('data-refresh', 'true'); // data-refresh="true"
        }
        img.src = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 9'/%3E";
        card.appendChild(img);
        const meta = document.createElement('div');
        meta.className = 'centra-screen-meta';
        meta.innerHTML = `<strong>${_esc(centraEntrance(camera))} · ${_esc(camera.title || camera.id)}</strong><small>${_esc(camera.id)} · ${_esc(centraCameraType(camera))} · ${_esc(camera.address || '')}</small>`;
        card.appendChild(meta);
        card.onclick = () => openCentraScreenCamera(index);
        fragment.appendChild(card);
        if (centraScreenObserver) centraScreenObserver.observe(img);
    });
    grid.appendChild(fragment);
}

function showAllCentraScreens() {
    window.centraScreensMode = 'all';
    window.centraPeopleShowingAllResults = false;
    const searchInput = document.getElementById('centra-people-id-search');
    if (searchInput) searchInput.value = '';
    if (window.updateCentraScreensModeButtons) updateCentraScreensModeButtons();
    const btn = document.getElementById('centra-people-show-all-btn');
    if (btn) btn.style.display = 'none';
    resetCentraScreens();
}
window.showAllCentraScreens = showAllCentraScreens;


// ════════════════════════════════════════════════════════════════
// MODULE: centra/people.js
// ════════════════════════════════════════════════════════════════

let centraPeoplePoller = null;
let activeCentraPeopleJobId = null;
let centraPeopleShowingAllResults = false;
let centraScreensMode = 'all';

async function loadSavedCentraPeopleCount() {
    const badge = document.getElementById('centra-people-saved-count');
    const type = document.getElementById('centra-screens-type')?.value || '';
    if (!badge) return;
    try {
        const response = await fetch(`/api/cameras/centra/people/results?offset=0&limit=1&camera_type=${encodeURIComponent(type)}`);
        const data = await response.json();
        if (response.ok) {
            badge.textContent = `${Number(data.total || 0).toLocaleString()}`;
        }
    } catch (_) {}
}
window.loadSavedCentraPeopleCount = loadSavedCentraPeopleCount;

async function showSavedCentraPeople() {
    window.centraScreensMode = 'people';
    window.centraPeopleShowingAllResults = true;
    updateCentraScreensModeButtons();
    const btn = document.getElementById('centra-people-show-all-btn');
    if (btn) btn.style.display = '';
    await resetCentraScreens();
}
window.showSavedCentraPeople = showSavedCentraPeople;

function updateCentraScreensModeButtons() {
    const allBtn = document.getElementById('centra-screens-mode-all');
    const peopleBtn = document.getElementById('centra-screens-mode-people');
    if (allBtn) allBtn.classList.toggle('active', window.centraScreensMode === 'all');
    if (peopleBtn) peopleBtn.classList.toggle('active', window.centraScreensMode === 'people');
}
window.updateCentraScreensModeButtons = updateCentraScreensModeButtons;

function renderCentraPeopleMatches(result, replaceGrid) {
    const matches = result?.matches || [];
    if (!matches.length) return;
    const grid = document.getElementById('centra-screens-grid');
    if (!grid) return;
    if (replaceGrid) {
        grid.innerHTML = '';
        centraScreenCameras = [];
    }
    const startIndex = centraScreenCameras.length;
    centraScreenCameras.push(...matches);
    ensureCentraScreenObserver();
    matches.forEach((camera, offset) => {
        const index = startIndex + offset;
        const card = document.createElement('div');
        card.className = 'centra-screen-card';
        card.innerHTML = `<img class="centra-screen-image" src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 9'/%3E" data-src="${_esc(camera.screenshot_url)}" alt="${_esc(camera.title || camera.id)}" loading="lazy"><div class="centra-screen-meta"><strong>${_esc(centraEntrance(camera))} · ${_esc(camera.title || camera.id)}</strong><small>${_esc(camera.id)} · ${_esc(centraCameraType(camera))} · Людей: ${camera.people_count || 1}</small></div>`;
        card.onclick = () => openCentraScreenCamera(index);
        grid.appendChild(card);
        const img = card.querySelector('img');
        if (img && centraScreenObserver) centraScreenObserver.observe(img);
    });
}

async function startCentraPeoplePolling(jobId, allCameras, replaceGrid = allCameras) {
    activeCentraPeopleJobId = jobId;
    localStorage.setItem('ip2domain_centra_people_job', jobId);
    const progress = document.getElementById('centra-people-progress');
    const analyzeBtn = document.getElementById('centra-people-analyze-btn');
    const cancelBtn = document.getElementById('centra-people-cancel-btn');
    if (analyzeBtn) analyzeBtn.disabled = true;
    if (cancelBtn) cancelBtn.style.display = '';
    if (progress) progress.style.display = 'block';
    let matchesCursor = 0;
    if (centraPeoplePoller) clearInterval(centraPeoplePoller);
    centraPeoplePoller = setInterval(async () => {
        try {
            const response = await fetch('/api/cameras/centra/people/active');
            const data = await response.json();
            const job = data?.job;
            if (!job || job.job_id !== jobId || ['completed', 'cancelled', 'error'].includes(job.status)) {
                clearInterval(centraPeoplePoller);
                centraPeoplePoller = null;
                activeCentraPeopleJobId = null;
                localStorage.removeItem('ip2domain_centra_people_job');
                if (analyzeBtn) analyzeBtn.disabled = false;
                if (cancelBtn) cancelBtn.style.display = 'none';
                if (progress) progress.textContent = job?.stage || 'Анализ завершён';
                loadSavedCentraPeopleCount();
                return;
            }
            const resultResponse = await fetch(`/api/cameras/centra/people/${jobId}?matches_from=${matchesCursor}`);
            if (resultResponse.ok) {
                const result = await resultResponse.json();
                if ((result.matches || []).length) {
                    renderCentraPeopleMatches(result, replaceGrid && matchesCursor === 0);
                    matchesCursor = result.matches_total || (matchesCursor + result.matches.length);
                }
            }
            if (progress) {
                const eta = job.eta_seconds ? ` · осталось ≈ ${Math.ceil(job.eta_seconds / 60)} мин.` : '';
                const lastErr = job.last_error ? ` · последняя ошибка: ${job.last_error}` : '';
                progress.textContent = `${job.stage || 'Анализ людей...'} (${job.progress_pct || 0}%)${eta}${lastErr}`;
            }
        } catch (error) {
            if (progress) progress.textContent = error.message;
        }
    }, 2500);
}

async function analyzeCentraScreenPeople(allCameras = false) {
    const type = document.getElementById('centra-screens-type')?.value || '';
    const body = allCameras
        ? {all_cameras: true, camera_type: type}
        : {camera_ids: centraScreenCameras.map((camera) => camera.id).filter(Boolean)};
    if (!allCameras && !body.camera_ids.length) {
        alert('Кадры ещё не загружены');
        return;
    }
    const progress = document.getElementById('centra-people-progress');
    if (progress) {
        progress.style.display = 'block';
        progress.textContent = 'Запуск распознавания людей...';
    }
    try {
        const response = await fetch('/api/cameras/centra/people', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось запустить анализ');
        await startCentraPeoplePolling(data.job_id, allCameras);
    } catch (error) {
        if (progress) progress.textContent = error.message;
    }
}
window.analyzeCentraScreenPeople = analyzeCentraScreenPeople;

async function restoreCentraPeopleAnalysis() {
    try {
        const response = await fetch('/api/cameras/centra/people/active');
        const data = await response.json();
        if (data?.job?.job_id) {
            await startCentraPeoplePolling(data.job.job_id, Boolean(data.job.all_cameras), false);
        }
    } catch (_) {}
}

async function cancelCentraPeopleAnalysis() {
    if (!activeCentraPeopleJobId) return;
    try {
        await fetch(`/api/cameras/centra/people/${activeCentraPeopleJobId}/cancel`, {method:'POST'});
        const progress = document.getElementById('centra-people-progress');
        if (progress) progress.textContent = 'Остановка анализа...';
    } catch (_) {}
}
window.cancelCentraPeopleAnalysis = cancelCentraPeopleAnalysis;

function filterCentraScreensByPeople(range) {
    const cards = document.querySelectorAll('.centra-screen-card');
    cards.forEach((card) => {
        const text = card.querySelector('.centra-screen-meta small')?.textContent || '';
        const match = text.match(/Людей:\s*(\d+)/i);
        const count = match ? Number(match[1]) : 0;
        let visible = true;
        if (range === 'none') visible = count === 0;
        else if (range === 'few') visible = count >= 1 && count <= 2;
        else if (range === 'many') visible = count >= 3;
        card.style.display = visible ? '' : 'none';
    });
}
window.filterCentraScreensByPeople = filterCentraScreensByPeople;

async function resetCentraPersonIdentities() {
    if (!confirm('Сбросить базу распознанных персон и начать сопоставление заново?')) return;
    try {
        const response = await fetch('/api/cameras/centra/people-identities/reset', {method:'POST'});
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось сбросить персоны');
        alert(`База персон очищена (удалено записей: ${data.deleted || 0})`);
        loadSavedCentraPeopleCount();
    } catch (error) {
        alert(error.message);
    }
}
window.resetCentraPersonIdentities = resetCentraPersonIdentities;
