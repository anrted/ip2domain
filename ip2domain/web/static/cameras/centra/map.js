'use strict';

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
    const coordinates = cameraIndexes.map((index) => centraCameras[index].coordinates);
    const unique = new Set(coordinates.map((point) => point.map((value) => Number(value).toFixed(7)).join(',')));
    if (unique.size === 1 || centraMap.getZoom() >= 12) {
        openCentraClusterList(cameraIndexes);
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
    const firstCam = centraCameras[ordered[0]];
    const addr = firstCam?.address ? centraSidebarAddress(firstCam.address) : '';
    const titleText = addr ? `${_esc(addr)} · ${ordered.length} камер` : `Камеры в доме · ${ordered.length}`;
    dialog.innerHTML = `<div class="centra-player-head"><strong>${titleText}</strong><button class="centra-player-close" type="button" onclick="document.getElementById('centra-cluster-dialog').close()" aria-label="Закрыть">×</button></div><div class="centra-cluster-camera-list">${ordered.map((index) => {
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
            hasBalloon: false,
            gridSize: 48,
            maxZoom: 23
        });
        function syncCentraClusterMode() {
            if (!centraMap || !clusterer) return;
            const currentZoom = centraMap.getZoom();
            const targetGroupBy = currentZoom >= 17;
            if (clusterer.options.get('groupByCoordinates') !== targetGroupBy) {
                clusterer.options.set('groupByCoordinates', targetGroupBy);
            }
        }
        centraMap.events.add('boundschange', (event) => {
            if (event.get('newZoom') !== event.get('oldZoom')) {
                syncCentraClusterMode();
            }
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
            centraMap.setBounds(clusterer.getBounds(), {checkZoomRange: true, zoomMargin: 35}).then(() => {
                syncCentraClusterMode();
            });
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
