'use strict';

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
