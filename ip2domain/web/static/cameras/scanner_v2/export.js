'use strict';
// ── Camera Scanner v2: Export, Go2rtc Sync, Filtering & Helpers ────────

async function v2AddToGo2rtc(ip) {
    const streamUrl = window.V2State.selectedStreams[ip];
    if (!streamUrl) {
        alert('Нет выбранного RTSP URL для добавления');
        return;
    }
    const safeIp = ip.replace(/\./g, '_');
    const streamName = `v2_${safeIp}_1`;
    try {
        const resp = await fetch(`/api/v2/results/${ip}/go2rtc?stream_url=${encodeURIComponent(streamUrl)}&stream_name=${encodeURIComponent(streamName)}`, {
            method: 'POST',
        });
        const data = await resp.json();
        if (data.success) {
            const btn = document.getElementById(`v2-go2rtc-${safeIp}`);
            if (btn) {
                btn.textContent = '✓ go2rtc';
                btn.classList.add('added');
            }
        } else {
            alert('Не удалось добавить в go2rtc: ' + JSON.stringify(data));
        }
    } catch (e) {
        alert('Ошибка: ' + e.message);
    }
}
window.v2AddToGo2rtc = v2AddToGo2rtc;

async function v2AddSpecificStreamToGo2rtc(ip, streamUrl, channelIdx) {
    const safeIp = ip.replace(/\./g, '_');
    const streamName = `v2_${safeIp}_ch${channelIdx}`;
    try {
        const resp = await fetch(`/api/v2/results/${ip}/go2rtc?stream_url=${encodeURIComponent(streamUrl)}&stream_name=${encodeURIComponent(streamName)}`, {
            method: 'POST',
        });
        const data = await resp.json();
        if (data.success) {
            alert(`Поток #${channelIdx} (${streamName}) успешно добавлен в go2rtc!`);
        } else {
            alert('Ошибка добавления: ' + JSON.stringify(data));
        }
    } catch (e) {
        alert('Ошибка сети: ' + e.message);
    }
}
window.v2AddSpecificStreamToGo2rtc = v2AddSpecificStreamToGo2rtc;

async function v2ExportAllToGo2rtc() {
    const cameras = (window.V2State.results || []).filter(c => !c.in_go2rtc);
    if (!cameras.length) {
        alert('Все камеры уже добавлены в go2rtc или результатов нет');
        return;
    }
    if (!confirm(`Добавить ${cameras.length} камер в go2rtc?`)) return;

    let success = 0;
    for (const cam of cameras) {
        const streamUrl = window.V2State.selectedStreams[cam.ip] || cam.streams?.[0]?.url;
        if (streamUrl) {
            try {
                const safeIp = cam.ip.replace(/\./g, '_');
                const resp = await fetch(`/api/v2/results/${cam.ip}/go2rtc?stream_url=${encodeURIComponent(streamUrl)}&stream_name=v2_${safeIp}_1`, {
                    method: 'POST',
                });
                if ((await resp.json()).success) success++;
            } catch (e) {}
        }
    }
    alert(`Добавлено ${success} из ${cameras.length} камер`);
    if (window.v2LoadStoredResults) v2LoadStoredResults();
}
window.v2ExportAllToGo2rtc = v2ExportAllToGo2rtc;

function v2CopySelectedUrl(ip) {
    const url = window.V2State.selectedStreams[ip];
    if (!url) { alert('URL недоступен'); return; }
    v2CopyUrl(url);
}
window.v2CopySelectedUrl = v2CopySelectedUrl;

function v2CopyUrl(url) {
    if (!url) { alert('URL недоступен'); return; }
    navigator.clipboard.writeText(url).then(() => {
        const toast = document.createElement('div');
        toast.textContent = 'URL скопирован в буфер';
        toast.style.cssText = 'position:fixed;bottom:2rem;right:2rem;background:#10b981;color:#fff;padding:0.55rem 1.2rem;border-radius:8px;font-size:0.8rem;font-weight:600;z-index:99999;box-shadow:0 4px 20px rgba(0,0,0,0.4);animation:v2-fade-in 0.2s ease';
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 2200);
    });
}
window.v2CopyUrl = v2CopyUrl;

function v2ShowDetails(ip) {
    const cam = (window.V2State.results || []).find(c => c.ip === ip);
    if (!cam) return;
    if (window.v2OpenStreamModal) v2OpenStreamModal(ip);
}
window.v2ShowDetails = v2ShowDetails;

function v2ExportJson() {
    const json = JSON.stringify(window.V2State.results, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `v2_cameras_${Date.now()}.json`;
    a.click();
}
window.v2ExportJson = v2ExportJson;

async function v2ClearResults() {
    if (!confirm('Удалить все результаты v2 из базы данных?')) return;
    await fetch('/api/v2/results', { method: 'DELETE' });
    window.V2State.results = [];
    if (window.v2RenderResults) v2RenderResults();
    if (window.v2UpdateResultsCount) v2UpdateResultsCount();
}
window.v2ClearResults = v2ClearResults;

async function v2ResolveAllGeo(btn) {
    if (!window.V2State.results || !window.V2State.results.length) {
        alert('Сначала выполните сканирование или загрузите список камер.');
        return;
    }

    const origText = btn ? btn.textContent : '';
    if (btn) {
        btn.disabled = true;
        btn.textContent = '⏳ Определение...';
    }

    let updatedCount = 0;

    // 1. Try server-side endpoint first
    try {
        const resp = await fetch('/api/v2/resolve_geo', { method: 'POST' });
        if (resp.ok) {
            const data = await resp.json();
            if (data.results && data.results.length) {
                window.V2State.results = data.results;
                if (window.v2RenderResults) v2RenderResults();
                _showV2Toast(`✓ Геолокация определена для ${data.updated_count || data.results.length} камер!`);
                if (btn) {
                    btn.disabled = false;
                    btn.textContent = origText;
                }
                return;
            }
        }
    } catch (e) {
        console.warn('[v2] Server geo endpoint unavailable, using live lookup fallback:', e);
    }

    // 2. Client-side parallel batch resolution via /api/geo/lookup?ip=...
    const cams = window.V2State.results;
    const batchSize = 10;
    for (let i = 0; i < cams.length; i += batchSize) {
        const chunk = cams.slice(i, i + batchSize);
        await Promise.all(chunk.map(async (cam) => {
            try {
                const r = await fetch(`/api/geo/lookup?ip=${encodeURIComponent(cam.ip)}`);
                if (r.ok) {
                    const j = await r.json();
                    if (j.found && j.data) {
                        cam.city = j.data.city || '';
                        cam.region = j.data.region || '';
                        cam.country_code = j.data.country_code || '';
                        cam.isp = j.data.isp || '';
                        if (cam.city) updatedCount++;
                    }
                }
            } catch (err) {}
        }));
        if (window.v2RenderResults) v2RenderResults();
    }

    _showV2Toast(`✓ Геолокация определена для ${updatedCount} из ${cams.length} камер!`);
    if (btn) {
        btn.disabled = false;
        btn.textContent = origText;
    }
}
window.v2ResolveAllGeo = v2ResolveAllGeo;

function _showV2Toast(msg) {
    const toast = document.createElement('div');
    toast.textContent = msg;
    toast.style.cssText = 'position:fixed;bottom:2rem;right:2rem;background:linear-gradient(135deg, #0ea5e9, #0284c7);color:#fff;padding:0.6rem 1.3rem;border-radius:8px;font-size:0.85rem;font-weight:600;z-index:99999;box-shadow:0 6px 25px rgba(0,0,0,0.5);animation:v2-fade-in 0.2s ease';
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

function v2SetFilter(type, value) {
    window.V2State[type === 'brand' ? 'filterBrand' : 'filterProtocol'] = value;
    const prefix = type === 'brand' ? 'v2-filter-brand-' : 'v2-filter-proto-';
    document.querySelectorAll(`.v2-filter-btn[id^="${prefix}"]`).forEach(btn => {
        btn.classList.toggle('active', btn.dataset.value === value);
    });
    if (window.v2RenderResults) v2RenderResults();
}
window.v2SetFilter = v2SetFilter;

function v2SetGeoFilter(val) {
    window.V2State.filterGeo = val;
    const select = document.getElementById('v2-filter-geo');
    if (select && select.value !== val) {
        select.value = val;
    }
    _updateGeoClearBtn();
    if (window.v2RenderResults) v2RenderResults();
}
window.v2SetGeoFilter = v2SetGeoFilter;

function v2SetGeoSearch(val) {
    window.V2State.geoSearch = val;
    _updateGeoClearBtn();
    if (window.v2RenderResults) v2RenderResults();
}
window.v2SetGeoSearch = v2SetGeoSearch;

function v2ClearGeoFilter() {
    window.V2State.filterGeo = 'all';
    window.V2State.geoSearch = '';
    const select = document.getElementById('v2-filter-geo');
    if (select) select.value = 'all';
    const searchInput = document.getElementById('v2-geo-search-input');
    if (searchInput) searchInput.value = '';
    _updateGeoClearBtn();
    if (window.v2RenderResults) v2RenderResults();
}
window.v2ClearGeoFilter = v2ClearGeoFilter;

function _updateGeoClearBtn() {
    const btn = document.getElementById('v2-geo-clear-btn');
    if (!btn) return;
    const hasActive = (window.V2State.filterGeo && window.V2State.filterGeo !== 'all') || (window.V2State.geoSearch && window.V2State.geoSearch.trim().length > 0);
    btn.style.display = hasActive ? 'block' : 'none';
}

function _esc(str) {
    if (!str && str !== 0) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
window._esc = _esc;

if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
        if (window.v2LoadTools) v2LoadTools();
        if (window.v2RenderCredentials) v2RenderCredentials();
        if (window.v2LoadStoredResults) v2LoadStoredResults();

        const savedVersion = localStorage.getItem('ip2domain_cam_version');
        if (savedVersion === 'v2') {
            setTimeout(() => {
                const v2Btn = document.getElementById('cam-ver-btn-v2');
                if (v2Btn && window.switchCameraVersion) {
                    switchCameraVersion('v2');
                }
            }, 50);
        }
    });
}

function v2CheckVersionOnTabOpen() {
    const savedVersion = localStorage.getItem('ip2domain_cam_version');
    if (savedVersion === 'v2') {
        if (window.switchCameraVersion) switchCameraVersion('v2');
    } else {
        if (window.v2LoadStoredResults) v2LoadStoredResults();
    }
}
window.v2CheckVersionOnTabOpen = v2CheckVersionOnTabOpen;
