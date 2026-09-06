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

let _bulkCaptureTimer = null;

async function v2ToggleBulkCapture(btn) {
    try {
        const statusResp = await fetch('/api/v2/bulk_capture/status').then(r => r.json()).catch(() => ({}));
        if (statusResp && statusResp.is_running) {
            await v2StopBulkCapture();
            return;
        }
    } catch (e) {}

    if (!confirm('Запустить массовую проверку потоков и получение превью для камер?\n\nПроцесс выполняется в фоновом режиме с безопасным ограничением (2 потока) и не перегружает сервер.')) {
        return;
    }

    await v2StartBulkCapture(btn);
}
window.v2ToggleBulkCapture = v2ToggleBulkCapture;

async function v2StartBulkCapture(btn) {
    const bar = document.getElementById('v2-bulk-capture-status');
    const textEl = document.getElementById('v2-bulk-capture-text');
    const b = btn || document.getElementById('v2-btn-bulk-capture');

    if (b) {
        b.textContent = '⏹ Остановить';
        b.style.color = '#f87171';
        b.style.borderColor = 'rgba(239,68,68,0.5)';
        b.style.background = 'rgba(239,68,68,0.2)';
    }
    if (bar) bar.style.display = 'flex';
    if (textEl) textEl.textContent = 'Запуск фонового процесса проверки...';

    try {
        const resp = await fetch('/api/v2/bulk_capture/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                concurrency: 2,
                only_unverified: true,
                max_streams_per_cam: 4,
            })
        });
        const data = await resp.json();
        if (!data.success && data.message) {
            _showV2Toast(data.message);
        } else {
            _showV2Toast('✓ Фоновый захват превью запущен');
        }
    } catch (e) {
        console.error('[BulkCapture] Failed to start:', e);
        _showV2Toast('Ошибка запуска фонового процесса');
    }

    _startBulkCapturePolling();
}
window.v2StartBulkCapture = v2StartBulkCapture;

async function v2StopBulkCapture() {
    try {
        await fetch('/api/v2/bulk_capture/stop', { method: 'POST' });
        _showV2Toast('Остановка процесса проверки...');
    } catch (e) {
        console.error('[BulkCapture] Failed to stop:', e);
    }
}
window.v2StopBulkCapture = v2StopBulkCapture;

function _startBulkCapturePolling() {
    if (_bulkCaptureTimer) clearInterval(_bulkCaptureTimer);
    let lastVerifiedCount = 0;

    const poll = async () => {
        try {
            const resp = await fetch('/api/v2/bulk_capture/status');
            if (!resp.ok) return;
            const s = await resp.json();

            const bar = document.getElementById('v2-bulk-capture-status');
            const textEl = document.getElementById('v2-bulk-capture-text');
            const statsEl = document.getElementById('v2-bulk-capture-stats');
            const btn = document.getElementById('v2-btn-bulk-capture');

            if (s.is_running) {
                if (bar) bar.style.display = 'flex';
                if (btn) {
                    btn.textContent = `⏹ Остановить (${s.processed_cameras}/${s.total_cameras})`;
                    btn.style.color = '#f87171';
                    btn.style.borderColor = 'rgba(239,68,68,0.5)';
                    btn.style.background = 'rgba(239,68,68,0.2)';
                }
                if (textEl) {
                    const ipLabel = s.current_ip ? ` • ${s.current_ip}` : '';
                    textEl.textContent = `Камеры: ${s.processed_cameras} / ${s.total_cameras} (потоков: ${s.processed_streams}/${s.total_streams})${ipLabel}`;
                }
                if (statsEl) {
                    statsEl.textContent = `✓ ${s.verified_streams} живых`;
                }

                // If new verified streams discovered, reload list in background
                if (s.verified_streams > lastVerifiedCount) {
                    lastVerifiedCount = s.verified_streams;
                    if (window.v2LoadResults) {
                        window.v2LoadResults(true);
                    }
                }
            } else {
                clearInterval(_bulkCaptureTimer);
                _bulkCaptureTimer = null;

                if (bar) bar.style.display = 'none';
                if (btn) {
                    btn.textContent = '📸 Получить все превью';
                    btn.style.color = '#34d399';
                    btn.style.borderColor = 'rgba(16,185,129,0.45)';
                    btn.style.background = 'rgba(16,185,129,0.2)';
                }

                if (s.processed_cameras > 0) {
                    _showV2Toast(`✓ Обработка завершена! Проверено: ${s.processed_cameras}, живых потоков: ${s.verified_streams}`);
                    if (window.v2LoadResults) {
                        window.v2LoadResults(true);
                    }
                }
            }
        } catch (err) {
            console.warn('[BulkCapture] Poll error:', err);
        }
    };

    poll();
    _bulkCaptureTimer = setInterval(poll, 2000);
}

// Check on page load if bulk capture was already running in background
function v2CheckBulkCaptureOnLoad() {
    fetch('/api/v2/bulk_capture/status')
        .then(r => r.json())
        .then(s => {
            if (s && s.is_running) {
                _startBulkCapturePolling();
            }
        })
        .catch(() => {});
}
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', v2CheckBulkCaptureOnLoad);
} else {
    v2CheckBulkCaptureOnLoad();
}


function _showV2Toast(msg) {
    const toast = document.createElement('div');
    toast.textContent = msg;
    toast.style.cssText = 'position:fixed;bottom:2rem;right:2rem;background:linear-gradient(135deg, #0ea5e9, #0284c7);color:#fff;padding:0.6rem 1.3rem;border-radius:8px;font-size:0.85rem;font-weight:600;z-index:99999;box-shadow:0 6px 25px rgba(0,0,0,0.5);animation:v2-fade-in 0.2s ease';
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

function v2SetFilter(type, value) {
    window.V2State.visibleCount = window.V2State.pageSize || 48;
    if (type === 'status') {
        const cur = window.V2State.filterStatus || 'all';
        window.V2State.filterStatus = (cur === value) ? 'all' : value;
        const activeVal = window.V2State.filterStatus;
        document.getElementById('v2-filter-status-live')?.classList.toggle('active', activeVal === 'live');
        document.getElementById('v2-filter-status-preview')?.classList.toggle('active', activeVal === 'preview');
    } else if (type === 'brand') {
        window.V2State.filterBrand = value;
        if (value === 'all') {
            window.V2State.filterProtocol = 'all';
            window.V2State.filterStatus = 'all';
            document.querySelectorAll('.v2-filter-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById('v2-filter-brand-all')?.classList.add('active');
        } else {
            document.querySelectorAll('.v2-filter-btn[id^="v2-filter-brand-"]').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.value === value);
            });
        }
    } else if (type === 'protocol') {
        window.V2State.filterProtocol = value;
        document.querySelectorAll('.v2-filter-btn[id^="v2-filter-proto-"]').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.value === value);
        });
    }

    const isAll = window.V2State.filterBrand === 'all' &&
                  window.V2State.filterProtocol === 'all' &&
                  (!window.V2State.filterStatus || window.V2State.filterStatus === 'all');
    document.getElementById('v2-filter-brand-all')?.classList.toggle('active', isAll);

    if (window.v2RenderResults) v2RenderResults();
}
window.v2SetFilter = v2SetFilter;

function v2SetGeoFilter(val) {
    window.V2State.visibleCount = window.V2State.pageSize || 48;
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
    window.V2State.visibleCount = window.V2State.pageSize || 48;
    window.V2State.geoSearch = val;
    _updateGeoClearBtn();
    if (window.v2RenderResults) v2RenderResults();
}
window.v2SetGeoSearch = v2SetGeoSearch;

function v2ClearGeoFilter() {
    window.V2State.visibleCount = window.V2State.pageSize || 48;
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
