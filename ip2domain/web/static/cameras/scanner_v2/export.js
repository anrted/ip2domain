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

function v2Export401() {
    window.open('/api/v2/export/401?format=txt', '_blank');
}
window.v2Export401 = v2Export401;

// ── RTSP Brute Force Modal & Real-time Runner ───────────────────────
let _v2BruterPollTimer = null;

function v2OpenBruterModal() {
    document.getElementById('v2-bruter-modal-overlay')?.remove();

    const cameras401 = (window.V2State.results || []).filter(window._isCam401 || (c => c.auth_required));
    const count401 = cameras401.length;

    const overlay = document.createElement('div');
    overlay.className = 'v2-modal-overlay';
    overlay.id = 'v2-bruter-modal-overlay';
    overlay.onclick = (e) => { if (e.target === overlay) v2CloseBruterModal(); };

    const defaultUsers = 'admin\nroot\nservice\nuser\noperator\nviewer';
    const defaultPass = '\nadmin\n12345\n123456\n12345678\nadmin123\nadmin12345\n12345admin\nroot\npass\npassword\nservice\n1111\n666666';

    overlay.innerHTML = `
        <div class="v2-modal-content" style="max-width:760px">
            <div class="v2-modal-header">
                <div class="v2-modal-title">
                    <span>🔨</span>
                    <span>RTSP Brute Force (/root/rtspBruter)</span>
                </div>
                <button class="v2-modal-close" onclick="v2CloseBruterModal()">✕</button>
            </div>
            <div class="v2-modal-body" style="padding:1.25rem;display:flex;flex-direction:column;gap:1rem;overflow-y:auto;max-height:calc(85vh - 70px);">
                <!-- Target Summary -->
                <div style="background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.35);padding:10px 14px;border-radius:8px;font-size:0.85rem;color:#fde68a;display:flex;align-items:center;justify-content:space-between">
                    <div>
                        <strong>🎯 Камеры для подбора:</strong>
                        <span>${count401 > 0 ? `${count401} камер с 401 в результатах` : 'Все камеры с ошибкой 401 из базы'}</span>
                    </div>
                    <button class="v2-btn-small" onclick="v2Export401()" title="Скачать targets.txt для ручного запуска">⬇ Скачать targets.txt</button>
                </div>

                <!-- Wordlists and Settings -->
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
                    <div>
                        <label style="display:block;font-size:0.75rem;font-weight:600;color:#94a3b8;margin-bottom:4px">Логины (один на строку):</label>
                        <textarea id="v2-brute-users" style="width:100%;height:100px;background:#020617;border:1px solid rgba(255,255,255,0.12);border-radius:6px;color:#e2e8f0;font-size:0.75rem;font-family:monospace;padding:6px;resize:none">${defaultUsers}</textarea>
                    </div>
                    <div>
                        <label style="display:block;font-size:0.75rem;font-weight:600;color:#94a3b8;margin-bottom:4px">Пароли (первая пустая = без пароля):</label>
                        <textarea id="v2-brute-passwords" style="width:100%;height:100px;background:#020617;border:1px solid rgba(255,255,255,0.12);border-radius:6px;color:#e2e8f0;font-size:0.75rem;font-family:monospace;padding:6px;resize:none">${defaultPass}</textarea>
                    </div>
                </div>

                <!-- Threads & Options -->
                <div style="display:flex;align-items:center;gap:16px;font-size:0.8rem;color:#cbd5e1">
                    <div style="display:flex;align-items:center;gap:8px">
                        <span>Потоков (Threads):</span>
                        <input type="number" id="v2-brute-threads" value="50" min="1" max="200" style="width:70px;background:#020617;border:1px solid rgba(255,255,255,0.12);color:#e2e8f0;padding:4px 8px;border-radius:4px;font-size:0.8rem">
                    </div>
                    <div style="color:rgba(255,255,255,0.45);font-size:0.75rem">
                        ✓ При успехе пароль сохраняется в базу и автоматически захватывается превью!
                    </div>
                </div>

                <!-- Action buttons -->
                <div style="display:flex;align-items:center;gap:10px;margin-top:4px">
                    <button class="v2-btn-small" id="v2-btn-start-brute" style="background:linear-gradient(135deg, #10b981, #059669);color:#fff;font-weight:600;padding:6px 14px" onclick="v2StartBruter()">▶ Запустить брутфорс</button>
                    <button class="v2-btn-small v2-btn-danger" id="v2-btn-stop-brute" style="display:none;padding:6px 14px" onclick="v2StopBruter()">⏹ Остановить</button>
                    <span id="v2-brute-status-indicator" style="font-size:0.8rem;color:#94a3b8;margin-left:auto">Готов к запуску</span>
                </div>

                <!-- Terminal / Console Log -->
                <div>
                    <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                        <span style="font-size:0.75rem;font-weight:600;color:#94a3b8">Лог работы rtspBrute:</span>
                        <span id="v2-brute-cracked-stats" style="font-size:0.75rem;color:#4ade80;font-weight:600">✓ Подобрано: 0</span>
                    </div>
                    <div class="v2-bruter-console" id="v2-bruter-log">Ожидание запуска задачи...</div>
                </div>

                <!-- Cracked cameras list -->
                <div id="v2-bruter-cracked-section" style="display:none">
                    <div style="font-size:0.75rem;font-weight:700;color:#4ade80;margin-bottom:6px">Успешно подобраны пароли:</div>
                    <div id="v2-bruter-cracked-list" style="display:flex;flex-direction:column;gap:6px;max-height:140px;overflow-y:auto"></div>
                </div>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);
    v2CheckBruterStatusOnOpen();
}
window.v2OpenBruterModal = v2OpenBruterModal;

function v2CloseBruterModal() {
    if (_v2BruterPollTimer) {
        clearInterval(_v2BruterPollTimer);
        _v2BruterPollTimer = null;
    }
    document.getElementById('v2-bruter-modal-overlay')?.remove();
}
window.v2CloseBruterModal = v2CloseBruterModal;

async function v2CheckBruterStatusOnOpen() {
    try {
        const resp = await fetch('/api/v2/bruter/status');
        if (!resp.ok) return;
        const data = await resp.json();
        v2UpdateBruterUI(data);
        if (data.is_running) {
            _v2StartBruterPolling();
        }
    } catch (e) {}
}

function _v2StartBruterPolling() {
    if (_v2BruterPollTimer) clearInterval(_v2BruterPollTimer);
    _v2BruterPollTimer = setInterval(async () => {
        try {
            const resp = await fetch('/api/v2/bruter/status');
            if (!resp.ok) return;
            const data = await resp.json();
            v2UpdateBruterUI(data);
            if (!data.is_running) {
                clearInterval(_v2BruterPollTimer);
                _v2BruterPollTimer = null;
                // Reload stored results to show updated cracked cameras
                if (window.v2LoadStoredResults) v2LoadStoredResults(true);
            }
        } catch (e) {}
    }, 1500);
}

function v2UpdateBruterUI(data) {
    const startBtn = document.getElementById('v2-btn-start-brute');
    const stopBtn = document.getElementById('v2-btn-stop-brute');
    const indicator = document.getElementById('v2-brute-status-indicator');
    const logBox = document.getElementById('v2-bruter-log');
    const crackedStats = document.getElementById('v2-brute-cracked-stats');
    const crackedSec = document.getElementById('v2-bruter-cracked-section');
    const crackedList = document.getElementById('v2-bruter-cracked-list');

    if (startBtn && stopBtn) {
        startBtn.style.display = data.is_running ? 'none' : 'inline-block';
        stopBtn.style.display = data.is_running ? 'inline-block' : 'none';
    }

    if (indicator) {
        if (data.is_running) {
            indicator.innerHTML = `<span style="color:#34d399;font-weight:600">⚡ Выполняется... (${data.elapsed_seconds || 0}с, целей: ${data.total_targets})</span>`;
        } else if (data.status === 'finished') {
            indicator.innerHTML = `<span style="color:#4ade80;font-weight:600">✓ Завершено (Взломано: ${data.cracked_count})</span>`;
        } else if (data.status === 'stopped') {
            indicator.innerHTML = `<span style="color:#f87171">⏹ Остановлено</span>`;
        } else if (data.status === 'error') {
            indicator.innerHTML = `<span style="color:#f87171">⚠️ Ошибка: ${_esc(data.error || 'unknown')}</span>`;
        }
    }

    if (crackedStats) {
        crackedStats.textContent = `✓ Подобрано: ${data.cracked_count || 0}`;
    }

    if (logBox && data.logs && data.logs.length) {
        logBox.textContent = data.logs.join('\n');
        logBox.scrollTop = logBox.scrollHeight;
    }

    if (crackedSec && crackedList && data.cracked_cameras && data.cracked_cameras.length) {
        crackedSec.style.display = 'block';
        crackedList.innerHTML = data.cracked_cameras.map(c => `
            <div style="background:rgba(16,185,129,0.15);border:1px solid rgba(16,185,129,0.3);padding:6px 10px;border-radius:6px;display:flex;align-items:center;justify-content:space-between;font-size:0.75rem">
                <div>
                    <strong style="color:#e2e8f0">${_esc(c.ip)}:${c.port}</strong>
                    <span style="color:#34d399;margin-left:8px;font-weight:600">🔑 ${_esc(c.user || 'none')}:${_esc(c.password || '')}</span>
                </div>
                <button class="v2-btn-small" onclick="v2CloseBruterModal();v2OpenSelectedStreamPlayer('${_esc(c.ip)}')" style="padding:2px 8px;font-size:0.7rem">▶ Просмотр</button>
            </div>
        `).join('');
    }
}

async function v2StartBruter() {
    const usersTxt = document.getElementById('v2-brute-users')?.value || '';
    const passTxt = document.getElementById('v2-brute-passwords')?.value || '';
    const threads = parseInt(document.getElementById('v2-brute-threads')?.value || '50', 10);

    const usernames = usersTxt.split('\n').map(u => u.trim()).filter(Boolean);
    const passwords = passTxt.split('\n');

    try {
        const resp = await fetch('/api/v2/bruter/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                usernames: usernames,
                passwords: passwords,
                threads: threads,
            }),
        });
        const data = await resp.json();
        if (data.started) {
            _showV2Toast(`Запущен подбор паролей для ${data.total_targets} камер!`);
            _v2StartBruterPolling();
        } else {
            alert(data.message || 'Не удалось запустить брутфорс');
        }
    } catch (e) {
        alert('Ошибка запуска: ' + e.message);
    }
}
window.v2StartBruter = v2StartBruter;

async function v2StopBruter() {
    try {
        await fetch('/api/v2/bruter/stop', { method: 'POST' });
        _showV2Toast('Остановка процесса брутфорса...');
    } catch (e) {}
}
window.v2StopBruter = v2StopBruter;

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
                max_streams_per_cam: 0,
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
    } else if (type === 'auth') {
        const cur = window.V2State.filterAuth || 'all';
        window.V2State.filterAuth = (cur === value) ? 'all' : value;
        const activeVal = window.V2State.filterAuth;
        document.getElementById('v2-filter-auth-open')?.classList.toggle('active', activeVal === 'open');
        document.getElementById('v2-filter-auth-401')?.classList.toggle('active', activeVal === '401');
    } else if (type === 'brand') {
        window.V2State.filterBrand = value;
        if (value === 'all') {
            window.V2State.filterProtocol = 'all';
            window.V2State.filterStatus = 'all';
            window.V2State.filterAuth = 'all';
            document.querySelectorAll('.v2-filter-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById('v2-filter-brand-all')?.classList.add('active');
            document.getElementById('v2-filter-auth-open')?.classList.remove('active');
            document.getElementById('v2-filter-auth-401')?.classList.remove('active');
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
                  (!window.V2State.filterStatus || window.V2State.filterStatus === 'all') &&
                  (!window.V2State.filterAuth || window.V2State.filterAuth === 'all');
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
