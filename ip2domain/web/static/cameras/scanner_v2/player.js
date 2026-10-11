'use strict';
// ── Camera Scanner v2: Stream Modal & Video Player Dialog ──────────────

if (typeof window._esc !== 'function') {
    window._esc = function(str) {
        if (str == null) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    };
}
if (typeof window._protoBadgeClass !== 'function') {
    window._protoBadgeClass = function(p) {
        if (!p) return 'generic';
        p = p.toLowerCase();
        if (p.includes('onvif')) return 'onvif';
        if (p.includes('hikvision')) return 'hikvision';
        if (p.includes('dahua')) return 'dahua';
        if (p.includes('axis')) return 'axis';
        if (p.includes('hls')) return 'hls';
        if (p.includes('mjpeg')) return 'mjpeg';
        if (p.includes('rtmp')) return 'rtmp';
        if (p.includes('rtsp')) return 'rtsp';
        return 'generic';
    };
}
if (typeof window.v2CopyUrl !== 'function') {
    window.v2CopyUrl = function(url) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(url).then(() => {
                _showStreamToast('✓ URL потока скопирован');
            }).catch(() => _fallbackCopy(url));
        } else {
            _fallbackCopy(url);
        }
        function _fallbackCopy(text) {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            ta.remove();
            _showStreamToast('✓ URL скопирован');
        }
        function _showStreamToast(msg) {
            const toast = document.createElement('div');
            toast.textContent = msg;
            toast.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:rgba(16,185,129,0.95);color:#fff;padding:8px 16px;border-radius:8px;font-size:13px;z-index:999999;box-shadow:0 4px 12px rgba(0,0,0,0.3);';
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 2500);
        }
    };
}
if (typeof window.v2AddSpecificStreamToGo2rtc !== 'function') {
    window.v2AddSpecificStreamToGo2rtc = async function(ip, streamUrl, channelIdx) {
        const safeIp = ip.replace(/\./g, '_');
        const streamName = `v2_${safeIp}_ch${channelIdx}`;
        try {
            const isHttp = streamUrl.startsWith('http://') || streamUrl.startsWith('https://');
            const urls = isHttp ? [streamUrl] : [streamUrl, `ffmpeg:${streamUrl}#video=copy`];
            const resp = await fetch("/api/go2rtc/streams", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    name: streamName,
                    url: urls
                })
            });
            if (resp.ok) {
                alert(`Поток #${channelIdx} (${streamName}) успешно добавлен в go2rtc!`);
            } else {
                const data = await resp.json().catch(() => ({}));
                alert('Ошибка добавления: ' + (data.detail || resp.statusText));
            }
        } catch (e) {
            alert('Ошибка сети: ' + e.message);
        }
    };
}

window._v2LiveSnapshotTimer = null;

function v2ToggleLiveSnapshot(ip, streamUrl) {
    const badge = document.getElementById('v2-modal-live-badge');
    const toggleBtn = document.getElementById('v2-modal-live-toggle');
    if (window._v2LiveSnapshotTimer) {
        clearInterval(window._v2LiveSnapshotTimer);
        window._v2LiveSnapshotTimer = null;
        if (badge) {
            badge.style.color = '#94a3b8';
            badge.innerHTML = '⏸ На паузе';
        }
        if (toggleBtn) {
            toggleBtn.style.borderColor = 'rgba(255,255,255,0.2)';
            toggleBtn.style.background = 'rgba(255,255,255,0.08)';
            toggleBtn.textContent = '▶ Запуск';
        }
    } else {
        if (badge) {
            badge.style.color = '#10b981';
            badge.innerHTML = '🟢 Realtime Live';
        }
        if (toggleBtn) {
            toggleBtn.style.borderColor = '#10b981';
            toggleBtn.style.background = 'rgba(16,185,129,0.2)';
            toggleBtn.textContent = '⏸ Пауза';
        }
        v2RefreshSingleSnapshot(ip, streamUrl);
        window._v2LiveSnapshotTimer = setInterval(() => {
            v2RefreshSingleSnapshot(ip, streamUrl);
        }, 1200);
    }
}
window.v2ToggleLiveSnapshot = v2ToggleLiveSnapshot;

function v2RefreshSingleSnapshot(ip, streamUrl) {
    const img = document.getElementById('v2-modal-live-img');
    const err = document.getElementById('v2-modal-live-err');
    if (img) {
        const userInput = document.getElementById('v2-player-user-input')?.value.trim();
        const passInput = document.getElementById('v2-player-pass-input')?.value;
        const cam = (window.V2State.results || []).find(c => c.ip === ip);
        const u = (userInput !== undefined && userInput !== '') ? userInput : (cam?.credentials?.user || '');
        const p = (passInput !== undefined && passInput !== '') ? passInput : (cam?.credentials?.password ?? '');
        let nextUrl = `/api/v2/preview?ip=${encodeURIComponent(ip)}&stream_url=${encodeURIComponent(streamUrl)}&_t=${Date.now()}`;
        if (u) {
            nextUrl += `&user=${encodeURIComponent(u)}&password=${encodeURIComponent(p)}`;
        }
        const testImg = new Image();
        testImg.onload = () => {
            img.src = nextUrl;
            img.style.display = '';
            if (err) err.style.display = 'none';
        };
        testImg.onerror = () => {
            if (err && !img.complete) err.style.display = 'flex';
        };
        testImg.src = nextUrl;
    }
}
window.v2RefreshSingleSnapshot = v2RefreshSingleSnapshot;

function v2OpenStreamModal(ip) {
    const cam = (window.V2State.results || []).find(c => c.ip === ip);
    if (!cam) return;

    document.getElementById('v2-stream-modal-overlay')?.remove();

    const streams = cam.streams || [];
    const overlay = document.createElement('div');
    overlay.className = 'v2-modal-overlay';
    overlay.id = 'v2-stream-modal-overlay';
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

    overlay.innerHTML = `
        <div class="v2-modal-content">
            <div class="v2-modal-header">
                <div class="v2-modal-title">
                    <span>🎥</span>
                    <span>Потоки камеры ${cam.ip} (${cam.brand || 'Unknown'})</span>
                    <span class="v2-stream-count-badge">${streams.filter(s => s.verified).length} подтверждено · ${streams.length} URL</span>
                </div>
                <button class="v2-modal-close" onclick="document.getElementById('v2-stream-modal-overlay').remove()">✕</button>
            </div>
            <div class="v2-modal-search">
                <input type="text" id="v2-modal-search-input" placeholder="Поиск по URL или типу потока (например: h264, ch1, main, rtsp)..."
                    oninput="v2FilterModalStreams('${_esc(cam.ip)}', this.value)">
            </div>
            <div class="v2-modal-body" id="v2-modal-stream-list">
                ${_renderModalStreamItems(cam, streams)}
            </div>
        </div>
    `;

    document.body.appendChild(overlay);
    document.getElementById('v2-modal-search-input')?.focus();
}
window.v2OpenStreamModal = v2OpenStreamModal;

function _renderModalStreamItems(cam, streams) {
    if (!streams.length) {
        return '<div style="text-align:center;padding:2rem;color:rgba(255,255,255,0.4)">Потоки не найдены</div>';
    }

    return streams.map((s, idx) => {
        const type = (s.type || s.stream_type || 'rtsp').toUpperCase();
        const verBadge = s.verified ? '<span class="v2-verified-badge" style="position:static;display:inline-block;padding:0.1rem 0.35rem;font-size:0.55rem">✓ Live</span>' : '';
        const source = (cam.endpoints || []).find(e => e.port === s.source_port);
        const sourceLabel = source ? `${source.brand || ''} ${source.model || ''} · порт ${source.port}` : '';
        const resText = s.resolution ? `<span style="color:rgba(255,255,255,0.4);font-size:0.65rem">${s.resolution}</span>` : '';

        return `
            <div class="v2-stream-item">
                <div style="display:flex;align-items:center;gap:0.5rem;flex:1;min-width:0">
                    <span style="font-size:0.7rem;color:rgba(255,255,255,0.3);min-width:28px">#${idx + 1}</span>
                    <span class="v2-proto-badge ${_protoBadgeClass(type.toLowerCase())}">${type}</span>
                    ${s.screenshot ? `<img loading="lazy" width="96" height="54" style="object-fit:contain" src="${_esc(s.screenshot.startsWith('blob:') ? s.screenshot : '/api/v2/capture?path=' + encodeURIComponent(s.screenshot))}" alt="Кадр потока ${idx + 1}">` : ''}
                    <span class="v2-stream-item-url" title="${_esc(s.url)}">${_esc(s.url)}</span>
                    ${verBadge} ${resText}
                    ${sourceLabel ? `<small>${_esc(sourceLabel)}</small>` : ''}
                </div>
                <div class="v2-stream-item-actions">
                    <button class="v2-btn-small" style="background:rgba(99,102,241,0.25);color:#c4b5fd;border:1px solid rgba(99,102,241,0.5);font-weight:600" onclick="v2OpenStreamPlayer('${_esc(s.url)}', '${_esc(cam.brand || cam.ip)}', '${_esc(cam.ip)}', ${idx})" title="Тест потока в реальном времени (WebRTC / MSE плеер)">▶ Тест</button>
                    <button class="v2-btn-small" onclick="v2CopyUrl('${_esc(s.url)}')" title="Скопировать URL">📋 Копировать</button>
                    <button class="v2-btn-small v2-btn-green" onclick="v2CaptureFromModal('${_esc(cam.ip)}', '${_esc(s.url)}', this)">📸 Превью</button>
                    <button class="v2-btn-small" onclick="v2AddSpecificStreamToGo2rtc('${_esc(cam.ip)}', '${_esc(s.url)}', ${idx + 1})">+ go2rtc</button>
                </div>
            </div>
        `;
    }).join('');
}

function v2FilterModalStreams(ip, query) {
    const cam = (window.V2State.results || []).find(c => c.ip === ip);
    if (!cam) return;
    const list = document.getElementById('v2-modal-stream-list');
    if (!list) return;

    const q = (query || '').toLowerCase().trim();
    const filtered = (cam.streams || []).filter(s => (s.url || '').toLowerCase().includes(q) || (s.type || s.stream_type || '').toLowerCase().includes(q));
    list.innerHTML = _renderModalStreamItems(cam, filtered);
}
window.v2FilterModalStreams = v2FilterModalStreams;

async function v2CaptureFromModal(ip, streamUrl, btn) {
    const origText = btn.textContent;
    btn.textContent = '⏳...';
    btn.disabled = true;
    window.V2State.selectedStreams[ip] = streamUrl;
    const ok = window.v2CapturePreview ? await v2CapturePreview(ip) : false;
    btn.textContent = ok ? '✓ Кадр получен' : 'Нет кадра';
    setTimeout(() => { btn.textContent = origText; btn.disabled = false; }, 2000);
}
window.v2CaptureFromModal = v2CaptureFromModal;

function v2OpenSelectedStreamPlayer(ip) {
    const cam = (window.V2State.results || []).find(c => c.ip === ip);
    if (!cam) return;
    if (_isSpRecord(cam)) {
        v2OpenSpRecordPlayer(ip);
        return;
    }
    if (!cam.streams || !cam.streams.length) return;
    let streamUrl = window.V2State.selectedStreams[ip] || '';
    if (!streamUrl || streamUrl.startsWith('ws://') || streamUrl.includes('.jpg') || streamUrl.includes('.jpeg') || streamUrl.includes('snapshot')) {
        const playable = cam.streams.find(s => (s.url || '').startsWith('rtsp://') || (s.url || '').startsWith('rtmp://') || (s.url || '').includes('.mjpg') || (s.url || '').includes('video.cgi') || (s.url || '').includes('.m3u8'));
        if (playable) {
            streamUrl = playable.url;
        } else {
            streamUrl = cam.streams[0].url;
        }
    }
    const idx = (cam.streams || []).findIndex(s => s.url === streamUrl);
    v2OpenStreamPlayer(streamUrl, cam.brand || cam.ip, ip, idx >= 0 ? idx : 0);
}
window.v2OpenSelectedStreamPlayer = v2OpenSelectedStreamPlayer;

async function v2OpenStreamPlayer(srcUrl, camName, ip, currentIdx = 0) {
    if (!srcUrl) return;

    const cam = (window.V2State.results || []).find(c => c.ip === ip);
    const streams = cam?.streams || [];
    const totalStreams = streams.length;

    let dialog = document.getElementById('v2-player-dialog');
    if (!dialog) {
        dialog = document.createElement('dialog');
        dialog.id = 'v2-player-dialog';
        dialog.className = 'centra-player-dialog';
        dialog.style.maxWidth = '940px';
        dialog.style.width = '94vw';
        dialog.style.background = '#0f172a';
        dialog.style.color = '#f8fafc';
        dialog.style.borderRadius = '16px';
        dialog.style.border = '1px solid rgba(255,255,255,0.15)';
        dialog.style.padding = '0';
        dialog.style.overflow = 'hidden';
        dialog.style.boxShadow = '0 25px 50px -12px rgba(0, 0, 0, 0.7)';

        dialog.addEventListener('close', async () => {
            if (window._v2LiveSnapshotTimer) {
                clearInterval(window._v2LiveSnapshotTimer);
                window._v2LiveSnapshotTimer = null;
            }
            const tempName = dialog.dataset.tempStreamName;
            if (tempName) {
                fetch(`/api/go2rtc/streams/${encodeURIComponent(tempName)}`, { method: "DELETE" }).catch(() => {});
                delete dialog.dataset.tempStreamName;
            }
            const iframe = dialog.querySelector('iframe');
            if (iframe) iframe.src = 'about:blank';
        });
        dialog.addEventListener('click', (event) => {
            if (event.target === dialog) dialog.close();
        });
        document.body.appendChild(dialog);
    }

    const prevTempName = dialog.dataset.tempStreamName;
    if (prevTempName) {
        fetch(`/api/go2rtc/streams/${encodeURIComponent(prevTempName)}`, { method: "DELETE" }).catch(() => {});
    }

    const tempName = `temp_v2_${Date.now()}`;
    dialog.dataset.tempStreamName = tempName;

    const prevIdx = (currentIdx - 1 + totalStreams) % totalStreams;
    const nextIdx = (currentIdx + 1) % totalStreams;
    const prevStream = totalStreams > 1 ? streams[prevIdx] : null;
    const nextStream = totalStreams > 1 ? streams[nextIdx] : null;

    dialog.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; gap: 0.75rem; padding: 0.85rem 1.2rem; background: rgba(15,23,42,0.95); border-bottom: 1px solid rgba(255,255,255,0.1);">
            <div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <span style="font-size:1.1rem">🎥</span>
                    <strong style="font-size:0.95rem">Тест видеопотока · ${_esc(ip)} (${_esc(camName)})</strong>
                    ${totalStreams > 1 ? `<span style="font-size: 0.72rem; padding: 0.15rem 0.45rem; border-radius: 6px; background: rgba(99,102,241,0.25); color: #c4b5fd; font-weight: 600;">Поток ${currentIdx + 1} из ${totalStreams}</span>` : ''}
                </div>
                <small style="display: block; color: #93c5fd; font-family: monospace; font-size: 0.72rem; overflow: hidden; text-overflow: ellipsis; margin-top: 2px;">${_esc(srcUrl)}</small>
            </div>
            <div style="display: flex; align-items: center; gap: 0.4rem; flex-shrink: 0;">
                ${totalStreams > 1 ? `
                    <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.75rem; padding: 0.3rem 0.6rem; border-radius:6px; background:rgba(255,255,255,0.06); color:#cbd5e1; border:1px solid rgba(255,255,255,0.1);" title="Предыдущий поток" onclick="v2OpenStreamPlayer('${_esc(prevStream.url)}', '${_esc(camName)}', '${_esc(ip)}', ${prevIdx})">◀ Назад</button>
                    <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.75rem; padding: 0.3rem 0.6rem; border-radius:6px; background:rgba(255,255,255,0.06); color:#cbd5e1; border:1px solid rgba(255,255,255,0.1);" title="Следующий поток" onclick="v2OpenStreamPlayer('${_esc(nextStream.url)}', '${_esc(camName)}', '${_esc(ip)}', ${nextIdx})">Вперед ▶</button>
                ` : ''}
                <button type="button" class="btn btn-small" style="background: #10b981; color:#fff; font-size: 0.75rem; font-weight:600; padding:0.3rem 0.65rem; border-radius:6px; border:none; cursor:pointer;" onclick="v2AddSpecificStreamToGo2rtc('${_esc(ip)}', '${_esc(srcUrl)}', ${currentIdx+1}); this.disabled=true; this.textContent='✓ Добавлено';">+ В go2rtc</button>
                <button type="button" style="background:none; border:none; color:#94a3b8; font-size:1.4rem; cursor:pointer; padding:0 4px; line-height:1;" onclick="document.getElementById('v2-player-dialog').close()" aria-label="Закрыть">×</button>
            </div>
        </div>
        <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; padding: 0.4rem 1.2rem; background: rgba(10,14,26,0.9); border-bottom: 1px solid rgba(255,255,255,0.06); font-size: 0.75rem;">
            <div style="display: flex; align-items: center; gap: 0.4rem;">
                <span style="color: #94a3b8;">🔒 Авторизация потока:</span>
                <input type="text" id="v2-player-user-input" placeholder="Логин (admin)" value="${_esc(cam?.credentials?.user || '')}" style="background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.15); color: #fff; padding: 3px 8px; border-radius: 4px; font-size: 0.72rem; width: 100px;">
                <input type="password" id="v2-player-pass-input" placeholder="Пароль" value="${_esc(cam?.credentials?.password || '')}" style="background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.15); color: #fff; padding: 3px 8px; border-radius: 4px; font-size: 0.72rem; width: 110px;">
                <button type="button" class="btn btn-small" style="font-size: 0.72rem; padding: 3px 10px; background: rgba(99,102,241,0.7); color: #fff; border: 1px solid #818cf8; border-radius: 4px; cursor: pointer; font-weight: 600;" onclick="v2ApplyCredentialsAndReload('${_esc(ip)}', '${_esc(srcUrl)}', '${_esc(camName)}', ${currentIdx})">▶ Воспроизвести с паролем</button>
            </div>
            <span style="color: #64748b; font-size: 0.7rem;">(Для Hikvision/HiWatch логин обычно admin)</span>
        </div>
        <div style="position: relative; width: 100%; aspect-ratio: 16/9; background: #000; display: flex; align-items: center; justify-content: center; overflow: hidden;">
            <div id="v2-modal-loader" style="display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 0.75rem; color: #cbd5e1;">
                <span class="v2-spinner" style="width: 32px; height: 32px; border-width:3px; border-top-color:#6366f1;"></span>
                <span style="font-size: 0.85rem; color:#a5b4fc;">Подключение к видеопотоку (WebRTC / MSE)...</span>
            </div>
            <iframe id="v2-modal-iframe" style="display: none; width: 100%; height: 100%; border: none;" allow="autoplay; fullscreen"></iframe>
            
            ${totalStreams > 1 ? `
                <button type="button" style="position: absolute; left: 12px; top: 50%; transform: translateY(-50%); width: 40px; height: 40px; border-radius: 50%; background: rgba(15,23,42,0.8); border: 1px solid rgba(255,255,255,0.25); color: #fff; display: flex; align-items: center; justify-content: center; cursor: pointer; backdrop-filter: blur(6px); transition: all 0.2s; z-index: 10; font-size:1.1rem;" onmouseover="this.style.background='rgba(99,102,241,0.9)'" onmouseout="this.style.background='rgba(15,23,42,0.8)'" onclick="v2OpenStreamPlayer('${_esc(prevStream.url)}', '${_esc(camName)}', '${_esc(ip)}', ${prevIdx})" title="Предыдущий поток (#${prevIdx+1})">◀</button>
                <button type="button" style="position: absolute; right: 12px; top: 50%; transform: translateY(-50%); width: 40px; height: 40px; border-radius: 50%; background: rgba(15,23,42,0.8); border: 1px solid rgba(255,255,255,0.25); color: #fff; display: flex; align-items: center; justify-content: center; cursor: pointer; backdrop-filter: blur(6px); transition: all 0.2s; z-index: 10; font-size:1.1rem;" onmouseover="this.style.background='rgba(99,102,241,0.9)'" onmouseout="this.style.background='rgba(15,23,42,0.8)'" onclick="v2OpenStreamPlayer('${_esc(nextStream.url)}', '${_esc(camName)}', '${_esc(ip)}', ${nextIdx})" title="Следующий поток (#${nextIdx+1})">▶</button>
            ` : ''}
        </div>
        ${totalStreams > 1 ? `
            <div style="display: flex; gap: 0.4rem; padding: 0.5rem 0.8rem; background: rgba(10, 14, 26, 0.98); overflow-x: auto; border-top: 1px solid rgba(255,255,255,0.08); align-items: center;" class="v2-modal-playlist">
                <span style="font-size: 0.72rem; color: #94a3b8; white-space: nowrap; margin-right: 0.3rem; font-weight: 600;">Каналы (${totalStreams}):</span>
                ${streams.map((st, i) => {
                    const isCur = i === currentIdx;
                    const stUrl = st.url || "";
                    const stType = (st.type || st.stream_type || 'RTSP').toUpperCase();
                    const live = st.verified ? '✓' : '';
                    return `
                        <button type="button" id="v2-stream-pill-${i}" class="v2-btn-small" style="font-size: 0.7rem; padding: 0.25rem 0.55rem; white-space: nowrap; border-radius: 6px; ${isCur ? 'background: rgba(99,102,241,0.9); color: #fff; border: 1px solid #a5b4fc; font-weight: 700; box-shadow: 0 0 10px rgba(99,102,241,0.6);' : 'background: rgba(255,255,255,0.06); color: #cbd5e1; border: 1px solid rgba(255,255,255,0.1);'}" onclick="v2OpenStreamPlayer('${_esc(stUrl)}', '${_esc(camName)}', '${_esc(ip)}', ${i})">
                            ${isCur ? '▶ ' : ''}#${i+1} · ${_esc(stType)} ${live}
                        </button>
                    `;
                }).join('')}
            </div>
        ` : ''}
    `;

    if (!dialog.open) {
        dialog.showModal();
    }

    try {
        const isHttpSnapshot = srcUrl.startsWith('http://') || srcUrl.startsWith('https://');

        if (isHttpSnapshot) {
            const iframe = document.getElementById('v2-modal-iframe');
            const loader = document.getElementById('v2-modal-loader');
            const playerContainer = iframe ? iframe.parentElement : null;
            if (playerContainer) {
                if (loader) loader.style.display = 'none';
                if (iframe) iframe.style.display = 'none';

                const u = cam?.credentials?.user || '';
                const p = cam?.credentials?.password ?? '';
                let initialSnapUrl = `/api/v2/preview?ip=${encodeURIComponent(ip)}&stream_url=${encodeURIComponent(srcUrl)}&_t=${Date.now()}`;
                if (u) {
                    initialSnapUrl += `&user=${encodeURIComponent(u)}&password=${encodeURIComponent(p)}`;
                }

                playerContainer.innerHTML = `
                    <div style="position: relative; width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; background: #000;">
                        <img id="v2-modal-live-img" src="${initialSnapUrl}" alt="Live Snapshot" style="max-width: 100%; max-height: 100%; object-fit: contain;" onerror="this.style.display='none'; const el=document.getElementById('v2-modal-live-err'); if(el) el.style.display='flex';">
                        <div id="v2-modal-live-err" style="display: none; flex-direction: column; align-items: center; justify-content: center; gap: 0.5rem; color: #ef4444; font-size: 0.85rem;">
                            <span>⚠️ Поток недоступен (камера не отвечает по HTTP)</span>
                        </div>
                        <div style="position: absolute; bottom: 12px; right: 12px; display: flex; gap: 6px; background: rgba(0,0,0,0.65); padding: 4px 10px; border-radius: 6px; align-items: center; z-index: 20; backdrop-filter: blur(4px);">
                            <span id="v2-modal-live-badge" style="font-size: 0.72rem; color: #10b981; font-weight: 600; display: flex; align-items: center; gap: 4px;">🟢 Realtime Live</span>
                            <button type="button" id="v2-modal-live-toggle" class="btn btn-ghost btn-small" style="font-size: 0.72rem; padding: 3px 8px; border-radius:4px; background:rgba(16,185,129,0.2); border:1px solid #10b981; color:#fff;" onclick="v2ToggleLiveSnapshot('${_esc(ip)}', '${_esc(srcUrl)}')">⏸ Пауза</button>
                            <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.72rem; padding: 3px 8px; border-radius:4px; background:rgba(255,255,255,0.1); color:#fff;" onclick="v2RefreshSingleSnapshot('${_esc(ip)}', '${_esc(srcUrl)}')">🔄 Обновить</button>
                        </div>
                    </div>
                `;
                if (window._v2LiveSnapshotTimer) clearInterval(window._v2LiveSnapshotTimer);
                window._v2LiveSnapshotTimer = setInterval(() => {
                    v2RefreshSingleSnapshot(ip, srcUrl);
                }, 1200);
            }
            return;
        }

        let actualSrcUrl = srcUrl;
        const u = cam?.credentials?.user || '';
        const p = cam?.credentials?.password ?? '';

        if (actualSrcUrl.startsWith('ws://') || actualSrcUrl.startsWith('wss://')) {
            const credsPart = u ? `${encodeURIComponent(u)}:${encodeURIComponent(p)}@` : '';
            if (actualSrcUrl.includes('rtsp-over-websocket')) {
                actualSrcUrl = `rtsp://${credsPart}${ip}:554/axis-media/media.amp`;
            } else {
                const rtspStream = (cam?.streams || []).find(s => (s.url || '').startsWith('rtsp://'));
                if (rtspStream) actualSrcUrl = rtspStream.url;
            }
        }

        if (actualSrcUrl.startsWith('rtsp://') || actualSrcUrl.startsWith('rtsps://')) {
            if (u) {
                const credsPart = `${encodeURIComponent(u)}:${encodeURIComponent(p)}@`;
                if (actualSrcUrl.includes(':***@')) {
                    actualSrcUrl = actualSrcUrl.replace(/:[^\/@]+@/, `:${encodeURIComponent(p)}@`);
                } else {
                    const hostPart = actualSrcUrl.split('://')[1]?.split('/')[0] || '';
                    if (!hostPart.includes('@')) {
                        actualSrcUrl = actualSrcUrl.replace('://', `://${credsPart}`);
                    }
                }
            }
        }

        const curStream = (cam?.streams || [])[currentIdx] || (cam?.streams || []).find(s => s.url === actualSrcUrl || s.url === srcUrl);
        const isHttpTransport = curStream?.transport === 'http';

        const mainUrl = (actualSrcUrl.startsWith('rtsp://') || actualSrcUrl.startsWith('rtsps://'))
            ? (actualSrcUrl.includes('#') ? actualSrcUrl : `${actualSrcUrl}#transport=tcp#backchannel=0`)
            : actualSrcUrl;
        const ffUrl = `ffmpeg:${actualSrcUrl}#video=copy`;
        const ffHttpUrl = `ffmpeg:${actualSrcUrl}#input=rtsp_http#video=copy`;

        const streamCandidates = (actualSrcUrl.startsWith('rtsp://') || actualSrcUrl.startsWith('rtsps://'))
            ? (isHttpTransport ? [ffHttpUrl, mainUrl, ffUrl] : [mainUrl, ffUrl, ffHttpUrl])
            : [actualSrcUrl];

        const regResp = await fetch("/api/go2rtc/streams", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name: tempName,
                url: streamCandidates
            })
        });

        if (!regResp.ok) {
            const err = await regResp.json();
            throw new Error(err.detail || "Не удалось запустить временный поток в go2rtc");
        }

        const iframe = document.getElementById('v2-modal-iframe');
        const loader = document.getElementById('v2-modal-loader');
        if (iframe && loader) {
            iframe.src = `/api/go2rtc/player/stream.html?src=${encodeURIComponent(tempName)}`;
            iframe.onload = () => {
                loader.style.display = 'none';
                iframe.style.display = 'block';
            };
            setTimeout(() => {
                loader.style.display = 'none';
                iframe.style.display = 'block';
            }, 800);
        }

    } catch (err) {
        const loader = document.getElementById('v2-modal-loader');
        if (loader) {
            loader.innerHTML = `<span style="color:#ef4444">⚠️ Ошибка запуска плеера: ${_esc(err.message)}</span>`;
        }
    }
}
window.v2OpenStreamPlayer = v2OpenStreamPlayer;

function v2ApplyCredentialsAndReload(ip, srcUrl, camName, currentIdx) {
    const u = document.getElementById('v2-player-user-input')?.value.trim() || '';
    const p = document.getElementById('v2-player-pass-input')?.value || '';
    const cam = (window.V2State.results || []).find(c => c.ip === ip);
    if (cam) {
        cam.credentials = { user: u, password: p };
        (cam.streams || []).forEach(s => {
            s.credentials = { user: u, password: p };
        });
    }
    const isHttpSnapshot = srcUrl.startsWith('http://') || srcUrl.startsWith('https://');
    if (isHttpSnapshot) {
        const img = document.getElementById('v2-modal-live-img');
        const err = document.getElementById('v2-modal-live-err');
        if (err) err.style.display = 'none';
        if (img) img.style.display = '';
        v2RefreshSingleSnapshot(ip, srcUrl);
        return;
    }
    v2OpenStreamPlayer(srcUrl, camName, ip, currentIdx);
}
window.v2ApplyCredentialsAndReload = v2ApplyCredentialsAndReload;

// ── SpRecord Audio Player Dialog & Dynamic Recordings ─────────────────────

window.V2SpRecordState = {
    ip: '',
    offset: 0,
    limit: 25,
    total: 0,
    currentRecord: null,
    records: [],
};

function v2OpenSpRecordPlayer(ip) {
    const cam = (window.V2State.results || []).find(c => c.ip === ip) || { ip: ip };
    window.V2SpRecordState = {
        ip: ip,
        offset: 0,
        limit: 25,
        total: 0,
        currentRecord: null,
        records: [],
    };

    let dialog = document.getElementById('v2-sprecord-dialog');
    if (!dialog) {
        dialog = document.createElement('dialog');
        dialog.id = 'v2-sprecord-dialog';
        dialog.className = 'v2-sprecord-modal';
        dialog.addEventListener('click', (e) => {
            if (e.target === dialog) dialog.close();
        });
        dialog.addEventListener('close', () => {
            const audio = dialog.querySelector('audio');
            if (audio) {
                audio.pause();
                audio.src = '';
            }
        });
        document.body.appendChild(dialog);
    }

    const recordCountMatch = (cam.model || '').match(/\(([^)]+)\)/);
    const recordSubtitle = recordCountMatch ? recordCountMatch[1] : `${cam.total_records || '132 300+'} записей`;

    dialog.innerHTML = `
        <div class="v2-sprecord-modal-header">
            <div style="display:flex;align-items:center;gap:10px">
                <span style="font-size:1.6rem">🎙️</span>
                <div>
                    <h3 style="margin:0;font-size:1.05rem;color:#ecfdf5">SpRecord · Система записи разговоров</h3>
                    <div style="font-size:0.75rem;color:#6ee7b7;margin-top:2px">
                        ${_esc(ip)}:${cam.http_port || 8002} • ${_esc(recordSubtitle)} • admin (без пароля)
                    </div>
                </div>
            </div>
            <div style="display:flex;align-items:center;gap:8px">
                <a href="http://${_esc(ip)}:${cam.http_port || 8002}/" target="_blank" class="v2-btn-small" style="text-decoration:none;background:rgba(59,130,246,0.25);color:#93c5fd;border:1px solid rgba(59,130,246,0.5);font-size:0.78rem;padding:4px 10px;font-weight:600">
                    🌐 SpRecord Web
                </a>
                <button type="button" class="btn btn-ghost" style="font-size:1.2rem;color:#94a3b8;cursor:pointer;padding:2px 8px" onclick="document.getElementById('v2-sprecord-dialog').close()">✕</button>
            </div>
        </div>
        <div class="v2-sprecord-now-playing">
            <div style="display:flex;justify-content:space-between;align-items:center">
                <div>
                    <span style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.05em;color:#10b981;font-weight:700">Сейчас играет</span>
                    <h4 id="v2-sprecord-cur-title" style="margin:3px 0 0 0;font-size:0.95rem;color:#f8fafc">
                        Загрузка записей разговоров с сервера...
                    </h4>
                </div>
                <a id="v2-sprecord-download-link" href="#" target="_blank" download class="v2-btn-small" style="display:none;text-decoration:none;background:rgba(16,185,129,0.25);color:#6ee7b7;border:1px solid rgba(16,185,129,0.4);font-size:0.78rem;padding:4px 10px;font-weight:600">
                    ⬇ Скачать MP3
                </a>
            </div>
            <audio id="v2-sprecord-audio-elem" controls class="v2-sprecord-audio-ctrl" src="">
                Ваш браузер не поддерживает воспроизведение MP3 аудио.
            </audio>
        </div>
        <div style="padding:0 1.2rem 1.2rem 1.2rem;max-height:360px;overflow-y:auto">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;gap:10px;flex-wrap:wrap">
                <span id="v2-sprecord-page-info" style="font-size:0.8rem;font-weight:700;color:#94a3b8">
                    Подключение к SpRecord...
                </span>
                <div style="display:flex;align-items:center;gap:6px">
                    <button id="v2-sprecord-prev-btn" class="v2-btn-small" style="font-size:0.75rem;padding:3px 8px" onclick="v2LoadSpRecordPage('${_esc(ip)}', Math.max(0, window.V2SpRecordState.offset - 25))" disabled>◀ Назад</button>
                    <button id="v2-sprecord-next-btn" class="v2-btn-small" style="font-size:0.75rem;padding:3px 8px" onclick="v2LoadSpRecordPage('${_esc(ip)}', window.V2SpRecordState.offset + 25)" disabled>Вперед ▶</button>
                    <button class="v2-btn-small" style="font-size:0.75rem;padding:3px 8px" onclick="v2LoadSpRecordPage('${_esc(ip)}', window.V2SpRecordState.offset)">🔄</button>
                </div>
            </div>
            <table class="v2-sprecord-calls-table">
                <thead>
                    <tr>
                        <th style="width:35px">#</th>
                        <th>Время записи</th>
                        <th>Канал</th>
                        <th>Длительность</th>
                        <th>Файл</th>
                        <th style="text-align:right">Действия</th>
                    </tr>
                </thead>
                <tbody id="v2-sprecord-tbody">
                    <tr><td colspan="6" style="text-align:center;padding:2rem;color:#94a3b8"><span class="v2-spinner" style="width:20px;height:20px;border-width:2px;border-top-color:#10b981;display:inline-block;vertical-align:middle;margin-right:8px"></span>Загрузка разговоров с сервера...</td></tr>
                </tbody>
            </table>
        </div>
    `;

    dialog.showModal();
    v2LoadSpRecordPage(ip, 0);
}
window.v2OpenSpRecordPlayer = v2OpenSpRecordPlayer;

async function v2LoadSpRecordPage(ip, offset) {
    const tbody = document.getElementById('v2-sprecord-tbody');
    const pageInfo = document.getElementById('v2-sprecord-page-info');
    const prevBtn = document.getElementById('v2-sprecord-prev-btn');
    const nextBtn = document.getElementById('v2-sprecord-next-btn');

    if (tbody) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:2rem;color:#94a3b8"><span class="v2-spinner" style="width:20px;height:20px;border-width:2px;border-top-color:#10b981;display:inline-block;vertical-align:middle;margin-right:8px"></span>Загрузка записей разговоров...</td></tr>`;
    }

    try {
        const res = await fetch(`/api/v2/sprecord/records?ip=${encodeURIComponent(ip)}&offset=${offset}&limit=25`);
        const data = await res.json();
        if (data.code !== 200) {
            if (tbody) tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:1.5rem;color:#f87171">Ошибка: ${data.error || 'Не удалось получить записи'}</td></tr>`;
            return;
        }

        window.V2SpRecordState.offset = offset;
        window.V2SpRecordState.total = data.total;
        window.V2SpRecordState.records = data.records || [];

        const curStart = data.records.length > 0 ? offset + 1 : 0;
        const curEnd = offset + data.records.length;
        if (pageInfo) {
            pageInfo.innerHTML = `Записи <strong>${curStart}–${curEnd}</strong> из <strong>${Number(data.total).toLocaleString('ru-RU')}</strong>`;
        }
        if (prevBtn) prevBtn.disabled = offset <= 0;
        if (nextBtn) nextBtn.disabled = curEnd >= data.total;

        if (!data.records.length) {
            if (tbody) tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:1.5rem;color:#94a3b8">Записей нет</td></tr>`;
            return;
        }

        const activeId = window.V2SpRecordState.currentRecord?.id || data.records[0].id;

        tbody.innerHTML = data.records.map((r, idx) => {
            const isCur = r.id === activeId;
            return `
                <tr id="v2-sp-row-${r.id}" style="${isCur ? 'background:rgba(16,185,129,0.15);font-weight:600' : ''}">
                    <td style="color:${isCur ? '#34d399' : '#94a3b8'}">${isCur ? '▶ ' : ''}${offset + idx + 1}</td>
                    <td><strong style="color:#e2e8f0">${_esc(r.time || '–')}</strong></td>
                    <td><span style="color:#6ee7b7;background:rgba(16,185,129,0.12);padding:2px 6px;border-radius:4px;font-size:0.75rem">${_esc(r.channel || 'Канал')}</span></td>
                    <td><span style="font-family:monospace;color:#f1f5f9">${_esc(r.duration || '00:00:00')}</span></td>
                    <td><span style="font-family:monospace;font-size:0.72rem;color:#64748b">${_esc(r.filename || '')}</span></td>
                    <td style="text-align:right">
                        <button class="v2-btn-small" style="padding:2px 8px;font-size:0.75rem;background:rgba(16,185,129,0.25);color:#34d399;border:1px solid rgba(16,185,129,0.4)" onclick="v2PlaySpRecordById('${_esc(ip)}', ${r.id})">▶ Слушать</button>
                        <a href="${_esc(r.download_url)}" target="_blank" download class="v2-btn-small" style="padding:2px 8px;font-size:0.75rem;background:rgba(255,255,255,0.08);color:#cbd5e1;border:1px solid rgba(255,255,255,0.15);text-decoration:none;margin-left:4px">⬇ MP3</a>
                    </td>
                </tr>
            `;
        }).join('');

        if (!window.V2SpRecordState.currentRecord && data.records.length > 0) {
            v2SetSpRecordTrack(ip, data.records[0], false);
        }
    } catch (err) {
        if (tbody) tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:1.5rem;color:#f87171">Сетевая ошибка: ${err.message}</td></tr>`;
    }
}
window.v2LoadSpRecordPage = v2LoadSpRecordPage;

function v2PlaySpRecordById(ip, recordId) {
    const rec = (window.V2SpRecordState.records || []).find(r => r.id === recordId) || {
        id: recordId,
        audio_url: `/api/v2/sprecord/audio?ip=${encodeURIComponent(ip)}&record_id=${recordId}`,
        download_url: `/api/v2/sprecord/audio?ip=${encodeURIComponent(ip)}&record_id=${recordId}&download=1`,
        channel: 'Запись #' + recordId,
        time: '',
        duration: '',
    };
    v2SetSpRecordTrack(ip, rec, true);
}
window.v2PlaySpRecordById = v2PlaySpRecordById;

function v2SetSpRecordTrack(ip, rec, autoplay = true) {
    window.V2SpRecordState.currentRecord = rec;
    const audio = document.getElementById('v2-sprecord-audio-elem');
    const titleElem = document.getElementById('v2-sprecord-cur-title');
    const downLink = document.getElementById('v2-sprecord-download-link');
    const title = rec.channel ? `${rec.channel} · ${rec.time} (${rec.duration})` : `Запись #${rec.id}`;

    if (titleElem) titleElem.textContent = title;
    if (downLink) {
        downLink.href = rec.download_url;
        downLink.style.display = 'inline-block';
    }
    if (audio) {
        audio.src = rec.audio_url;
        if (autoplay) {
            audio.play().catch(() => {});
        }
    }

    // Highlight active row in table
    const tbody = document.getElementById('v2-sprecord-tbody');
    if (tbody) {
        tbody.querySelectorAll('tr').forEach(tr => {
            const isMatch = tr.id === `v2-sp-row-${rec.id}`;
            tr.style.background = isMatch ? 'rgba(16,185,129,0.15)' : '';
            tr.style.fontWeight = isMatch ? '600' : '';
        });
    }
}
window.v2SetSpRecordTrack = v2SetSpRecordTrack;
