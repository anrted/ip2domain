'use strict';
// ── Camera Scanner v2: Stream Modal & Video Player Dialog ──────────────

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
                    <span class="v2-stream-count-badge">${streams.length} потоков</span>
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
        const resText = s.resolution ? `<span style="color:rgba(255,255,255,0.4);font-size:0.65rem">${s.resolution}</span>` : '';

        return `
            <div class="v2-stream-item">
                <div style="display:flex;align-items:center;gap:0.5rem;flex:1;min-width:0">
                    <span style="font-size:0.7rem;color:rgba(255,255,255,0.3);min-width:28px">#${idx + 1}</span>
                    <span class="v2-proto-badge ${_protoBadgeClass(type.toLowerCase())}">${type}</span>
                    <span class="v2-stream-item-url" title="${_esc(s.url)}">${_esc(s.url)}</span>
                    ${verBadge} ${resText}
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
    if (window.v2CapturePreview) await v2CapturePreview(ip);
    btn.textContent = '✓ Готово';
    setTimeout(() => { btn.textContent = origText; btn.disabled = false; }, 2000);
}
window.v2CaptureFromModal = v2CaptureFromModal;

function v2OpenSelectedStreamPlayer(ip) {
    const cam = (window.V2State.results || []).find(c => c.ip === ip);
    if (!cam || !cam.streams || !cam.streams.length) return;
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

                playerContainer.innerHTML = `
                    <div style="position: relative; width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; background: #000;">
                        <img id="v2-modal-live-img" src="/api/v2/preview?ip=${encodeURIComponent(ip)}&stream_url=${encodeURIComponent(srcUrl)}&_t=${Date.now()}" alt="Live Snapshot" style="max-width: 100%; max-height: 100%; object-fit: contain;" onerror="this.style.display='none'; const el=document.getElementById('v2-modal-live-err'); if(el) el.style.display='flex';">
                        <div id="v2-modal-live-err" style="display: none; flex-direction: column; align-items: center; justify-content: center; gap: 0.5rem; color: #ef4444; font-size: 0.85rem;">
                            <span>⚠️ Поток недоступен (камера не отвечает по HTTP)</span>
                        </div>
                        <div style="position: absolute; bottom: 12px; right: 12px; display: flex; gap: 6px; background: rgba(0,0,0,0.6); padding: 4px 8px; border-radius: 6px;">
                            <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.72rem; padding: 3px 8px; border-radius:4px; background:rgba(255,255,255,0.1); color:#fff;" onclick="const img=document.getElementById('v2-modal-live-img'); const err=document.getElementById('v2-modal-live-err'); if(img){ img.style.display=''; img.src='/api/v2/preview?ip=${encodeURIComponent(ip)}&stream_url=${encodeURIComponent(srcUrl)}&_t='+Date.now(); } if(err) err.style.display='none';">🔄 Обновить</button>
                        </div>
                    </div>
                `;
            }
            return;
        }

        let actualSrcUrl = srcUrl;
        if (actualSrcUrl.startsWith('ws://') || actualSrcUrl.startsWith('wss://')) {
            const u = cam?.credentials?.user || '';
            const p = cam?.credentials?.password || '';
            const credsPart = u ? `${encodeURIComponent(u)}:${encodeURIComponent(p)}@` : '';
            if (actualSrcUrl.includes('rtsp-over-websocket')) {
                actualSrcUrl = `rtsp://${credsPart}${ip}:554/axis-media/media.amp`;
            } else {
                const rtspStream = (cam?.streams || []).find(s => (s.url || '').startsWith('rtsp://'));
                if (rtspStream) actualSrcUrl = rtspStream.url;
            }
        }

        const regResp = await fetch("/api/go2rtc/streams", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name: tempName,
                url: [actualSrcUrl, `ffmpeg:${actualSrcUrl}#video=h264#audio=aac`]
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
