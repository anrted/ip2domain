'use strict';
// ── Strix Scanner: Stream Player Dialog, Quick Go2rtc, and PTZ ──

async function quickAddGo2rtc(name, url) {
    try {
        const response = await fetch("/api/go2rtc/streams", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({name, url})
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Ошибка добавления в go2rtc");
        if (name && window.strixActiveGo2rtcStreams) window.strixActiveGo2rtcStreams.add(name);
        if (url && window.strixActiveGo2rtcUrls) window.strixActiveGo2rtcUrls.add(url.trim().toLowerCase());
        alert(`Камера "${name}" успешно добавлена в go2rtc!`);
        if (window.loadGo2rtcStreams) loadGo2rtcStreams();
        if (window.renderStrixResults && window.strixCachedItems) renderStrixResults(window.strixCachedItems);
    } catch (err) {
        alert(err.message);
    }
}
window.quickAddGo2rtc = quickAddGo2rtc;

async function openStrixStreamPlayer(srcUrl, camName, ip, currentIdx = 0) {
    if (!srcUrl) return;
    
    // Find all streams for this IP group to enable switching
    let ipGroupStreams = [];
    const ipItem = (window.strixCachedItems || []).find(item => item.ip === ip);
    if (ipItem && ipItem.streams && ipItem.streams.length > 0) {
        ipGroupStreams = ipItem.streams;
    }
    const totalStreams = ipGroupStreams.length;

    // Create or reuse modal dialog
    let dialog = document.getElementById('strix-player-dialog');
    if (!dialog) {
        dialog = document.createElement('dialog');
        dialog.id = 'strix-player-dialog';
        dialog.className = 'centra-player-dialog';
        dialog.style.maxWidth = '920px';
        dialog.style.width = '92vw';
        dialog.addEventListener('close', async () => {
            const tempName = dialog.dataset.tempStreamName;
            if (tempName) {
                // Remove temporary test stream from go2rtc
                fetch(`/api/go2rtc/streams/${encodeURIComponent(tempName)}`, {method: "DELETE"}).catch(() => {});
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

    // Clean up previous temp stream if switching inside open dialog
    const prevTempName = dialog.dataset.tempStreamName;
    if (prevTempName) {
        fetch(`/api/go2rtc/streams/${encodeURIComponent(prevTempName)}`, {method: "DELETE"}).catch(() => {});
    }

    const tempName = `temp_test_${Date.now()}`;
    dialog.dataset.tempStreamName = tempName;

    // Navigation indexes
    const prevIdx = (currentIdx - 1 + totalStreams) % totalStreams;
    const nextIdx = (currentIdx + 1) % totalStreams;
    const prevStream = totalStreams > 1 ? ipGroupStreams[prevIdx] : null;
    const nextStream = totalStreams > 1 ? ipGroupStreams[nextIdx] : null;

    const isIpGarbage = Boolean(ipItem && ipItem.is_garbage);

    dialog.innerHTML = `
        <div class="centra-player-head" style="display: flex; justify-content: space-between; align-items: center; gap: 0.75rem;">
            <div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <strong>Тест видеопотока · ${_esc(ip)}</strong>
                    ${isIpGarbage ? `<span style="font-size: 0.68rem; padding: 0.1rem 0.4rem; border-radius: 4px; background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4);">🗑 Мусорная</span>` : ''}
                    ${totalStreams > 1 ? `<span style="font-size: 0.72rem; padding: 0.1rem 0.4rem; border-radius: 4px; background: rgba(99,102,241,0.25); color: #c4b5fd; font-weight: 600;">Поток ${currentIdx + 1} из ${totalStreams}</span>` : ''}
                </div>
                <small style="display: block; color: #93c5fd; font-family: monospace; font-size: 0.72rem; overflow: hidden; text-overflow: ellipsis;">${_esc(srcUrl)}</small>
            </div>
            <div style="display: flex; align-items: center; gap: 0.4rem; flex-shrink: 0;">
                <button type="button" id="strix-modal-garbage-btn" class="btn btn-small" style="font-size: 0.72rem; padding: 0.25rem 0.5rem; ${isIpGarbage ? 'background: rgba(34, 197, 94, 0.25); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.4);' : 'background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4);'}" onclick="toggleStrixGarbage('${_esc(ip)}', ${isIpGarbage}); document.getElementById('strix-player-dialog').close();">
                    ${isIpGarbage ? '✓ Снять метку мусора' : '🗑 В мусорные'}
                </button>
                ${totalStreams > 1 ? `
                    <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.75rem; padding: 0.25rem 0.55rem;" title="Предыдущий поток" onclick="openStrixStreamPlayer('${_esc(prevStream.source)}', '${_esc(ip)}_stream${prevIdx+1}', '${_esc(ip)}', ${prevIdx})">◀ Назад</button>
                    <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.75rem; padding: 0.25rem 0.55rem;" title="Следующий поток" onclick="openStrixStreamPlayer('${_esc(nextStream.source)}', '${_esc(ip)}_stream${nextIdx+1}', '${_esc(ip)}', ${nextIdx})">Вперед ▶</button>
                ` : ''}
                <button type="button" class="btn btn-small" style="background: rgba(99,102,241,0.5); font-size: 0.75rem;" onclick="quickAddGo2rtc('${_esc(camName)}', '${_esc(srcUrl)}'); this.disabled=true; this.textContent='Добавлено';">+ В go2rtc</button>
                <button class="centra-player-close" type="button" onclick="document.getElementById('strix-player-dialog').close()" aria-label="Закрыть">×</button>
            </div>
        </div>
        <div style="position: relative; width: 100%; aspect-ratio: 16/9; background: #000; display: flex; align-items: center; justify-content: center; overflow: hidden;">
            <div id="strix-modal-loader" style="display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 0.75rem; color: #cbd5e1;">
                <span class="spinner" style="width: 24px; height: 24px;"></span>
                <span style="font-size: 0.85rem;">Инициализация WebRTC/MSE трансляции...</span>
            </div>
            <iframe id="strix-modal-iframe" style="display: none; width: 100%; height: 100%; border: none;" allow="autoplay; fullscreen"></iframe>
            
            ${totalStreams > 1 ? `
                <button type="button" style="position: absolute; left: 10px; top: 50%; transform: translateY(-50%); width: 36px; height: 36px; border-radius: 50%; background: rgba(15,23,42,0.75); border: 1px solid rgba(255,255,255,0.2); color: #fff; display: flex; align-items: center; justify-content: center; cursor: pointer; backdrop-filter: blur(4px); transition: all 0.2s; z-index: 10;" onmouseover="this.style.background='rgba(99,102,241,0.85)'" onmouseout="this.style.background='rgba(15,23,42,0.75)'" onclick="openStrixStreamPlayer('${_esc(prevStream.source)}', '${_esc(ip)}_stream${prevIdx+1}', '${_esc(ip)}', ${prevIdx})" title="Предыдущий поток (#${prevIdx+1})">◀</button>
                <button type="button" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); width: 36px; height: 36px; border-radius: 50%; background: rgba(15,23,42,0.75); border: 1px solid rgba(255,255,255,0.2); color: #fff; display: flex; align-items: center; justify-content: center; cursor: pointer; backdrop-filter: blur(4px); transition: all 0.2s; z-index: 10;" onmouseover="this.style.background='rgba(99,102,241,0.85)'" onmouseout="this.style.background='rgba(15,23,42,0.75)'" onclick="openStrixStreamPlayer('${_esc(nextStream.source)}', '${_esc(ip)}_stream${nextIdx+1}', '${_esc(ip)}', ${nextIdx})" title="Следующий поток (#${nextIdx+1})">▶</button>
            ` : ''}

            <!-- Floating PTZ Overlay Controller -->
            <div id="strix-ptz-overlay" style="display: none; position: absolute; right: 16px; bottom: 16px; background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(255,255,255,0.2); border-radius: 12px; padding: 8px; backdrop-filter: blur(8px); box-shadow: 0 8px 32px rgba(0,0,0,0.6); z-index: 20; flex-direction: column; gap: 6px; align-items: center;">
                <div style="display: flex; justify-content: space-between; width: 100%; align-items: center; font-size: 0.7rem; color: #a5b4fc; font-weight: 600; padding: 0 2px;">
                    <span>🕹️ PTZ / Patrol</span>
                    <button type="button" style="background: none; border: none; color: #94a3b8; cursor: pointer; font-size: 0.8rem;" onclick="document.getElementById('strix-ptz-overlay').style.display='none'">✕</button>
                </div>
                <!-- 3x3 Direction Pad -->
                <div style="display: grid; grid-template-columns: repeat(3, 28px); grid-template-rows: repeat(3, 28px); gap: 3px;">
                    <button type="button" class="btn btn-ghost" style="padding:0; font-size:0.75rem;" onmousedown="sendPTZ('${_esc(ip)}', 'upleft')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')">↖</button>
                    <button type="button" class="btn btn-ghost" style="padding:0; font-size:0.75rem;" onmousedown="sendPTZ('${_esc(ip)}', 'up')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')">▲</button>
                    <button type="button" class="btn btn-ghost" style="padding:0; font-size:0.75rem;" onmousedown="sendPTZ('${_esc(ip)}', 'upright')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')">↗</button>
                    <button type="button" class="btn btn-ghost" style="padding:0; font-size:0.75rem;" onmousedown="sendPTZ('${_esc(ip)}', 'left')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')">◀</button>
                    <button type="button" class="btn btn-ghost" style="padding:0; font-size:0.65rem; color:#ef4444;" onclick="sendPTZ('${_esc(ip)}', 'stop')">■</button>
                    <button type="button" class="btn btn-ghost" style="padding:0; font-size:0.75rem;" onmousedown="sendPTZ('${_esc(ip)}', 'right')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')">▶</button>
                    <button type="button" class="btn btn-ghost" style="padding:0; font-size:0.75rem;" onmousedown="sendPTZ('${_esc(ip)}', 'downleft')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')">↙</button>
                    <button type="button" class="btn btn-ghost" style="padding:0; font-size:0.75rem;" onmousedown="sendPTZ('${_esc(ip)}', 'down')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')">▼</button>
                    <button type="button" class="btn btn-ghost" style="padding:0; font-size:0.75rem;" onmousedown="sendPTZ('${_esc(ip)}', 'downright')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')">↘</button>
                </div>
                <!-- Zoom & Patrol actions -->
                <div style="display: flex; gap: 4px; width: 100%; justify-content: center; margin-top: 2px;">
                    <button type="button" class="btn btn-small" style="font-size:0.65rem; padding: 2px 6px;" onmousedown="sendPTZ('${_esc(ip)}', 'zoom_in')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')" title="Приблизить">🔍 +</button>
                    <button type="button" class="btn btn-small" style="font-size:0.65rem; padding: 2px 6px;" onmousedown="sendPTZ('${_esc(ip)}', 'zoom_out')" onmouseup="sendPTZ('${_esc(ip)}', 'stop')" title="Отдалить">🔍 -</button>
                </div>
                <div style="display: flex; gap: 4px; width: 100%; justify-content: center; margin-top: 2px;">
                    <button type="button" class="btn btn-small btn-ghost" style="font-size:0.62rem; padding: 2px 5px;" onclick="sendPTZ('${_esc(ip)}', 'goto_preset', '1')">Поз.1</button>
                    <button type="button" class="btn btn-small btn-ghost" style="font-size:0.62rem; padding: 2px 5px;" onclick="sendPTZ('${_esc(ip)}', 'goto_preset', '2')">Поз.2</button>
                    <button type="button" class="btn btn-small" style="font-size:0.62rem; padding: 2px 5px; background: rgba(139,92,246,0.6);" onclick="sendPTZ('${_esc(ip)}', 'start_patrol', '1')" title="Запустить тур патрулирования">⚡ Тур</button>
                </div>
            </div>
            
            <!-- PTZ Toggle Button -->
            <button type="button" id="strix-ptz-toggle-btn" style="position: absolute; right: 12px; bottom: 12px; background: rgba(15,23,42,0.8); border: 1px solid rgba(255,255,255,0.25); border-radius: 6px; padding: 4px 8px; color: #fff; font-size: 0.72rem; cursor: pointer; backdrop-filter: blur(4px); z-index: 15; display: flex; align-items: center; gap: 4px;" onclick="const ov = document.getElementById('strix-ptz-overlay'); if (ov) ov.style.display = (ov.style.display === 'none' ? 'flex' : 'none');">
                🕹️ <span>PTZ / Патруль</span>
            </button>
        </div>
        ${totalStreams > 1 ? `
            <div style="display: flex; gap: 0.35rem; padding: 0.4rem 0.6rem; background: rgba(10, 14, 26, 0.95); overflow-x: auto; border-top: 1px solid rgba(255,255,255,0.08); align-items: center; scrollbar-width: thin; scrollbar-color: rgba(99,102,241,0.4) transparent;" class="strix-modal-playlist">
                <span style="font-size: 0.68rem; color: #94a3b8; white-space: nowrap; margin-right: 0.2rem; font-weight: 500;">Каналы (${totalStreams}):</span>
                ${ipGroupStreams.map((st, i) => {
                    const isCur = i === currentIdx;
                    const stSrc = st.source || "";
                    const stRes = (st.width && st.height) ? `${st.width}p` : '';
                    const stCodecs = Array.isArray(st.codecs) ? st.codecs[0] : (st.codecs || 'RTSP');
                    const badge = stRes ? `${stRes}` : stCodecs;
                    return `
                        <button type="button" id="strix-stream-pill-${i}" class="btn btn-small" style="font-size: 0.65rem; padding: 0.18rem 0.45rem; white-space: nowrap; border-radius: 4px; ${isCur ? 'background: rgba(99,102,241,0.8); color: #fff; border: 1px solid #a5b4fc; font-weight: 700; box-shadow: 0 0 8px rgba(99,102,241,0.5);' : 'background: rgba(255,255,255,0.05); color: #cbd5e1; border: 1px solid rgba(255,255,255,0.1); font-weight: 400;'}" onclick="openStrixStreamPlayer('${_esc(stSrc)}', '${_esc(ip)}_stream${i+1}', '${_esc(ip)}', ${i})">
                            ${isCur ? '▶ ' : ''}#${i+1} · ${_esc(badge)}
                        </button>
                    `;
                }).join('')}
            </div>
        ` : ''}
    `;

    if (!dialog.open) {
        dialog.showModal();
    }

    // Auto-scroll active pill into view smoothly
    setTimeout(() => {
        const activePill = document.getElementById(`strix-stream-pill-${currentIdx}`);
        if (activePill) {
            activePill.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
        }
    }, 50);

    try {
        const isHttpSnapshot = srcUrl.startsWith('http://') || srcUrl.startsWith('https://');
        
        if (isHttpSnapshot) {
            // For HTTP JPEG/MJPEG snapshots or endpoints, show direct live player or frame with auto-refresh
            const iframe = document.getElementById('strix-modal-iframe');
            const loader = document.getElementById('strix-modal-loader');
            const playerContainer = iframe ? iframe.parentElement : null;
            if (playerContainer) {
                if (loader) loader.style.display = 'none';
                if (iframe) iframe.style.display = 'none';
                
                // Render live snapshot player with refresh capability
                playerContainer.innerHTML = `
                    <div style="position: relative; width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; background: #000;">
                        <img id="strix-modal-live-img" src="/api/strix/preview?url=${encodeURIComponent(srcUrl)}&t=${Date.now()}" alt="Live Snapshot" style="max-width: 100%; max-height: 100%; object-fit: contain;" onerror="this.style.display='none'; const el=document.getElementById('strix-modal-live-err'); if(el) el.style.display='flex';">
                        <div id="strix-modal-live-err" style="display: none; flex-direction: column; align-items: center; justify-content: center; gap: 0.5rem; color: #ef4444; font-size: 0.85rem;">
                            <span>⚠️ Поток недоступен (камера не отвечает по HTTP/MJPEG)</span>
                        </div>
                        <div style="position: absolute; bottom: 10px; right: 10px; display: flex; gap: 6px; background: rgba(0,0,0,0.6); padding: 4px 8px; border-radius: 6px;">
                            <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.7rem; padding: 2px 6px;" onclick="const img=document.getElementById('strix-modal-live-img'); const err=document.getElementById('strix-modal-live-err'); if(img){ img.style.display=''; img.src='/api/strix/preview?url=${encodeURIComponent(srcUrl)}&t='+Date.now(); } if(err) err.style.display='none';">🔄 Повторить</button>
                        </div>
                    </div>
                `;
            }
            return;
        }

        // Register temporary RTSP stream in go2rtc (with auto-transcode fallback for MPEG4/MJPEG)
        const response = await fetch("/api/go2rtc/streams", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                name: tempName,
                url: [srcUrl, `ffmpeg:${srcUrl}#video=h264#audio=aac`]
            })
        });
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || "Не удалось запустить временный поток в go2rtc");
        }

        const iframe = document.getElementById('strix-modal-iframe');
        const loader = document.getElementById('strix-modal-loader');
        if (iframe && loader) {
            iframe.src = `/api/go2rtc/player/stream.html?src=${encodeURIComponent(tempName)}`;
            iframe.onload = () => {
                loader.style.display = 'none';
                iframe.style.display = 'block';
            };
            // Fallback show iframe
            setTimeout(() => {
                loader.style.display = 'none';
                iframe.style.display = 'block';
            }, 800);
        }
    } catch (error) {
        const loader = document.getElementById('strix-modal-loader');
        if (loader) {
            loader.innerHTML = `<span style="color: #ef4444; font-size: 0.85rem;">Ошибка запуска: ${_esc(error.message)}</span>`;
        }
    }
}
window.openStrixStreamPlayer = openStrixStreamPlayer;

async function sendPTZ(ip, command, preset = '1') {
    try {
        await fetch('/api/go2rtc/ptz/control', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                ip: ip,
                command: command,
                preset_token: preset,
                speed: 0.5
            })
        });
    } catch (_) {}
}
window.sendPTZ = sendPTZ;

// Initialize presets and database target counts on load
if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            if (window.updateStrixDbCounts) updateStrixDbCounts();
        });
    } else {
        if (window.updateStrixDbCounts) updateStrixDbCounts();
    }
}
