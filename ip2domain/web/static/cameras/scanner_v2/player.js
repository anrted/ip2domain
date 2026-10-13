'use strict';
// ── Camera Scanner v2: Stream Modal & Video Player Dialog ──────────────

if (typeof window._esc !== 'function') {
    window._esc = function (str) {
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
    window._protoBadgeClass = function (p) {
        if (!p) return 'generic';
        p = p.toLowerCase();
        if (p.includes('onvif')) return 'onvif';
        if (p.includes('hikvision')) return 'hikvision';
        if (p.includes('dahua')) return 'dahua';
        if (p.includes('axis')) return 'axis';
        if (p.includes('hls')) return 'hls';
        if (p.includes('mjpeg')) return 'mjpeg';
        if (p.includes('rtmp')) return 'rtmp';
        if (p.includes('flv')) return 'flv';
        if (p.includes('rtsp')) return 'rtsp';
        if (p.includes('sofia') || p.includes('vesta') || p.includes('xiongmai')) return 'sofia';
        if (p.includes('webrtc') || p.includes('whep')) return 'webrtc';
        if (p.includes('vms') || p.includes('devline') || p.includes('macroscop') || p.includes('trassir') || p.includes('mobotix') || p.includes('frigate') || p.includes('blue_iris') || p.includes('avtech')) return 'vms';
        if (p.includes('snapshot')) return 'snapshot';
        return 'generic';
    };
}
if (typeof window.v2CopyUrl !== 'function') {
    window.v2CopyUrl = function (url) {
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

window.v2GetStreamKind = function (url, st) {
    if (!url) return 'unknown';
    const u = url.toLowerCase();
    const type = (st && (st.type || st.stream_type) || '').toLowerCase();
    if (type === 'web_panel') return 'web_panel';
    if (u.startsWith('rtsp://') || u.startsWith('rtsps://') || type === 'rtsp') return 'rtsp';
    if (u.startsWith('rtmp://') || u.startsWith('rtmps://') || type === 'rtmp') return 'rtmp';
    if (u.includes('.m3u8') || u.includes('/hls/') || type === 'hls') return 'hls';
    if (
        type === 'mjpeg' ||
        u.includes('.mjpg') ||
        u.includes('mjpeg') ||
        u.includes('video.cgi') ||
        u.includes('faststream') ||
        u.includes('container=mjpeg') ||
        u.includes('action=stream') ||
        u.includes('videostream')
    ) {
        return 'mjpeg';
    }
    if (u.includes('.flv') || type === 'flv') return 'flv';
    if (u.startsWith('webrtc://') || u.startsWith('whep:') || u.includes('/whep') || type === 'webrtc' || type === 'whep') return 'webrtc';
    if (type === 'http_audio') return 'http_audio';
    if (
        type === 'http_snapshot' ||
        u.includes('.jpg') ||
        u.includes('.jpeg') ||
        u.includes('snapshot') ||
        u.includes('/screenshot') ||
        u.includes('/image') ||
        u.includes('latest.jpg')
    ) {
        return 'http_snapshot';
    }
    if (u.startsWith('http://') || u.startsWith('https://')) return 'http_stream';
    return 'generic';
};

window.v2IsPlayableVideoStream = function (st) {
    if (!st) return false;
    const u = (typeof st === 'string' ? st : (st.url || '')).toLowerCase();
    const type = (typeof st === 'object' ? (st.type || st.stream_type || '') : '').toLowerCase();
    if (type === 'web_panel') return false;
    if (['rtsp', 'rtsps', 'rtmp', 'rtmps', 'hls', 'mjpeg', 'flv', 'webrtc', 'whep'].includes(type)) return true;
    if (u.startsWith('rtsp://') || u.startsWith('rtsps://') || u.startsWith('rtmp://') || u.startsWith('rtmps://') || u.startsWith('webrtc://') || u.startsWith('whep:')) return true;
    if (u.includes('.m3u8') || u.includes('/hls/')) return true;
    if (u.includes('.mjpg') || u.includes('mjpeg') || u.includes('video.cgi') || u.includes('faststream') || u.includes('container=mjpeg') || u.includes('action=stream') || u.includes('videostream')) return true;
    if (u.includes('.flv')) return true;
    return false;
};

window.v2InjectCredentials = function (url, user, pass) {
    if (!url || !user) return url;
    const credsPart = `${encodeURIComponent(user)}:${encodeURIComponent(pass || '')}@`;
    if (url.includes(':***@')) {
        return url.replace(/:[^\/@]+@/, `:${encodeURIComponent(pass || '')}@`);
    }
    const schemeSep = url.indexOf('://');
    if (schemeSep === -1) return url;
    const scheme = url.substring(0, schemeSep);
    const rest = url.substring(schemeSep + 3);
    const hostPart = rest.split('/')[0];
    if (hostPart.includes('@')) {
        return url;
    }
    return `${scheme}://${credsPart}${rest}`;
};

window.v2GetBrandHint = function (brand, model) {
    const b = (brand || '').toLowerCase();
    const m = (model || '').toLowerCase();
    if (b.includes('devline') || b.includes('линия')) return 'DevLine («Линия»): admin / (без пароля)';
    if (b.includes('macroscop') || b.includes('макроскоп')) return 'Macroscop VMS: root / root (или admin / admin)';
    if (b.includes('trassir')) return 'Trassir VMS: admin / 12345 (или admin / admin)';
    if (b.includes('vesta') || b.includes('xiongmai') || b.includes('sofia') || m.includes('xiongmai')) return 'VeSta / Xiongmai (34567): admin / (без пароля)';
    if (b.includes('hikvision') || b.includes('hiwatch')) return 'Hikvision / HiWatch: admin / 12345 (или admin12345)';
    if (b.includes('dahua')) return 'Dahua: admin / admin (или admin123)';
    if (b.includes('axis')) return 'Axis: root / pass (или root / root)';
    if (b.includes('mobotix')) return 'Mobotix (MXPEG): admin / meinsm';
    if (b.includes('frigate')) return 'Frigate NVR: обычно без авторизации';
    if (b.includes('blue iris')) return 'Blue Iris: логин учетной записи VMS';
    if (b.includes('avtech')) return 'Avtech: admin / admin';
    if (b.includes('raysharp') || b.includes('tvt')) return 'TVT / RaySharp: admin / 123456 (или без пароля)';
    return 'Камера: логин обычно admin';
};

window.v2AddSpecificStreamToGo2rtc = async function (ip, streamUrl, channelIdx) {
    const safeIp = ip.replace(/\./g, '_');
    const streamName = `v2_${safeIp}_ch${channelIdx}`;
    try {
        const uLower = (streamUrl || '').toLowerCase();
        let urls = [streamUrl];
        if (streamUrl.startsWith('rtsp://') || streamUrl.startsWith('rtsps://')) {
            urls = [streamUrl, `ffmpeg:${streamUrl}#video=copy`, `ffmpeg:${streamUrl}#input=rtsp_http#video=copy`];
        } else if (uLower.includes('.m3u8')) {
            urls = [streamUrl, `ffmpeg:${streamUrl}#video=copy`];
        } else if (uLower.includes('mjpg') || uLower.includes('mjpeg') || uLower.includes('video.cgi') || uLower.includes('faststream') || uLower.includes('container=mjpeg')) {
            urls = [`mjpeg:${streamUrl}`, `ffmpeg:${streamUrl}#video=copy`, streamUrl];
        } else if (uLower.includes('.flv')) {
            urls = [streamUrl, `ffmpeg:${streamUrl}#video=copy`];
        } else {
            urls = [streamUrl, `ffmpeg:${streamUrl}#video=copy`];
        }
        const resp = await fetch("/api/go2rtc/streams", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name: streamName,
                url: urls
            })
        });
        if (resp.ok) {
            window.v2CopyUrl && window.v2CopyUrl ? null : null;
            const toast = document.createElement('div');
            toast.textContent = `✓ Поток #${channelIdx} (${streamName}) добавлен в go2rtc!`;
            toast.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:rgba(16,185,129,0.95);color:#fff;padding:8px 16px;border-radius:8px;font-size:13px;z-index:999999;box-shadow:0 4px 12px rgba(0,0,0,0.3);';
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 2500);
        } else {
            const data = await resp.json().catch(() => ({}));
            alert('Ошибка добавления: ' + (data.detail || resp.statusText));
        }
    } catch (e) {
        alert('Ошибка сети: ' + e.message);
    }
};

window._v2LiveSnapshotTimer = null;
window._v2LiveSnapshotInterval = 1200;

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
        }, window._v2LiveSnapshotInterval || 1200);
    }
}
window.v2ToggleLiveSnapshot = v2ToggleLiveSnapshot;

function v2SetSnapshotInterval(ms, ip, streamUrl) {
    window._v2LiveSnapshotInterval = ms;
    const btns = document.querySelectorAll('.v2-snap-speed-btn');
    btns.forEach(b => {
        b.style.background = 'rgba(255,255,255,0.08)';
        b.style.color = '#cbd5e1';
    });
    const cur = document.getElementById(`v2-speed-${ms}`);
    if (cur) {
        cur.style.background = 'rgba(99,102,241,0.8)';
        cur.style.color = '#fff';
    }
    if (window._v2LiveSnapshotTimer) {
        clearInterval(window._v2LiveSnapshotTimer);
        window._v2LiveSnapshotTimer = setInterval(() => {
            v2RefreshSingleSnapshot(ip, streamUrl);
        }, ms);
    }
}
window.v2SetSnapshotInterval = v2SetSnapshotInterval;

function v2DownloadCurrentSnapshot(ip, streamUrl, currentIdx = 0) {
    const img = document.getElementById('v2-modal-live-img');
    if (!img || !img.src) return;
    const a = document.createElement('a');
    a.href = img.src;
    a.download = `cam_${ip.replace(/\./g, '_')}_ch${currentIdx + 1}_${Date.now()}.jpg`;
    document.body.appendChild(a);
    a.click();
    a.remove();
}
window.v2DownloadCurrentSnapshot = v2DownloadCurrentSnapshot;

function v2FullscreenPlayer() {
    const el = document.getElementById('v2-player-viewport');
    if (!el) return;
    if (document.fullscreenElement) {
        document.exitFullscreen().catch(() => {});
    } else {
        el.requestFullscreen().catch(() => {});
    }
}
window.v2FullscreenPlayer = v2FullscreenPlayer;

function v2SwitchMjpegMode(mode, ip, streamUrl) {
    const iframe = document.getElementById('v2-modal-iframe');
    const directImg = document.getElementById('v2-modal-mjpeg-direct');
    const loader = document.getElementById('v2-modal-loader');
    const btnRtc = document.getElementById('v2-mjpeg-btn-rtc');
    const btnDir = document.getElementById('v2-mjpeg-btn-dir');

    if (mode === 'direct') {
        if (iframe) iframe.style.display = 'none';
        if (loader) loader.style.display = 'none';
        if (directImg) {
            directImg.src = streamUrl;
            directImg.style.display = 'block';
        }
        if (btnDir) {
            btnDir.style.background = 'rgba(6,182,212,0.9)';
            btnDir.style.color = '#fff';
        }
        if (btnRtc) {
            btnRtc.style.background = 'rgba(255,255,255,0.08)';
            btnRtc.style.color = '#cbd5e1';
        }
    } else {
        if (directImg) {
            directImg.style.display = 'none';
            directImg.src = '';
        }
        if (iframe) iframe.style.display = 'block';
        if (btnRtc) {
            btnRtc.style.background = 'rgba(99,102,241,0.9)';
            btnRtc.style.color = '#fff';
        }
        if (btnDir) {
            btnDir.style.background = 'rgba(255,255,255,0.08)';
            btnDir.style.color = '#cbd5e1';
        }
    }
}
window.v2SwitchMjpegMode = v2SwitchMjpegMode;

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
                <input type="text" id="v2-modal-search-input" placeholder="Поиск по URL или типу потока (h264, hls, mjpeg, rtsp, ch1, sub)..."
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
        const kind = window.v2GetStreamKind(s.url, s);
        const type = (s.type || s.stream_type || kind).toUpperCase();
        const verBadge = s.verified ? '<span class="v2-verified-badge" style="position:static;display:inline-block;padding:0.1rem 0.35rem;font-size:0.55rem">✓ Live</span>' : '';
        const source = (cam.endpoints || []).find(e => e.port === s.source_port);
        const sourceLabel = source ? `${source.brand || ''} ${source.model || ''} · порт ${source.port}` : '';
        const resText = s.resolution ? `<span style="color:rgba(255,255,255,0.4);font-size:0.65rem">${s.resolution}</span>` : '';

        return `
            <div class="v2-stream-item">
                <div style="display:flex;align-items:center;gap:0.5rem;flex:1;min-width:0">
                    <span style="font-size:0.7rem;color:rgba(255,255,255,0.3);min-width:28px">#${idx + 1}</span>
                    <span class="v2-proto-badge ${_protoBadgeClass(kind || type.toLowerCase())}">${type}</span>
                    ${s.screenshot ? `<img loading="lazy" width="96" height="54" style="object-fit:contain" src="${_esc(s.screenshot.startsWith('blob:') ? s.screenshot : '/api/v2/capture?path=' + encodeURIComponent(s.screenshot))}" alt="Кадр потока ${idx + 1}">` : ''}
                    <span class="v2-stream-item-url" title="${_esc(s.url)}">${_esc(s.url)}</span>
                    ${verBadge} ${resText}
                    ${sourceLabel ? `<small>${_esc(sourceLabel)}</small>` : ''}
                </div>
                <div class="v2-stream-item-actions">
                    <button class="v2-btn-small" style="background:rgba(99,102,241,0.25);color:#c4b5fd;border:1px solid rgba(99,102,241,0.5);font-weight:600" onclick="v2OpenStreamPlayer('${_esc(s.url)}', '${_esc(cam.brand || cam.ip)}', '${_esc(cam.ip)}', ${idx})" title="Тест потока в реальном времени (WebRTC / MSE / MJPEG)">▶ Тест</button>
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
    const streams = (cam.streams || []).filter(s => s.type !== 'web_panel');
    if (!streams.length) return;

    let streamUrl = window.V2State.selectedStreams[ip] || '';
    if (!streamUrl || streamUrl.startsWith('ws://') || (!window.v2IsPlayableVideoStream(streamUrl) && streams.some(s => window.v2IsPlayableVideoStream(s)))) {
        const playable = streams.find(s => window.v2IsPlayableVideoStream(s));
        if (playable) {
            streamUrl = playable.url;
        } else {
            streamUrl = streams[0].url;
        }
    }
    const idx = streams.findIndex(s => s.url === streamUrl);
    v2OpenStreamPlayer(streamUrl, cam.brand || cam.ip, ip, idx >= 0 ? idx : 0);
}
window.v2OpenSelectedStreamPlayer = v2OpenSelectedStreamPlayer;

async function v2OpenStreamPlayer(srcUrl, camName, ip, currentIdx = 0) {
    if (!srcUrl) return;

    const cam = (window.V2State.results || []).find(c => c.ip === ip);
    const streams = (cam?.streams || []).filter(s => s.type !== 'web_panel');
    const totalStreams = streams.length;
    const curStream = streams[currentIdx] || streams.find(s => s.url === srcUrl) || { url: srcUrl };
    const kind = window.v2GetStreamKind(srcUrl, curStream);

    let dialog = document.getElementById('v2-player-dialog');
    if (!dialog) {
        dialog = document.createElement('dialog');
        dialog.id = 'v2-player-dialog';
        dialog.className = 'centra-player-dialog';
        dialog.style.maxWidth = '960px';
        dialog.style.width = '95vw';
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
                fetch(`/api/go2rtc/streams/${encodeURIComponent(tempName)}`, { method: "DELETE" }).catch(() => { });
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

    if (window._v2LiveSnapshotTimer) {
        clearInterval(window._v2LiveSnapshotTimer);
        window._v2LiveSnapshotTimer = null;
    }

    const prevTempName = dialog.dataset.tempStreamName;
    if (prevTempName) {
        fetch(`/api/go2rtc/streams/${encodeURIComponent(prevTempName)}`, { method: "DELETE" }).catch(() => { });
    }

    const tempName = `temp_v2_${Date.now()}`;
    dialog.dataset.tempStreamName = tempName;

    const prevIdx = (currentIdx - 1 + totalStreams) % totalStreams;
    const nextIdx = (currentIdx + 1) % totalStreams;
    const prevStream = totalStreams > 1 ? streams[prevIdx] : null;
    const nextStream = totalStreams > 1 ? streams[nextIdx] : null;

    const brandHint = window.v2GetBrandHint(cam?.brand, cam?.model);
    const kindLabelMap = {
        rtsp: '🎥 RTSP Stream',
        hls: '📺 HLS (VMS / Web Stream)',
        mjpeg: '🎞️ MJPEG (VMS / IPCam)',
        rtmp: '🔴 RTMP Stream',
        flv: '⚡ HTTP-FLV Stream',
        webrtc: '🟢 WebRTC / WHEP',
        http_snapshot: '📷 HTTP Snapshot (Кадр)',
        http_stream: '🌐 HTTP Stream',
        generic: '🎥 Видеопоток'
    };
    const streamKindTitle = kindLabelMap[kind] || '🎥 Видеопоток';

    dialog.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; gap: 0.75rem; padding: 0.85rem 1.2rem; background: rgba(15,23,42,0.98); border-bottom: 1px solid rgba(255,255,255,0.1);">
            <div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1;">
                <div style="display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;">
                    <span style="font-size:1.1rem">🎥</span>
                    <strong style="font-size:0.95rem">${_esc(streamKindTitle)} · ${_esc(ip)}</strong>
                    <span style="color:#94a3b8;font-size:0.85rem">(${_esc(camName)})</span>
                    <span class="v2-proto-badge ${_protoBadgeClass(kind)}" style="font-size:0.68rem;padding:2px 6px">${kind.toUpperCase()}</span>
                    ${totalStreams > 1 ? `<span style="font-size: 0.72rem; padding: 0.15rem 0.45rem; border-radius: 6px; background: rgba(99,102,241,0.25); color: #c4b5fd; font-weight: 600;">Поток ${currentIdx + 1} из ${totalStreams}</span>` : ''}
                </div>
                <small style="display: block; color: #93c5fd; font-family: monospace; font-size: 0.72rem; overflow: hidden; text-overflow: ellipsis; margin-top: 3px;">${_esc(srcUrl)}</small>
            </div>
            <div style="display: flex; align-items: center; gap: 0.4rem; flex-shrink: 0;">
                ${totalStreams > 1 ? `
                    <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.75rem; padding: 0.3rem 0.6rem; border-radius:6px; background:rgba(255,255,255,0.06); color:#cbd5e1; border:1px solid rgba(255,255,255,0.1);" title="Предыдущий поток" onclick="v2OpenStreamPlayer('${_esc(prevStream.url)}', '${_esc(camName)}', '${_esc(ip)}', ${prevIdx})">◀ Назад</button>
                    <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.75rem; padding: 0.3rem 0.6rem; border-radius:6px; background:rgba(255,255,255,0.06); color:#cbd5e1; border:1px solid rgba(255,255,255,0.1);" title="Следующий поток" onclick="v2OpenStreamPlayer('${_esc(nextStream.url)}', '${_esc(camName)}', '${_esc(ip)}', ${nextIdx})">Вперед ▶</button>
                ` : ''}
                <button type="button" class="btn btn-small" style="background: rgba(255,255,255,0.08); color:#cbd5e1; border:1px solid rgba(255,255,255,0.15); font-size: 0.75rem; padding:0.3rem 0.6rem; border-radius:6px; cursor:pointer;" onclick="v2CopyUrl('${_esc(srcUrl)}')" title="Скопировать URL">📋 URL</button>
                <a href="${_esc(srcUrl)}" target="_blank" class="btn btn-small" style="background: rgba(59,130,246,0.2); color:#93c5fd; border:1px solid rgba(59,130,246,0.4); font-size: 0.75rem; padding:0.3rem 0.6rem; border-radius:6px; text-decoration:none;" title="Открыть в новой вкладке">↗ Вкладка</a>
                <button type="button" class="btn btn-small" style="background: #10b981; color:#fff; font-size: 0.75rem; font-weight:600; padding:0.3rem 0.65rem; border-radius:6px; border:none; cursor:pointer;" onclick="v2AddSpecificStreamToGo2rtc('${_esc(ip)}', '${_esc(srcUrl)}', ${currentIdx + 1}); this.disabled=true; this.textContent='✓ В go2rtc';">+ В go2rtc</button>
                <button type="button" style="background:none; border:none; color:#94a3b8; font-size:1.4rem; cursor:pointer; padding:0 4px; line-height:1;" onclick="document.getElementById('v2-player-dialog').close()" aria-label="Закрыть">×</button>
            </div>
        </div>

        <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; padding: 0.4rem 1.2rem; background: rgba(10,14,26,0.92); border-bottom: 1px solid rgba(255,255,255,0.06); font-size: 0.75rem; flex-wrap: wrap;">
            <div style="display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap;">
                <span style="color: #94a3b8;">🔒 Авторизация:</span>
                <input type="text" id="v2-player-user-input" placeholder="Логин (admin)" value="${_esc(cam?.credentials?.user || curStream?.credentials?.user || '')}" style="background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.15); color: #fff; padding: 3px 8px; border-radius: 4px; font-size: 0.72rem; width: 100px;">
                <input type="password" id="v2-player-pass-input" placeholder="Пароль" value="${_esc(cam?.credentials?.password || curStream?.credentials?.password || '')}" style="background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.15); color: #fff; padding: 3px 8px; border-radius: 4px; font-size: 0.72rem; width: 110px;">
                <button type="button" class="btn btn-small" style="font-size: 0.72rem; padding: 3px 10px; background: rgba(99,102,241,0.7); color: #fff; border: 1px solid #818cf8; border-radius: 4px; cursor: pointer; font-weight: 600;" onclick="v2ApplyCredentialsAndReload('${_esc(ip)}', '${_esc(srcUrl)}', '${_esc(camName)}', ${currentIdx})">▶ Воспроизвести с паролем</button>
            </div>
            <span style="color: #64748b; font-size: 0.7rem;">${_esc(brandHint)}</span>
        </div>

        ${kind === 'mjpeg' ? `
            <div style="display: flex; align-items: center; justify-content: space-between; padding: 0.35rem 1.2rem; background: rgba(15,23,42,0.95); border-bottom: 1px solid rgba(255,255,255,0.06); font-size: 0.74rem;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <span style="color: #06b6d4; font-weight: 600;">🎞️ Режим воспроизведения MJPEG:</span>
                    <button type="button" id="v2-mjpeg-btn-rtc" class="btn btn-small" style="background: rgba(99,102,241,0.9); color: #fff; border: 1px solid rgba(99,102,241,0.5); font-size: 0.7rem; padding: 2px 8px; border-radius: 4px; cursor: pointer;" onclick="v2SwitchMjpegMode('go2rtc', '${_esc(ip)}', '${_esc(srcUrl)}')">🎥 WebRTC / MSE (go2rtc)</button>
                    <button type="button" id="v2-mjpeg-btn-dir" class="btn btn-small" style="background: rgba(255,255,255,0.08); color: #cbd5e1; border: 1px solid rgba(255,255,255,0.15); font-size: 0.7rem; padding: 2px 8px; border-radius: 4px; cursor: pointer;" onclick="v2SwitchMjpegMode('direct', '${_esc(ip)}', '${_esc(srcUrl)}')">🖼️ Прямой MJPEG браузера (30 FPS)</button>
                </div>
                <span style="color: #94a3b8; font-size: 0.7rem;">Прямой режим работает без транскодирования через браузер</span>
            </div>
        ` : ''}

        <div id="v2-player-viewport" style="position: relative; width: 100%; aspect-ratio: 16/9; background: #000; display: flex; align-items: center; justify-content: center; overflow: hidden;">
            <div id="v2-modal-loader" style="display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 0.75rem; color: #cbd5e1;">
                <span class="v2-spinner" style="width: 32px; height: 32px; border-width:3px; border-top-color:#6366f1;"></span>
                <span style="font-size: 0.85rem; color:#a5b4fc;">Подключение к видеопотоку (WebRTC / MSE / go2rtc)...</span>
            </div>
            <iframe id="v2-modal-iframe" style="display: none; width: 100%; height: 100%; border: none;" allow="autoplay; fullscreen"></iframe>
            <img id="v2-modal-mjpeg-direct" style="display: none; max-width: 100%; max-height: 100%; object-fit: contain;" alt="Прямой MJPEG поток">

            ${totalStreams > 1 ? `
                <button type="button" style="position: absolute; left: 12px; top: 50%; transform: translateY(-50%); width: 40px; height: 40px; border-radius: 50%; background: rgba(15,23,42,0.8); border: 1px solid rgba(255,255,255,0.25); color: #fff; display: flex; align-items: center; justify-content: center; cursor: pointer; backdrop-filter: blur(6px); transition: all 0.2s; z-index: 10; font-size:1.1rem;" onmouseover="this.style.background='rgba(99,102,241,0.9)'" onmouseout="this.style.background='rgba(15,23,42,0.8)'" onclick="v2OpenStreamPlayer('${_esc(prevStream.url)}', '${_esc(camName)}', '${_esc(ip)}', ${prevIdx})" title="Предыдущий поток (#${prevIdx + 1})">◀</button>
                <button type="button" style="position: absolute; right: 12px; top: 50%; transform: translateY(-50%); width: 40px; height: 40px; border-radius: 50%; background: rgba(15,23,42,0.8); border: 1px solid rgba(255,255,255,0.25); color: #fff; display: flex; align-items: center; justify-content: center; cursor: pointer; backdrop-filter: blur(6px); transition: all 0.2s; z-index: 10; font-size:1.1rem;" onmouseover="this.style.background='rgba(99,102,241,0.9)'" onmouseout="this.style.background='rgba(15,23,42,0.8)'" onclick="v2OpenStreamPlayer('${_esc(nextStream.url)}', '${_esc(camName)}', '${_esc(ip)}', ${nextIdx})" title="Следующий поток (#${nextIdx + 1})">▶</button>
            ` : ''}
        </div>

        ${totalStreams > 1 ? `
            <div style="display: flex; gap: 0.4rem; padding: 0.5rem 0.8rem; background: rgba(10, 14, 26, 0.98); overflow-x: auto; border-top: 1px solid rgba(255,255,255,0.08); align-items: center;" class="v2-modal-playlist">
                <span style="font-size: 0.72rem; color: #94a3b8; white-space: nowrap; margin-right: 0.3rem; font-weight: 600;">Каналы / Потоки (${totalStreams}):</span>
                ${streams.map((st, i) => {
                    const isCur = i === currentIdx;
                    const stUrl = st.url || "";
                    const stKind = window.v2GetStreamKind(stUrl, st);
                    const stType = (st.type || st.stream_type || stKind).toUpperCase();
                    const live = st.verified ? '✓' : '';
                    return `
                        <button type="button" id="v2-stream-pill-${i}" class="v2-btn-small" style="font-size: 0.7rem; padding: 0.25rem 0.55rem; white-space: nowrap; border-radius: 6px; ${isCur ? 'background: rgba(99,102,241,0.9); color: #fff; border: 1px solid #a5b4fc; font-weight: 700; box-shadow: 0 0 10px rgba(99,102,241,0.6);' : 'background: rgba(255,255,255,0.06); color: #cbd5e1; border: 1px solid rgba(255,255,255,0.1);'}" onclick="v2OpenStreamPlayer('${_esc(stUrl)}', '${_esc(camName)}', '${_esc(ip)}', ${i})">
                            ${isCur ? '▶ ' : ''}#${i + 1} · ${_esc(stType)} ${live}
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
        const userInput = document.getElementById('v2-player-user-input')?.value.trim();
        const passInput = document.getElementById('v2-player-pass-input')?.value;
        const u = (userInput !== undefined && userInput !== '') ? userInput : (cam?.credentials?.user || curStream?.credentials?.user || '');
        const p = (passInput !== undefined && passInput !== '') ? passInput : (cam?.credentials?.password ?? curStream?.credentials?.password ?? '');

        // ── Case A: Pure HTTP Snapshot Mode ──────────────────────────────────
        if (kind === 'http_snapshot') {
            const viewport = document.getElementById('v2-player-viewport');
            const loader = document.getElementById('v2-modal-loader');
            const iframe = document.getElementById('v2-modal-iframe');
            if (loader) loader.style.display = 'none';
            if (iframe) iframe.style.display = 'none';

            let initialSnapUrl = `/api/v2/preview?ip=${encodeURIComponent(ip)}&stream_url=${encodeURIComponent(srcUrl)}&_t=${Date.now()}`;
            if (u) {
                initialSnapUrl += `&user=${encodeURIComponent(u)}&password=${encodeURIComponent(p)}`;
            }

            viewport.innerHTML = `
                <div style="position: relative; width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; background: #000;">
                    <img id="v2-modal-live-img" src="${initialSnapUrl}" alt="Live Snapshot" style="max-width: 100%; max-height: 100%; object-fit: contain;" onerror="this.style.display='none'; const el=document.getElementById('v2-modal-live-err'); if(el) el.style.display='flex';">
                    
                    <div id="v2-modal-live-err" style="display: none; flex-direction: column; align-items: center; justify-content: center; gap: 0.5rem; color: #ef4444; font-size: 0.85rem; padding: 1rem; text-align: center;">
                        <span style="font-weight:600">⚠️ Кадр недоступен</span>
                        <small style="color:#94a3b8">Возможно, требуется авторизация. Введите логин и пароль в поле выше и нажмите «Воспроизвести с паролем».</small>
                    </div>

                    <div style="position: absolute; bottom: 12px; right: 12px; display: flex; gap: 6px; background: rgba(0,0,0,0.75); padding: 5px 10px; border-radius: 8px; align-items: center; z-index: 20; backdrop-filter: blur(6px); border: 1px solid rgba(255,255,255,0.15);">
                        <span id="v2-modal-live-badge" style="font-size: 0.72rem; color: #10b981; font-weight: 600; display: flex; align-items: center; gap: 4px;">🟢 Realtime Snapshot</span>
                        <button type="button" id="v2-speed-500" class="btn btn-ghost btn-small v2-snap-speed-btn" style="font-size: 0.68rem; padding: 2px 6px; border-radius:4px; background:rgba(255,255,255,0.08); color:#cbd5e1;" onclick="v2SetSnapshotInterval(500, '${_esc(ip)}', '${_esc(srcUrl)}')">0.5с</button>
                        <button type="button" id="v2-speed-1200" class="btn btn-ghost btn-small v2-snap-speed-btn" style="font-size: 0.68rem; padding: 2px 6px; border-radius:4px; background:rgba(99,102,241,0.8); color:#fff;" onclick="v2SetSnapshotInterval(1200, '${_esc(ip)}', '${_esc(srcUrl)}')">1.2с</button>
                        <button type="button" id="v2-speed-3000" class="btn btn-ghost btn-small v2-snap-speed-btn" style="font-size: 0.68rem; padding: 2px 6px; border-radius:4px; background:rgba(255,255,255,0.08); color:#cbd5e1;" onclick="v2SetSnapshotInterval(3000, '${_esc(ip)}', '${_esc(srcUrl)}')">3с</button>
                        <button type="button" id="v2-modal-live-toggle" class="btn btn-ghost btn-small" style="font-size: 0.72rem; padding: 3px 8px; border-radius:4px; background:rgba(16,185,129,0.2); border:1px solid #10b981; color:#fff;" onclick="v2ToggleLiveSnapshot('${_esc(ip)}', '${_esc(srcUrl)}')">⏸ Пауза</button>
                        <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.72rem; padding: 3px 8px; border-radius:4px; background:rgba(255,255,255,0.1); color:#fff;" onclick="v2RefreshSingleSnapshot('${_esc(ip)}', '${_esc(srcUrl)}')">🔄 Обновить</button>
                        <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.72rem; padding: 3px 8px; border-radius:4px; background:rgba(59,130,246,0.2); color:#93c5fd; border:1px solid rgba(59,130,246,0.4);" onclick="v2DownloadCurrentSnapshot('${_esc(ip)}', '${_esc(srcUrl)}', ${currentIdx})" title="Скачать снимок">⬇ JPG</button>
                        <button type="button" class="btn btn-ghost btn-small" style="font-size: 0.72rem; padding: 3px 8px; border-radius:4px; background:rgba(255,255,255,0.1); color:#fff;" onclick="v2FullscreenPlayer()" title="Полный экран">⛶</button>
                    </div>
                </div>
            `;

            window._v2LiveSnapshotTimer = setInterval(() => {
                v2RefreshSingleSnapshot(ip, srcUrl);
            }, window._v2LiveSnapshotInterval || 1200);
            return;
        }

        // ── Case B: Real Video Streams (RTSP, HLS, MJPEG, RTMP, FLV, WebRTC) ──
        let actualSrcUrl = srcUrl;

        // WebSocket wrapper resolution
        if (actualSrcUrl.startsWith('ws://') || actualSrcUrl.startsWith('wss://')) {
            if (actualSrcUrl.includes('rtsp-over-websocket')) {
                actualSrcUrl = `rtsp://${ip}:554/axis-media/media.amp`;
            } else {
                const rtspStream = streams.find(s => (s.url || '').startsWith('rtsp://'));
                if (rtspStream) actualSrcUrl = rtspStream.url;
            }
        }

        // Inject credentials into actual source URL
        if (u) {
            actualSrcUrl = window.v2InjectCredentials(actualSrcUrl, u, p);
        }

        const isHttpTransport = curStream?.transport === 'http';
        const isRtsp = actualSrcUrl.startsWith('rtsp://') || actualSrcUrl.startsWith('rtsps://');
        const mainUrl = isRtsp
            ? (actualSrcUrl.includes('#') ? actualSrcUrl : `${actualSrcUrl}#transport=tcp#backchannel=0`)
            : actualSrcUrl;
        const ffUrl = `ffmpeg:${actualSrcUrl}#video=copy`;
        const ffHttpUrl = `ffmpeg:${actualSrcUrl}#input=rtsp_http#video=copy`;

        let streamCandidates = [actualSrcUrl];
        if (isRtsp) {
            streamCandidates = isHttpTransport ? [ffHttpUrl, mainUrl, ffUrl] : [mainUrl, ffUrl, ffHttpUrl];
        } else if (kind === 'hls') {
            streamCandidates = [actualSrcUrl, ffUrl];
        } else if (kind === 'mjpeg') {
            streamCandidates = [`mjpeg:${actualSrcUrl}`, ffUrl, actualSrcUrl];
        } else if (kind === 'flv' || kind === 'rtmp') {
            streamCandidates = [actualSrcUrl, ffUrl];
        } else {
            streamCandidates = [actualSrcUrl, ffUrl];
        }

        const regResp = await fetch("/api/go2rtc/streams", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name: tempName,
                url: streamCandidates
            })
        });

        if (!regResp.ok) {
            const err = await regResp.json().catch(() => ({}));
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
                if (loader && loader.style.display !== 'none') {
                    loader.style.display = 'none';
                    if (iframe) iframe.style.display = 'block';
                }
            }, 800);
        }

    } catch (err) {
        const loader = document.getElementById('v2-modal-loader');
        if (loader) {
            loader.innerHTML = `
                <div style="padding: 1.5rem; text-align: center; color: #ef4444;">
                    <div style="font-size: 1.1rem; font-weight: 600; margin-bottom: 0.5rem;">⚠️ Ошибка запуска плеера</div>
                    <div style="font-size: 0.85rem; color: #fca5a5; margin-bottom: 1rem;">${_esc(err.message)}</div>
                    <div style="font-size: 0.78rem; color: #94a3b8;">
                        Возможные причины: видеопоток защищен паролем, камера не поддерживает выбранный протокол или порт закрыт брандмауэром.
                    </div>
                </div>
            `;
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
    const kind = window.v2GetStreamKind(srcUrl);
    if (kind === 'http_snapshot') {
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
            audio.play().catch(() => { });
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
