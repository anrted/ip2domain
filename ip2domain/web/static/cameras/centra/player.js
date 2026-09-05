'use strict';

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
