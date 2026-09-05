'use strict';
// ── Strix Scanner: Targets & Database Presets ───────────────────

function refreshStrixGraphTargets() {
    const container = document.getElementById('strix-graph-targets');
    if (!container) return;
    const ips = window.getGraphUniqueIPs ? window.getGraphUniqueIPs() : [];
    if (!ips.length) {
        container.innerHTML = '';
        return;
    }
    container.innerHTML = `<span style="font-size:0.7rem; color:var(--text-muted); width:100%;">Цели из текущего графа (${ips.length}):</span>` +
        ips.slice(0, 10).map((ip) => `<button type="button" class="btn btn-ghost btn-small" onclick="appendStrixTarget('${_esc(ip)}')">+ ${_esc(ip)}</button>`).join('') +
        (ips.length > 10 ? `<button type="button" class="btn btn-ghost btn-small" onclick="appendAllStrixTargets()">+ Добавить все (${ips.length})</button>` : '');
}
window.refreshStrixGraphTargets = refreshStrixGraphTargets;

function appendStrixTarget(ip) {
    const area = document.getElementById('strix-target');
    if (!area) return;
    const lines = area.value.split('\n').map(l => l.trim()).filter(Boolean);
    if (!lines.includes(ip)) {
        lines.push(ip);
        area.value = lines.join('\n');
    }
}
window.appendStrixTarget = appendStrixTarget;

function appendAllStrixTargets() {
    const area = document.getElementById('strix-target');
    if (!area) return;
    const ips = window.getGraphUniqueIPs ? window.getGraphUniqueIPs() : [];
    const lines = new Set(area.value.split('\n').map(l => l.trim()).filter(Boolean));
    ips.forEach(ip => lines.add(ip));
    area.value = Array.from(lines).join('\n');
}
window.appendAllStrixTargets = appendAllStrixTargets;

async function loadAsnPrefixesForStrix() {
    const input = document.getElementById('strix-asn-input');
    const btn = document.getElementById('strix-asn-btn');
    const status = document.getElementById('strix-asn-status');
    const area = document.getElementById('strix-target');
    if (!input || !area) return;

    const asnVal = input.value.trim();
    if (!asnVal) {
        if (status) {
            status.style.color = '#ef4444';
            status.textContent = 'Укажите номер ASN (напр. 12958)';
        }
        return;
    }

    if (btn) btn.disabled = true;
    if (status) {
        status.style.color = '#93c5fd';
        status.textContent = `Запрос префиксов для ${asnVal}...`;
    }

    try {
        const resp = await fetch(`/api/asn/lookup?asn=${encodeURIComponent(asnVal)}`);
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || 'Не удалось получить префиксы');

        const v4 = data.prefixes_v4 || [];
        const v6 = data.prefixes_v6 || [];
        const all = [...v4];

        if (!all.length) {
            if (status) {
                status.style.color = '#eab308';
                status.textContent = `Для ${data.asn} не найдено IPv4 диапазонов (${v6.length} IPv6 пропущено)`;
            }
            return;
        }

        const lines = new Set(area.value.split('\n').map(l => l.trim()).filter(Boolean));
        all.forEach(p => lines.add(p));
        area.value = Array.from(lines).join('\n');

        if (status) {
            status.style.color = '#4ade80';
            status.textContent = `✓ Загружено ${v4.length} IPv4 диапазонов (${data.asn}, источник: ${data.source || '2ip.io/RIPE'})`;
            setTimeout(() => { if (status.textContent.startsWith('✓')) status.textContent = ''; }, 6000);
        }
    } catch (err) {
        if (status) {
            status.style.color = '#ef4444';
            status.textContent = err.message;
        }
    } finally {
        if (btn) btn.disabled = false;
    }
}
window.loadAsnPrefixesForStrix = loadAsnPrefixesForStrix;

let _strixDbTargetsCache = null;

async function updateStrixDbCounts() {
    try {
        const resp = await fetch('/api/strix/targets/db_ips');
        if (!resp.ok) return;
        const data = await resp.json();
        _strixDbTargetsCache = data;

        const countNotGo2rtc = document.getElementById('count-not-go2rtc');
        const countAllDb = document.getElementById('count-all-db');

        if (countNotGo2rtc) countNotGo2rtc.textContent = data.counts?.not_in_go2rtc ?? 0;
        if (countAllDb) countAllDb.textContent = data.counts?.total_saved ?? 0;
    } catch (e) {
        console.debug('Failed to fetch DB targets count:', e);
    }
}
window.updateStrixDbCounts = updateStrixDbCounts;

async function insertStrixDbTargets(type = 'not_in_go2rtc') {
    const area = document.getElementById('strix-target');
    const status = document.getElementById('strix-asn-status');
    if (!area) return;

    try {
        let data = _strixDbTargetsCache;
        if (!data) {
            if (status) {
                status.style.color = '#93c5fd';
                status.textContent = 'Загрузка списка IP из базы...';
            }
            const resp = await fetch('/api/strix/targets/db_ips');
            if (!resp.ok) throw new Error('Ошибка получения списка IP из базы');
            data = await resp.json();
            _strixDbTargetsCache = data;
        }

        const ipList = type === 'not_in_go2rtc' ? (data.not_in_go2rtc || []) : (data.all_ips || []);
        if (!ipList.length) {
            if (status) {
                status.style.color = '#eab308';
                status.textContent = type === 'not_in_go2rtc'
                    ? 'Все найденные камеры из базы уже добавлены в go2rtc!'
                    : 'В базе пока нет сохраненных камер';
            }
            return;
        }

        area.value = ipList.join('\n');
        if (status) {
            status.style.color = '#4ade80';
            status.textContent = type === 'not_in_go2rtc'
                ? `✓ Подставлено ${ipList.length} IP (не добавленных в go2rtc)`
                : `✓ Подставлено ${ipList.length} всех IP из базы`;
            setTimeout(() => { if (status.textContent.startsWith('✓')) status.textContent = ''; }, 6000);
        }
    } catch (err) {
        if (status) {
            status.style.color = '#ef4444';
            status.textContent = err.message;
        }
    }
}
window.insertStrixDbTargets = insertStrixDbTargets;

let strixPresetsLoaded = false;
async function loadStrixPresets() {
    if (strixPresetsLoaded) return;
    const select = document.getElementById('strix-preset');
    if (!select) return;
    try {
        const response = await fetch('/api/strix/presets');
        if (!response.ok) return;
        const data = await response.json();
        const results = data.results || [];
        if (results.length) {
            const presets = results.filter(r => r.type === 'preset');
            const brands = results.filter(r => r.type === 'brand');
            
            let html = '<optgroup label="Пресеты потоков">';
            presets.forEach(p => {
                const selected = p.id === 'p:top-150' ? 'selected' : '';
                html += `<option value="${_esc(p.id)}" ${selected}>${_esc(p.name)}</option>`;
            });
            html += '</optgroup>';
            
            if (brands.length) {
                html += '<optgroup label="Бренды и производители">';
                brands.forEach(b => {
                    html += `<option value="${_esc(b.id)}">${_esc(b.name)}</option>`;
                });
                html += '</optgroup>';
            }
            select.innerHTML = html;
            strixPresetsLoaded = true;
        }
    } catch (_) {}
}
window.loadStrixPresets = loadStrixPresets;
