'use strict';
// ── Camera Scanner v2: Targets, CIDR Math, Tools & Credentials ─────────

const V2State = window.V2State || {
    currentJobId: null,
    isStarting: false,
    pollTimer: null,
    pollInterval: 2000,
    results: [],           // CameraResult[]
    selectedStreams: {},   // { [ip]: streamUrl }
    previewCache: {},      // { [ip]: blobUrl }
    filterBrand: 'all',
    filterProtocol: 'all',
    filterGeo: 'all',
    geoSearch: '',
    filterStatus: 'all',   // all | live | preview
    totalInDb: 0,
    visibleCount: 48,
    pageSize: 48,
    isLoadingResults: false,
    resultsLoaded: false,
    credentials: [
        { user: 'admin', password: '' },
        { user: 'admin', password: 'admin' },
        { user: 'admin', password: '12345' },
        { user: 'admin', password: '123456' },
        { user: 'admin', password: '12345admin' },
        { user: 'admin', password: 'admin123' },
        { user: 'admin', password: 'admin12345' },
        { user: 'root',  password: '' },
        { user: 'root',  password: 'root' },
        { user: 'root',  password: 'pass' },
        { user: 'root',  password: '123456' },
        { user: 'service', password: 'service' },
    ],
};
window.V2State = V2State;

const MAX_V2_TARGETS = 5000000;

function _ipToInt(ip) {
    if (!ip || typeof ip !== 'string') return null;
    const parts = ip.trim().split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
    return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function v2CountIPsFromText(text) {
    if (!text || !text.trim()) return 0;
    const tokens = text.split(/[\s,;\n\r]+/).filter(Boolean);
    let total = 0;

    for (const token of tokens) {
        let clean = token.trim();
        if (!clean || clean.startsWith('#')) continue;

        // Skip IPv6 subnets / addresses (e.g. 2a02:f800::/29)
        if (clean.includes(':') && (clean.includes('::') || clean.split(':').length > 2)) {
            continue;
        }

        // Strip port if IPv4 with port (e.g. 1.2.3.4:554)
        if (clean.includes(':')) {
            clean = clean.split(':')[0].trim();
        }

        // 1. CIDR notation (e.g. 192.168.1.0/24)
        if (clean.includes('/')) {
            const [ip, maskStr] = clean.split('/');
            const mask = parseInt(maskStr, 10);
            if (!isNaN(mask) && mask >= 0 && mask <= 32) {
                total += Math.pow(2, 32 - mask);
                continue;
            }
        }

        // 2. Range notation (e.g. 10.0.0.1-10.0.0.255 or 10.0.0.1-255)
        if (clean.includes('-')) {
            const parts = clean.split('-');
            const startStr = parts[0].trim();
            let endStr = parts[1].trim();

            const startInt = _ipToInt(startStr);
            if (startInt !== null) {
                // Short range notation like 10.0.0.1-255
                if (!endStr.includes('.') && /^\d+$/.test(endStr)) {
                    const lastOctet = parseInt(endStr, 10);
                    if (lastOctet >= 0 && lastOctet <= 255) {
                        const startParts = startStr.split('.');
                        endStr = `${startParts[0]}.${startParts[1]}.${startParts[2]}.${lastOctet}`;
                    }
                }
                const endInt = _ipToInt(endStr);
                if (endInt !== null && endInt >= startInt) {
                    total += (endInt - startInt + 1);
                    continue;
                }
            }
        }

        // 3. Single IPv4 address
        if (_ipToInt(clean) !== null) {
            total += 1;
            continue;
        }

        // Fallback: if it looks like an IP or hostname
        if (/^[a-zA-Z0-9.-]+$/.test(clean)) {
            total += 1;
        }
    }

    return total;
}

function v2CalculateTargetsCount() {
    const textarea = document.getElementById('v2-targets');
    const counter = document.getElementById('v2-targets-counter');
    if (!textarea || !counter) return;

    const count = v2CountIPsFromText(textarea.value);
    const countFormatted = count.toLocaleString('ru-RU');
    const maxFormatted = MAX_V2_TARGETS.toLocaleString('ru-RU');

    if (count === 0) {
        counter.innerHTML = `<span style="color:rgba(255,255,255,0.45)">0 IP (макс. ${maxFormatted})</span>`;
    } else if (count > MAX_V2_TARGETS) {
        counter.innerHTML = `<span style="color:#f87171;font-weight:700">⚠️ ${countFormatted} / ${maxFormatted} IP (превышен лимит 5 млн!)</span>`;
    } else {
        const pct = ((count / MAX_V2_TARGETS) * 100).toFixed(count >= 100000 ? 1 : 2);
        counter.innerHTML = `<span style="color:#6ee7b7;font-weight:600">🎯 ${countFormatted} IP</span> <span style="color:rgba(255,255,255,0.45);font-size:0.7rem">(${pct}% от 5 млн)</span>`;
    }
}
window.v2CalculateTargetsCount = v2CalculateTargetsCount;

async function loadAsnPrefixesForV2() {
    const asnInput = document.getElementById('v2-asn-input');
    const targets = document.getElementById('v2-targets');
    if (!asnInput || !targets) return;
    const rawAsn = asnInput.value.trim().toUpperCase();
    if (!rawAsn) return;
    const asn = rawAsn.startsWith('AS') ? rawAsn.slice(2) : rawAsn;
    if (!/^\d+$/.test(asn)) {
        alert('Введите корректный номер ASN, например AS12345 или 12345');
        return;
    }
    try {
        const resp = await fetch(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}`);
        if (!resp.ok) throw new Error('Ошибка RIPE API');
        const data = await resp.json();
        // Strictly filter for IPv4 prefixes (ignore IPv6)
        const prefixes = (data?.data?.prefixes || [])
            .map(p => p.prefix)
            .filter(p => p && !p.includes(':'));
        if (!prefixes.length) {
            alert(`IPv4 префиксы для AS${asn} не найдены`);
            return;
        }
        const existing = targets.value.trim();
        targets.value = existing ? `${existing}\n${prefixes.join('\n')}` : prefixes.join('\n');
        v2CalculateTargetsCount();
    } catch (e) {
        alert(`Не удалось загрузить префиксы: ${e.message}`);
    }
}
window.loadAsnPrefixesForV2 = loadAsnPrefixesForV2;

function switchCameraVersion(version) {
    const v1Tabs   = document.querySelectorAll('.camera-tab');
    const v1Panels = document.querySelectorAll('.camera-tab-panel');
    const v2Panel  = document.getElementById('camera-v2-panel');
    const btn1 = document.getElementById('cam-ver-btn-v1');
    const btn2 = document.getElementById('cam-ver-btn-v2');

    if (version === 'v2') {
        v1Tabs.forEach(t => t.style.display = 'none');
        v1Panels.forEach(p => { p.style.display = 'none'; p.classList.remove('active'); });
        if (v2Panel) v2Panel.classList.add('v2-active');
        if (btn1) btn1.classList.remove('active');
        if (btn2) btn2.classList.add('active', 'active-v2');
        localStorage.setItem('ip2domain_cam_version', 'v2');
        v2OnActivate();
    } else {
        v1Tabs.forEach(t => t.style.display = '');
        if (v2Panel) v2Panel.classList.remove('v2-active');
        if (btn1) btn1.classList.add('active');
        if (btn2) btn2.classList.remove('active', 'active-v2');
        localStorage.setItem('ip2domain_cam_version', 'v1');
        const activeTab = document.querySelector('.camera-tab.active');
        if (activeTab) {
            const tabId = activeTab.id.replace('camera-', '').replace('-tab', '');
            if (window.switchCameraTab) switchCameraTab(tabId);
        } else {
            if (window.switchCameraTab) switchCameraTab('go2rtc');
        }
    }
}
window.switchCameraVersion = switchCameraVersion;

function v2OnActivate() {
    v2LoadTools();
    v2RenderCredentials();
    if (window.v2LoadStoredResults) v2LoadStoredResults();
    v2CheckActiveScan();
    v2CalculateTargetsCount();
}
window.v2OnActivate = v2OnActivate;

async function v2CheckActiveScan() {
    let savedJobId = localStorage.getItem('ip2domain_v2_active_job');
    if (!savedJobId) {
        try {
            const resp = await fetch('/api/v2/active_job');
            if (resp.ok) {
                const data = await resp.json();
                if (data.active && data.job) {
                    savedJobId = data.job.job_id;
                    localStorage.setItem('ip2domain_v2_active_job', savedJobId);
                }
            }
        } catch (e) {}
    }
    if (!savedJobId) {
        if (window.v2SetScanState) v2SetScanState('idle');
        return;
    }
    try {
        const resp = await fetch(`/api/v2/scan/${savedJobId}`);
        if (!resp.ok) {
            localStorage.removeItem('ip2domain_v2_active_job');
            if (window.v2SetScanState) v2SetScanState('idle');
            return;
        }
        const job = await resp.json();
        if (['queued', 'running'].includes(job.status)) {
            V2State.currentJobId = savedJobId;
            if (window.v2ShowProgress) v2ShowProgress();
            if (window.v2SetScanState) v2SetScanState('running');
            if (window.v2UpdateProgress) v2UpdateProgress(job);
            if (window.v2MergeResults) v2MergeResults(job.results || []);
            if (window.v2StartPolling) v2StartPolling();
        } else {
            localStorage.removeItem('ip2domain_v2_active_job');
            if (window.v2SetScanState) v2SetScanState('idle');
            if (job.results && job.results.length && window.v2MergeResults) {
                v2MergeResults(job.results);
            }
        }
    } catch (e) {
        if (window.v2SetScanState) v2SetScanState('idle');
    }
}
window.v2CheckActiveScan = v2CheckActiveScan;

async function v2LoadTools() {
    const container = document.getElementById('v2-tools-status');
    if (!container) return;
    container.innerHTML = '<span class="v2-tool-badge">Проверка...</span>';
    try {
        const resp = await fetch('/api/v2/tools');
        if (!resp.ok) return;
        const tools = await resp.json();
        const badges = [];
        badges.push(v2ToolBadge('masscan', tools.masscan));
        badges.push(v2ToolBadge('nmap', tools.nmap));
        badges.push(v2ToolBadge('ffmpeg', tools.ffmpeg));
        badges.push(v2ToolBadge(tools.is_root ? 'root ✓' : 'no-root', tools.is_root, !tools.is_root ? 'warn' : 'ok'));

        const masscanOpt = document.getElementById('v2-engine-masscan');
        const nmapOpt = document.getElementById('v2-engine-nmap');
        if (masscanOpt && !tools.masscan) {
            masscanOpt.closest('.v2-radio-item').style.opacity = '0.45';
            masscanOpt.disabled = true;
        }
        if (nmapOpt && !tools.nmap) {
            nmapOpt.closest('.v2-radio-item').style.opacity = '0.45';
            nmapOpt.disabled = true;
        }
        container.innerHTML = badges.join('');
    } catch (e) {
        container.innerHTML = '<span class="v2-tool-badge warn">Ошибка проверки</span>';
    }
}
window.v2LoadTools = v2LoadTools;

function v2ToolBadge(name, ok, cls) {
    const c = cls || (ok ? 'ok' : 'missing');
    const icon = ok ? '✓' : '✗';
    return `<span class="v2-tool-badge ${c}">${icon} ${name}</span>`;
}

function v2RenderCredentials() {
    const list = document.getElementById('v2-creds-list');
    if (!list) return;
    list.innerHTML = V2State.credentials.map((c, i) => `
        <div class="v2-cred-row">
            <input type="text" value="${_esc(c.user)}" placeholder="login"
                oninput="V2State.credentials[${i}].user = this.value">
            <input type="password" value="${_esc(c.password)}" placeholder="password"
                oninput="V2State.credentials[${i}].password = this.value">
            <button class="v2-del-btn" onclick="v2RemoveCred(${i})" title="Удалить">✕</button>
        </div>
    `).join('');
}
window.v2RenderCredentials = v2RenderCredentials;

function v2RemoveCred(idx) {
    V2State.credentials.splice(idx, 1);
    v2RenderCredentials();
}
window.v2RemoveCred = v2RemoveCred;

function v2AddCred() {
    V2State.credentials.push({ user: '', password: '' });
    v2RenderCredentials();
    const inputs = document.querySelectorAll('#v2-creds-list .v2-cred-row input[type="text"]');
    if (inputs.length) inputs[inputs.length - 1].focus();
}
window.v2AddCred = v2AddCred;

function v2OnRateChange(val) {
    const display = document.getElementById('v2-rate-display');
    if (display) display.textContent = Number(val).toLocaleString() + ' pps';
}
window.v2OnRateChange = v2OnRateChange;
