/* ============================================================
   ip2domain — scan.js
   Scan job management: start scan, poll status, vuln scan,
   HTTP tech stack analysis.
   ============================================================ */

'use strict';

/* ----------------------------------------------------------
   handleScan — form submit: start a new reverse-IP scan
   ---------------------------------------------------------- */
async function handleScan(e) {
    e.preventDefault();

    const target      = document.getElementById('target-input').value.trim();
    const verify      = document.getElementById('verify-toggle').checked;
    const scanMode    = getScanMode();
    const nmap        = scanMode === 'nmap' || scanMode === 'combined';
    const nmapPorts   = document.getElementById('nmap-ports-input').value.trim() || null;
    const nmapProfile = document.getElementById('nmap-profile').value;
    const concurrency = parseInt(document.getElementById('concurrency-input').value, 10) || 10;

    _setScanBtnState(true);

    try {
        const resp = await fetch('/api/scan', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ target, verify, nmap, scan_mode: scanMode, nmap_ports: nmapPorts, nmap_profile: nmapProfile, concurrency }),
        });

        if (!resp.ok) {
            const err = await resp.json().catch(() => ({ detail: resp.statusText }));
            throw new Error(err.detail || 'Ошибка сервера');
        }

        const data = await resp.json();
        if (data.status === 'already_running') {
            _showProgress(5, data.message || 'Сканирование уже выполняется...');
        }
        _pollScanJob(data.job_id, data.status === 'already_running');
    } catch (err) {
        alert('Ошибка запуска сканирования: ' + err.message);
        _setScanBtnState(false);
    }
}

/* Re-scan only scan-worthy nodes visible in the current graph.
   Subdomain nodes are deliberately excluded: their apex parent is scanned instead. */
async function rescanCurrentGraph() {
    const graphNodes = (currentGraphData && currentGraphData.nodes) || [];
    const targets = Array.from(new Set(graphNodes.flatMap((node) => {
        if (node.group === 'subdomain') return [];
        if (node.group === 'ip') {
            const ip = node.details && node.details.ip;
            return [ip || String(node.id || '').replace(/^ip:/, '') || node.label].filter(Boolean);
        }
        if (node.group === 'apex_domain') {
            const domain = node.details && node.details.domain;
            return [domain || String(node.id || '').replace(/^domain:/, '') || node.label].filter(Boolean);
        }
        return [];
    }))).sort();

    if (!targets.length) {
        alert('На текущем графе нет IP или корневых доменов для повторного сканирования.');
        return;
    }

    const verify = document.getElementById('verify-toggle').checked;
    const scanMode = getScanMode();
    const nmap = scanMode === 'nmap' || scanMode === 'combined';
    const nmapPorts = document.getElementById('nmap-ports-input').value.trim() || null;
    const nmapProfile = document.getElementById('nmap-profile').value;
    const concurrency = parseInt(document.getElementById('concurrency-input').value, 10) || 10;
    const savedPositions = network ? network.getPositions() : {};
    let mergedGraph = currentGraphData || {nodes: [], edges: [], stats: {}};
    let mergedResults = lastScanResults || [];
    const failures = [];
    const startedAt = Date.now();

    _setScanBtnState(true);
    try {
        for (let index = 0; index < targets.length; index += 1) {
            const target = targets[index];
            const basePct = Math.floor((index / targets.length) * 100);
            _showProgress(basePct, `Повторное сканирование ${index + 1}/${targets.length}: ${target}`,
                (Date.now() - startedAt) / 1000);
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target, verify, nmap, scan_mode: scanMode, nmap_ports: nmapPorts, nmap_profile: nmapProfile, concurrency}),
                });
                if (!response.ok) {
                    const error = await response.json().catch(() => ({}));
                    throw new Error(error.detail || response.statusText);
                }
                const created = await response.json();
                const job = await _waitForRescanJob(created.job_id, index, targets.length, target, startedAt);
                mergedResults = _mergeScanResults(mergedResults, job.results || []);
                mergedGraph = _mergeGraphData(mergedGraph, job.graph || {}, savedPositions);
            } catch (error) {
                failures.push(`${target}: ${error.message}`);
            }
        }

        window.currentGraphMode = 'canvas';
        window.currentScanJobId = null;
        renderResults({results: mergedResults, graph: mergedGraph, hidden_node_ids: []});
        loadScanHistory();
        _showProgress(100,
            failures.length ? `Завершено с ошибками: ${failures.length} из ${targets.length}` : `Пересканировано целей: ${targets.length}`,
            (Date.now() - startedAt) / 1000);
        if (failures.length) alert(`Не удалось пересканировать:\n${failures.join('\n')}`);
        setTimeout(_hideProgress, 5000);
    } finally {
        _setScanBtnState(false);
    }
}

function _waitForRescanJob(jobId, targetIndex, totalTargets, target, startedAt) {
    return new Promise((resolve, reject) => {
        const poll = async () => {
            try {
                const response = await fetch(`/api/scan/${jobId}`);
                if (!response.ok) throw new Error(response.statusText || 'Задание недоступно');
                const job = await response.json();
                const itemProgress = Math.max(0, Math.min(100, job.progress_pct || 0));
                const overallProgress = Math.floor(((targetIndex + itemProgress / 100) / totalTargets) * 100);
                _showProgress(overallProgress,
                    `${targetIndex + 1}/${totalTargets} · ${target}: ${job.stage || 'Сканирование...'}`,
                    (Date.now() - startedAt) / 1000);
                if (job.status === 'completed') return resolve(job);
                if (job.status === 'error' || job.status === 'interrupted') {
                    return reject(new Error(job.error || 'Сканирование прервано'));
                }
                setTimeout(poll, 500);
            } catch (error) {
                reject(error);
            }
        };
        poll();
    });
}

/* ----------------------------------------------------------
   _pollScanJob — poll /api/scan/{jobId} until done
   ---------------------------------------------------------- */
let scanStartTime = null;
let activeScanPoller = null;
let activeScanJobId = null;

function _pollScanJob(jobId, resumed = false, initialJob = null) {
    if (activeScanPoller && activeScanJobId === jobId) return;
    if (activeScanPoller) clearInterval(activeScanPoller);
    activeScanJobId = jobId;
    scanStartTime = Date.now();
    _setScanBtnState(true);
    _showProgress(
        initialJob ? (initialJob.progress_pct || 0) : 5,
        initialJob ? (initialJob.stage || 'Сканирование продолжается...') :
            (resumed ? 'Восстановление активного сканирования...' : 'Подготовка к сканированию...'),
        0,
    );

    activeScanPoller = setInterval(async () => {
        try {
            const elapsed = Math.round((Date.now() - scanStartTime) / 100) / 10;
            const res = await fetch(`/api/scan/${jobId}`);
            if (!res.ok) { _finishActiveScanPolling(); return; }
            const job = await res.json();

            if (job.progress_pct !== undefined) {
                _showProgress(job.progress_pct, job.stage || 'Сканирование...', elapsed);
            }

            if (job.status === 'completed') {
                _finishActiveScanPolling();
                _showProgress(100, `✅ Сканирование успешно завершено за ${elapsed.toFixed(1)} сек.!`, elapsed);
                appendScanToCurrentGraph(jobId);
                setTimeout(_hideProgress, 5000);   // B-13 fix: 5s instead of 2.5s
            } else if (job.status === 'error') {
                _finishActiveScanPolling();
                _hideProgress();
                alert('Ошибка сканирования: ' + job.error);
            }
        } catch (err) {
            console.error('Polling error:', err);
            _finishActiveScanPolling();
        }
    }, 500);
}

function _finishActiveScanPolling() {
    if (activeScanPoller) clearInterval(activeScanPoller);
    activeScanPoller = null;
    activeScanJobId = null;
    _setScanBtnState(false);
}

async function restoreActiveScan() {
    try {
        const response = await fetch('/api/scan/active');
        if (!response.ok) return;
        const data = await response.json();
        const jobs = data.jobs || [];
        if (!jobs.length) return;
        const job = jobs[jobs.length - 1];
        const targetInput = document.getElementById('target-input');
        if (targetInput && job.target) targetInput.value = job.target;
        if (document.getElementById('verify-toggle')) document.getElementById('verify-toggle').checked = job.verify !== false;
        const restoredMode = job.scan_mode || (job.nmap ? 'combined' : 'domains');
        const modeInput = document.querySelector(`input[name="scan-mode"][value="${restoredMode}"]`);
        if (modeInput) modeInput.checked = true;
        if (document.getElementById('nmap-profile') && job.nmap_profile) document.getElementById('nmap-profile').value = job.nmap_profile;
        if (document.getElementById('nmap-ports-input')) document.getElementById('nmap-ports-input').value = job.nmap_ports || '';
        if (document.getElementById('concurrency-input') && job.concurrency) document.getElementById('concurrency-input').value = job.concurrency;
        if (typeof updateScanModeControls === 'function') updateScanModeControls();
        _pollScanJob(job.job_id, true, job);
    } catch (error) {
        console.error('Не удалось восстановить активное сканирование:', error);
    }
}

window.currentGraphMode = 'global';
window.currentScanJobId = null;

function _mergeScanResults(existingResults, incomingResults) {
    const byIp = new Map();
    [...(existingResults || []), ...(incomingResults || [])].forEach((item) => {
        const previous = byIp.get(item.ip);
        if (!previous) {
            byIp.set(item.ip, {
                ...item,
                domains: Array.from(new Set(item.domains || [])).sort(),
                provider_details: {...(item.provider_details || {})},
            });
            return;
        }

        previous.domains = Array.from(new Set([
            ...(previous.domains || []), ...(item.domains || [])
        ])).sort();
        previous.total_domains = previous.domains.length;
        previous.verified_live = previous.verified_live || item.verified_live;
        if (item.nmap_status === 'completed') previous.open_ports = item.open_ports || [];
        else if (item.open_ports && item.open_ports.length && !(previous.open_ports || []).length) previous.open_ports = item.open_ports;
        ['nmap_status', 'nmap_error', 'nmap_hostname', 'nmap_os', 'nmap_tech_stack'].forEach((field) => {
            if (item[field] !== undefined && item[field] !== '') previous[field] = item[field];
        });

        Object.entries(item.provider_details || {}).forEach(([provider, domains]) => {
            previous.provider_details[provider] = Array.from(new Set([
                ...(previous.provider_details[provider] || []), ...(domains || [])
            ])).sort();
        });
    });
    return Array.from(byIp.values());
}

function _mergeGraphData(existingGraph, incomingGraph, savedPositions = {}) {
    const nodeMap = new Map();
    const mergeNode = (node) => {
        const previous = nodeMap.get(node.id);
        if (!previous) {
            nodeMap.set(node.id, {...node, details: {...(node.details || {})}});
            return;
        }
        const connectedIps = new Set([
            ...((previous.details && previous.details.connected_ips) || []),
            ...((node.details && node.details.connected_ips) || []),
        ]);
        const details = {...(previous.details || {}), ...(node.details || {})};
        if (connectedIps.size) details.connected_ips = Array.from(connectedIps).sort();
        if (previous.details && previous.details.open_ports &&
            !(node.details && node.details.nmap_status === 'completed') &&
            !(node.details && node.details.open_ports && node.details.open_ports.length)) {
            details.open_ports = previous.details.open_ports;
        }
        nodeMap.set(node.id, {...previous, ...node, details});
    };

    (existingGraph.nodes || []).forEach(mergeNode);
    (incomingGraph.nodes || []).forEach(mergeNode);

    const nodes = Array.from(nodeMap.values()).map((node) => {
        const position = savedPositions[node.id];
        return position ? {...node, x: position.x, y: position.y} : node;
    });

    const edgeMap = new Map();
    [...(existingGraph.edges || []), ...(incomingGraph.edges || [])].forEach((edge) => {
        const key = `${edge.from}\u0000${edge.to}\u0000${edge.label || ''}`;
        if (!edgeMap.has(key)) edgeMap.set(key, {...edge});
    });
    const edges = Array.from(edgeMap.values());

    return {
        nodes,
        edges,
        stats: {
            total_nodes: nodes.length,
            total_edges: edges.length,
            ip_count: nodes.filter((node) => node.group === 'ip').length,
            apex_count: nodes.filter((node) => node.group === 'apex_domain').length,
            subdomain_count: nodes.filter((node) => node.group === 'subdomain').length,
        },
    };
}

/* Add a completed scan to exactly what is currently displayed on the canvas. */
async function appendScanToCurrentGraph(jobId) {
    try {
        const res = await fetch(`/api/scan/${jobId}`);
        if (!res.ok) return;
        const job = await res.json();
        const positions = network ? network.getPositions() : {};
        const existingGraph = currentGraphData || {nodes: [], edges: [], stats: {}};
        const incomingGraph = job.graph || {nodes: [], edges: [], stats: {}};

        window.currentGraphMode = 'canvas';
        window.currentScanJobId = null;
        renderResults({
            results: _mergeScanResults(lastScanResults, job.results || []),
            graph: _mergeGraphData(existingGraph, incomingGraph, positions),
            hidden_node_ids: job.hidden_node_ids || [],
        });
        loadScanHistory();
    } catch (e) {
        console.error('Failed to append scan graph:', e);
    }
}

function reloadCurrentGraph() {
    if (window.currentGraphMode === 'scan' && window.currentScanJobId) {
        loadScanGraph(window.currentScanJobId);
    } else {
        loadGlobalGraph();
    }
}

/* ----------------------------------------------------------
   loadScanGraph — fetch and render ONLY a specific scan's topology
   ---------------------------------------------------------- */
async function loadScanGraph(jobId) {
    window.currentGraphMode = 'scan';
    window.currentScanJobId = jobId;
    try {
        const res = await fetch(`/api/scan/${jobId}`);
        if (!res.ok) return;
        const job = await res.json();
        const data = {
            results: job.results || [],
            graph: job.graph || { nodes: [], edges: [], stats: {} },
            hidden_node_ids: job.hidden_node_ids || [],
        };
        renderResults(data);
        const graphNav = document.querySelector('.nav-item[data-view="graph-view"]');
        if (typeof switchView === 'function') switchView('graph-view', graphNav);
        loadScanHistory();     // refresh history table too
    } catch (e) {
        console.error('Failed to load scan graph:', e);
    }
}

/* ----------------------------------------------------------
   loadGlobalGraph — fetch merged topology of entire DB from SQLite
   ---------------------------------------------------------- */
async function loadGlobalGraph() {
    window.currentGraphMode = 'global';
    try {
        const res  = await fetch('/api/graph/global');
        if (!res.ok) return;
        const data = await res.json();
        renderResults(data);
        loadScanHistory();     // refresh history table too
    } catch (e) {
        console.error('Failed to load global graph:', e);
    }
}

/* ----------------------------------------------------------
   loadScanHistory — populate the history table
   ---------------------------------------------------------- */
async function loadScanHistory() {
    const tbody = document.getElementById('history-body');
    if (!tbody) return;

    try {
        const res  = await fetch('/api/history');
        if (!res.ok) return;
        const list = await res.json();

        tbody.innerHTML = '';
        if (!list || list.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">История пуста</td></tr>';
            return;
        }

        list.forEach((h) => {
            const tr = document.createElement('tr');
            const statusClass = h.status === 'completed' ? 'status-completed' : 'status-error';
            const verifyBadge = h.verify ? '✅' : '—';
            const nmapBadge   = h.nmap   ? '✅' : '—';

            tr.innerHTML = `
                <td style="font-family:monospace;font-size:0.8rem;">${h.created_at || ''}</td>
                <td><strong>${_esc(h.target)}</strong></td>
                <td>${h.total_ips || 0}</td>
                <td>${h.total_domains || 0}</td>
                <td>${verifyBadge} / ${nmapBadge}</td>
                <td>
                    <span class="status-badge ${statusClass}">${h.status}</span>
                    <button onclick="loadScanGraph('${h.id}')" title="Показать только этот скан на графе"
                        style="background:rgba(99,102,241,0.2);color:#a5b4fc;border:1px solid rgba(99,102,241,0.4);border-radius:4px;padding:2px 8px;font-size:0.75rem;cursor:pointer;margin-left:6px;">
                        👁️ Показать
                    </button>
                    <button onclick="deleteScanHistory('${h.id}')" title="Удалить из истории"
                        style="background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.4);border-radius:4px;padding:2px 8px;font-size:0.75rem;cursor:pointer;margin-left:4px;">
                        🗑
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error('Failed to load history:', e);
    }
}

/* ----------------------------------------------------------
   deleteScanHistory — remove a scan entry
   ---------------------------------------------------------- */
async function deleteScanHistory(jobId) {
    if (!confirm('Удалить запись из истории?')) return;
    try {
        await fetch(`/api/history/${jobId}`, { method: 'DELETE' });
        loadScanHistory();
        loadGlobalGraph();
    } catch (e) {
        console.error('Failed to delete scan:', e);
    }
}

/* ----------------------------------------------------------
   checkNodeVulnStatus — check existing vuln result for node
   ---------------------------------------------------------- */
async function checkNodeVulnStatus(target) {
    const container = document.getElementById('vuln-scan-container');
    const btn       = document.getElementById('btn-vuln-scan');
    if (!container || !target) return;

    try {
        const res  = await fetch(`/api/vuln/check/${encodeURIComponent(target)}`);
        const data = await res.json();

        if (data.status === 'queued' || data.status === 'running') {
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;"></span> Поиск выполняется...';
            }
            container.innerHTML = _vulnRunningHtml(data.stage || 'Nmap & Nikto...');
            _pollVulnJob(data.job_id, target, container, btn);
        } else if (data.status === 'completed' && data.results) {
            if (btn) { btn.disabled = false; btn.innerHTML = '🔄 Пересканировать уязвимости'; }
            renderVulnResults(data.results, container);
        }
    } catch (e) {
        console.error('Error checking vuln status:', e);
    }
}

/* ----------------------------------------------------------
   triggerVulnScan — start a new vulnerability scan
   ---------------------------------------------------------- */
async function triggerVulnScan(target, targetType, openPorts = []) {
    const btn       = document.getElementById('btn-vuln-scan');
    const container = document.getElementById('vuln-scan-container');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;"></span> Проверка состояния...';
    }

    try {
        const res  = await fetch('/api/vuln/scan', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ target, target_type: targetType, open_ports: openPorts }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || res.statusText || 'Не удалось запустить проверку');

        if (data.status === 'already_running') {
            alert(`⚠️ ${data.message}`);
            _pollVulnJob(data.job_id, target, container, btn);
        } else if (data.status === 'queued') {
            if (container) container.innerHTML = _vulnRunningHtml('Инициализация Nmap & Nikto...');
            _pollVulnJob(data.job_id, target, container, btn);
        }
    } catch (e) {
        alert('Ошибка запуска сканирования: ' + e.message);
        if (btn) { btn.disabled = false; }
    }
}

/* ----------------------------------------------------------
   _pollVulnJob — poll vuln job with guard against duplicates
   B-07 fix: store intervalId per job to avoid multiple pollers
   ---------------------------------------------------------- */
const _vulnPollers = {};   // { jobId: intervalId }

function _pollVulnJob(jobId, target, container, btn) {
    // Prevent duplicate pollers for the same job
    if (_vulnPollers[jobId]) return;

    _vulnPollers[jobId] = setInterval(async () => {
        try {
            const res  = await fetch(`/api/vuln/scan/${jobId}`);
            const data = await res.json();

            if (container) {
                container.innerHTML = _vulnRunningHtml(`Поиск уязвимостей (${data.progress_pct || 0}%) — ${data.stage || '...'}`);
            }
            if (btn && data.status !== 'completed' && data.status !== 'error') {
                btn.disabled = true;
                btn.innerHTML = `<span class="spinner" style="width:14px;height:14px;"></span> Проверка... ${data.progress_pct || 0}%`;
            }

            if (data.status === 'completed') {
                clearInterval(_vulnPollers[jobId]);
                delete _vulnPollers[jobId];
                if (btn) { btn.disabled = false; btn.innerHTML = '🔄 Пересканировать уязвимости'; }
                if (container && data.results) renderVulnResults(data.results, container);
            } else if (data.status === 'error') {
                clearInterval(_vulnPollers[jobId]);
                delete _vulnPollers[jobId];
                if (btn) btn.disabled = false;
                if (container) container.innerHTML = `<div style="color:#f87171;font-size:0.85rem;">Ошибка: ${_esc(data.error)}</div>`;
            }
        } catch (e) {
            console.error('Vuln polling error:', e);
        }
    }, 2500);
}

/* ----------------------------------------------------------
   renderVulnResults — display nmap + nikto findings
   ---------------------------------------------------------- */
function renderVulnResults(results, container) {
    let html = `<div style="margin-top:10px;">
        <h5 style="color:var(--accent-orange);font-size:0.95rem;margin-bottom:6px;">
            Подтверждённые и потенциальные риски (${results.actionable_findings || 0}):
        </h5>`;

    if (results.scanned_ports && results.scanned_ports.length) {
        html += `<div class="vuln-scan-meta"><span>Проверенные порты: <b>${results.scanned_ports.map((p) => `${p.port}/${_esc(p.protocol || 'tcp')}`).join(', ')}</b></span><span>Время: <b>${results.scan_duration_sec || 0} сек.</b></span></div>`;
    }

    if (results.service_coverage && results.service_coverage.length) {
        html += `<details class="vuln-coverage"><summary>Покрытие сервисов и CVE · ${results.service_coverage.length}</summary><div>`;
        results.service_coverage.forEach((item) => {
            const product = item.version || item.service || 'неизвестный сервис';
            html += `<div class="vuln-coverage-row"><b>${item.port}/${_esc(item.protocol)} · ${_esc(product)}</b><span>${(item.checks || []).map(_esc).join(' · ')}</span>${item.cpe ? `<code>${_esc(item.cpe)}</code>` : ''}</div>`;
        });
        html += `</div></details>`;
    }

    if (results.severity_counts) {
        const severityLabels = {critical:'Критические',high:'Высокие',medium:'Средние',low:'Низкие',info:'Информация'};
        html += `<div class="vuln-severity-grid">${Object.entries(severityLabels).map(([level,label]) => `<div class="severity-${level}"><b>${results.severity_counts[level] || 0}</b><span>${label}</span></div>`).join('')}</div>`;
    }

    if (results.adapted_stack && results.adapted_stack.length > 0) {
        html += `<div style="margin-bottom:8px;font-size:0.78rem;background:rgba(99,102,241,0.15);border:1px solid rgba(99,102,241,0.3);padding:4px 8px;border-radius:6px;color:#a5b4fc;">
            🎯 <b>Адаптировано под стек:</b> ${results.adapted_stack.map(_esc).join(', ')}
        </div>`;
    }

    if (results.detected_stack && results.detected_stack.length > 0) {
        html += `<div class="vuln-detected-stack">🔎 <b>Распознано во время проверки:</b> ${results.detected_stack.map(_esc).join(', ')}</div>`;
    }

    const renderFindings = (list, title, titleColor) => {
        if (!list || list.length === 0) return '';
        const groups = new Map();
        list.forEach((finding) => {
            const scope = finding.endpoint || finding.port || (finding.tool === 'CVE DB' ? 'Версия компонента' : 'Без привязки к порту');
            if (!groups.has(scope)) groups.set(scope, []);
            groups.get(scope).push(finding);
        });
        let s = `<div class="vuln-tool-title" style="color:${titleColor};">${title}</div>`;
        groups.forEach((findings, scope) => {
            const first = findings[0] || {};
            const service = first.service ? ` · ${_esc(first.service)}` : '';
            s += `<details class="vuln-finding-group" open>
                <summary><b>${_esc(scope)}</b>${service}<span>${findings.length} находок</span></summary>
                <div class="vuln-finding-list">`;
            findings.forEach((f) => {
            const colors = {critical:'#ef4444',high:'#f87171',medium:'#fbbf24',low:'#60a5fa',warning:'#fbbf24',error:'#ef4444',info:'#9ca3af'};
            const c = colors[f.severity] || '#9ca3af';
            const severityNames = {critical:'Критическая',high:'Высокая',medium:'Средняя',low:'Низкая',warning:'Предупреждение',error:'Ошибка',info:'Информация'};
            s += `<div class="vuln-finding-item">
                <span style="color:${c};font-weight:600;">${severityNames[f.severity] || f.severity}</span>
                <b>${_esc(f.title || '')}</b>
                <div class="vuln-finding-details">${_esc(f.details || '')}</div>
            </div>`;
            });
            s += `</div></details>`;
        });
        return s;
    };

    html += renderFindings(results.version_cves,   'CVE Database (По версии компонента):', '#f43f5e');
    html += renderFindings(results.nmap_findings,  'Nmap NSE Findings:',    '#60a5fa');
    html += renderFindings(results.nikto_findings, 'Nikto Web Findings:',   '#a78bfa');

    if ((!results.nmap_findings || !results.nmap_findings.length) &&
        (!results.nikto_findings || !results.nikto_findings.length) &&
        (!results.version_cves || !results.version_cves.length)) {
        html += `<p style="color:var(--text-muted);font-size:0.85rem;">Уязвимостей не найдено.</p>`;
    }

    html += '</div>';
    container.innerHTML = html;
}

/* ----------------------------------------------------------
   loadHTTPTechStack — fetch and render HTTP header analysis
   ---------------------------------------------------------- */
async function loadHTTPTechStack(target, force = false) {
    const container = document.getElementById('http-tech-container');
    if (!container || !target) return;

    if (force) {
        container.innerHTML = `<div style="font-size:0.85rem;color:var(--text-muted);">🔄 Обновление HTTP безопасности...</div>`;
    }

    try {
        const url  = `/api/http/analyze/${encodeURIComponent(target)}${force ? '?force=true' : ''}`;
        const res  = await fetch(url);
        if (!res.ok) throw new Error(res.statusText);
        const data = await res.json();

        const gradeColors = { 'A+': '#10b981', A: '#10b981', B: '#3b82f6', C: '#f59e0b', D: '#f97316', F: '#ef4444' };
        const gradeBg     = gradeColors[data.grade] || '#6b7280';

        let html = `<div style="margin-top:4px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <h5 style="color:var(--primary);font-size:0.95rem;">HTTP Безопасность &amp; Стек:</h5>
                <div style="display:flex;align-items:center;gap:6px;">
                    <span style="background:${gradeBg};color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:0.8rem;">Grade ${_esc(data.grade)}</span>
                    <button onclick="loadHTTPTechStack('${_esc(target)}',true)" title="Обновить"
                        style="background:transparent;border:none;color:var(--text-muted);cursor:pointer;font-size:0.9rem;">🔄</button>
                </div>
            </div>`;

        if (data.server && data.server !== 'Unknown') {
            html += `<div style="font-size:0.85rem;margin-top:6px;"><b>Сервер:</b> ${_esc(data.server)}</div>`;
        }

        if (data.tech_stack && data.tech_stack.length > 0) {
            const nmapTech = new Set((data.tech_sources && data.tech_sources.nmap) || []);
            html += `<div style="margin-top:8px;">
                <div style="font-size:0.8rem;color:var(--text-muted);">Обнаруженный стек:</div>
                <div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:4px;">`;
            data.tech_stack.forEach((t) => {
                const source = nmapTech.has(t) ? 'Nmap -sV' : 'HTTP';
                html += `<span class="badge badge-port" title="Источник: ${source}" style="background:rgba(139,92,246,0.2);color:#c4b5fd;border:1px solid rgba(139,92,246,0.4);font-size:0.75rem;">${nmapTech.has(t) ? '⌁' : '⚡'} ${_esc(t)}</span>`;
            });
            html += `</div></div>`;
        }

        html += `<div style="margin-top:10px;font-size:0.8rem;">
            <b>Заголовки безопасности:</b> ${data.total_present}/${data.total_security_headers}`;
        if (data.missing_headers && data.missing_headers.length > 0) {
            html += `<div style="color:#f87171;font-size:0.75rem;margin-top:2px;">⚠️ Отсутствуют: ${data.missing_headers.map(_esc).join(', ')}</div>`;
        }
        html += `</div></div>`;

        container.innerHTML = html;
    } catch (e) {
        container.innerHTML = `<div style="color:var(--text-muted);font-size:0.8rem;">
            Не удалось получить HTTP заголовки
            <button onclick="loadHTTPTechStack('${_esc(target)}',true)"
                style="background:transparent;border:none;color:#60a5fa;cursor:pointer;text-decoration:underline;">повторить</button>
        </div>`;
    }
}

/* ----------------------------------------------------------
   Helpers
   ---------------------------------------------------------- */
function _setScanBtnState(scanning) {
    const btnText   = document.getElementById('btn-text');
    const btnSpinner= document.getElementById('btn-spinner');
    const submitBtn = document.getElementById('submit-btn');
    const rescanBtn = document.getElementById('rescan-graph-btn');
    if (btnText)    btnText.textContent               = scanning ? 'Сканирование...' : 'Запустить сканирование';
    if (btnSpinner) btnSpinner.style.display          = scanning ? 'inline-block' : 'none';
    if (submitBtn)  submitBtn.disabled                = scanning;
    if (rescanBtn)  rescanBtn.disabled                = scanning;
}

function _showProgress(pct, stage, elapsedSec = null) {
    const container = document.getElementById('progress-container');
    const fill      = document.getElementById('progress-fill');
    const text      = document.getElementById('progress-text');
    const stageElem = document.getElementById('progress-stage');

    if (container) container.style.display = 'block';
    if (fill)      fill.style.width        = pct + '%';
    if (text)      text.textContent        = pct + '%';
    
    let displayStage = _esc(stage);
    if (elapsedSec !== null && elapsedSec !== undefined) {
        displayStage += ` <span style="background:rgba(99,102,241,0.2);color:#a5b4fc;border:1px solid rgba(99,102,241,0.3);padding:2px 7px;border-radius:4px;font-size:0.78rem;margin-left:8px;font-family:monospace;">⏱️ ${elapsedSec.toFixed(1)}s</span>`;
    }
    if (stageElem) stageElem.innerHTML = displayStage;
}

function _hideProgress() {
    document.getElementById('progress-container').style.display = 'none';
}

function _vulnRunningHtml(msg) {
    return `<div style="background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.3);border-radius:6px;padding:10px;font-size:0.85rem;">
        <div style="font-weight:600;color:#60a5fa;">⏳ ${_esc(msg)}</div>
    </div>`;
}

/* ----------------------------------------------------------
   Init — run on DOMContentLoaded
   ---------------------------------------------------------- */
document.addEventListener('DOMContentLoaded', () => {
    loadGlobalGraph();
    loadScanHistory();
    restoreActiveScan();
});
