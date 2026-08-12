/* ============================================================
   ip2domain — graph.js
   Vis.js network graph rendering, filtering, clustering,
   node-click details and graph position persistence.
   ============================================================ */

'use strict';

/** @type {import('vis-network').Network|null} */
let network = null;
let nodesDataSet = null;
let edgesDataSet = null;

/** @type {Array} Full raw graph data from API */
let currentGraphData = null;

/** @type {Array} Latest scan results for sidebar detail lookup */
let lastScanResults = [];

/* ----------------------------------------------------------
   renderResults — main entry point after scan/load
   ---------------------------------------------------------- */
function renderResults(data) {
    lastScanResults = data.results || [];
    currentGraphData = data.graph || { nodes: [], edges: [], stats: {} };

    const graph = currentGraphData;

    // Filter out server-persisted hidden nodes
    const hiddenNodeIds = new Set(data.hidden_node_ids || []);
    if (hiddenNodeIds.size > 0 && graph.nodes) {
        const visibleNodes = graph.nodes.filter((n) => !hiddenNodeIds.has(n.id));
        const visibleNodeIds = new Set(visibleNodes.map((n) => n.id));
        const visibleEdges = (graph.edges || []).filter(
            (e) => visibleNodeIds.has(e.from) && visibleNodeIds.has(e.to)
        );
        graph.nodes = visibleNodes;
        graph.edges = visibleEdges;
    }

    // Stats Bar
    document.getElementById('stat-ips').textContent         = graph.stats.ip_count       || 0;
    document.getElementById('stat-apex').textContent        = graph.stats.apex_count      || 0;
    document.getElementById('stat-subdomains').textContent  = graph.stats.subdomain_count || 0;
    document.getElementById('stat-edges').textContent       = graph.stats.total_edges     || 0;

    _buildNetwork(graph);
    renderTable(data.results || []);
    updateHiddenNodesUI();
}

/* ----------------------------------------------------------
   _buildNetwork — create / recreate Vis.js Network
   ---------------------------------------------------------- */
function _buildNetwork(graph) {
    const container = document.getElementById('network-graph');
    if (network) {
        network.destroy();
        network = null;
    }
    nodesDataSet = new vis.DataSet(graph.nodes);
    edgesDataSet = new vis.DataSet(graph.edges);

    const visData = {
        nodes: nodesDataSet,
        edges: edgesDataSet,
    };

    const options = {
        nodes: {
            font: { color: '#ffffff', face: 'Inter', size: 14 },
            borderWidth: 2,
            margin: 10,
        },
        physics: {
            enabled: true,
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {
                gravitationalConstant: -180,
                centralGravity: 0.01,
                springLength: 220,
                springConstant: 0.08,
                damping: 0.4,
                avoidOverlap: 1.0,
            },
            stabilization: { enabled: true, iterations: 300, updateInterval: 25 },
        },
        layout: { randomSeed: 42, improvedLayout: true },
        interaction: {
            hover: true,
            tooltipDelay: 100,
            hideEdgesOnDrag: graph.nodes.length > 150,
            hideEdgesOnZoom: graph.nodes.length > 150,
        },
    };

    network = new vis.Network(container, visData, options);

    // Disable physics after stabilization so layout stays fixed
    network.once('stabilizationIterationsDone', () => {
        network.setOptions({ physics: { enabled: false } });
    });

    // Persist only nodes that were explicitly dragged
    network.on('dragEnd', (params) => {
        if (params.nodes.length > 0) {
            saveNodePositionsBatch(network.getPositions(params.nodes));
        }
    });

    // Node click → show details in sidebar
    network.on('click', (params) => {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            if (network.isCluster(nodeId)) {
                network.openCluster(nodeId);
                return;
            }
            const selectedNode = graph.nodes.find((n) => n.id === nodeId);
            showNodeDetails(selectedNode);
        }
    });
}

/* ----------------------------------------------------------
   applyGraphFilters — show/hide node types
   ---------------------------------------------------------- */
function applyGraphFilters() {
    if (!network || !currentGraphData) return;

    const showIp   = document.getElementById('filter-ip').checked;
    const showApex = document.getElementById('filter-apex').checked;
    const showSub  = document.getElementById('filter-subdomains').checked;

    const allowed = new Set();
    if (showIp)   allowed.add('ip');
    if (showApex) allowed.add('apex_domain');
    if (showSub)  allowed.add('subdomain');

    const filteredNodes = currentGraphData.nodes.filter((n) => allowed.has(n.group));
    const visibleIds    = new Set(filteredNodes.map((n) => n.id));
    const filteredEdges = currentGraphData.edges.filter(
        (e) => visibleIds.has(e.from) && visibleIds.has(e.to)
    );

    nodesDataSet = new vis.DataSet(filteredNodes);
    edgesDataSet = new vis.DataSet(filteredEdges);
    network.setData({nodes: nodesDataSet, edges: edgesDataSet});

    if (document.getElementById('cluster-toggle').checked) {
        toggleClustering();
    }
}

/* ----------------------------------------------------------
   toggleClustering — cluster all subdomain nodes together
   ---------------------------------------------------------- */
function toggleClustering() {
    if (!network) return;
    if (document.getElementById('cluster-toggle').checked) {
        network.cluster({
            joinCondition: (opts) => opts.group === 'subdomain',
            clusterNodeProperties: {
                id: 'subdomainCluster',
                borderWidth: 3,
                shape: 'database',
                color: '#8b5cf6',
                label: '📦 Группа поддоменов (Кликните для раскрытия)',
            },
        });
    } else {
        try { network.openCluster('subdomainCluster'); } catch (_) {}
    }
}

/* ----------------------------------------------------------
   handleSearch — highlight matching nodes on the graph
   ---------------------------------------------------------- */
function handleSearch(e) {
    const query = e.target.value.toLowerCase().trim();
    if (!network || !currentGraphData) return;

    if (!query) {
        network.unselectAll();
        return;
    }

    const matching = currentGraphData.nodes.filter((n) =>
        n.label.toLowerCase().includes(query)
    );
    if (matching.length > 0) {
        const ids = matching.map((n) => n.id);
        network.selectNodes(ids);
        network.focus(ids[0], { scale: 1.2, animation: true });
    } else {
        network.unselectAll();
    }
}

/* ----------------------------------------------------------
   showNodeDetails — populate right sidebar
   ---------------------------------------------------------- */
function showNodeDetails(node) {
    const panel = document.getElementById('node-info-content');
    if (!node) return;
    window.selectedVulnPorts = _knownPortsForNode(node);
    const drawer = document.getElementById('details-sidebar');
    if (drawer) {
        drawer.classList.add('open');
        drawer.setAttribute('aria-hidden', 'false');
    }

    let typeLabel = 'Неизвестно';
    if (node.group === 'ip')           typeLabel = 'IP-адрес';
    else if (node.group === 'apex_domain') typeLabel = 'Apex-домен (корневой)';
    else if (node.group === 'subdomain')   typeLabel = 'Поддомен';

    let html = `<div style="display:flex;justify-content:space-between;align-items:center;gap:10px;">
        <h4 style="color:var(--primary);font-size:1.1rem;margin:0;">${_esc(node.label)}</h4>
        <button type="button" onclick="hideSelectedNode('${_esc(node.id)}')" title="Скрыть узел с холста графа"
            style="background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.4);border-radius:6px;padding:3px 8px;font-size:0.75rem;cursor:pointer;display:flex;align-items:center;gap:4px;flex-shrink:0;">
            🙈 Скрыть узел
        </button>
    </div>`;
    html += `<p style="margin-top:6px;font-size:0.9rem;"><strong>Тип узла:</strong> ${typeLabel}</p>`;

    if (node.group === 'ip') {
        html += _buildIpSection(node);
    } else {
        html += _buildDomainSection(node);
    }

    // HTTP Tech Stack block (loaded async)
    html += `<div id="http-tech-container" style="margin-top:1.25rem;padding-top:1rem;border-top:1px solid rgba(255,255,255,0.1);">
        <div style="font-size:0.85rem;color:var(--text-muted);">⏳ Анализ HTTP Security Headers &amp; Стек технологий...</div>
    </div>`;

    // Vuln scan button
    html += `<div style="margin-top:1.5rem;padding-top:1rem;border-top:1px solid rgba(255,255,255,0.1);">
        <button id="btn-vuln-scan" class="btn" style="width:100%;justify-content:center;"
            onclick="triggerVulnScan('${_esc(node.label)}','${node.group}',window.selectedVulnPorts)">
            🛡️ Поиск уязвимостей (Nmap &amp; Nikto)
        </button>
        <p class="vuln-scan-hint">${window.selectedVulnPorts.length
            ? `Будут проверены уже найденные порты: ${window.selectedVulnPorts.map((p) => `${p.port}/${p.protocol}`).join(', ')}`
            : 'Открытые порты ещё не известны — будет выполнен базовый поиск по популярным портам.'}</p>
        <div id="vuln-scan-container" style="margin-top:10px;"></div>
    </div>`;

    panel.innerHTML = html;

    loadHTTPTechStack(node.label);
    checkNodeVulnStatus(node.label);
}

function _knownPortsForNode(node) {
    const ports = [];
    if (node.group === 'ip') {
        ports.push(...((node.details && node.details.open_ports) || []));
    } else {
        const connected = new Set((node.details && node.details.connected_ips) || []);
        ((currentGraphData && currentGraphData.nodes) || []).forEach((candidate) => {
            if (candidate.group === 'ip' && connected.has(candidate.label)) {
                ports.push(...((candidate.details && candidate.details.open_ports) || []));
            }
        });
    }
    const unique = new Map();
    ports.forEach((port) => {
        const normalized = {
            port: Number(port.port), protocol: port.protocol || 'tcp', service: port.service || '',
            version: port.version || '', tunnel: port.tunnel || '',
            http_detected: Boolean(port.http_detected), service_confidence: Number(port.service_confidence || 0),
            cpe: port.cpe || '',
        };
        if (normalized.port >= 1 && normalized.port <= 65535) unique.set(`${normalized.protocol}:${normalized.port}`, normalized);
    });
    return Array.from(unique.values()).sort((a, b) => a.port - b.port);
}

function closeNodeDetails() {
    const drawer = document.getElementById('details-sidebar');
    if (!drawer) return;
    drawer.classList.remove('open');
    drawer.setAttribute('aria-hidden', 'true');
    if (network) network.unselectAll();
}

document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeNodeDetails();
});

function _buildIpSection(node) {
    const ip = node.label;
    const scanItem = lastScanResults.find((item) => item.ip === ip);
    const domains  = scanItem ? (scanItem.domains || []) : [];

    let html = `<p style="margin-top:6px;font-size:0.9rem;"><strong>Привязанных доменов:</strong> ${domains.length}</p>`;
    html += `<h5 style="margin-top:1.25rem;">Список привязанных доменов (${domains.length}):</h5>`;

    if (domains.length === 0) {
        html += `<p style="color:var(--text-muted);font-size:0.85rem;margin-top:4px;">Привязанные домены не обнаружены</p>`;
    } else {
        html += `<div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;max-height:220px;overflow-y:auto;padding-right:4px;">`;
        domains.forEach((d) => {
            html += `<span class="badge badge-live" style="font-size:0.85rem;padding:6px 10px;">🔗 ${_esc(d)}</span>`;
        });
        html += `</div>`;
    }

    html += `<div style="display:flex;gap:8px;margin-top:12px;margin-bottom:12px;flex-wrap:wrap;">
        <button type="button" onclick="rescanSingleIp('${_esc(ip)}',false)"
            style="background:rgba(16,185,129,0.15);color:#34d399;border:1px solid rgba(16,185,129,0.4);border-radius:6px;padding:6px 12px;font-size:0.8rem;cursor:pointer;flex:1;display:flex;align-items:center;justify-content:center;gap:4px;">
            🔍 Повторный поиск доменов
        </button>
        <button type="button" onclick="rescanSingleIp('${_esc(ip)}',true)"
            style="background:rgba(139,92,246,0.15);color:#c4b5fd;border:1px solid rgba(139,92,246,0.4);border-radius:6px;padding:6px 12px;font-size:0.8rem;cursor:pointer;flex:1;display:flex;align-items:center;justify-content:center;gap:4px;">
            ⚡ Сканировать порты Nmap
        </button>
    </div>`;

    html += `<h5 style="margin-top:1rem;">Открытые порты Nmap:</h5>`;
    const ports = node.details && node.details.open_ports ? node.details.open_ports : [];
    const nmapStatus = node.details && node.details.nmap_status;
    const nmapError = node.details && node.details.nmap_error;
    if (nmapStatus === 'error' || nmapStatus === 'unavailable' || nmapStatus === 'skipped') {
        html += `<div class="nmap-notice">⚠ ${_esc(nmapError || 'Сканирование портов не выполнено')}</div>`;
    } else if (nmapStatus === 'completed') {
        const hostInfo = [node.details.nmap_hostname, node.details.nmap_os].filter(Boolean).map(_esc).join(' · ');
        html += `<div class="nmap-success">✓ Nmap завершён${hostInfo ? ` · ${hostInfo}` : ''}</div>`;
    }
    if (ports.length === 0 && nmapStatus === 'completed') {
        html += `<p style="color:var(--text-muted);font-size:0.85rem;margin-top:4px;">Nmap успешно завершён: в выбранном профиле открытые порты не обнаружены.</p>`;
    } else if (ports.length === 0 && !nmapStatus) {
        html += `<div class="nmap-notice">Результат Nmap отсутствует или создан старой версией сервера. Перезапустите сервер и выполните сканирование с включённым Nmap.</div>`;
    } else if (ports.length > 0) {
        html += `<ul style="margin-top:6px;padding-left:18px;font-size:0.85rem;">`;
        ports.forEach((p) => {
            const service = p.tunnel ? `${p.tunnel}/${p.service}` : p.service;
            const confidence = p.service_method === 'table' && !p.version ? ' · предположение по номеру порта' : '';
            html += `<li><b>${p.port}/${p.protocol}</b> — ${_esc(service)} (${_esc(p.version || 'версия не определена')})<span class="service-confidence">${confidence}</span></li>`;
        });
        html += `</ul>`;
    }
    return html;
}

function _buildDomainSection(node) {
    let connectedIPs = [];
    if (node.details && node.details.connected_ips && node.details.connected_ips.length > 0) {
        connectedIPs = node.details.connected_ips;
    } else if (currentGraphData && currentGraphData.edges) {
        // B-01 fix: was .startswith (Python), must be .startsWith (JS)
        currentGraphData.edges.forEach((e) => {
            const otherId = e.to === node.id ? e.from : e.to;
            if (otherId.startsWith('ip:')) {
                connectedIPs.push(otherId.replace('ip:', ''));
            }
        });
    }

    let html = '';
    if (node.group === 'subdomain' && node.details && node.details.parent) {
        html += `<p style="margin-top:4px;font-size:0.9rem;"><strong>Родительский домен:</strong> ${_esc(node.details.parent)}</p>`;
    }

    html += `<h5 style="margin-top:1.25rem;">Привязанные IP-адреса:</h5>`;
    if (connectedIPs.length === 0) {
        html += `<p style="color:var(--text-muted);font-size:0.85rem;margin-top:4px;">Прямых привязок к IP не найдено</p>`;
    } else {
        html += `<div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;">`;
        connectedIPs.forEach((ip) => {
            html += `<span class="badge badge-port" style="font-size:0.85rem;padding:6px 10px;">🌐 ${_esc(ip)}</span>`;
        });
        html += `</div>`;
    }
    return html;
}

/* ----------------------------------------------------------
   renderTable — results table below the graph
   ---------------------------------------------------------- */
function renderTable(results) {
    const tbody = document.getElementById('table-body');
    tbody.innerHTML = '';

    const withDomains = results.filter((item) => item.domains && item.domains.length > 0);
    if (withDomains.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state">База данных пуста. Введите целевой IP/диапазон и нажмите «Сканировать».</td></tr>';
        return;
    }

    withDomains.forEach((item) => {
        const tr = document.createElement('tr');
        const portsHtml = item.open_ports && item.open_ports.length > 0
            ? item.open_ports.map((p) => `<span class="badge badge-port">${p.port}/${_esc(p.service)}</span>`).join(' ')
            : '<span style="color:var(--text-muted)">—</span>';
        const domainsHtml = item.domains.map((d) => `<span class="badge badge-live">${_esc(d)}</span>`).join(' ');

        tr.innerHTML = `
            <td><strong>${_esc(item.ip)}</strong></td>
            <td>${item.total_domains}</td>
            <td>${portsHtml}</td>
            <td>${domainsHtml}</td>
        `;
        tbody.appendChild(tr);
    });
}

/* ----------------------------------------------------------
   saveNodePositionsBatch — persist drag positions to SQLite
   ---------------------------------------------------------- */
async function saveNodePositionsBatch(positionsMap) {
    if (!positionsMap || Object.keys(positionsMap).length === 0) return;
    try {
        await fetch('/api/graph/positions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ positions: positionsMap }),
        });
    } catch (e) {
        console.error('Failed to save node positions:', e);
    }
}

/* ----------------------------------------------------------
   rescanSingleIp — quick-action from node detail sidebar
   ---------------------------------------------------------- */
function rescanSingleIp(ip, enableNmap = false) {
    const input      = document.getElementById('target-input');
    input.value      = ip;
    const mode = enableNmap ? 'nmap' : 'domains';
    const modeInput = document.querySelector(`input[name="scan-mode"][value="${mode}"]`);
    if (modeInput) modeInput.checked = true;
    if (typeof updateScanModeControls === 'function') updateScanModeControls();
    window.scrollTo({ top: 0, behavior: 'smooth' });
    input.style.border = '2px solid var(--primary)';
    setTimeout(() => { input.style.border = ''; }, 1500);
}

/* ----------------------------------------------------------
   exportData — client-side JSON / CSV export
   ---------------------------------------------------------- */
function exportData(format) {
    if (!lastScanResults.length) {
        alert('Нет данных для экспорта!');
        return;
    }
    let blob, filename;
    if (format === 'json') {
        blob     = new Blob([JSON.stringify(lastScanResults, null, 2)], { type: 'application/json' });
        filename = 'ip2domain_topology.json';
    } else {
        const rows = ['IP,Domain,Ports'];
        lastScanResults.forEach((item) => {
            const ports = (item.open_ports || []).map((p) => `${p.port}/${p.service}`).join(';');
            if (item.domains && item.domains.length > 0) {
                item.domains.forEach((d) => rows.push(`${item.ip},${d},"${ports}"`));
            } else {
                rows.push(`${item.ip},,`);
            }
        });
        blob     = new Blob([rows.join('\n')], { type: 'text/csv' });
        filename = 'ip2domain_topology.csv';
    }
    const a  = document.createElement('a');
    a.href   = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
}

/* ----------------------------------------------------------
   _esc — minimal HTML escape to prevent XSS in innerHTML
   ---------------------------------------------------------- */
function _esc(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

/* ----------------------------------------------------------
   clearGraphCanvas — clears graph network and UI tables,
   preserving SQLite database records.
   ---------------------------------------------------------- */
function clearGraphCanvas() {
    if (network) {
        network.destroy();
        network = null;
    }
    currentGraphData = { nodes: [], edges: [], stats: {} };
    lastScanResults  = [];
    closeNodeDetails();

    // Reset stat values
    document.getElementById('stat-ips').textContent         = '0';
    document.getElementById('stat-apex').textContent        = '0';
    document.getElementById('stat-subdomains').textContent  = '0';
    document.getElementById('stat-edges').textContent       = '0';

    // Reset details sidebar
    const sidebarContent = document.getElementById('node-info-content');
    if (sidebarContent) {
        sidebarContent.innerHTML = `<p style="color:var(--text-muted);font-size:0.9rem;">
            Холст очищен (данные в базе сохранены). Выполните новое сканирование или нажмите «Загрузить из БД».
        </p>`;
    }

    // Reset results table
    const tbody = document.getElementById('table-body');
    if (tbody) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-state">Холст очищен. Введите целевой адрес и нажмите «Сканировать»</td></tr>`;
    }
}

function _getCascadeHiddenNodeIds(nodeId) {
    const graph = currentGraphData || {nodes: [], edges: []};
    const nodeMap = new Map((graph.nodes || []).map((node) => [node.id, node]));
    const selected = nodeMap.get(nodeId);
    if (!selected) return [nodeId];

    const hidden = new Set([nodeId]);
    if (selected.group === 'subdomain') return Array.from(hidden);

    if (selected.group === 'apex_domain') {
        const apex = (selected.details && selected.details.domain) || selected.label;
        (graph.nodes || []).forEach((node) => {
            if (node.group === 'subdomain' && node.details && node.details.parent === apex) hidden.add(node.id);
        });
        // Keep shared IPs visible when they also host domains outside this apex branch.
        ((selected.details && selected.details.connected_ips) || []).forEach((ip) => {
            const hasOutsideDomain = (graph.nodes || []).some((node) =>
                !hidden.has(node.id) &&
                (node.group === 'apex_domain' || node.group === 'subdomain') &&
                node.details && (node.details.connected_ips || []).includes(ip)
            );
            if (!hasOutsideDomain) hidden.add(`ip:${ip}`);
        });
        return Array.from(hidden);
    }

    if (selected.group === 'ip') {
        const ip = (selected.details && selected.details.ip) || selected.label || nodeId.replace(/^ip:/, '');
        (graph.nodes || []).forEach((node) => {
            if ((node.group === 'apex_domain' || node.group === 'subdomain') &&
                node.details && (node.details.connected_ips || []).includes(ip)) {
                hidden.add(node.id);
            }
        });
    }
    return Array.from(hidden);
}

/* Hide a node using type-aware cascade rules, without walking unrelated branches. */
async function hideSelectedNode(nodeId) {
    if (!nodesDataSet || !nodeId) return;

    try {
        const nodeIdsArray = _getCascadeHiddenNodeIds(nodeId);
        const hiddenSet = new Set(nodeIdsArray);
        const edgesToRemove = edgesDataSet
            ? edgesDataSet.get().filter((edge) => hiddenSet.has(edge.from) || hiddenSet.has(edge.to)).map((edge) => edge.id)
            : [];

        if (edgesDataSet && edgesToRemove.length) edgesDataSet.remove(edgesToRemove);
        nodesDataSet.remove(nodeIdsArray);

        currentGraphData.nodes = (currentGraphData.nodes || []).filter((node) => !hiddenSet.has(node.id));
        currentGraphData.edges = (currentGraphData.edges || []).filter(
            (edge) => !hiddenSet.has(edge.from) && !hiddenSet.has(edge.to)
        );
        currentGraphData.stats = {
            total_nodes: currentGraphData.nodes.length,
            total_edges: currentGraphData.edges.length,
            ip_count: currentGraphData.nodes.filter((node) => node.group === 'ip').length,
            apex_count: currentGraphData.nodes.filter((node) => node.group === 'apex_domain').length,
            subdomain_count: currentGraphData.nodes.filter((node) => node.group === 'subdomain').length,
        };
        document.getElementById('stat-ips').textContent = currentGraphData.stats.ip_count;
        document.getElementById('stat-apex').textContent = currentGraphData.stats.apex_count;
        document.getElementById('stat-subdomains').textContent = currentGraphData.stats.subdomain_count;
        document.getElementById('stat-edges').textContent = currentGraphData.stats.total_edges;

        try {
            await fetch('/api/graph/nodes/hide', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ node_ids: nodeIdsArray }),
            });
        } catch (e) {
            console.error('Failed to persist hidden nodes on server:', e);
        }
    } catch (e) {
        console.error('Error hiding graph nodes:', e);
    }

    const panel = document.getElementById('node-info-content');
    if (panel) {
        panel.innerHTML = `<p style="color:var(--text-muted);font-size:0.9rem;">
            Выбранный узел и соответствующие ему связи скрыты. Вернуть их можно через меню «Скрытые».
        </p>`;
    }
    closeNodeDetails();
    updateHiddenNodesUI();
}

/* ----------------------------------------------------------
   Hidden Nodes Dropdown & Selective Unhide Manager
   ---------------------------------------------------------- */
function toggleHiddenDropdown() {
    const dropdown = document.getElementById('hidden-nodes-dropdown');
    if (!dropdown) return;
    const isVisible = dropdown.style.display === 'block';
    dropdown.style.display = isVisible ? 'none' : 'block';
    if (!isVisible) {
        updateHiddenNodesUI();
    }
}

async function updateHiddenNodesUI() {
    const countSpan = document.getElementById('hidden-count');
    const listDiv   = document.getElementById('hidden-nodes-list');
    if (!listDiv) return;

    try {
        const res = await fetch('/api/graph/nodes/hidden');
        if (!res.ok) return;
        const data = await res.json();
        const hiddenIds = data.hidden_nodes || [];

        if (countSpan) countSpan.textContent = hiddenIds.length;

        if (hiddenIds.length === 0) {
            listDiv.innerHTML = '<div style="color:var(--text-muted);padding:8px 0;text-align:center;">Скрытых узлов нет</div>';
            return;
        }

        const groups = [
            ['ip:', 'IP-адреса', '🖥', 'var(--accent-orange)'],
            ['domain:', 'Домены', '◆', 'var(--accent-green)'],
            ['subdomain:', 'Поддомены', '◇', 'var(--accent-purple)'],
        ];
        listDiv.innerHTML = groups.map(([prefix, title, icon, color]) => {
            const ids = hiddenIds.filter((id) => id.startsWith(prefix));
            if (!ids.length) return '';
            return `<div class="hidden-node-group"><div class="hidden-node-group-title" style="color:${color}">${title} · ${ids.length}</div>${ids.map((id) => {
                const label = id.slice(prefix.length);
                return `<div class="hidden-node-row"><span>${icon} ${_esc(label)}</span><button type="button" onclick="unhideSingleNode('${id}')" title="Вернуть на граф">Вернуть</button></div>`;
            }).join('')}</div>`;
        }).join('');
    } catch (e) {
        console.error('Failed to update hidden nodes UI:', e);
    }
}

async function unhideSingleNode(nodeId) {
    try {
        await fetch('/api/graph/nodes/unhide', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ node_ids: [nodeId] }),
        });
        reloadCurrentGraph();
        setTimeout(updateHiddenNodesUI, 300);
    } catch (e) {
        console.error('Failed to unhide node:', e);
    }
}

async function unhideAllNodes() {
    try {
        await fetch('/api/graph/nodes/unhide-all', { method: 'POST' });
        reloadCurrentGraph();
        setTimeout(updateHiddenNodesUI, 300);
    } catch (e) {
        console.error('Failed to restore hidden nodes:', e);
    }
}
