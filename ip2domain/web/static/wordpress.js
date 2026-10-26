/**
 * WordPress Hunter Frontend Module
 * High-speed mass discovery, version fingerprinting, and security audit client.
 */

(function () {
    const WPHunterApp = {
        activeJobId: null,
        pollInterval: null,
        currentPage: 0,
        pageSize: 50,
        currentFilter: {
            onlyWp: true,
            version: '',
            plugin: '',
            search: ''
        },

        init() {
            this.loadStats();
            this.loadJobs();
            this.loadResults();

            const targetsTextarea = document.getElementById('wp-input-targets');
            if (targetsTextarea) {
                targetsTextarea.addEventListener('input', () => this.updateTargetCounter());
                document.querySelectorAll('.wp-port-cb').forEach(cb => {
                    cb.addEventListener('change', () => this.updateTargetCounter());
                });
                this.updateTargetCounter();
            }
        },

        async loadStats() {
            try {
                const res = await fetch('/api/wp/stats');
                if (!res.ok) return;
                const stats = await res.json();
                
                const setEl = (id, val) => {
                    const el = document.getElementById(id);
                    if (el) el.textContent = val;
                };

                setEl('wp-stat-scanned', stats.total_scanned || 0);
                setEl('wp-stat-total-wp', stats.total_wp || 0);
                setEl('wp-stat-versions', stats.total_versions || 0);
                setEl('wp-stat-outdated', stats.outdated_wp || 0);

                // Populate plugin filter options
                const pluginSelect = document.getElementById('wp-filter-plugin');
                if (pluginSelect && stats.top_plugins) {
                    const currentVal = pluginSelect.value;
                    let opts = '<option value="">Все плагины</option>';
                    for (const [p, cnt] of Object.entries(stats.top_plugins)) {
                        opts += `<option value="${p}">${p} (${cnt})</option>`;
                    }
                    pluginSelect.innerHTML = opts;
                    pluginSelect.value = currentVal;
                }

                // Render top plugins tags in summary card
                const pluginTagsEl = document.getElementById('wp-top-plugins-tags');
                if (pluginTagsEl && stats.top_plugins) {
                    const badges = Object.entries(stats.top_plugins).slice(0, 6).map(([p, cnt]) => 
                        `<span class="wp-badge wp-badge-plugin" onclick="WPHunterApp.setFilterPlugin('${p}')">${p} <small>(${cnt})</small></span>`
                    ).join(' ');
                    pluginTagsEl.innerHTML = badges || '<span style="color:#64748b;font-size:0.75rem;">Пока нет данных</span>';
                }
            } catch (err) {
                console.error('[WPHunter] Failed to load stats:', err);
            }
        },

        async loadJobs() {
            try {
                const res = await fetch('/api/wp/jobs');
                if (!res.ok) return;
                const jobs = await res.json();
                const running = jobs.find(j => j.status === 'running' || j.status === 'queued');
                
                if (running) {
                    this.activeJobId = running.id || running.job_id;
                    this.renderActiveJob(running);
                    this.startPolling();
                } else {
                    this.stopPolling();
                    this.activeJobId = null;
                    const banner = document.getElementById('wp-active-job-banner');
                    if (banner) banner.style.display = 'none';
                    const stopBtn = document.getElementById('wp-stop-btn');
                    if (stopBtn) stopBtn.style.display = 'none';
                }
            } catch (err) {
                console.error('[WPHunter] Failed to load jobs:', err);
            }
        },

        async startScan() {
            const rawTargets = document.getElementById('wp-input-targets').value.trim();
            if (!rawTargets) {
                alert('Пожалуйста, укажите хотя бы одну цель (домен, IP или CIDR)');
                return;
            }

            const stats = this.calculateTargetStats(rawTargets);
            if (stats.totalIps > 50000) {
                const confirmed = confirm(
                    `⚠️ Внимание: в списке указано ${stats.totalIps.toLocaleString()} IP адресов (около ${stats.totalChecks.toLocaleString()} проверок портов).\n\n` +
                    `Сканирование такого огромного диапазона выполняется в фоновом режиме через асинхронный пул и может занять длительное время.\n\n` +
                    `Запустить сканирование?`
                );
                if (!confirmed) return;
            }

            const targets = rawTargets.split(/[\r\n]+/).map(t => t.trim()).filter(Boolean);
            const ports = [];
            document.querySelectorAll('.wp-port-cb:checked').forEach(cb => {
                ports.push(parseInt(cb.value, 10));
            });

            const concurrency = parseInt(document.getElementById('wp-concurrency-input').value, 10) || 150;
            const deepScan = document.getElementById('wp-deep-scan-toggle').checked;

            const startBtn = document.getElementById('wp-start-btn');
            startBtn.disabled = true;
            startBtn.innerHTML = '<span class="wp-spinner"></span> Запуск...';

            try {
                const res = await fetch('/api/wp/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        targets: targets,
                        ports: ports.length ? ports : [80, 443],
                        concurrency: concurrency,
                        deep_scan: deepScan
                    })
                });

                if (!res.ok) {
                    const err = await res.json();
                    alert('Ошибка: ' + (err.detail || 'Не удалось запустить сканирование'));
                    return;
                }

                const data = await res.json();
                this.activeJobId = data.job_id;
                this.startPolling();
                this.loadStats();
                this.loadResults();
            } catch (err) {
                alert('Ошибка сети: ' + err.message);
            } finally {
                startBtn.disabled = false;
                startBtn.innerHTML = '🚀 Запустить сканирование';
            }
        },

        async stopScan() {
            const stopBtn = document.getElementById('wp-stop-btn');
            if (stopBtn) stopBtn.disabled = true;

            const jId = this.activeJobId;
            this.stopPolling();
            this.activeJobId = null;

            const banner = document.getElementById('wp-active-job-banner');
            if (banner) banner.style.display = 'none';
            if (stopBtn) stopBtn.style.display = 'none';

            try {
                if (jId) {
                    await fetch(`/api/wp/job/${jId}/stop`, { method: 'POST' });
                }
                await fetch('/api/wp/jobs/stop-all', { method: 'POST' });
                await this.loadJobs();
                await this.loadResults();
                await this.loadStats();
            } catch (err) {
                console.error('[WPHunter] Failed to stop job:', err);
            } finally {
                if (stopBtn) stopBtn.disabled = false;
            }
        },

        startPolling() {
            if (this.pollInterval) clearInterval(this.pollInterval);
            this.pollInterval = setInterval(async () => {
                if (!this.activeJobId) {
                    this.stopPolling();
                    return;
                }
                try {
                    const res = await fetch(`/api/wp/job/${this.activeJobId}`);
                    if (!res.ok) {
                        this.stopPolling();
                        this.loadJobs();
                        return;
                    }
                    const job = await res.json();
                    this.renderActiveJob(job);
                    this.loadResults(false);
                    this.loadStats();

                    if (job.status === 'completed' || job.status === 'stopped' || job.status === 'error') {
                        this.stopPolling();
                        if (job.status === 'stopped') {
                            const banner = document.getElementById('wp-active-job-banner');
                            if (banner) banner.style.display = 'none';
                        }
                    }
                } catch (e) {
                    console.error('[WPHunter] Polling error:', e);
                }
            }, 1500);
        },

        stopPolling() {
            if (this.pollInterval) {
                clearInterval(this.pollInterval);
                this.pollInterval = null;
            }
        },

        renderActiveJob(job) {
            const container = document.getElementById('wp-active-job-banner');
            const stopBtn = document.getElementById('wp-stop-btn');
            if (!container) return;

            if (job.status === 'stopped') {
                container.style.display = 'none';
                if (stopBtn) stopBtn.style.display = 'none';
                return;
            }

            const isRunning = job.status === 'running' || job.status === 'queued';
            container.style.display = 'block';

            const pct = job.progress_pct || 0;
            const stage = job.stage || 'Выполняется сканирование...';
            const found = job.found_wp || 0;
            const completed = job.completed_targets || 0;
            const total = job.total_targets || 0;

            document.getElementById('wp-job-status-text').innerHTML = `
                <div style="display:flex;align-items:center;gap:8px;">
                    ${isRunning ? '<span class="wp-spinner"></span>' : '✓'}
                    <span style="font-weight:600;color:#e2e8f0;">${stage}</span>
                </div>
            `;
            document.getElementById('wp-job-counter-text').textContent = `WordPress: ${found} · Готово: ${completed}/${total}`;
            document.getElementById('wp-job-progress-bar').style.width = `${pct}%`;

            const stopBtn = document.getElementById('wp-stop-btn');
            if (stopBtn) stopBtn.style.display = isRunning ? 'inline-flex' : 'none';
        },

        async loadResults(resetPage = true) {
            if (resetPage) this.currentPage = 0;
            const offset = this.currentPage * this.pageSize;

            const params = new URLSearchParams({
                only_wp: this.currentFilter.onlyWp ? 'true' : 'false',
                limit: this.pageSize,
                offset: offset
            });
            if (this.currentFilter.version) params.append('version', this.currentFilter.version);
            if (this.currentFilter.plugin) params.append('plugin', this.currentFilter.plugin);
            if (this.currentFilter.search) params.append('search', this.currentFilter.search);

            try {
                const res = await fetch(`/api/wp/results?${params.toString()}`);
                if (!res.ok) return;
                const data = await res.json();
                this.renderResultsTable(data.items, data.total);
            } catch (err) {
                console.error('[WPHunter] Failed to load results:', err);
            }
        },

        renderResultsTable(items, total) {
            const tbody = document.getElementById('wp-results-tbody');
            const totalCountEl = document.getElementById('wp-results-count');
            if (totalCountEl) totalCountEl.textContent = `Найдено сайтов: ${total}`;

            if (!items || !items.length) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="7" style="text-align:center;padding:36px;color:#94a3b8;">
                            <div style="font-size:2rem;margin-bottom:8px;">🌐</div>
                            <div>Результатов сканирования пока нет. Введите цели и запустите поиск.</div>
                        </td>
                    </tr>
                `;
                return;
            }

            tbody.innerHTML = items.map(item => {
                const isWp = item.is_wordpress;
                const ver = item.version;
                let verBadge = '<span class="wp-badge wp-badge-gray">Не определена</span>';
                if (ver) {
                    const major = parseFloat(ver) || 0;
                    if (major >= 6.0) {
                        verBadge = `<span class="wp-badge wp-badge-green" title="Источник: ${item.version_source || 'авто'}">v${ver}</span>`;
                    } else if (major >= 5.0) {
                        verBadge = `<span class="wp-badge wp-badge-yellow" title="Источник: ${item.version_source || 'авто'}">v${ver} (устаревшая)</span>`;
                    } else {
                        verBadge = `<span class="wp-badge wp-badge-red" title="Источник: ${item.version_source || 'авто'}">v${ver} (критично стара)</span>`;
                    }
                } else if (!isWp) {
                    verBadge = '<span class="wp-badge wp-badge-gray">—</span>';
                }

                // Plugins pills
                const plugins = item.plugins || [];
                const pluginsHtml = plugins.slice(0, 3).map(p => 
                    `<span class="wp-badge wp-badge-plugin">${p}</span>`
                ).join(' ') + (plugins.length > 3 ? ` <span class="wp-badge wp-badge-gray">+${plugins.length - 3}</span>` : '');

                // Security posture
                const sec = item.security || {};
                const secBadges = [];
                if (sec.users_exposed && sec.users_exposed.length) {
                    secBadges.push(`<span class="wp-badge wp-badge-red" title="Логины: ${sec.users_exposed.join(', ')}">👤 ${sec.users_exposed[0]}</span>`);
                }
                if (sec.xmlrpc_open) {
                    secBadges.push('<span class="wp-badge wp-badge-yellow" title="XML-RPC открыт для внешних запросов">XML-RPC</span>');
                }
                if (sec.registration_open) {
                    secBadges.push('<span class="wp-badge wp-badge-red" title="Регистрация пользователей открыта">Регистрация</span>');
                }

                const theme = item.theme ? `<span class="wp-badge wp-badge-theme">🎨 ${item.theme}</span>` : '<span style="color:#64748b;">—</span>';
                const statusBadge = item.status_code ? `<span class="wp-badge ${item.status_code === 200 ? 'wp-badge-green' : 'wp-badge-gray'}">${item.status_code}</span>` : '';

                return `
                    <tr>
                        <td>
                            <div style="font-weight:600;display:flex;align-items:center;gap:6px;">
                                <a href="${item.url}" target="_blank" rel="noopener" style="color:#60a5fa;text-decoration:none;" class="wp-host-link">
                                    ${item.host}
                                </a>
                                <span style="font-size:0.75rem;color:#64748b;">:${item.port}</span>
                            </div>
                            ${item.title ? `<div style="font-size:0.75rem;color:#94a3b8;max-width:260px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${this.escapeHtml(item.title)}</div>` : ''}
                        </td>
                        <td>${statusBadge}</td>
                        <td>${verBadge}</td>
                        <td>${theme}</td>
                        <td>${pluginsHtml || '<span style="color:#64748b;">—</span>'}</td>
                        <td>${secBadges.join(' ') || '<span class="wp-badge wp-badge-gray">Норма</span>'}</td>
                        <td style="text-align:right;">
                            <button class="v2-btn-small" onclick='WPHunterApp.showModal(${JSON.stringify(item)})' style="padding:3px 10px;font-size:0.75rem;">🔍 Детали</button>
                        </td>
                    </tr>
                `;
            }).join('');
        },

        async importFromTopology() {
            const btn = document.getElementById('wp-import-topology-btn');
            btn.disabled = true;
            btn.innerHTML = '<span class="wp-spinner"></span> Импорт...';

            try {
                const res = await fetch('/api/wp/import_topology', { method: 'POST' });
                if (!res.ok) throw new Error('Не удалось получить данные топологии');
                const data = await res.json();
                
                if (!data.targets || !data.targets.length) {
                    alert('В текущей топологии пока нет сохранённых хостов с веб-портами (80, 443). Сначала запустите сканирование.');
                    return;
                }

                const textarea = document.getElementById('wp-input-targets');
                textarea.value = data.targets.join('\n');
                this.updateTargetCounter();
                alert(`Успешно импортировано ${data.targets.length} хостов из текущей топологии!`);
            } catch (err) {
                alert('Ошибка импорта: ' + err.message);
            } finally {
                btn.disabled = false;
                btn.innerHTML = '📋 Импорт из топологии';
            }
        },

        insertSampleTargets() {
            const textarea = document.getElementById('wp-input-targets');
            if (!textarea) return;
            textarea.value = [
                'eshdesign.ru',
                '193.168.47.0/24',
                '87.236.16.69',
                'https://wordpress.org'
            ].join('\n');
            this.updateTargetCounter();
        },

        calculateTargetStats(rawText) {
            const lines = (rawText || '').split(/[\r\n]+/).map(t => t.trim()).filter(Boolean);
            let totalIps = 0;
            let subnetCount = 0;
            for (const line of lines) {
                if (line.startsWith('#')) continue;
                const m = line.match(/\/(\d{1,2})/);
                if (m) {
                    subnetCount++;
                    const mask = parseInt(m[1], 10);
                    if (mask >= 0 && mask <= 32) {
                        totalIps += Math.pow(2, 32 - mask);
                    } else {
                        totalIps += 1;
                    }
                } else {
                    totalIps += 1;
                }
            }
            const portsCount = document.querySelectorAll('.wp-port-cb:checked').length || 2;
            const totalChecks = totalIps * portsCount;
            return { linesCount: lines.length, subnetCount, totalIps, totalChecks };
        },

        updateTargetCounter() {
            const textarea = document.getElementById('wp-input-targets');
            const counter = document.getElementById('wp-targets-counter');
            if (!textarea || !counter) return;
            const stats = this.calculateTargetStats(textarea.value);
            const strong = counter.querySelector('strong');
            if (strong) {
                if (stats.subnetCount > 0) {
                    strong.innerHTML = `${stats.linesCount} строк <span style="color:#38bdf8;font-weight:600;">(~${stats.totalIps.toLocaleString()} IP)</span> <span style="color:#94a3b8;font-size:0.75rem;">· ~${stats.totalChecks.toLocaleString()} проверок</span>`;
                } else {
                    strong.textContent = stats.linesCount;
                }
            }
        },

        exportResults(format) {
            window.location.href = `/api/wp/export?format=${format}&only_wp=${this.currentFilter.onlyWp}`;
        },

        async clearResults() {
            if (!confirm('Вы уверены, что хотите удалить все сохранённые результаты WordPress?')) return;
            try {
                await fetch('/api/wp/results', { method: 'DELETE' });
                this.loadStats();
                this.loadResults();
                const banner = document.getElementById('wp-active-job-banner');
                if (banner) banner.style.display = 'none';
            } catch (err) {
                alert('Ошибка при очистке: ' + err.message);
            }
        },

        setFilterVersion(val) {
            this.currentFilter.version = val;
            this.loadResults();
        },

        setFilterPlugin(val) {
            this.currentFilter.plugin = val;
            const select = document.getElementById('wp-filter-plugin');
            if (select) select.value = val;
            this.loadResults();
        },

        applySearch(query) {
            this.currentFilter.search = query.trim();
            const clearBtn = document.getElementById('wp-search-clear-btn');
            if (clearBtn) clearBtn.style.display = query.trim() ? 'block' : 'none';
            this.loadResults();
        },

        clearSearch() {
            const searchInput = document.getElementById('wp-search-input');
            const clearBtn = document.getElementById('wp-search-clear-btn');
            if (searchInput) searchInput.value = '';
            if (clearBtn) clearBtn.style.display = 'none';
            this.applySearch('');
        },

        toggleOnlyWp(checked) {
            this.currentFilter.onlyWp = checked;
            this.loadResults();
        },

        showModal(item) {
            const modal = document.getElementById('wp-detail-modal');
            if (!modal) return;

            document.getElementById('wp-modal-url').textContent = item.url || '';
            document.getElementById('wp-modal-url').href = item.url || '#';
            document.getElementById('wp-modal-ip').textContent = `${item.host}:${item.port}`;
            document.getElementById('wp-modal-server').textContent = item.server || 'Не указан';
            document.getElementById('wp-modal-powered').textContent = item.powered_by || 'Не указан';
            document.getElementById('wp-modal-version').textContent = item.version ? `${item.version} (источник: ${item.version_source})` : 'Не определена';
            document.getElementById('wp-modal-theme').textContent = item.theme || 'Не определена';
            document.getElementById('wp-modal-latency').textContent = item.latency_ms ? `${item.latency_ms} мс` : '—';
            document.getElementById('wp-modal-title').textContent = item.title || '—';

            // Plugins
            const plugins = item.plugins || [];
            document.getElementById('wp-modal-plugins').innerHTML = plugins.length 
                ? plugins.map(p => `<span class="wp-badge wp-badge-plugin">${p}</span>`).join(' ')
                : '<span style="color:#64748b;">Плагины в HTML не обнаружены</span>';

            // Security details
            const sec = item.security || {};
            let secHtml = `
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:0.8rem;margin-top:6px;">
                    <div><strong>XML-RPC:</strong> ${sec.xmlrpc_open ? '<span style="color:#eab308;">Открыт для запросов (405/200)</span>' : '<span style="color:#10b981;">Заблокирован (403/404)</span>'}</div>
                    <div><strong>Регистрация аккаунтов:</strong> ${sec.registration_open ? '<span style="color:#ef4444;">Включена!</span>' : '<span style="color:#10b981;">Отключена</span>'}</div>
                </div>
            `;
            if (sec.users_exposed && sec.users_exposed.length) {
                secHtml += `
                    <div style="margin-top:8px;font-size:0.8rem;background:rgba(239,68,68,0.1);padding:6px 10px;border-radius:6px;border:1px solid rgba(239,68,68,0.25);">
                        ⚠️ <strong>Раскрыты логины через REST API:</strong> ${sec.users_exposed.map(u => `<code>${u}</code>`).join(', ')}
                    </div>
                `;
            }
            document.getElementById('wp-modal-security').innerHTML = secHtml;

            modal.style.display = 'flex';
        },

        closeModal() {
            const modal = document.getElementById('wp-detail-modal');
            if (modal) modal.style.display = 'none';
        },

        escapeHtml(text) {
            return String(text || '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }
    };

    window.WPHunterApp = WPHunterApp;
})();
