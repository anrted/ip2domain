/**
 * City IP Finder — Russian & Belarusian Subnet Explorer & Direct Scanner Dispatcher
 * Instant direct CIDR pipeline transfer into Camera Scanner v2, RDP/VNC, and Recon Graph.
 */

(function () {
    'use strict';

    // State
    const state = {
        activeCountry: 'ALL', // 'ALL' | 'RU' | 'BY'
        selectedRegion: '',
        selectedCity: '',
        selectedIsp: '',
        searchQuery: '',
        limit: 100,
        offset: 0,
        totalSubnets: 0,
        subnets: [],
        selectedCidrs: new Set(),
        countriesSummary: [],
        regions: [],
        cities: [],
        providers: [],
    };

    // DOM Elements Cache
    let dom = {};

    function initDomElements() {
        dom = {
            countryBtns: document.querySelectorAll('.geo-country-tab-btn'),
            regionSelect: document.getElementById('geo-region-select'),
            ispSelect: document.getElementById('geo-isp-select'),
            citySearchInput: document.getElementById('geo-search-input'),
            quickChipsContainer: document.getElementById('geo-quick-chips'),
            statsRuIps: document.getElementById('geo-stat-ru-ips'),
            statsByIps: document.getElementById('geo-stat-by-ips'),
            statsTotalSubnets: document.getElementById('geo-stat-total-subnets'),
            statsSelectedCount: document.getElementById('geo-stat-selected-count'),
            subnetsTableBody: document.getElementById('geo-subnets-tbody'),
            selectAllCheckbox: document.getElementById('geo-select-all'),
            paginationInfo: document.getElementById('geo-pagination-info'),
            btnPrevPage: document.getElementById('geo-prev-page'),
            btnNextPage: document.getElementById('geo-next-page'),
            selectedCidrsTextarea: document.getElementById('geo-selected-cidrs-text'),
            selectedCountBadge: document.getElementById('geo-selected-count-badge'),
            btnSelectAllFilter: document.getElementById('geo-btn-select-all-filter'),
            btnClearSelection: document.getElementById('geo-btn-clear-selection'),
            btnSendToCamV2: document.getElementById('geo-btn-send-cam-v2'),
            btnSendToCamV2Top: document.getElementById('geo-btn-send-cam-v2-top'),
            btnSendToRdp: document.getElementById('geo-btn-send-rdp'),
            btnSendToRdpTop: document.getElementById('geo-btn-send-rdp-top'),
            btnSendToRecon: document.getElementById('geo-btn-send-recon'),
            btnSendToReconTop: document.getElementById('geo-btn-send-recon-top'),
            btnCopyCidrs: document.getElementById('geo-btn-copy-cidrs'),
            btnCopyCidrsTop: document.getElementById('geo-btn-copy-cidrs-top'),
            btnDownloadTxt: document.getElementById('geo-btn-download-txt'),
            btnDownloadJson: document.getElementById('geo-btn-download-json'),
            btnDownloadCsv: document.getElementById('geo-btn-download-csv'),
            btnResetFilters: document.getElementById('geo-btn-reset-filters'),
            lookupInput: document.getElementById('geo-lookup-input'),
            btnLookup: document.getElementById('geo-btn-lookup'),
            lookupResult: document.getElementById('geo-lookup-result'),
        };
    }

    // Popular Quick City presets
    const POPULAR_CITIES = {
        RU: [
            'Москва', 'Санкт-Петербург', 'Новокузнецк', 'Новосибирск', 'Екатеринбург',
            'Казань', 'Нижний Новгород', 'Челябинск', 'Самара', 'Ростов-на-Дону',
            'Уфа', 'Красноярск', 'Кемерово', 'Краснодар', 'Воронеж', 'Пермь',
            'Волгоград', 'Саратов', 'Тюмень', 'Сургут', 'Сочи', 'Калининград'
        ],
        BY: [
            'Минск', 'Гомель', 'Могилёв', 'Витебск', 'Гродно',
            'Брест', 'Бобруйск', 'Барановичи', 'Борисов', 'Пинск',
            'Мозырь', 'Солигорск', 'Лида', 'Орша', 'Полоцк'
        ]
    };

    function formatNumber(num) {
        return (num || 0).toLocaleString('ru-RU');
    }

    // ─────────────────────────────────────────────────────────────────────────
    // API Data Loaders
    // ─────────────────────────────────────────────────────────────────────────

    async function loadCountriesSummary() {
        try {
            const resp = await fetch('/api/geo/countries');
            if (!resp.ok) return;
            const data = await resp.json();
            state.countriesSummary = data.countries || [];

            let ruTotal = 0, byTotal = 0, totalSub = 0;
            state.countriesSummary.forEach(c => {
                totalSub += c.subnets || 0;
                if (c.code === 'RU') ruTotal = c.ip_count || 0;
                if (c.code === 'BY') byTotal = c.ip_count || 0;
            });

            if (dom.statsRuIps) dom.statsRuIps.textContent = `${formatNumber(ruTotal)} IP`;
            if (dom.statsByIps) dom.statsByIps.textContent = `${formatNumber(byTotal)} IP`;
            if (dom.statsTotalSubnets) dom.statsTotalSubnets.textContent = `${formatNumber(totalSub)} подсетей`;
        } catch (e) {
            console.error('Failed to load countries summary', e);
        }
    }

    async function loadRegions() {
        try {
            const url = state.activeCountry !== 'ALL' ? `/api/geo/regions?country=${state.activeCountry}` : '/api/geo/regions';
            const resp = await fetch(url);
            if (!resp.ok) return;
            const data = await resp.json();
            state.regions = data.regions || [];

            if (!dom.regionSelect) return;
            const curVal = dom.regionSelect.value;
            dom.regionSelect.innerHTML = '<option value="">Все регионы и области</option>';
            state.regions.forEach(r => {
                const opt = document.createElement('option');
                opt.value = r.region;
                const flag = r.country_code === 'RU' ? '🇷🇺 ' : '🇧🇾 ';
                opt.textContent = `${flag}${r.region} (${r.subnets} подсетей, ~${formatNumber(r.ip_count)} IP)`;
                if (r.region === curVal) opt.selected = true;
                dom.regionSelect.appendChild(opt);
            });
        } catch (e) {
            console.error('Failed to load regions', e);
        }
    }

    async function loadProviders() {
        try {
            const url = state.activeCountry !== 'ALL' ? `/api/geo/providers?country=${state.activeCountry}` : '/api/geo/providers';
            const resp = await fetch(url);
            if (!resp.ok) return;
            const data = await resp.json();
            state.providers = data.providers || [];

            if (!dom.ispSelect) return;
            const curVal = dom.ispSelect.value;
            dom.ispSelect.innerHTML = '<option value="">Все провайдеры / ISP</option>';
            state.providers.forEach(p => {
                const opt = document.createElement('option');
                opt.value = p.isp;
                const flag = p.country_code === 'RU' ? '🇷🇺 ' : '🇧🇾 ';
                opt.textContent = `${flag}${p.isp} [${p.asn}] (${p.subnets} диапазонов)`;
                if (p.isp === curVal) opt.selected = true;
                dom.ispSelect.appendChild(opt);
            });
        } catch (e) {
            console.error('Failed to load providers', e);
        }
    }

    function renderQuickCityChips() {
        if (!dom.quickChipsContainer) return;
        dom.quickChipsContainer.innerHTML = '';

        let cityList = [];
        if (state.activeCountry === 'RU') {
            cityList = POPULAR_CITIES.RU;
        } else if (state.activeCountry === 'BY') {
            cityList = POPULAR_CITIES.BY;
        } else {
            cityList = [...POPULAR_CITIES.RU.slice(0, 11), ...POPULAR_CITIES.BY.slice(0, 6)];
        }

        cityList.forEach(cityName => {
            const chip = document.createElement('button');
            chip.type = 'button';
            chip.className = `geo-chip ${state.selectedCity === cityName ? 'active' : ''}`;
            const flag = POPULAR_CITIES.BY.includes(cityName) ? '🇧🇾 ' : '🇷🇺 ';
            chip.innerHTML = `<span class="geo-chip-flag">${flag}</span><span>${cityName}</span>`;
            chip.onclick = () => {
                if (state.selectedCity === cityName) {
                    state.selectedCity = '';
                    chip.classList.remove('active');
                } else {
                    state.selectedCity = cityName;
                    document.querySelectorAll('.geo-chip').forEach(c => c.classList.remove('active'));
                    chip.classList.add('active');
                }
                state.offset = 0;
                loadSubnets();
            };
            dom.quickChipsContainer.appendChild(chip);
        });
    }

    async function loadSubnets() {
        if (!dom.subnetsTableBody) return;

        dom.subnetsTableBody.innerHTML = `<tr><td colspan="7" class="geo-table-loading"><div class="loading-spinner"></div> Поиск диапазонов в базе...</td></tr>`;

        const params = new URLSearchParams();
        if (state.activeCountry !== 'ALL') params.append('country', state.activeCountry);
        if (state.selectedRegion) params.append('region', state.selectedRegion);
        if (state.selectedCity) params.append('city', state.selectedCity);
        if (state.selectedIsp) params.append('isp', state.selectedIsp);
        if (state.searchQuery) params.append('q', state.searchQuery);
        params.append('limit', String(state.limit));
        params.append('offset', String(state.offset));

        try {
            const resp = await fetch(`/api/geo/subnets?${params.toString()}`);
            if (!resp.ok) throw new Error('Ошибка загрузки подсетей');
            const data = await resp.json();
            state.subnets = data.subnets || [];
            state.totalSubnets = data.total || 0;

            renderSubnetsTable();
            updatePagination();
            updateSelectedStats();
        } catch (e) {
            dom.subnetsTableBody.innerHTML = `<tr><td colspan="7" class="geo-table-empty">Ошибка загрузки данных: ${e.message}</td></tr>`;
        }
    }

    function renderSubnetsTable() {
        if (!dom.subnetsTableBody) return;
        dom.subnetsTableBody.innerHTML = '';

        if (!state.subnets.length) {
            dom.subnetsTableBody.innerHTML = `<tr><td colspan="7" class="geo-table-empty">Диапазоны не найдены по заданным критериям фильтрации</td></tr>`;
            return;
        }

        state.subnets.forEach(s => {
            const tr = document.createElement('tr');
            const isChecked = state.selectedCidrs.has(s.cidr);
            const flag = s.country_code === 'RU' ? '🇷🇺' : '🇧🇾';

            tr.innerHTML = `
                <td class="geo-col-select">
                    <input type="checkbox" class="geo-row-checkbox" data-cidr="${s.cidr}" ${isChecked ? 'checked' : ''}>
                </td>
                <td class="geo-col-cidr">
                    <strong class="geo-cidr-text">${s.cidr}</strong>
                    <button type="button" class="geo-mini-btn" title="Копировать CIDR" onclick="window.CityIpFinder.copyText('${s.cidr}')">📋</button>
                </td>
                <td class="geo-col-location">
                    <span class="geo-flag-badge" title="${s.country_name}">${flag}</span>
                    <strong class="geo-city-text">${s.city}</strong>
                    <div class="geo-region-hint">${s.region}</div>
                </td>
                <td class="geo-col-isp">
                    <span class="geo-isp-badge">${s.isp}</span>
                    <div class="geo-org-hint" title="${s.org || ''}">${s.org || ''}</div>
                </td>
                <td class="geo-col-asn">
                    <a href="https://bgp.he.net/${s.asn}" target="_blank" rel="noopener noreferrer" class="geo-asn-link" title="Посмотреть AS в BGP Toolkit">${s.asn}</a>
                </td>
                <td class="geo-col-count">
                    <span class="geo-count-badge">~${formatNumber(s.ip_count)} IP</span>
                </td>
                <td class="geo-col-actions">
                    <button type="button" class="geo-btn-table-action" title="Отправить этот CIDR напрямую в Сканер Камер v2" onclick="window.CityIpFinder.sendSingleCidrToV2('${s.cidr}')">📹 В Камеры v2</button>
                    <button type="button" class="geo-btn-table-action" title="Отправить этот CIDR в RDP/VNC" onclick="window.CityIpFinder.sendSingleCidrToRdp('${s.cidr}')">🖥️ RDP</button>
                </td>
            `;

            const chk = tr.querySelector('.geo-row-checkbox');
            chk.addEventListener('change', (e) => {
                if (e.target.checked) {
                    state.selectedCidrs.add(s.cidr);
                } else {
                    state.selectedCidrs.delete(s.cidr);
                }
                updateSelectAllState();
                updateSelectedStats();
            });

            dom.subnetsTableBody.appendChild(tr);
        });

        updateSelectAllState();
    }

    function updateSelectAllState() {
        if (!dom.selectAllCheckbox) return;
        const pageCidrs = state.subnets.map(s => s.cidr);
        if (!pageCidrs.length) {
            dom.selectAllCheckbox.checked = false;
            dom.selectAllCheckbox.indeterminate = false;
            return;
        }
        const selectedOnPage = pageCidrs.filter(c => state.selectedCidrs.has(c));
        if (selectedOnPage.length === pageCidrs.length) {
            dom.selectAllCheckbox.checked = true;
            dom.selectAllCheckbox.indeterminate = false;
        } else if (selectedOnPage.length > 0) {
            dom.selectAllCheckbox.checked = false;
            dom.selectAllCheckbox.indeterminate = true;
        } else {
            dom.selectAllCheckbox.checked = false;
            dom.selectAllCheckbox.indeterminate = false;
        }
    }

    function updateSelectedStats() {
        const count = state.selectedCidrs.size;
        if (dom.statsSelectedCount) {
            dom.statsSelectedCount.textContent = `${formatNumber(count)} подсетей`;
        }
        if (dom.selectedCountBadge) {
            dom.selectedCountBadge.textContent = `${count} CIDR`;
        }
        if (dom.selectedCidrsTextarea) {
            dom.selectedCidrsTextarea.value = Array.from(state.selectedCidrs).join('\n');
        }
    }

    function updatePagination() {
        if (!dom.paginationInfo) return;
        const start = state.totalSubnets ? state.offset + 1 : 0;
        const end = Math.min(state.offset + state.limit, state.totalSubnets);
        dom.paginationInfo.textContent = `Показано ${start} – ${end} из ${state.totalSubnets}`;

        if (dom.btnPrevPage) dom.btnPrevPage.disabled = state.offset <= 0;
        if (dom.btnNextPage) dom.btnNextPage.disabled = state.offset + state.limit >= state.totalSubnets;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Bulk CIDR Fetcher & Selection
    // ─────────────────────────────────────────────────────────────────────────

    async function selectAllFilterSubnets() {
        if (dom.btnSelectAllFilter) {
            dom.btnSelectAllFilter.disabled = true;
            dom.btnSelectAllFilter.textContent = '⏳ Загрузка...';
        }

        const params = new URLSearchParams();
        if (state.activeCountry !== 'ALL') params.append('country', state.activeCountry);
        if (state.selectedRegion) params.append('region', state.selectedRegion);
        if (state.selectedCity) params.append('city', state.selectedCity);
        if (state.selectedIsp) params.append('isp', state.selectedIsp);
        if (state.searchQuery) params.append('q', state.searchQuery);
        params.append('limit', '5000');

        try {
            const resp = await fetch(`/api/geo/all-cidrs?${params.toString()}`);
            if (!resp.ok) throw new Error('Ошибка получения всех подсетей');
            const data = await resp.json();
            const cidrs = data.cidrs || [];

            cidrs.forEach(c => state.selectedCidrs.add(c));
            renderSubnetsTable();
            updateSelectedStats();
            showToast(`Выбрано ${cidrs.length} подсетей!`);
        } catch (e) {
            alert(`Ошибка: ${e.message}`);
        } finally {
            if (dom.btnSelectAllFilter) {
                dom.btnSelectAllFilter.disabled = false;
                dom.btnSelectAllFilter.textContent = '✓ Выбрать ВСЕ найденные подсети';
            }
        }
    }

    function clearSelection() {
        state.selectedCidrs.clear();
        renderSubnetsTable();
        updateSelectedStats();
    }

    async function getCidrListToTransfer() {
        const textVal = dom.selectedCidrsTextarea?.value.trim() || '';
        if (textVal) return textVal;
        if (state.selectedCidrs.size > 0) return Array.from(state.selectedCidrs).join('\n');

        // If none ticked, fetch all CIDRs for the active filter view automatically
        const params = new URLSearchParams();
        if (state.activeCountry !== 'ALL') params.append('country', state.activeCountry);
        if (state.selectedRegion) params.append('region', state.selectedRegion);
        if (state.selectedCity) params.append('city', state.selectedCity);
        if (state.selectedIsp) params.append('isp', state.selectedIsp);
        if (state.searchQuery) params.append('q', state.searchQuery);
        params.append('limit', '2000');

        try {
            const resp = await fetch(`/api/geo/all-cidrs?${params.toString()}`);
            if (resp.ok) {
                const data = await resp.json();
                const cidrs = data.cidrs || [];
                if (cidrs.length) return cidrs.join('\n');
            }
        } catch (e) {}

        if (state.subnets.length > 0) return state.subnets.map(s => s.cidr).join('\n');
        return '';
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Direct Scanner Pipeline Transfers
    // ─────────────────────────────────────────────────────────────────────────

    async function sendToCameraScannerV2() {
        const targets = await getCidrListToTransfer();
        if (!targets) {
            alert('Сначала выберите диапазоны или город.');
            return;
        }

        const v2Area = document.getElementById('v2-targets');
        if (v2Area) {
            v2Area.value = targets;
        }

        // Switch view to Cameras tab and ensure v2 is active
        if (typeof window.switchView === 'function') {
            const camNavBtn = document.querySelector('.nav-item[data-view="cameras-view"]');
            window.switchView('cameras-view', camNavBtn);
        }
        if (typeof window.switchCameraVersion === 'function') {
            window.switchCameraVersion('v2');
        }
    }

    async function sendToReconGraph() {
        const targets = await getCidrListToTransfer();
        if (!targets) {
            alert('Сначала выберите диапазоны или город.');
            return;
        }

        const firstTarget = targets.split('\n')[0].trim();
        const targetInput = document.getElementById('target-input');
        if (targetInput) {
            targetInput.value = firstTarget;
        }

        if (typeof window.switchView === 'function') {
            const graphNavBtn = document.querySelector('.nav-item[data-view="graph-view"]');
            window.switchView('graph-view', graphNavBtn);
        }
    }

    async function sendToRemoteDesktop() {
        const targets = await getCidrListToTransfer();
        if (!targets) {
            alert('Сначала выберите диапазоны или город.');
            return;
        }

        const remoteArea = document.getElementById('remote-target');
        if (remoteArea) {
            remoteArea.value = targets;
        }

        if (typeof window.switchView === 'function') {
            const rdpNavBtn = document.querySelector('.nav-item[data-view="remote-desktop-view"]');
            window.switchView('remote-desktop-view', rdpNavBtn);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Reverse Geo Lookup Tool
    // ─────────────────────────────────────────────────────────────────────────

    async function performLookup() {
        const query = dom.lookupInput?.value.trim();
        if (!query) return;

        if (dom.btnLookup) {
            dom.btnLookup.disabled = true;
            dom.btnLookup.textContent = '⏳ Поиск...';
        }
        if (dom.lookupResult) {
            dom.lookupResult.style.display = 'block';
            dom.lookupResult.innerHTML = '<div class="loading-spinner"></div> Определение геолокации...';
        }

        try {
            const resp = await fetch(`/api/geo/lookup?ip=${encodeURIComponent(query)}`);
            if (!resp.ok) throw new Error('Ошибка сервера');
            const json = await resp.json();

            if (!json.found || !json.data) {
                dom.lookupResult.innerHTML = `
                    <div class="geo-lookup-not-found">
                        Информация для <code>${query}</code> не найдена в базе РФ/РБ.
                    </div>
                `;
                return;
            }

            const d = json.data;
            const flag = d.country_code === 'RU' ? '🇷🇺 Россия' : d.country_code === 'BY' ? '🇧🇾 Беларусь' : d.country_name;

            dom.lookupResult.innerHTML = `
                <div class="geo-lookup-card">
                    <div class="geo-lookup-header">
                        <h4>${flag} • ${d.city || 'Неизвестно'}</h4>
                        <span class="geo-source-tag">${json.source === 'local_db' ? 'GeoLite2 РФ/РБ' : 'Online GeoIP'}</span>
                    </div>
                    <div class="geo-lookup-grid">
                        <div><strong>Подсеть/CIDR:</strong> <code>${d.cidr}</code></div>
                        <div><strong>Регион:</strong> ${d.region || '—'}</div>
                        <div><strong>Провайдер (ISP):</strong> ${d.isp || '—'}</div>
                        <div><strong>ASN:</strong> <a href="https://bgp.he.net/${d.asn}" target="_blank" class="geo-asn-link">${d.asn || '—'}</a></div>
                        <div><strong>Организация:</strong> ${d.org || '—'}</div>
                        <div><strong>Координаты:</strong> ${d.lat ? `${d.lat}, ${d.lon}` : '—'}</div>
                    </div>
                    <div class="geo-lookup-actions" style="margin-top:8px; display:flex; gap:6px;">
                        <button type="button" class="btn btn-small" onclick="window.CityIpFinder.filterByCityName('${d.city}')">🔍 Все подсети города ${d.city}</button>
                        <button type="button" class="btn btn-small btn-ghost" onclick="window.CityIpFinder.sendSingleCidrToV2('${d.cidr}')">📹 В Сканер Камер</button>
                    </div>
                </div>
            `;
        } catch (e) {
            dom.lookupResult.innerHTML = `<div class="geo-lookup-not-found">Ошибка: ${e.message}</div>`;
        } finally {
            if (dom.btnLookup) {
                dom.btnLookup.disabled = false;
                dom.btnLookup.textContent = 'Найти';
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Exporters
    // ─────────────────────────────────────────────────────────────────────────

    function copyText(text) {
        if (!text) return;
        navigator.clipboard.writeText(text).then(() => {
            showToast('Скопировано в буфер обмена!');
        }).catch(() => {
            prompt('Скопируйте текст вручную:', text);
        });
    }

    function downloadFile(content, fileName, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    async function exportTxt() {
        const content = await getCidrListToTransfer();
        if (!content) { alert('Нет данных для экспорта'); return; }
        const filename = `ip2domain_cidrs_${state.selectedCity || state.activeCountry}_${Date.now()}.txt`;
        downloadFile(content, filename, 'text/plain;charset=utf-8');
    }

    async function exportJson() {
        const cidrs = (await getCidrListToTransfer()).split('\n').filter(Boolean);
        const payload = {
            export_date: new Date().toISOString(),
            country_filter: state.activeCountry,
            region_filter: state.selectedRegion,
            city_filter: state.selectedCity,
            isp_filter: state.selectedIsp,
            total_cidrs: cidrs.length,
            cidrs: cidrs,
            subnets: state.subnets,
        };
        const filename = `ip2domain_subnets_${state.selectedCity || state.activeCountry}_${Date.now()}.json`;
        downloadFile(JSON.stringify(payload, null, 2), filename, 'application/json;charset=utf-8');
    }

    function exportCsv() {
        if (!state.subnets.length) { alert('Нет подсетей для экспорта'); return; }
        let csv = 'CIDR,Страна,Регион,Город,Провайдер,ASN,Организация,Кол-во IP\n';
        state.subnets.forEach(s => {
            const row = [
                `"${s.cidr}"`,
                `"${s.country_name}"`,
                `"${s.region}"`,
                `"${s.city}"`,
                `"${s.isp}"`,
                `"${s.asn}"`,
                `"${s.org || ''}"`,
                s.ip_count
            ];
            csv += row.join(',') + '\n';
        });
        const filename = `ip2domain_geo_subnets_${Date.now()}.csv`;
        downloadFile(csv, filename, 'text/csv;charset=utf-8');
    }

    function showToast(msg) {
        const toast = document.createElement('div');
        toast.className = 'geo-toast';
        toast.textContent = msg;
        document.body.appendChild(toast);
        setTimeout(() => toast.classList.add('visible'), 20);
        setTimeout(() => {
            toast.classList.remove('visible');
            setTimeout(() => toast.remove(), 300);
        }, 2000);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Event Handlers Setup
    // ─────────────────────────────────────────────────────────────────────────

    function attachEventListeners() {
        // Country tabs
        dom.countryBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                dom.countryBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                state.activeCountry = btn.dataset.country;
                state.selectedRegion = '';
                state.selectedCity = '';
                state.selectedIsp = '';
                state.offset = 0;
                loadRegions();
                loadProviders();
                renderQuickCityChips();
                loadSubnets();
            });
        });

        // Region select
        dom.regionSelect?.addEventListener('change', (e) => {
            state.selectedRegion = e.target.value;
            state.selectedCity = '';
            state.offset = 0;
            loadSubnets();
        });

        // ISP select
        dom.ispSelect?.addEventListener('change', (e) => {
            state.selectedIsp = e.target.value;
            state.offset = 0;
            loadSubnets();
        });

        // Search input with debounce
        let searchTimer;
        dom.citySearchInput?.addEventListener('input', (e) => {
            clearTimeout(searchTimer);
            searchTimer = setTimeout(() => {
                state.searchQuery = e.target.value.trim();
                state.offset = 0;
                loadSubnets();
            }, 300);
        });

        // Select All Checkbox
        dom.selectAllCheckbox?.addEventListener('change', (e) => {
            const checked = e.target.checked;
            state.subnets.forEach(s => {
                if (checked) state.selectedCidrs.add(s.cidr);
                else state.selectedCidrs.delete(s.cidr);
            });
            document.querySelectorAll('.geo-row-checkbox').forEach(chk => {
                chk.checked = checked;
            });
            updateSelectedStats();
        });

        // Pagination
        dom.btnPrevPage?.addEventListener('click', () => {
            if (state.offset > 0) {
                state.offset = Math.max(0, state.offset - state.limit);
                loadSubnets();
            }
        });
        dom.btnNextPage?.addEventListener('click', () => {
            if (state.offset + state.limit < state.totalSubnets) {
                state.offset += state.limit;
                loadSubnets();
            }
        });

        // Bulk selection buttons
        dom.btnSelectAllFilter?.addEventListener('click', selectAllFilterSubnets);
        dom.btnClearSelection?.addEventListener('click', clearSelection);

        // Pipeline transfers
        dom.btnSendToCamV2?.addEventListener('click', sendToCameraScannerV2);
        dom.btnSendToCamV2Top?.addEventListener('click', sendToCameraScannerV2);
        dom.btnSendToRdp?.addEventListener('click', sendToRemoteDesktop);
        dom.btnSendToRdpTop?.addEventListener('click', sendToRemoteDesktop);
        dom.btnSendToRecon?.addEventListener('click', sendToReconGraph);
        dom.btnSendToReconTop?.addEventListener('click', sendToReconGraph);

        // Copy & Download
        dom.btnCopyCidrs?.addEventListener('click', async () => {
            const cidrs = await getCidrListToTransfer();
            if (!cidrs) alert('Нет выбранных CIDR');
            else copyText(cidrs);
        });
        dom.btnCopyCidrsTop?.addEventListener('click', async () => {
            const cidrs = await getCidrListToTransfer();
            if (!cidrs) alert('Нет выбранных CIDR');
            else copyText(cidrs);
        });
        dom.btnDownloadTxt?.addEventListener('click', exportTxt);
        dom.btnDownloadJson?.addEventListener('click', exportJson);
        dom.btnDownloadCsv?.addEventListener('click', exportCsv);

        // Lookup
        dom.btnLookup?.addEventListener('click', performLookup);
        dom.lookupInput?.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                performLookup();
            }
        });

        // Reset filters
        dom.btnResetFilters?.addEventListener('click', () => {
            state.activeCountry = 'ALL';
            state.selectedRegion = '';
            state.selectedCity = '';
            state.selectedIsp = '';
            state.searchQuery = '';
            state.offset = 0;
            state.selectedCidrs.clear();

            dom.countryBtns.forEach(b => b.classList.toggle('active', b.dataset.country === 'ALL'));
            if (dom.regionSelect) dom.regionSelect.value = '';
            if (dom.ispSelect) dom.ispSelect.value = '';
            if (dom.citySearchInput) dom.citySearchInput.value = '';

            loadRegions();
            loadProviders();
            renderQuickCityChips();
            loadSubnets();
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public Global API for Inline Callbacks
    // ─────────────────────────────────────────────────────────────────────────

    window.CityIpFinder = {
        init: function () {
            initDomElements();
            attachEventListeners();
            loadCountriesSummary();
            loadRegions();
            loadProviders();
            renderQuickCityChips();
            loadSubnets();
        },
        copyText: copyText,
        filterByCityName: function (cityName) {
            state.selectedCity = cityName;
            state.offset = 0;
            if (dom.citySearchInput) dom.citySearchInput.value = cityName;
            loadSubnets();
            dom.subnetsTableBody?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        },
        sendSingleCidrToV2: function (cidr) {
            const v2Area = document.getElementById('v2-targets');
            if (v2Area) v2Area.value = cidr;
            if (typeof window.switchView === 'function') {
                const camNavBtn = document.querySelector('.nav-item[data-view="cameras-view"]');
                window.switchView('cameras-view', camNavBtn);
            }
            if (typeof window.switchCameraVersion === 'function') {
                window.switchCameraVersion('v2');
            }
        },
        sendSingleCidrToRdp: function (cidr) {
            const remoteArea = document.getElementById('remote-target');
            if (remoteArea) remoteArea.value = cidr;
            if (typeof window.switchView === 'function') {
                const rdpNavBtn = document.querySelector('.nav-item[data-view="remote-desktop-view"]');
                window.switchView('remote-desktop-view', rdpNavBtn);
            }
        },
    };

    // Auto-init on DOMContentLoaded
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => window.CityIpFinder.init());
    } else {
        window.CityIpFinder.init();
    }
})();
