'use strict';

let centraPeoplePoller = null;
let activeCentraPeopleJobId = null;
let centraPeopleShowingAllResults = false;
let centraScreensMode = 'all';

async function loadSavedCentraPeopleCount() {
    const badge = document.getElementById('centra-people-saved-count');
    const type = document.getElementById('centra-screens-type')?.value || '';
    if (!badge) return;
    try {
        const response = await fetch(`/api/cameras/centra/people/results?offset=0&limit=1&camera_type=${encodeURIComponent(type)}`);
        const data = await response.json();
        if (response.ok) {
            badge.textContent = `${Number(data.total || 0).toLocaleString()}`;
        }
    } catch (_) {}
}
window.loadSavedCentraPeopleCount = loadSavedCentraPeopleCount;

async function showSavedCentraPeople() {
    window.centraScreensMode = 'people';
    window.centraPeopleShowingAllResults = true;
    updateCentraScreensModeButtons();
    const btn = document.getElementById('centra-people-show-all-btn');
    if (btn) btn.style.display = '';
    await resetCentraScreens();
}
window.showSavedCentraPeople = showSavedCentraPeople;

function updateCentraScreensModeButtons() {
    const allBtn = document.getElementById('centra-screens-mode-all');
    const peopleBtn = document.getElementById('centra-screens-mode-people');
    if (allBtn) allBtn.classList.toggle('active', window.centraScreensMode === 'all');
    if (peopleBtn) peopleBtn.classList.toggle('active', window.centraScreensMode === 'people');
}
window.updateCentraScreensModeButtons = updateCentraScreensModeButtons;

function renderCentraPeopleMatches(result, replaceGrid) {
    const matches = result?.matches || [];
    if (!matches.length) return;
    const grid = document.getElementById('centra-screens-grid');
    if (!grid) return;
    if (replaceGrid) {
        grid.innerHTML = '';
        centraScreenCameras = [];
    }
    const startIndex = centraScreenCameras.length;
    centraScreenCameras.push(...matches);
    ensureCentraScreenObserver();
    matches.forEach((camera, offset) => {
        const index = startIndex + offset;
        const card = document.createElement('div');
        card.className = 'centra-screen-card';
        card.innerHTML = `<img class="centra-screen-image" src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 9'/%3E" data-src="${_esc(camera.screenshot_url)}" alt="${_esc(camera.title || camera.id)}" loading="lazy"><div class="centra-screen-meta"><strong>${_esc(centraEntrance(camera))} · ${_esc(camera.title || camera.id)}</strong><small>${_esc(camera.id)} · ${_esc(centraCameraType(camera))} · Людей: ${camera.people_count || 1}</small></div>`;
        card.onclick = () => openCentraScreenCamera(index);
        grid.appendChild(card);
        const img = card.querySelector('img');
        if (img && centraScreenObserver) centraScreenObserver.observe(img);
    });
}

async function startCentraPeoplePolling(jobId, allCameras, replaceGrid = allCameras) {
    activeCentraPeopleJobId = jobId;
    localStorage.setItem('ip2domain_centra_people_job', jobId);
    const progress = document.getElementById('centra-people-progress');
    const analyzeBtn = document.getElementById('centra-people-analyze-btn');
    const cancelBtn = document.getElementById('centra-people-cancel-btn');
    if (analyzeBtn) analyzeBtn.disabled = true;
    if (cancelBtn) cancelBtn.style.display = '';
    if (progress) progress.style.display = 'block';
    let matchesCursor = 0;
    if (centraPeoplePoller) clearInterval(centraPeoplePoller);
    centraPeoplePoller = setInterval(async () => {
        try {
            const response = await fetch('/api/cameras/centra/people/active');
            const data = await response.json();
            const job = data?.job;
            if (!job || job.job_id !== jobId || ['completed', 'cancelled', 'error'].includes(job.status)) {
                clearInterval(centraPeoplePoller);
                centraPeoplePoller = null;
                activeCentraPeopleJobId = null;
                localStorage.removeItem('ip2domain_centra_people_job');
                if (analyzeBtn) analyzeBtn.disabled = false;
                if (cancelBtn) cancelBtn.style.display = 'none';
                if (progress) progress.textContent = job?.stage || 'Анализ завершён';
                loadSavedCentraPeopleCount();
                return;
            }
            const resultResponse = await fetch(`/api/cameras/centra/people/${jobId}?matches_from=${matchesCursor}`);
            if (resultResponse.ok) {
                const result = await resultResponse.json();
                if ((result.matches || []).length) {
                    renderCentraPeopleMatches(result, replaceGrid && matchesCursor === 0);
                    matchesCursor = result.matches_total || (matchesCursor + result.matches.length);
                }
            }
            if (progress) {
                const eta = job.eta_seconds ? ` · осталось ≈ ${Math.ceil(job.eta_seconds / 60)} мин.` : '';
                const lastErr = job.last_error ? ` · последняя ошибка: ${job.last_error}` : '';
                progress.textContent = `${job.stage || 'Анализ людей...'} (${job.progress_pct || 0}%)${eta}${lastErr}`;
            }
        } catch (error) {
            if (progress) progress.textContent = error.message;
        }
    }, 2500);
}

async function analyzeCentraScreenPeople(allCameras = false) {
    const type = document.getElementById('centra-screens-type')?.value || '';
    const body = allCameras
        ? {all_cameras: true, camera_type: type}
        : {camera_ids: centraScreenCameras.map((camera) => camera.id).filter(Boolean)};
    if (!allCameras && !body.camera_ids.length) {
        alert('Кадры ещё не загружены');
        return;
    }
    const progress = document.getElementById('centra-people-progress');
    if (progress) {
        progress.style.display = 'block';
        progress.textContent = 'Запуск распознавания людей...';
    }
    try {
        const response = await fetch('/api/cameras/centra/people', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось запустить анализ');
        await startCentraPeoplePolling(data.job_id, allCameras);
    } catch (error) {
        if (progress) progress.textContent = error.message;
    }
}
window.analyzeCentraScreenPeople = analyzeCentraScreenPeople;

async function restoreCentraPeopleAnalysis() {
    try {
        const response = await fetch('/api/cameras/centra/people/active');
        const data = await response.json();
        if (data?.job?.job_id) {
            await startCentraPeoplePolling(data.job.job_id, Boolean(data.job.all_cameras), false);
        }
    } catch (_) {}
}

async function cancelCentraPeopleAnalysis() {
    if (!activeCentraPeopleJobId) return;
    try {
        await fetch(`/api/cameras/centra/people/${activeCentraPeopleJobId}/cancel`, {method:'POST'});
        const progress = document.getElementById('centra-people-progress');
        if (progress) progress.textContent = 'Остановка анализа...';
    } catch (_) {}
}
window.cancelCentraPeopleAnalysis = cancelCentraPeopleAnalysis;

function filterCentraScreensByPeople(range) {
    const cards = document.querySelectorAll('.centra-screen-card');
    cards.forEach((card) => {
        const text = card.querySelector('.centra-screen-meta small')?.textContent || '';
        const match = text.match(/Людей:\s*(\d+)/i);
        const count = match ? Number(match[1]) : 0;
        let visible = true;
        if (range === 'none') visible = count === 0;
        else if (range === 'few') visible = count >= 1 && count <= 2;
        else if (range === 'many') visible = count >= 3;
        card.style.display = visible ? '' : 'none';
    });
}
window.filterCentraScreensByPeople = filterCentraScreensByPeople;

async function resetCentraPersonIdentities() {
    if (!confirm('Сбросить базу распознанных персон и начать сопоставление заново?')) return;
    try {
        const response = await fetch('/api/cameras/centra/people-identities/reset', {method:'POST'});
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось сбросить персоны');
        alert(`База персон очищена (удалено записей: ${data.deleted || 0})`);
        loadSavedCentraPeopleCount();
    } catch (error) {
        alert(error.message);
    }
}
window.resetCentraPersonIdentities = resetCentraPersonIdentities;
