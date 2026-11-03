
const gradientStyles = document.createElement('style');
gradientStyles.textContent = `
    .table tr.row-active {
        background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%) !important;
        border-left: 3px solid #28a745;
    }
    .table tr.row-active:hover {
        background: linear-gradient(135deg, #c3e6cb 0%, #b1dfbb 100%) !important;
    }
    
    .table tr.row-inactive {
        background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%) !important;
        border-left: 3px solid #dc3545;
    }
    .table tr.row-inactive:hover {
        background: linear-gradient(135deg, #f5c6cb 0%, #f1b0b7 100%) !important;
    }
    
    .table tr.row-warning {
        background: linear-gradient(135deg, #fff3cd 0%, #ffe69c 100%) !important;
        border-left: 3px solid #ffc107;
    }
    .table tr.row-warning:hover {
        background: linear-gradient(135deg, #ffe69c 0%, #ffda6a 100%) !important;
    }
`;
document.head.appendChild(gradientStyles);

// Экранирование HTML и уведомления: единые реализации escapeHtml/showNotification
// находятся в static/js/common.js (подключается в base.html до этого скрипта).

const monitoring = {
    progressInterval: null,
    statusInterval: null,
    devicesDataInterval: null,
    isScanning: false,

    init() {
        this.bindEvents();
        this.startAutoRefresh();
        this.loadInitialData();
    },

    bindEvents() {
        const searchBtn = document.getElementById('search-button');
        const searchInput = document.getElementById('search-input');
        const duplicateBtn = document.getElementById('duplicate-search-button');
        const noDescBtn = document.getElementById('no-description-search-button');
        const clearBtn = document.getElementById('clear-search-button');

        if (searchBtn) searchBtn.addEventListener('click', () => this.performSearch());
        if (searchInput) {
            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') this.performSearch();
            });
        }
        if (duplicateBtn) duplicateBtn.addEventListener('click', () => this.searchDuplicates());
        if (noDescBtn) noDescBtn.addEventListener('click', () => this.searchOnuWithoutDescription());
        if (clearBtn) clearBtn.addEventListener('click', () => this.clearSearch());

        document.querySelectorAll('.refresh-device').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const deviceId = e.currentTarget.dataset.deviceId;
                this.refreshSingleDevice(deviceId);
            });
        });
    },

    startAutoRefresh() {
        this.devicesDataInterval = setInterval(() => {
            this.refreshDevicesData();
        }, 30000);
    },

    async loadInitialData() {
        try {
            await this.refreshDevicesData();
        } catch (error) {
            console.error('Error loading initial data:', error);
        }
    },

    async refreshDevicesData() {
        try {
            const response = await fetch('/api/devices_data');
            const data = await response.json();
            this.updateDevicesUI(data);
        } catch (error) {
            console.error('Error refreshing devices data:', error);
        }
    },

    updateDevicesUI(data) {
        for (const [deviceId, deviceData] of Object.entries(data)) {
            const statusEl = document.getElementById(`status-${deviceId}`);
            const timestampEl = document.getElementById(`timestamp-${deviceId}`);
            const totalEl = document.getElementById(`total-${deviceId}`);
            const activeEl = document.getElementById(`active-${deviceId}`);
            const inactiveEl = document.getElementById(`inactive-${deviceId}`);
            const signalEl = document.getElementById(`signal-${deviceId}`);
            const mcdEl = document.getElementById(`mcd-${deviceId}`);
            const singleEl = document.getElementById(`single-${deviceId}`);
            const goodEl = document.getElementById(`good-${deviceId}`);
            const warningEl = document.getElementById(`warning-${deviceId}`);
            const badEl = document.getElementById(`bad-${deviceId}`);

            if (statusEl) {
                if (deviceData.enriched) {
                    statusEl.innerHTML = '<i class="bi bi-check-circle"></i> Синхронизирован';
                    statusEl.className = 'badge bg-info';
                } else {
                    statusEl.innerHTML = '<i class="bi bi-hourglass"></i> Сканирование';
                    statusEl.className = 'badge bg-warning';
                }
            }
            if (timestampEl) timestampEl.textContent = `Обновление: ${deviceData.timestamp}`;

            const stats = deviceData.stats || {};
            if (totalEl) totalEl.textContent = stats.total || 0;
            if (activeEl) activeEl.textContent = stats.active || 0;
            if (inactiveEl) inactiveEl.textContent = stats.inactive || 0;
            if (signalEl) signalEl.textContent = stats.signal || 0;
            if (mcdEl) mcdEl.textContent = stats.mcd || 0;
            if (singleEl) singleEl.textContent = stats.single || (stats.total - (stats.mcd || 0));
            if (goodEl) goodEl.textContent = stats.good_signal || 0;
            if (warningEl) warningEl.textContent = stats.warning_signal || 0;
            if (badEl) badEl.textContent = stats.bad_signal || 0;
        }
    },

    _sortActiveFirst(arr, key = 'optical_power') {
        return arr.sort((a, b) => {
            const aActive = a[key] !== null && a[key] !== undefined;
            const bActive = b[key] !== null && b[key] !== undefined;
            if (aActive && !bActive) return -1;
            if (!aActive && bActive) return 1;
            return 0;
        });
    },

	_getRowClass(item) {
		const isActive = item.optical_power !== null && item.optical_power !== undefined;
		return isActive ? 'table-success' : 'table-danger';
	},

    _contractCell(item) {
        const cn = item && item.contract && item.contract !== 'N/A' ? item.contract : null;
        if (!cn) return '<span class="text-muted">\u2014</span>';
        // Единый стандарт: договор + логин/IP клиента из справочника договоров.
        const login = item.contract_login && item.contract_login !== 'N/A' ? item.contract_login : null;
        const ip = item.contract_ip && item.contract_ip !== 'N/A' ? item.contract_ip : null;
        const titleBits = [cn];
        if (login) titleBits.push('Логин: ' + login);
        if (ip) titleBits.push('IP: ' + ip);
        let html = `<code class="font-monospace" title="${escapeHtml(titleBits.join(' | '))}">${escapeHtml(cn)}</code>`;
        if (login) {
            html += `<div class="small text-muted text-truncate" style="max-width:160px;">${escapeHtml(login)}</div>`;
        }
        return html;
    },

    _deviceBadges(item) {
        let badges = '';
        if (item.is_moved || item.moved_to || item.moved_from) {
            badges += ' <span class="badge bg-info" title="ONU переехала"><i class="bi bi-arrow-left-right"></i></span>';
        }
        if (item.is_mcd) {
            badges += ' <span class="badge bg-warning text-dark" title="Многоэтажный жилой дом"><i class="bi bi-buildings"></i></span>';
        }
        return badges;
    },

    async performSearch() {
        const searchInput = document.getElementById('search-input');
        const query = searchInput.value.trim();
        if (!query || query.length < 2) {
            showNotification('Введите минимум 2 символа для поиска', 'warning');
            return;
        }
        const resultsDiv = document.getElementById('search-results');
        const indicator = document.getElementById('search-indicator');
        resultsDiv.style.display = 'block';
        indicator.style.display = 'block';
        resultsDiv.innerHTML = '';

        try {
            const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
            const data = await response.json();
            indicator.style.display = 'none';
            this.displaySearchResults(data.results || []);
        } catch (error) {
            indicator.style.display = 'none';
            resultsDiv.innerHTML = `<div class="alert alert-danger"><i class="bi bi-x-circle"></i> Ошибка поиска: ${escapeHtml(error)}</div>`;
        }
    },

    displaySearchResults(results) {
        const resultsDiv = document.getElementById('search-results');
        if (!results || results.length === 0) {
            resultsDiv.innerHTML = `<div class="alert alert-warning"><i class="bi bi-exclamation-triangle"></i> Ничего не найдено</div>`;
            return;
        }
        this._sortActiveFirst(results);

        let html = `<div class="alert alert-info small py-2"><i class="bi bi-info-circle"></i> Найдено <strong>${results.length}</strong> результатов</div>`;
        html += `<div class="table-responsive"><table class="table table-sm table-hover table-striped mb-0 small">
            <thead class="table-light"><tr>
                <th>Тип</th><th>Устройство</th><th>Интерфейс</th>
                <th>MAC</th><th>Описание</th><th>Договор</th><th>Статус</th>
                <th>Сигнал</th><th>Действия</th>
            </tr></thead><tbody>`;
        results.forEach(r => {
            const typeLabels = {
                'onu_mac': 'MAC ONU',
                'client_mac': 'MAC клиента',
                'onu_description': 'Описание',
                'contract': 'Договор'
            };
            let typeBadge;
            if (r.match_type === 'full_mac') {
                typeBadge = '<span class="badge bg-success">Полный</span>';
            } else if (r.match_type === 'partial_mac') {
                typeBadge = '<span class="badge bg-warning text-dark">Частичный</span>';
            } else if (r.type === 'onu_description') {
                typeBadge = '<span class="badge bg-info">Текст</span>';
            } else if (r.type === 'contract') {
                typeBadge = '<span class="badge bg-primary">Номер</span>';
            } else {
                typeBadge = '';
            }
            const clientMacNote = r.client_mac_match
                ? ' <span class="badge bg-secondary" title="Совпадение и по MAC клиента">+клиент</span>'
                : '';
            const statusBadge = r.optical_power !== null && r.optical_power !== undefined
                ? `<span class="badge bg-success">${escapeHtml(r.status) || 'active'}</span>`
                : `<span class="badge bg-danger">${escapeHtml(r.status) || 'off-line'}</span>`;
            const signalBadge = r.optical_power !== null && r.optical_power !== undefined
                ? `<span class="badge bg-info">${parseFloat(r.optical_power).toFixed(2)} dBm</span>`
                : '<span class="badge bg-secondary">—</span>';
            const duplicateBadge = r.has_duplicates
                ? ` <span class="badge bg-danger" title="Дубликат MAC">×${r.duplicate_count}</span>`
                : '';
            
            const rowClass = this._getRowClass(r);
            
            html += `<tr class="${rowClass}">
                <td>${escapeHtml(typeLabels[r.type] || r.type)} ${typeBadge}${clientMacNote}${duplicateBadge}</td>
                <td>${escapeHtml(r.device)}${this._deviceBadges(r)}</td>
                <td><code class="font-monospace">${escapeHtml(r.interface)}</code></td>
                <td><code>${escapeHtml(r.mac)}</code></td>
                <td class="text-truncate" style="max-width: 200px;" title="${escapeHtml(r.description || '')}">${escapeHtml(r.description) || '—'}</td>
                <td class="text-truncate" style="max-width: 140px;">${this._contractCell(r)}</td>
                <td>${statusBadge}</td>
                <td>${signalBadge}</td>
                <td>
                    <div class="d-flex gap-1">
                        <a href="/onu/${encodeURIComponent(r.device_id)}/${encodeURIComponent(r.interface)}" class="btn btn-outline-primary btn-xs py-0 px-1" title="Детали ONU"><i class="bi bi-eye"></i></a>
                        <a href="/device/${encodeURIComponent(r.device_id)}" class="btn btn-outline-secondary btn-xs py-0 px-1" title="Детали узла"><i class="bi bi-cpu"></i></a>
                    </div>
                </td>
            </tr>`;
        });
        html += `</tbody></table></div>`;
        resultsDiv.innerHTML = html;
    },

    async searchDuplicates() {
        const resultsDiv = document.getElementById('search-results');
        const indicator = document.getElementById('search-indicator');
        resultsDiv.style.display = 'block';
        indicator.style.display = 'block';
        resultsDiv.innerHTML = '';
        try {
            const response = await fetch('/api/duplicate_macs');
            const data = await response.json();
            indicator.style.display = 'none';
            this.displayDuplicates(data);
        } catch (error) {
            indicator.style.display = 'none';
            resultsDiv.innerHTML = `<div class="alert alert-danger"><i class="bi bi-x-circle"></i> Ошибка: ${escapeHtml(error)}</div>`;
        }
    },

    displayDuplicates(data) {
        const resultsDiv = document.getElementById('search-results');
        const duplicates = data.duplicates || [];
        if (duplicates.length === 0) {
            resultsDiv.innerHTML = `<div class="alert alert-success"><i class="bi bi-check-circle"></i> Дубликатов MAC не найдено</div>`;
            return;
        }

        let html = `<div class="alert alert-warning small py-2 mb-2">
            <i class="bi bi-info-circle"></i> Найдено <strong>${data.total_duplicates}</strong> групп дубликатов
        </div>`;

        duplicates.forEach((dup, idx) => {
            const isMoved = dup.is_moved;
            const movedBadge = isMoved
                ? '<span class="badge bg-info"><i class="bi bi-arrow-left-right"></i> Переезд</span>'
                : '<span class="badge bg-warning text-dark">Дубликат</span>';

            const allMacs = dup.all_macs || [];
            const macsInline = allMacs.map(m => `<code class="me-1">${escapeHtml(m)}</code>`).join('<span class="text-muted">→</span> ');

            const sortedOccurrences = [...(dup.occurrences || [])];
            this._sortActiveFirst(sortedOccurrences);

            html += `<div class="border rounded-top bg-light px-2 py-1 small d-flex flex-wrap align-items-center gap-2 mt-2">
                <strong class="text-primary">#${idx + 1}</strong>
                <span>Последние 8: <code>${escapeHtml(dup.mac_last_8)}</code></span>
                ${movedBadge}
                <span class="badge bg-dark">${dup.count} запис.</span>
                <span class="text-muted ms-auto">${macsInline}</span>
            </div>`;

            html += `<div class="table-responsive border border-top-0 rounded-bottom mb-1">
                <table class="table table-sm table-hover mb-0 small">
                    <thead class="table-light"><tr>
                        <th>Устройство</th><th>Интерфейс</th><th>Полный MAC</th>
                        <th>Описание</th><th>Договор</th><th>Статус</th><th>Сигнал</th>
                        <th>Послед. активность</th><th>Действия</th>
                    </tr></thead><tbody>`;

            sortedOccurrences.forEach(occ => {
                const rowClass = this._getRowClass(occ);
                
                const isActive = occ.optical_power !== null && occ.optical_power !== undefined;
                const statusBadge = isActive
                    ? `<span class="badge bg-success">${escapeHtml(occ.status) || 'active'}</span>`
                    : `<span class="badge bg-danger">${escapeHtml(occ.status) || 'off-line'}</span>`;
                const signalBadge = isActive
                    ? `<span class="badge bg-info">${parseFloat(occ.optical_power).toFixed(2)} dBm</span>`
                    : '<span class="badge bg-secondary">—</span>';
                html += `<tr class="${rowClass}">
                    <td>${escapeHtml(occ.device)}${this._deviceBadges(occ)}</td>
                    <td><code class="font-monospace">${escapeHtml(occ.interface)}</code></td>
                    <td><code class="text-primary"><strong>${escapeHtml(occ.mac)}</strong></code></td>
                    <td class="text-truncate" style="max-width: 200px;" title="${escapeHtml(occ.description || '')}">${escapeHtml(occ.description) || '—'}</td>
                    <td class="text-truncate" style="max-width: 140px;">${this._contractCell(occ)}</td>
                    <td>${statusBadge}</td>
                    <td>${signalBadge}</td>
                    <td><small class="text-muted">${escapeHtml(occ.last_seen) || '—'}</small></td>
                    <td>
                        <div class="d-flex gap-1">
                            <a href="/onu/${encodeURIComponent(occ.device_id)}/${encodeURIComponent(occ.interface)}" class="btn btn-outline-primary btn-xs py-0 px-1"><i class="bi bi-eye"></i></a>
                            <a href="/device/${encodeURIComponent(occ.device_id)}" class="btn btn-outline-secondary btn-xs py-0 px-1"><i class="bi bi-cpu"></i></a>
                        </div>
                    </td>
                </tr>`;
            });
            html += `</tbody></table></div>`;
        });
        resultsDiv.innerHTML = html;
    },

    async searchOnuWithoutDescription() {
        const resultsDiv = document.getElementById('search-results');
        const indicator = document.getElementById('search-indicator');
        resultsDiv.style.display = 'block';
        indicator.style.display = 'block';
        resultsDiv.innerHTML = '';
        try {
            const response = await fetch('/api/onu_without_description');
            const data = await response.json();
            indicator.style.display = 'none';
            let onus = data.onus_without_description || [];
            if (onus.length === 0) {
                resultsDiv.innerHTML = `<div class="alert alert-success"><i class="bi bi-check-circle"></i> Все ONU имеют описание</div>`;
                return;
            }
            this._sortActiveFirst(onus);

            let html = `<div class="alert alert-info small py-2 mb-2">
                <i class="bi bi-info-circle"></i> Найдено <strong>${onus.length}</strong> ONU без описания
            </div>
            <div class="table-responsive"><table class="table table-sm table-hover mb-0 small">
                <thead class="table-light"><tr>
                    <th>Устройство</th><th>Интерфейс</th><th>MAC</th>
                    <th>Вендор</th><th>Модель</th><th>Договор</th><th>Статус</th><th>Сигнал</th><th>Действия</th>
                </tr></thead><tbody>`;
            onus.forEach(onu => {
                const isActive = onu.optical_power !== null && onu.optical_power !== undefined;
                const signalBadge = isActive
                    ? `<span class="badge bg-info">${parseFloat(onu.optical_power).toFixed(2)} dBm</span>`
                    : '<span class="badge bg-secondary">—</span>';
                const statusBadge = isActive
                    ? `<span class="badge bg-success">${escapeHtml(onu.status) || 'active'}</span>`
                    : `<span class="badge bg-danger">${escapeHtml(onu.status) || 'off-line'}</span>`;
                
                const rowClass = this._getRowClass(onu);
                
                html += `<tr class="${rowClass}">
                    <td>${escapeHtml(onu.device)}${this._deviceBadges(onu)}</td>
                    <td><code class="font-monospace">${escapeHtml(onu.interface)}</code></td>
                    <td><code>${escapeHtml(onu.mac)}</code></td>
                    <td>${escapeHtml(onu.vendor) || '—'}</td>
                    <td>${escapeHtml(onu.model) || '—'}</td>
                    <td class="text-truncate" style="max-width: 140px;">${this._contractCell(onu)}</td>
                    <td>${statusBadge}</td>
                    <td>${signalBadge}</td>
                    <td>
                        <div class="d-flex gap-1">
                            <a href="/onu/${encodeURIComponent(onu.device_id)}/${encodeURIComponent(onu.interface)}" class="btn btn-outline-primary btn-xs py-0 px-1"><i class="bi bi-eye"></i></a>
                            <a href="/device/${encodeURIComponent(onu.device_id)}" class="btn btn-outline-secondary btn-xs py-0 px-1"><i class="bi bi-cpu"></i></a>
                        </div>
                    </td>
                </tr>`;
            });
            html += `</tbody></table></div>`;
            resultsDiv.innerHTML = html;
        } catch (error) {
            indicator.style.display = 'none';
            resultsDiv.innerHTML = `<div class="alert alert-danger"><i class="bi bi-x-circle"></i> Ошибка: ${escapeHtml(error)}</div>`;
        }
    },

    clearSearch() {
        const searchInput = document.getElementById('search-input');
        const resultsDiv = document.getElementById('search-results');
        if (searchInput) searchInput.value = '';
        if (resultsDiv) {
            resultsDiv.style.display = 'none';
            resultsDiv.innerHTML = '';
        }
    },

    async refreshAllDevices() {
        if (this.isScanning) {
            showNotification('Сканирование уже выполняется', 'warning');
            return;
        }
        if (!confirm('Запустить полное сканирование всех устройств? Это может занять несколько минут.')) return;
        this.isScanning = true;
        showNotification('Сканирование запущено...', 'info');
        this.showProgress();
        try {
            const response = await fetch('/api/start_manual_scan');
            const data = await response.json();
            if (data.status === 'success') {
                this.startProgressPolling();
                showNotification(data.message, 'success');
            } else {
                this.isScanning = false;
                this.hideProgress();
                showNotification(data.message, 'danger');
            }
        } catch (error) {
            this.isScanning = false;
            this.hideProgress();
            showNotification('Ошибка сети: ' + error, 'danger');
        }
    },

    async refreshSingleDevice(deviceId) {
        if (!confirm('Пересканировать это устройство?')) return;
        showNotification('Сканирование устройства...', 'info');
        try {
            const response = await fetch(`/api/scan_device/${deviceId}`);
            const data = await response.json();
            if (data.status === 'success') {
                showNotification(data.message, 'success');
                setTimeout(() => this.refreshDevicesData(), 2000);
            } else {
                showNotification(data.message, 'danger');
            }
        } catch (error) {
            showNotification('Ошибка сети: ' + error, 'danger');
        }
    },

    showProgress() {
        const container = document.getElementById('scan-progress-container');
        if (container) container.style.display = 'block';
    },

    hideProgress() {
        const container = document.getElementById('scan-progress-container');
        if (container) container.style.display = 'none';
        if (this.progressInterval) {
            clearInterval(this.progressInterval);
            this.progressInterval = null;
        }
    },

    startProgressPolling() {
        if (this.progressInterval) clearInterval(this.progressInterval);
        this.progressInterval = setInterval(async () => {
            try {
                const response = await fetch('/api/scan_progress');
                const data = await response.json();
                this.updateProgressUI(data);
                if (!data.is_scanning) {
                    clearInterval(this.progressInterval);
                    this.progressInterval = null;
                    this.isScanning = false;
                    setTimeout(() => {
                        this.hideProgress();
                        this.refreshDevicesData();
                        showNotification('Сканирование завершено', 'success');
                    }, 2000);
                }
            } catch (error) {
                console.error('Error polling progress:', error);
            }
        }, 2000);
    },

    updateProgressUI(data) {
        const progressBar = document.getElementById('progress-bar');
        const progressPercent = document.getElementById('progress-percent');
        const progressText = document.getElementById('progress-text');
        const currentDevice = document.getElementById('current-device');
        const completedCount = document.getElementById('completed-count');
        const totalCount = document.getElementById('total-count');
        const timeRemaining = document.getElementById('time-remaining');
        const scanStatus = document.getElementById('scan-status');
        const scanMessage = document.getElementById('scan-message');
        if (progressBar) progressBar.style.width = data.progress_percent + '%';
        if (progressPercent) progressPercent.textContent = data.progress_percent + '%';
        if (currentDevice) currentDevice.textContent = data.current_device || '-';
        if (completedCount) completedCount.textContent = data.completed_devices;
        if (totalCount) totalCount.textContent = data.total_devices;
        if (timeRemaining) timeRemaining.textContent = data.estimated_time_remaining || '--:--';
        if (scanStatus) {
            if (data.is_scanning) {
                scanStatus.textContent = 'Сканирование...';
                scanStatus.className = 'badge bg-light text-primary ms-2';
            } else {
                scanStatus.textContent = 'Завершено';
                scanStatus.className = 'badge bg-success ms-2';
            }
        }
        if (progressText) {
            if (data.progress_percent < 30) progressText.textContent = 'Подключение к устройствам...';
            else if (data.progress_percent < 70) progressText.textContent = 'Сбор данных...';
            else if (data.progress_percent < 100) progressText.textContent = 'Обработка данных...';
            else progressText.textContent = 'Завершение...';
        }
        if (scanMessage) scanMessage.textContent = `Обработано ${data.completed_devices} из ${data.total_devices}`;
    },

    async exportInactiveONUsToExcel() {
        window.location.href = '/api/export/inactive_onus';
    }
};

document.addEventListener('DOMContentLoaded', () => {
    monitoring.init();
});