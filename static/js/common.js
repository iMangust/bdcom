// Общие утилиты фронтенда EPON Monitor.
// Подключается в base.html до блока extra_js, поэтому доступен всем страницам
// (index, device_detail, onu_detail, settings, contracts, telegram_settings).

// CSRF: оборачиваем fetch, чтобы все POST/PUT/PATCH/DELETE запросы
// автоматически отправляли токен в заголовке X-CSRF-Token.
(function () {
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const csrfToken = csrfMeta ? csrfMeta.getAttribute('content') : '';
    const originalFetch = window.fetch;
    window.fetch = function (input, init) {
        init = init || {};
        const method = (init.method || (input && input.method) || 'GET').toUpperCase();
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
            init.headers = new Headers(init.headers || {});
            if (!init.headers.has('X-CSRF-Token')) {
                init.headers.set('X-CSRF-Token', csrfToken);
            }
        }
        return originalFetch.call(this, input, init);
    };
})();

// Единая утилита экранирования HTML для защиты от XSS при вставке данных
// через innerHTML. Экранирует также кавычки, поэтому значения безопасны
// и в текстовых узлах, и в HTML-атрибутах (title, href и т.п.).
window.escapeHtml = function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
};

// Экранирование значения для подстановки в JS-строку внутри HTML-атрибута
// onclick="fn('${jsAttr(x)}')". escapeHtml здесь НЕДОСТАТОЧНО: HTML-парсер
// раскодирует сущности (&quot; -> ") ДО выполнения JS, поэтому кавычки и
// обратные слеши нужно экранировать на JS-уровне. Аналог Jinja-фильтра jsattr.
window.jsAttr = function jsAttr(value) {
    if (value === null || value === undefined) return '';
    return String(value)
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '&quot;')
        .replace(/</g, '\\u003c')
        .replace(/>/g, '\\u003e')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r');
};

// Единая разметка строки таблицы ONU. Используется на всех страницах
// (index, device_detail, contracts, monitoring) вместо нескольких копий
// шаблонного кода — меньше рассинхронов и меньше поверхность XSS.
// Ожидает объект с полями: device_id, device, interface, mac, description,
// status, optical_power, last_seen; опционально is_mcd, contract.
window.onuRowHtml = function onuRowHtml(onu, opts) {
    opts = opts || {};
    const esc = window.escapeHtml;
    const isActive = onu.optical_power !== null && onu.optical_power !== undefined;
    // rowClassMode: 'default' (success/danger), 'mcd' (''/danger), 'full' (+moved)
    let rowClass;
    if (opts.rowClassMode === 'mcd') {
        rowClass = isActive ? '' : 'table-danger';
    } else if (opts.rowClassMode === 'full') {
        rowClass = !isActive ? 'table-danger' : (onu.is_mcd ? 'table-warning' : (onu.is_moved_from ? 'table-info' : ''));
    } else {
        rowClass = isActive ? 'table-success' : 'table-danger';
    }
    const statusBadge = `<span class="badge ${isActive ? 'bg-success' : 'bg-danger'}">${esc(onu.status) || '—'}</span>`;
    const signalBadge = isActive
        ? `<span class="badge bg-info">${parseFloat(onu.optical_power).toFixed(2)} dBm</span>`
        : '<span class="badge bg-secondary">—</span>';
    const mcdBadge = onu.is_mcd
        ? ' <span class="badge bg-warning text-dark" title="МКД"><i class="bi bi-buildings"></i></span>'
        : '';
    const contractCell = (onu.contract && onu.contract !== 'N/A')
        ? `<code class="font-monospace" title="${esc(onu.contract)}">${esc(onu.contract)}</code>`
        : '<span class="text-muted">\u2014</span>';
    const deviceId = encodeURIComponent(String(onu.device_id));
    const iface = encodeURIComponent(String(onu.interface));
    const macCell = opts.showMac === false ? '' : `
            <td><code>${esc(onu.mac) || '—'}</code></td>`;
    let cells = `<tr class="${rowClass}">
            <td>${esc(onu.device)}</td>
            <td><code class="font-monospace">${esc(onu.interface)}</code></td>${macCell}
            <td class="text-truncate" style="max-width: 200px;" title="${esc(onu.description || '')}"><strong>${esc(onu.description) || '—'}</strong>${mcdBadge}</td>`;
    if (opts.showContract) {
        cells += `
            <td class="text-truncate" style="max-width: 140px;">${contractCell}</td>`;
    }
    cells += `
            <td>${statusBadge}</td>
            <td>${signalBadge}</td>`;
    if (opts.moveCell !== undefined) {
        cells += `
            <td>${opts.moveCell}</td>`;
    }
    cells += `
            <td><small class="text-muted">${esc(onu.last_seen) || '—'}</small></td>
            <td>
                <div class="d-flex gap-1">
                    <a href="/onu/${deviceId}/${iface}" class="btn btn-outline-primary btn-xs py-0 px-1" title="Детали ONU"><i class="bi bi-eye"></i></a>
                    <a href="/device/${deviceId}" class="btn btn-outline-secondary btn-xs py-0 px-1" title="Детали узла"><i class="bi bi-cpu"></i></a>
                </div>
            </td>
        </tr>`;
    return cells;
};

// Всплывающее уведомление (правый верхний угол). Единственная реализация
// для всего приложения — страницы не должны объявлять свою копию.
window.showNotification = function showNotification(message, type = 'info', timeoutMs = 4000) {
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    alert.style.cssText = 'top: 20px; right: 20px; z-index: 1050; min-width: 300px;';
    const icons = {
        'success': 'check-circle',
        'danger': 'exclamation-triangle',
        'warning': 'exclamation-triangle',
        'info': 'info-circle'
    };
    alert.innerHTML = `<i class="bi bi-${icons[type] || 'info-circle'}"></i> ${window.escapeHtml(message)}<button type="button" class="btn-close" data-bs-dismiss="alert"></button>`;
    document.body.appendChild(alert);
    setTimeout(() => { if (alert.parentNode) bootstrap.Alert.getOrCreateInstance(alert).close(); }, timeoutMs);
};
