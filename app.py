import os
import re
import io
import json
import html
import hmac
import secrets
import time
import logging
import threading
import functools
import concurrent.futures
from queue import Queue, Empty
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import pandas as pd
import werkzeug
from werkzeug.utils import secure_filename
from flask import (Flask, render_template, request, jsonify, send_file,
session, redirect, url_for, flash, abort)
from flask_caching import Cache
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger


from config import (DEVICES, USERS, SESSION_CONFIG, UPLOAD_CONFIG,
UPDATE_CONFIG, BACKUP_CONFIG, TELEGRAM_CONFIG,
add_device, remove_device_from_config,
get_devices_source_info, get_next_device_id, test_device_connection,
verify_password, _env, _env_int)
from ssh_client import BDCOMSSHClient, is_valid_interface
from database import (
init_db, get_db_session, save_device_status, save_onu_data,
run_migrations,
get_cached_device_data, cleanup_old_data, DeviceStatus, ONU, ONUClientMAC,
Contract, get_optical_status, get_device_stats, get_global_stats,
normalize_mac_address, save_contracts_from_file,
match_mac_query, is_hex_query, like_pattern, LIKE_ESCAPE,
bind_contracts_to_onu, search_contracts, get_contract_stats, ONUContract,
set_onu_contract, find_duplicate_onus, get_onu_contracts as db_get_onu_contracts,
cleanup_moved_onus, get_moved_onus, is_mcd, get_mcd_onus,
get_onu_list_by_filter, delete_onu_safely, delete_device_completely,
refresh_db_device_names, get_contracts_map_for_onus
)
from telegram_bot import (
telegram_bot, initialize_telegram_bot, start_telegram_monitoring,
stop_telegram_monitoring, cleanup_telegram_notifications,
get_telegram_bot_status, send_test_telegram_message, test_telegram_notification,
apply_telegram_settings
)


def setup_logging():
    """Централизованная настройка логирования (только для точки входа — app.py).

    Модули-библиотеки (database, ssh_client, telegram_bot) НЕ должны вызывать
    logging.basicConfig: это меняет глобальное состояние корневого логгера при
    любом их импорте. Здесь конфигурируется один раз: консоль + файл app.log
    с ротацией (LOG_FILE / LOG_MAX_BYTES / LOG_BACKUP_COUNT в env; пустой
    LOG_FILE отключает файловое логирование). Повторные вызовы идемпотентны.
    """
    root = logging.getLogger()
    if getattr(root, '_epon_configured', False):
        return
    level = getattr(logging, _env('LOG_LEVEL', 'INFO').upper(), logging.INFO)
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    class _JsonLinesFormatter(logging.Formatter):
        """JSON Lines: одна запись = одна строка; traceback (exc_info) — в поле `exc`.

        Обычный Formatter через json.dumps шаблона не годился: stacktrace
        попадал в msg как многострочный текст и ломал JSONL-парсинг.
        """

        def format(self, record):
            entry = {
                'ts': self.formatTime(record, self.datefmt),
                'name': record.name,
                'level': record.levelname,
                'msg': record.getMessage(),
            }
            if record.exc_info:
                entry['exc'] = self.formatException(record.exc_info)
            if record.stack_info:
                entry['stack'] = self.formatStack(record.stack_info)
            return json.dumps(entry, ensure_ascii=False)

    json_fmt = _JsonLinesFormatter()
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root.addHandler(console)
    log_file = _env('LOG_FILE', 'app.log')
    if log_file:
        try:
            from logging.handlers import RotatingFileHandler
            fh = RotatingFileHandler(
                log_file, maxBytes=_env_int('LOG_MAX_BYTES', 5 * 1024 * 1024),
                backupCount=_env_int('LOG_BACKUP_COUNT', 3), encoding='utf-8')
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except OSError as e:
            root.error(f"Не удалось открыть лог-файл {log_file}: {e}")
    # JSON Lines-лог (machine-readable): включается переменной окружения
    # LOG_JSON_FILE (по умолчанию выключена — поведение не меняется).
    # Удобно для сбора логов ELK/Loki/CloudWatch и для alerting по exc_info.
    json_log_file = _env('LOG_JSON_FILE', '')
    if json_log_file:
        try:
            from logging.handlers import RotatingFileHandler
            jh = RotatingFileHandler(
                json_log_file, maxBytes=_env_int('LOG_MAX_BYTES', 5 * 1024 * 1024),
                backupCount=_env_int('LOG_BACKUP_COUNT', 3), encoding='utf-8')
            jh.setFormatter(json_fmt)
            root.addHandler(jh)
        except OSError as e:
            root.error(f"Не удалось открыть JSON лог-файл {json_log_file}: {e}")
    root._epon_configured = True


setup_logging()
logging.getLogger('werkzeug').setLevel(logging.WARNING)
logging.getLogger('apscheduler').setLevel(logging.WARNING)
logger = logging.getLogger('EPON_Monitor')

app = Flask(__name__)
app.secret_key = SESSION_CONFIG['secret_key']
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=SESSION_CONFIG['permanent_session_lifetime'])
app.config['DEBUG'] = False
app.config['USE_RELOADER'] = False
# Безопасные флаги cookie сессии (httponly/samesite/secure из SESSION_CONFIG)
app.config['SESSION_COOKIE_HTTPONLY'] = SESSION_CONFIG.get('session_cookie_httponly', True)
app.config['SESSION_COOKIE_SAMESITE'] = SESSION_CONFIG.get('session_cookie_samesite', 'Lax')
app.config['SESSION_COOKIE_SECURE'] = SESSION_CONFIG.get('session_cookie_secure', False)
app.config['UPLOAD_FOLDER'] = UPLOAD_CONFIG['upload_folder']
app.config['MAX_CONTENT_LENGTH'] = UPLOAD_CONFIG['max_file_size']
ALLOWED_EXTENSIONS = UPLOAD_CONFIG['allowed_extensions']
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 300})


# ---------------------------------------------------------------------------
# CSRF-защита: токен в сессии, проверяется на всех изменяющих запросах.
# Клиент может прислать токен в форме (csrf_token), заголовке X-CSRF-Token
# или query-параметре csrf_token.
# ---------------------------------------------------------------------------
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(32)
    return session['_csrf_token']


app.jinja_env.globals['csrf_token'] = generate_csrf_token


def jsattr_filter(value):
    """Экранирует значение для подстановки в JS-строку внутри HTML-атрибута.

    Используется в onclick="fn('{{ value | jsattr }}')" — защищает от
    инъекций JS через данные, влияющие на содержимое атрибута события.
    Результат дополнительно проходит автоэкранирование Jinja (& -> &amp;).
    """
    s = '' if value is None else str(value)
    out = []
    for ch in s:
        if ch == '\\':
            out.append('\\\\')
        elif ch == "'":
            out.append("\\'")
        elif ch == '"':
            out.append('&quot;')
        elif ch == '<':
            out.append('\\u003c')
        elif ch == '>':
            out.append('\\u003e')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        else:
            out.append(ch)
    return ''.join(out)


app.jinja_env.filters['jsattr'] = jsattr_filter


@app.before_request
def csrf_protect():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        # Логин защищен SameSite=Lax cookie; отдельные исключения не требуются,
        # но токен для формы логина генерируется при GET-запросе.
        token = (request.form.get('csrf_token')
                 or request.headers.get('X-CSRF-Token')
                 or request.args.get('csrf_token')
                 or '')
        expected = session.get('_csrf_token')
        if not expected or not hmac.compare_digest(str(token), str(expected)):
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'CSRF token missing or invalid'}), 400
            abort(400, description='CSRF token missing or invalid')


# ---------------------------------------------------------------------------
# Rate limiting: защита от перебора паролей (brute-force) на /login.
# Скользящее окно инкрементов на IP хранится в кэше приложения
# (SimpleCache — потокобезопасен). Пороги можно настроить через env:
# LOGIN_MAX_ATTEMPTS (по умолчанию 5 попыток) и LOGIN_WINDOW_SECONDS
# (по умолчанию 300 сек). Успешный логин сбрасывает счётчик.
# ---------------------------------------------------------------------------
LOGIN_RATE_LIMIT = {
    'max_attempts': int(os.environ.get('LOGIN_MAX_ATTEMPTS', '5')),
    'window_seconds': int(os.environ.get('LOGIN_WINDOW_SECONDS', '300')),
}


def _login_attempts_key():
    # remote_addr — самый надёжный источник IP внутри нашего периметра;
    # X-Forwarded-For принимаем во внимание только если приложение
    # осознанно работает за реверс-прокси (TRUST_PROXY=1).
    if os.environ.get('TRUST_PROXY') == '1':
        fwd = request.headers.get('X-Forwarded-For', '')
        ip = fwd.split(',')[0].strip() if fwd else (request.remote_addr or 'unknown')
    else:
        ip = request.remote_addr or 'unknown'
    return f'rl:login:{ip}'


def check_login_rate_limit():
    """True — запрос разрешён; False — лимит исчерпан (429)."""
    key = _login_attempts_key()
    now = time.monotonic()
    window = LOGIN_RATE_LIMIT['window_seconds']
    attempts = cache.get(key) or []
    # Скользящее окно: устаревшие записи отбрасываются. TTL кэша ставим с
    # запасом (2x окна): если выставить timeout=window, SimpleCache удалит
    # всю запись ровно через window после последнего обращения — в тот же
    # момент, когда монотонное время объявляет её протухшей. На меденных CI
    # это гонка: «окно ещё не истекло» vs «кэш уже пуст», и тест
    # «заблокирован до истечения окна» становится flaky. Избыточный TTL
    # безвреден: корректность обеспечивает фильтрация по now - t < window,
    # а память чистится по idle-таймауту.
    ttl = 2 * window
    attempts = [t for t in attempts if now - t < window]
    if len(attempts) >= LOGIN_RATE_LIMIT['max_attempts']:
        cache.set(key, attempts, timeout=ttl)
        return False
    attempts.append(now)
    cache.set(key, attempts, timeout=ttl)
    return True


def reset_login_rate_limit():
    cache.delete(_login_attempts_key())

# Схема БД управляется Alembic-миграциями (каталог migrations/).
# run_migrations() идемпотентен: на чистой БД применит baseline-миграцию,
# на существующей production-БД просто выставит точку отсчёта (stamp head)
# и ничего менять не будет. Ошибку пробрасываем — рассинхрон схемы молча
# игнорировать нельзя.
try:
    run_migrations()
except Exception as e:
    logger.error(f"Не удалось применить миграции схемы: {e}", exc_info=True)
    raise
Session = init_db()
scheduler = BackgroundScheduler(daemon=True)
scheduler_thread = None
CACHE_TIMEOUT = UPDATE_CONFIG['device_cache_timeout']


scan_progress = {
'is_scanning': False, 'current_device': None, 'total_devices': 0,
'completed_devices': 0, 'start_time': None, 'estimated_time_remaining': None
}
progress_lock = threading.RLock()
thread_pool = concurrent.futures.ThreadPoolExecutor(
    # max_workers >= числа устройств: иначе update_all_devices (параллельная
    # отправка задач в пул) и fetch_device_data конкурируют за одни и те же
    # воркеры, и прогресс сканирования встаёт в очередь.
    max_workers=max(5, len(DEVICES)))


BASE_DIR = Path(__file__).resolve().parent
BACKUP_ABSOLUTE_DIR = BASE_DIR / BACKUP_CONFIG['backup_directory']


# Таймауты memoize-кэша согласованы с UPDATE_CONFIG: раньше все они были
# захардкожены (30/10/60) и не менялись вместе с настройками из .env.
@cache.memoize(timeout=UPDATE_CONFIG.get('memoize_cache_timeout', 30))
def get_cached_devices_data():
    devices_data = {}
    with get_db_session() as session_db:
        for device_id in DEVICES:
            data = get_cached_device_data(session_db, device_id, CACHE_TIMEOUT)
            if data:
                devices_data[device_id] = data
    return devices_data

@cache.memoize(timeout=UPDATE_CONFIG.get('memoize_cache_timeout', 30))
def get_cached_devices_stats():
    devices_stats = {}
    with get_db_session() as session_db:
        for device_id in DEVICES:
            stats = get_device_stats(session_db, device_id)
            devices_stats[device_id] = stats
    return devices_stats

@cache.memoize(timeout=UPDATE_CONFIG.get('status_cache_timeout', 10))
def get_cached_update_status():
    # ВАЖНО: раньше здесь вызывался start_update_worker(), т.е. любой GET
    # /api/update_status мог запустить фоновый поток UpdateWorker — это и
    # скрытая гонка (несколько воркеров при параллельных запросах до
    # установки global update_worker), и нежелательная побочная работа для
    # чисто-ридинг эндпоинта. Статус читается из уже существующего воркера;
    # запуск воркера — ответственность POST-эндпоинтов (api_start_update).
    worker = update_worker
    if worker and worker.is_alive():
        return worker.get_update_status()
    return {}

@cache.memoize(timeout=UPDATE_CONFIG.get('global_stats_cache_timeout', 60))
def get_cached_global_stats_memoized():
    with get_db_session() as session_db:
        return get_global_stats(session_db)

def invalidate_devices_cache():
    try:
        cache.delete_memoized(get_cached_devices_data)
        cache.delete_memoized(get_cached_devices_stats)
        cache.delete_memoized(get_cached_global_stats_memoized)
        logger.info("Devices cache invalidated")
    except Exception as e:
        logger.warning(f"Cache invalidation error: {e}")

def invalidate_update_status_cache():
    try:
        cache.delete_memoized(get_cached_update_status)
    except Exception as e:
        # Безобидно: ключ мог ещё не существовать в кэше.
        logger.debug("update-status cache invalidation skipped: %s", e)


def allowed_file(filename):
    if not filename or '.' not in filename:
        return False
    return filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def normalize_device_id(device_id):
    if isinstance(device_id, str) and device_id.isdigit() and device_id in DEVICES:
        return device_id
    for dev_id, config in DEVICES.items():
        if config['name'] == device_id:
            return dev_id
    return None

def is_valid_device_id(device_id):
    return normalize_device_id(device_id) is not None

def get_device_id_from_name(device_name):
    for dev_id, config in DEVICES.items():
        if config['name'] == device_name:
            return dev_id
    return None


# Управляющие символы C0/C1: \x00-\x1f и \x7f-\x9f (включая U+0085 NEL).
# Раньше blacklist покрывал только ASCII-подмножество и пропускал NEL:
# Cisco/Comware-парсеры OLT режут ввод по U+0085 так же, как по \n, что
# позволяло инъекцию второй строки команд ("abon\u0085no interface epon1/2:0").
# Табуляция (\t) тоже входит в диапазон \x00-\x1f — это осознанно: sanitize_string
# применяется к полям ONU/hostname/контрактов перед записью в БД и ответами API,
# а netmiko-колонки парсятся ДО санитизации (ssh_client -> raw parse -> validate).
_CONTROL_CHARS_RE = re.compile(r'[\x00-\x1f\x7f-\x9f]')


def strip_control_chars(value):
    """Заменяет все управляющие символы C0/C1 (\\x00-\\x1f, \\x7f-\\x9f, включая
    \\n, \\r, \\t и U+0085 NEL) на пробелы. Пробел вместо вырезания сохраняет
    разделители слов/колонок и исключает склейку токенов."""
    return _CONTROL_CHARS_RE.sub(' ', value)


def sanitize_string(value, max_length=100):
    if not isinstance(value, str):
        return ''
    # Unicode-контрольные символы недопустимы (см. этап 25).
    value = strip_control_chars(value)
    value = value.strip()
    if len(value) > max_length:
        value = value[:max_length]
    return value


# Общее безопасное сообщение об ошибке для API-ответов: внутренние детали
# (пути, стектрейсы, строки исключений драйверов) клиенту не отдаём —
# они пишутся только в лог с exc_info=True.
_INTERNAL_ERROR_MSG = 'Внутренняя ошибка сервера. Обратитесь к администратору.'

# Whitelist символов для ONU-описаний, которые подставляются в SSH-команду
# 'description ...' на OLT: буквы любого языка (\w с re.UNICODE), цифры,
# пробел и нейтральные разделители -_:/. #. Все shell/CLI-спецсимволы
# (' ; ` $ \ " ' < > | & ( ) { } [ ] * ? ! ~ @ ^ + = % , и т.п.) вырезаются
# целиком. Раньше использовался quote_plus() — он ломал кириллицу в
# конфигурации устройств (%D0%9C%D0%B5... вместо читаемого описания).
DESCRIPTION_ALLOWED_RE = re.compile(r'[^\w \-_:/.#]|[\x00-\x1f\x7f-\x9f]', re.UNICODE)


def sanitize_description(value, max_length=100):
    """Санитизирует ONU-описание для безопасной передачи на OLT по SSH.

    Сначала sanitize_string (вырезает управляющие символы, strip, cap по
    длине), затем whitelist-regex вырезает все печатные спецсимволы, кроме
    разрешённых. Пустая строка допустима (означает 'no description').
    """
    value = sanitize_string(value, max_length=max_length)
    return DESCRIPTION_ALLOWED_RE.sub('', value)[:max_length]

# like_pattern/LIKE_ESCAPE импортируются из database — единый источник
# логики экранирования wildcard-символов ('%', '_') в LIKE-паттернах поиска.

def validate_interface(interface):
    """Строгая проверка формата интерфейса ONU (EPON/GPON x/y:z).

    Единый источник истины — ssh_client.is_valid_interface (fullmatch,
    который пропускает завершающий '\\n', что позволяло инъекцию второй
    строки команд на OLT). Здесь только нормализуем тип аргумента.
    """
    return is_valid_interface(interface)


def safe_interface(value):
    """Возвращает интерфейс для отправки клиенту только если он проходит
    строгую проверку формата; иначе '' (defense-in-depth: даже если в БД
    окажется мусор из legacy-сканов, фронтенд не получит недоверенную
    подстановку)."""
    s = sanitize_string(value, max_length=32)
    return s if validate_interface(s) else ''


# Строгий whitelist для hostname/IP устройств: IPv4 в dotted-quad записи или
# стандартное DNS-имя (буквы/цифры/дефис/точка, без подчёркиваний и т.п.).
# Раньше здесь был r'[\d.]+' — regex совпадал с любым набором цифр и точек,
# включая '999.999.999.999', '1.2.3.4.5', '..' и '.1'. Плюс re.fullmatch
# эквивалентен search+anchoring, но [\d.]+ всё равно не валидировал диапазоны.
HOSTNAME_RE = re.compile(
    r'^(?:'
    r'(?:\d{1,3}\.){3}\d{1,3}'                      # IPv4 dotted-quad
    r'|[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'  # single DNS label
    r'(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*'  # + more labels
    r')$'
)


def is_valid_hostname(hostname):
    """Возвращает True, если hostname — корректный IPv4 или DNS-имя."""
    if not isinstance(hostname, str) or not hostname or len(hostname) > 253:
        return False
    if not HOSTNAME_RE.match(hostname):
        return False
    # Для IPv4 дополнительно проверяем диапазоны октетов.
    parts = hostname.split('.')
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return all(0 <= int(p) <= 255 for p in parts)
    return True

def escape_html(text):
    if text is None:
        return ''
    return html.escape(str(text))


def _safe_next_url():
    """Возвращает безопасный относительный URL для редиректа после логина."""
    next_url = request.path
    if request.query_string:
        next_url = f"{next_url}?{request.query_string.decode('utf-8', 'ignore')}"
    return next_url


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=_safe_next_url()))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=_safe_next_url()))
        if session.get('role') != 'admin':
            flash('Недостаточно прав для выполнения этого действия', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def cache_response(timeout=60):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            cache_key = f"response_{f.__name__}_{str(args)}_{str(kwargs)}"
            cached = cache.get(cache_key)
            if cached is not None:
                return cached
            response = f(*args, **kwargs)
            if response is not None:
                cache.set(cache_key, response, timeout=timeout)
            return response
        return decorated_function
    return decorator


update_queue = Queue()
update_worker = None
update_worker_lock = threading.RLock()

class UpdateWorker(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.running = True
        self.current_updates = {}
        self.update_lock = threading.RLock()
        self.device_update_started = {}
        self._stop_event = threading.Event()

    def run(self):
        # diagnostic heartbeat: logs every 60s so operators can confirm the
        # worker thread is alive even when no tasks are queued (queue depth
        # included to reveal backlog/stall situations).
        _last_heartbeat = time.time()
        _HEARTBEAT_INTERVAL = 60
        while self.running and not self._stop_event.is_set():
            now_hb = time.time()
            if now_hb - _last_heartbeat >= _HEARTBEAT_INTERVAL:
                qsize = update_queue.qsize()
                logger.info(
                    f"UpdateWorker heartbeat: alive, queue_size={qsize}, "
                    f"in_progress={len([u for u in self.current_updates.values() if u.get('status') == 'in_progress'])}"
                )
                _last_heartbeat = now_hb
            try:
                try:
                    task = update_queue.get(timeout=1)
                except Empty:
                    continue

                if self._stop_event.is_set():
                    update_queue.task_done()
                    break

                if task == 'STOP':
                    logger.info("Update worker received STOP signal")
                    update_queue.task_done()
                    break

                device_id = task.get('device_id')
                force_fresh = task.get('force_fresh', True)
                task_type = task.get('type', 'update')

                if device_id:
                    device_name = DEVICES.get(device_id, {}).get('name', device_id)

                    with self.update_lock:
                        self.current_updates[device_id] = {
'status': 'in_progress', 'start_time': time.time(),
'device_name': device_name, 'type': task_type
}

                    try:
                        if device_id == 'all':
                            result = self.update_all_devices(task_type)
                        else:
                            result = self.update_single_device(device_id, force_fresh, task_type)
                    except Exception as e:
                        # Подробности — только в логе (могут содержать пути/хосты);
                        # UI получает generic-сообщение.
                        logger.error(f"Update task error for {device_id}: {e}", exc_info=True)
                        result = {'success': False, 'message': _INTERNAL_ERROR_MSG}

                    with self.update_lock:
                        if device_id in self.current_updates:
                            self.current_updates[device_id].update({
'status': 'completed', 'end_time': time.time(),
'success': result.get('success', False),
'message': result.get('message', '')
})
                    logger.info(f"Update task completed for {device_name}: {result.get('message', '')}")
                    update_queue.task_done()

            except Exception as e:
                logger.error(f"Update worker error: {e}", exc_info=True)
                if 'device_id' in locals() and device_id:
                    with self.update_lock:
                        if device_id in self.current_updates:
                            self.current_updates[device_id].update({
'status': 'failed', 'end_time': time.time(),
'error': _INTERNAL_ERROR_MSG
})

    def update_single_device(self, device_id, force_fresh=True, task_type='update'):
        # Тестовый хук: подменяя app_module._DEVICE_UPDATE_STUB, тесты
        # проверяют структуру параллельного опроса без реального SSH-обхода.
        stub = globals().get('_DEVICE_UPDATE_STUB')
        if stub is not None:
            return stub(device_id)
        try:
            device_config = DEVICES.get(device_id)
            if not device_config:
                return {'success': False, 'message': f'Устройство {device_id} не найдено'}

            logger.info(f"Starting {task_type} for device: {device_config['name']}")

            with get_db_session() as session_db:
                status = session_db.query(DeviceStatus).filter_by(device_id=device_id).first()
                if status:
                    status.is_online = True
                    status.error_message = f"{task_type.capitalize()} in progress..."
                    session_db.commit()

            data = fetch_device_data_parallel(device_id, force_fresh=force_fresh, is_background_task=True)
            if data and data.get('success'):
                message = f"Успешно обновлено: {len(data.get('onu_info', []))} ONU"
                return {'success': True, 'message': message}
            else:
                error_msg = data.get('error', 'Unknown error') if data else 'No data received'
                return {'success': False, 'message': f'Ошибка: {error_msg}'}
        except Exception as e:
            logger.error(f"Error updating device {device_id}: {e}", exc_info=True)
            return {'success': False, 'message': _INTERNAL_ERROR_MSG}

    def update_all_devices(self, task_type='update'):
        """Обновляет все устройства ПАРАЛЛЕЛЬНО через thread_pool.

        Раньше устройства обрабатывались последовательным циклом: общее время
        равнялось сумме таймаутов всех устройств (SSH-опрос медленный). Теперь
        задачи ставятся в единый пул и ожидаются через as_completed.
        """
        device_ids = list(DEVICES.keys())
        results = []

        invalidate_devices_cache()
        invalidate_update_status_cache()

        with progress_lock:
            scan_progress['is_scanning'] = True
            scan_progress['current_device'] = None
            scan_progress['total_devices'] = len(device_ids)
            scan_progress['completed_devices'] = 0
            scan_progress['start_time'] = time.time()

        # Регистрируем статусы «в процессе» до старта, чтобы UI видел все устройства сразу
        for device_id in device_ids:
            with self.update_lock:
                self.current_updates[device_id] = {
                    'status': 'in_progress', 'start_time': time.time(),
                    'device_name': DEVICES[device_id]['name'], 'type': task_type
                }

        try:
            futures = {}
            for device_id in device_ids:
                if self._stop_event.is_set():
                    break
                fut = thread_pool.submit(
                    self.update_single_device, device_id, True, task_type)
                futures[fut] = device_id

            for completed, fut in enumerate(concurrent.futures.as_completed(futures), start=1):
                device_id = futures[fut]
                device_config = DEVICES.get(device_id, {'name': device_id})
                try:
                    # Внутренний таймаут (300 c) уже обрабатывается в
                    # fetch_device_data_parallel; здесь только защита от зависания.
                    result = fut.result()
                except Exception as e:
                    logger.error(f"Device {device_config['name']} update raised: {e}", exc_info=True)
                    result = {'success': False, 'message': _INTERNAL_ERROR_MSG}
                results.append(result)

                with progress_lock:
                    scan_progress['current_device'] = device_config['name']
                    scan_progress['completed_devices'] = completed

                with self.update_lock:
                    if device_id in self.current_updates:
                        self.current_updates[device_id].update({
                            'status': 'completed', 'end_time': time.time(),
                            'success': result.get('success', False),
                            'message': result.get('message', '')
                        })
                logger.info(f"Device {device_config['name']} update: {result.get('message', '')}")

            success_count = sum(1 for r in results if r.get('success', False))
            failed_count = len(results) - success_count

            return {
                'success': failed_count == 0,
                'message': f'Обновлено {success_count}/{len(results)} устройств',
                'details': results
            }
        finally:
            with progress_lock:
                scan_progress['is_scanning'] = False
                scan_progress['completed_devices'] = len(device_ids)
            # прогресс хранится в памяти (scan_progress) — отдельной инвалидации не требуется

    def get_update_status(self, device_id=None):
        with self.update_lock:
            if device_id:
                return self.current_updates.get(device_id, {'status': 'not_started'})
            else:
                all_status = {}
                for dev_id in DEVICES:
                    status = self.current_updates.get(dev_id, {'status': 'not_started'})
                    all_status[dev_id] = status
                return all_status

    def stop(self):
        self.running = False
        self._stop_event.set()
        update_queue.put('STOP')
        self.join(timeout=5)

def start_update_worker():
    global update_worker
    with update_worker_lock:
        if update_worker is None or not update_worker.is_alive():
            update_worker = UpdateWorker()
            update_worker.start()
            logger.info("Update worker started")
            return update_worker
        else:
            logger.debug("Update worker already running")
            return update_worker

def update_scan_progress(is_scanning=False, current_device=None, total_devices=0, completed_devices=0):
    with progress_lock:
        scan_progress['is_scanning'] = is_scanning
        scan_progress['current_device'] = current_device
        scan_progress['total_devices'] = total_devices
        scan_progress['completed_devices'] = completed_devices

        if is_scanning and completed_devices > 0:
            if scan_progress['start_time'] is None:
                scan_progress['start_time'] = time.time()
            elapsed_time = time.time() - scan_progress['start_time']
            avg_time_per_device = elapsed_time / completed_devices
            remaining_devices = total_devices - completed_devices
            scan_progress['estimated_time_remaining'] = avg_time_per_device * remaining_devices
        else:
            scan_progress['start_time'] = None
            scan_progress['estimated_time_remaining'] = None


# Поддерживаемые форматы MAC-адресов (Cisco AAAA.AAAA.AAAA, пунктирный,
# двоичный и др.). Компилируются один раз на уровне модуля.
MAC_PATTERNS = [
    re.compile(r'^[a-zA-Z0-9]{4}\.[a-zA-Z0-9]{4}\.[a-zA-Z0-9]{4}$'),
    re.compile(r'^[a-zA-Z0-9]{4}:[a-zA-Z0-9]{8}$'),
    re.compile(r'^[a-zA-Z0-9]{4}:[a-zA-Z0-9]{12}$'),
    re.compile(r'^[a-zA-Z0-9]{12}$'),
    re.compile(r'^([a-zA-Z0-9]{2}[-:]){5}[a-zA-Z0-9]{2}$'),
]


def is_valid_mac(mac):
    """Проверяет MAC по списку компилированных паттернов (fullmatch)."""
    return bool(mac) and any(p.fullmatch(mac) for p in MAC_PATTERNS)


def validate_onu_data(onu_data):
    """Strict validation of one parsed ONU record before it reaches the DB.

    All string fields are sanitized (control chars stripped, length-capped)
    IN PLACE so that downstream consumers (DB writes, JSON responses) see
    clean values. Interface must match the strict EPON/GPON pattern — this
    is the last line of defense against command injection into SSH CLI
    commands built from stored interfaces (e.g. by a malicious device
    banner or a manually edited DB row).
    """
    if not isinstance(onu_data, dict):
        return False
    required_fields = ['interface', 'vendor', 'model', 'mac', 'status']
    for field in required_fields:
        if field not in onu_data:
            logger.warning("Missing required field '%s' in ONU data", field)
            return False
    # Sanitize all string fields in place (strip control chars, cap length).
    max_lengths = {'interface': 32, 'vendor': 64, 'model': 64,
                   'mac': 32, 'status': 32, 'description': 100}
    for field, max_len in max_lengths.items():
        if field in onu_data and isinstance(onu_data[field], str):
            onu_data[field] = sanitize_string(onu_data[field], max_length=max_len)
    if not onu_data['interface'] or onu_data['interface'] == 'N/A':
        logger.warning("Invalid interface: %s", onu_data['interface'])
        return False
    if not validate_interface(onu_data['interface']):
        logger.warning("Rejected non-conforming interface format: %r",
                       onu_data['interface'])
        return False
    mac = onu_data.get('mac')
    if mac and mac != 'N/A' and not is_valid_mac(mac):
        logger.warning("Invalid MAC format: %s", mac)
        return False
    return True

def deduplicate_onu_list(onu_list):
    seen_interfaces = set()
    unique_onus = []
    for onu in onu_list:
        interface = onu.get('interface')
        if not interface or interface in seen_interfaces:
            continue
        seen_interfaces.add(interface)
        unique_onus.append(onu)
    if len(onu_list) != len(unique_onus):
        logger.info(f"Deduplication: {len(onu_list)} -> {len(unique_onus)} ONUs")
    return unique_onus

def fetch_device_data_parallel(device_id, force_fresh=False, is_background_task=False):
    normalized_id = normalize_device_id(device_id)
    if not normalized_id:
        logger.warning(f"Invalid device identifier: {device_id}")
        return None

    device_config = DEVICES.get(normalized_id)
    if not device_config:
        logger.warning(f"Device {device_id} (normalized: {normalized_id}) not found in config")
        return None

    with get_db_session() as session_db:
        if not force_fresh and not is_background_task:
            cached_data = get_cached_device_data(session_db, normalized_id, CACHE_TIMEOUT)
            if cached_data:
                logger.info(f"DEBUG: Using cached data from DB for {device_config['name']}")
                return cached_data

        logger.info(f"Fetching FRESH data for {device_config['name']}")

        ssh_client = BDCOMSSHClient(
device_config['hostname'], device_config['username'],
device_config['password'], device_config['enable_password'],
model=device_config.get('model', '3310')
)

        if not ssh_client.connect():
            error_msg = f"Failed to connect to {device_config['name']}"
            logger.error(error_msg)
            with get_db_session() as session_db:
                save_device_status(session_db, normalized_id, device_config['name'], {}, success=False, error_message=error_msg)
            return {'onu_info': [], 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'success': False, 'error': error_msg}

        logger.info(f"Getting ONU information from {device_config['name']}...")

        try:
            onu_info = ssh_client.get_onu_information()
            ssh_client.close()

            if onu_info is None:
                error_msg = f"Failed to poll ONU data from {device_config['name']} (SSH/command error)"
                logger.error(error_msg)
                with get_db_session() as session_db:
                    save_device_status(session_db, normalized_id, device_config['name'], {}, success=False, error_message=error_msg)
                return {'onu_info': [], 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'success': False, 'error': error_msg}

            valid_onus = [onu for onu in onu_info if validate_onu_data(onu)]
            valid_onus = deduplicate_onu_list(valid_onus)

            data = {
'onu_info': valid_onus, 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
'success': True, 'enriched': True
}

            with get_db_session() as session_db:
                save_result = save_onu_data(session_db, normalized_id, device_config['name'], valid_onus)
                save_device_status(session_db, normalized_id, device_config['name'], data, success=True)

                desc_sync_list = save_result.get('desc_sync', [])
                if desc_sync_list:
                    logger.info(f"Found {len(desc_sync_list)} ONUs needing description sync on {device_config['name']}")
                    sync_client = BDCOMSSHClient(
device_config['hostname'], device_config['username'],
device_config['password'], device_config['enable_password'],
model=device_config.get('model', '3310')
)
                    try:
                        synced = sync_client.sync_onu_descriptions(desc_sync_list)
                        logger.info(f"✅ Synced {synced} descriptions on {device_config['name']}")
                    except Exception as e:
                        logger.error(f"❌ Error syncing descriptions on {device_config['name']}: {e}", exc_info=True)
                    finally:
                        sync_client.close()

            invalidate_devices_cache()
            logger.info(f"Successfully fetched and saved data for {device_config['name']}: {len(valid_onus)} ONUs")
            return data

        except Exception as e:
            # Клиенту — generic-сообщение; в error_message БД и возврате —
            # только тип ошибки (сырое str(e) может содержать пути/хосты).
            logger.error(f"Error during data collection for {device_config['name']}: {e}", exc_info=True)
            error_msg = f"Ошибка сбора данных: {type(e).__name__}"
            try:
                ssh_client.close()
            except Exception as close_err:
                logger.debug("SSH close after collection error skipped: %s", close_err)
            with get_db_session() as session_db:
                save_device_status(session_db, normalized_id, device_config['name'], {}, success=False, error_message=error_msg)
            return {'onu_info': [], 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'success': False, 'error': error_msg}

def fetch_device_data(device_id, force_fresh=False):
    future = thread_pool.submit(fetch_device_data_parallel, device_id, force_fresh, False)
    device_name = DEVICES.get(normalize_device_id(device_id), {}).get('name', device_id)
    try:
        result = future.result(timeout=300)
        if result:
            logger.info(f"DEBUG: fetch_device_data for {device_name} got {len(result.get('onu_info', []))} ONUs")
        else:
            logger.warning(f"DEBUG: fetch_device_data for {device_name} returned None")
            result = {'onu_info': [], 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'success': False, 'error': 'No data received'}
        return result
    except concurrent.futures.TimeoutError:
        logger.error(f"Timeout while fetching data from {device_name}")
        return {'onu_info': [], 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'success': False, 'error': 'Timeout'}
    except Exception as e:
        logger.error(f"Error in fetch_device_data for {device_name}: {e}", exc_info=True)
        # Клиенту (страница index.html показывает data.error) не отдаём
        # сырое сообщение исключения — только тип ошибки. Подробности в логе.
        return {'onu_info': [], 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'success': False, 'error': type(e).__name__}

def get_device_data(device_id):
    normalized_id = normalize_device_id(device_id)
    if not normalized_id:
        return {'onu_info': [], 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'success': False, 'enriched': False, 'error': f'Invalid device identifier: {device_id}'}
    data = fetch_device_data(normalized_id, force_fresh=False)
    if not data:
        data = {'onu_info': [], 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'success': False, 'enriched': False, 'error': 'No data received'}
    return data

def refresh_device_data(device_id):
    normalized_id = normalize_device_id(device_id)
    if not normalized_id:
        return None
    invalidate_devices_cache()
    return fetch_device_data(normalized_id, force_fresh=True)

def group_and_sort_onus_by_interface(onus: list) -> dict:
    grouped = {}
    for onu in onus:
        interface = onu['interface']
        if ':' in interface:
            parent_interface = interface.split(':')[0]
            if parent_interface not in grouped:
                grouped[parent_interface] = []
            grouped[parent_interface].append(onu)

    def interface_sort_key(interface_name):
        try:
            parts = interface_name.split('/')
            if len(parts) == 2:
                return int(parts[1])
        except (ValueError, IndexError):
            pass
        return 999

    sorted_interfaces = sorted(grouped.keys(), key=interface_sort_key)

    for interface in grouped:
        def onu_sort_key(onu):
            try:
                onu_parts = onu['interface'].split(':')
                if len(onu_parts) == 2:
                    return int(onu_parts[1])
            except (ValueError, IndexError):
                pass
            return 999
        grouped[interface] = sorted(grouped[interface], key=onu_sort_key)

    return {interface: grouped[interface] for interface in sorted_interfaces}

def apply_signal_filter(onu_list, signal_filter):
    _SIGNAL_FILTERS = ('has_signal', 'no_signal', 'good', 'warning', 'bad')

    def _match(power):
        if signal_filter not in _SIGNAL_FILTERS:
            return True  # неизвестный/пустой фильтр — не сужаем выборку (как раньше)
        if signal_filter == 'has_signal':
            return power is not None
        if signal_filter == 'no_signal':
            return power is None
        if power is None:
            # статусные фильтры требуют измеренного уровня сигнала
            return False
        if signal_filter == 'good':
            return power > -25
        if signal_filter == 'warning':
            return -27 <= power <= -25
        return power < -27  # bad

    return [onu for onu in onu_list if _match(onu.get('optical_power'))]


def safe_max_len(df, col):
    try:
        lengths = df[col].astype(str).map(len)
        max_val = lengths.max()
        if pd.isna(max_val) or not isinstance(max_val, (int, float)):
            max_val = 0
        return int(max(max_val, len(str(col)))) + 2
    except Exception:
        return len(str(col)) + 2

def build_onu_dataframe(onus, include_extended=False):
    df_data = []
    for onu in onus:
        optical_power = onu.get('optical_power')
        optical_status = onu.get('optical_status') or get_optical_status(optical_power)
        description = onu.get('description', '') or ''
        is_mcd_flag = onu.get('is_mcd') or is_mcd(description)

        row = {
'Устройство': onu.get('device', onu.get('device_name', '')),
'Интерфейс': onu.get('interface', ''),
'MAC': onu.get('mac', ''),
'Описание': description,
'Договор': onu.get('contract', ''),
'Статус': onu.get('status', ''),
'Причина откл.': onu.get('dereg_reason', ''),
'Оптич. сигнал': f"{optical_power:.2f} dBm" if optical_power is not None else '',
'Статус сигнала': optical_status,
'Клиентов': onu.get('client_macs_count', 0),
'Вендор': onu.get('vendor', ''),
'Модель': onu.get('model', ''),
'МКД': 'ДА' if is_mcd_flag else '',
}
        if include_extended:
            row['Последняя активность'] = onu.get('last_seen', '')
            row['Переезд'] = onu.get('moved_to', '')
        df_data.append(row)
    return pd.DataFrame(df_data) if df_data else None

def write_excel(df, sheet_name, header_color='#D7E4BD'):
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, sheet_name=sheet_name, index=False)
        workbook = writer.book
        worksheet = writer.sheets[sheet_name]
        header_format = workbook.add_format({
'bold': True, 'text_wrap': True, 'valign': 'top',
'fg_color': header_color, 'border': 1
})
        for col_num, value in enumerate(df.columns.values):
            worksheet.write(0, col_num, value, header_format)
        for i, col in enumerate(df.columns):
            worksheet.set_column(i, i, min(safe_max_len(df, col), 50))
    output.seek(0)
    return output

def export_device_to_excel(device_id):
    normalized_id = normalize_device_id(device_id)
    if not normalized_id:
        return None
    with get_db_session() as session_db:
        device_config = DEVICES.get(normalized_id)
        if not device_config:
            return None
        onus = session_db.query(ONU).filter_by(device_id=normalized_id, is_active=True).all()
        if not onus:
            logger.warning(f"No ONU data found in database for {device_config['name']}")
            return None
        logger.info(f"Found {len(onus)} ONUs in database for {device_config['name']}")

        onu_interfaces = [f"{normalized_id}:{onu.interface}" for onu in onus]
        all_macs = session_db.query(ONUClientMAC).filter(ONUClientMAC.onu_interface.in_(onu_interfaces)).all()
        macs_by_interface = {}
        for mac in all_macs:
            macs_by_interface.setdefault(mac.onu_interface, []).append(mac.mac_address)

        df_data = []
        for onu in onus:
            full_iface = f"{normalized_id}:{onu.interface}"
            macs_list = macs_by_interface.get(full_iface, [])
            optical_status = 'unknown'
            if onu.optical_power is not None:
                if onu.optical_power > -25:
                    optical_status = 'good'
                elif onu.optical_power >= -27:
                    optical_status = 'warning'
                else:
                    optical_status = 'bad'

            df_data.append({
'Interface': onu.interface, 'Vendor': onu.vendor or '', 'Model': onu.model or '',
'MAC': onu.mac or '', 'Description': onu.description or '', 'Contract': onu.contract or '',
'Bind Type': onu.bind_type or 'static', 'Status': onu.status or 'N/A',
'Dereg Reason': onu.dereg_reason or '',
'Optical Power': f"{onu.optical_power:.2f} dBm" if onu.optical_power is not None else '',
'Optical Status': optical_status, 'Client MACs Count': len(macs_list),
'Client MACs': ', '.join(macs_list) if macs_list else '',
'МКД': 'ДА' if is_mcd(onu.description) else '',
})

        if not df_data:
            return None
        df = pd.DataFrame(df_data)
        return write_excel(df, 'ONU Data', '#D7E4BD')

def export_mcd_onus_to_excel():
    with get_db_session() as session_db:
        result = get_mcd_onus(session_db, None)
        mcd_onus = result.get('mcd_onus', [])
        if not mcd_onus:
            return None
        df = build_onu_dataframe(mcd_onus, include_extended=True)
        if df is None:
            return None
        return write_excel(df, 'МКД-ONU', '#FFF2CC')

def export_inactive_onus_to_excel():
    with get_db_session() as session_db:
        inactive_onus = session_db.query(ONU).filter(ONU.optical_power.is_(None), ONU.is_active.is_(True)).all()
        if not inactive_onus:
            return None
        df_data = []
        for onu in inactive_onus:
            bind_type = 'dynamic' if onu.description and ('dynamic' in onu.description.lower() or 'динам' in onu.description.lower()) else 'static'
            df_data.append({
'Device': onu.device_name, 'Interface': onu.interface, 'Vendor': onu.vendor or '',
'Model': onu.model or '', 'MAC': onu.mac or '', 'Description': onu.description or '',
'Contract': onu.contract or '', 'Bind Type': bind_type,
'Status': onu.status or 'off-line', 'Dereg Reason': onu.dereg_reason or '',
'Optical Power': '', 'Optical Status': 'unknown',
'Client MACs Count': onu.client_macs_count or 0,
'МКД': 'ДА' if is_mcd(onu.description) else '',
})
        df = pd.DataFrame(df_data)
        return write_excel(df, 'Inactive ONUs', '#D7E4BD')


def save_running_config(device_id):
    normalized_id = normalize_device_id(device_id)
    device_config = DEVICES.get(normalized_id)
    if not device_config:
        logger.error(f"Device {device_id} not found in config")
        return False

    try:
        ssh_client = BDCOMSSHClient(
device_config['hostname'], device_config['username'],
device_config['password'], device_config['enable_password'],
model=device_config.get('model', '3310')
)
        logger.info(f"Getting running config for {device_config['name']}")
        config_output = ssh_client.save_running_config()
        ssh_client.close()

        if not config_output:
            logger.error(f"Failed to get running config for {device_config['name']}")
            return False

        current_date = datetime.now().strftime('%d.%m.%Y')
        base_dir = BACKUP_ABSOLUTE_DIR / device_config['name'] / current_date
        base_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = base_dir / f"show_running-config_{timestamp}.txt"

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"# Device: {device_config['name']}\n")
            f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Hostname: {device_config['hostname']}\n")
            f.write("# " * 80 + "\n")
            f.write(config_output)

        logger.info(f"Running config saved to {filename}")
        return True
    except Exception as e:
        logger.error(f"Error saving running config for {device_config['name']}: {e}", exc_info=True)
        return False

def _run_per_device_parallel(job_label, worker):
    """Общий фреймворк периодических задач: параллельный опрос устройств.

    Раньше бэкап конфигов и экспорт Excel обходили устройства последовательным
    циклом — общее время равнялось сумме таймаутов всех SSH-сессий. Теперь
    задачи ставятся в thread_pool (как в update_all_devices), а запись файлов
    выполняется из основного потока (worker возвращает данные).
    Исключение одного устройства не прерывает обработку остальных.
    """
    device_ids = list(DEVICES.keys())
    futures = {thread_pool.submit(worker, did): did for did in device_ids}
    ok = failed = 0
    for fut in concurrent.futures.as_completed(futures):
        did = futures[fut]
        name = DEVICES.get(did, {}).get('name', did)
        try:
            result = fut.result()
        except Exception as e:
            logger.error(f"💥 {job_label} error for {name}: {e}", exc_info=True)
            failed += 1
            continue
        if result:
            logger.info(f"✅ {job_label} done for {name}")
            ok += 1
        else:
            logger.error(f"❌ {job_label} failed for {name}")
            failed += 1
    logger.info(f"{job_label} completed: {ok} ok, {failed} failed")


def save_all_running_configs():
    logger.info("Starting scheduled running config backup")
    _run_per_device_parallel("Running config backup", save_running_config)


def _export_onu_excel(device_id):
    """Экспорт ONU одного устройства в файл (вызывается из пула; запись файла
    выполняется синхронно в момент генерации — это быстрый локальный I/O)."""
    output = export_device_to_excel(device_id)
    if not output:
        return False
    device_config = DEVICES[device_id]
    current_date = datetime.now().strftime('%d.%m.%Y')
    base_dir = BACKUP_ABSOLUTE_DIR / device_config['name'] / current_date
    base_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = base_dir / f"{device_config['name']}_onu_data_{timestamp}.xlsx"
    with open(filename, 'wb') as f:
        f.write(output.getvalue())
    logger.info(f"ONU data exported to {filename}")
    return True


def save_all_onu_data_excel():
    logger.info("Starting scheduled ONU data export")
    _run_per_device_parallel("ONU data export", _export_onu_excel)


def is_safe_redirect_url(target):
    """Защита от open redirect: разрешаем только относительные URL нашего приложения.

    Отклоняем протокольно-относительные ('//host'), схемы ('http://...', 'javascript:...')
    и пути с обратными слэшами.
    """
    if not target:
        return False
    if target.startswith(('//', '/\\', '\\')):
        return False
    return target.startswith('/')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Rate limiting: защита от перебора паролей по IP (скользящее окно).
        if not check_login_rate_limit():
            logger.warning(
                f"Login rate limit exceeded for {request.remote_addr}")
            flash(('Слишком много неудачных попыток входа. '
                   f"Повторите через {LOGIN_RATE_LIMIT['window_seconds'] // 60} мин."),
                  'danger')
            return render_template('login.html'), 429
        username = request.form.get('username')
        password = request.form.get('password')
        # Проверяем пароль по хэшу (bcrypt/pbkdf2) из config.verify_password;
        # сравнение constant-time выполняется внутри библиотек хеширования.
        info = USERS.get(username)
        stored = (info or {}).get('password_hash') or (info or {}).get('password', '')
        password_ok = bool(info) and verify_password(stored, password)
        if password_ok:
            reset_login_rate_limit()
            # Защита от CSRF-атак нового логина и фиксации сессии:
            # полностью сбрасываем предшествовавшую анонимную сессию
            session.clear()
            session['username'] = username
            session['role'] = USERS[username]['role']
            session.permanent = True
            next_url = request.form.get('next') or request.args.get('next')
            if is_safe_redirect_url(next_url):
                return redirect(next_url)
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'danger')
            return render_template('login.html')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы успешно вышли из системы', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    with get_db_session() as session_db:
        global_stats = get_global_stats(session_db)
        devices_data, devices_stats = {}, {}
        for device_id, _device_config in DEVICES.items():
            devices_stats[device_id] = get_device_stats(session_db, device_id)
            cached_data = get_cached_device_data(session_db, device_id, CACHE_TIMEOUT)
            devices_data[device_id] = cached_data if cached_data else {'onu_info': [], 'timestamp': 'Данные не загружены', 'success': False, 'enriched': False}
    return render_template('index.html', devices_data=devices_data, devices_stats=devices_stats,
global_stats=global_stats, DEVICES=DEVICES, get_device_stats=get_device_stats,
username=session.get('username'), role=session.get('role'))

@app.route('/device/<device_id>')
@login_required
def device_detail(device_id):
    normalized_id = normalize_device_id(device_id)
    if not normalized_id:
        return render_template('error.html', message=f"Устройство '{escape_html(device_id)}' не найдено")

    status_filter = request.args.get('status', 'all')
    branch_filter = request.args.get('branch', 'all')
    reason_filter = request.args.get('reason', 'all')
    signal_filter = request.args.get('signal', 'all')
    contract_filter = request.args.get('contract', 'all')
    moved_filter = request.args.get('moved', 'all')
    mcd_filter = request.args.get('mcd', 'all')
    search_query = sanitize_string(request.args.get('search', ''), max_length=100)

    with get_db_session() as session_db:
        device_config = DEVICES.get(normalized_id)
        if not device_config:
            return render_template('error.html', message="Устройство не найдено")

        data = get_cached_device_data(session_db, normalized_id, CACHE_TIMEOUT)
        if not data:
            # error.html экранирует {{ message }} — никаких HTML/JS-вставок сюда,
            # только plain text (раньше здесь была битая javascript:-ссылка,
            # которая показывалась как сырой HTML-текст; startUpdate не существует).
            return render_template(
                'error.html',
                message=(f"Данные для {device_config['name']} ещё не собраны. "
                         f'Откройте страницу устройства и нажмите «Сканировать»: /device/{normalized_id}'),
            )

        filtered_onus = data.get('onu_info', [])

        if status_filter != 'all':
            filtered_onus = [onu for onu in filtered_onus if onu['status'] == status_filter]
        if branch_filter != 'all':
            filtered_onus = [onu for onu in filtered_onus if onu['interface'].startswith(branch_filter)]
        if reason_filter != 'all':
            filtered_onus = [onu for onu in filtered_onus if onu['dereg_reason'] == reason_filter]
        if signal_filter != 'all':
            filtered_onus = apply_signal_filter(filtered_onus, signal_filter)
        if contract_filter == 'with_contract':
            filtered_onus = [onu for onu in filtered_onus if onu.get('contract')]
        elif contract_filter == 'without_contract':
            filtered_onus = [onu for onu in filtered_onus if not onu.get('contract')]
        if moved_filter == 'moved':
            filtered_onus = [onu for onu in filtered_onus if onu.get('is_moved', False)]
        elif moved_filter == 'not_moved':
            filtered_onus = [onu for onu in filtered_onus if not onu.get('is_moved', False)]
        if mcd_filter == 'only_mcd':
            filtered_onus = [onu for onu in filtered_onus if onu.get('is_mcd', False)]
        elif mcd_filter == 'only_single':
            filtered_onus = [onu for onu in filtered_onus if not onu.get('is_mcd', False)]

        if search_query:
            search_lower = search_query.lower()
            filtered_onus = [onu for onu in filtered_onus if (
search_lower in onu['interface'].lower() or
search_lower in (onu['description'] or '').lower() or
search_lower in (onu['mac'] or '').lower() or
search_lower in (onu.get('contract', '') or '').lower()
)]

        onu_by_interface = group_and_sort_onus_by_interface(filtered_onus)
        stats = get_device_stats(session_db, normalized_id)

        statuses = sorted({onu['status'] for onu in data.get('onu_info', [])})
        reasons = sorted({onu['dereg_reason'] for onu in data.get('onu_info', []) if onu['dereg_reason'] and onu['dereg_reason'] != 'N/A'})
        branches = sorted({onu['interface'].split(':')[0] for onu in data.get('onu_info', [])}, key=lambda x: (x.upper(), 0, 0))

        return render_template(
            'device_detail.html',
            device_id=normalized_id,
            device_name=device_config['name'],
            onu_by_interface=onu_by_interface,
            timestamp=data.get('timestamp', 'Неизвестно'),
            branches=branches, statuses=statuses, reasons=reasons,
            current_status=status_filter,
            current_branch=branch_filter, current_reason=reason_filter,
            current_signal=signal_filter, current_contract=contract_filter,
            current_moved=moved_filter, current_mcd=mcd_filter,
            moved_count=sum(1 for onu in data.get('onu_info', []) if onu.get('is_moved', False)),
            mcd_count=sum(1 for onu in data.get('onu_info', []) if onu.get('is_mcd', False)),
            search_query=search_query, stats=stats,
            is_enriched=data.get('enriched', False),
            username=session.get('username'), role=session.get('role'),
        )

@app.route('/onu/<device_id>/<path:interface>')
@login_required
def onu_detail(device_id, interface):
    normalized_id = normalize_device_id(device_id)
    if not normalized_id:
        return render_template('error.html', message=f"Устройство '{escape_html(device_id)}' не найдена"), 404
    with get_db_session() as session_db:
        device_config = DEVICES.get(normalized_id)
        if not device_config:
            return render_template('error.html', message="Устройство не найдена"), 404
        data = get_cached_device_data(session_db, normalized_id, CACHE_TIMEOUT)
        if not data:
            # Fallback к данным из БД (как в device_detail): если live-кэш
            # пуст/устарел — ищем ONU по сохранённым в базе записям.
            result = get_onu_list_by_filter(session_db, 'all', normalized_id, limit=10000)
            onu = next((o for o in result.get('onus', []) if o['interface'] == interface), None)
            if not onu:
                return render_template('error.html', message="ONU не найдена"), 404
            return render_template(
                'onu_detail.html',
                device_id=normalized_id,
                device_name=device_config['name'],
                onu=onu,
                timestamp='По сохранённым данным (live-опрос недоступен)',
                username=session.get('username'), role=session.get('role'),
            )
        onu = next((o for o in data.get('onu_info', []) if o['interface'] == interface), None)
        if not onu:
            return render_template('error.html', message="ONU не найдена"), 404
    return render_template(
        'onu_detail.html',
        device_id=normalized_id,
        device_name=device_config['name'],
        onu=onu,
        timestamp=data.get('timestamp', 'Неизвестно'),
        username=session.get('username'), role=session.get('role'),
    )


@app.route('/api/force_refresh/<device_id>')
@admin_required
def api_force_refresh(device_id):
    # admin_required вместо login_required: эндпоинт ставит в очередь полную
    # live-перезагрузку устройства по SSH (тяжёлая внешняя операция). Как и
    # /api/clear_cache и удаление устройств, это mutating-действие доступно
    # только администратору.
    normalized_id = normalize_device_id(device_id)
    device_config = DEVICES.get(normalized_id)
    if not normalized_id or not device_config:
        return jsonify({'status': 'error', 'message': 'Invalid device identifier or not found'})
    try:
        start_update_worker()  # GET-путь не проходит через api_start_update
        update_queue.put({'device_id': normalized_id, 'force_fresh': True, 'type': 'refresh'})
        return jsonify({'status': 'success', 'message': f'Обновление {device_config["name"]} запущено в фоне', 'task_id': normalized_id})
    except Exception:
        logger.error("Error in api_force_refresh", exc_info=True)
        return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG})

@app.route('/api/clear_cache')
@admin_required
def api_clear_cache():
    try:
        invalidate_devices_cache()
        invalidate_update_status_cache()
        # прогресс хранится в памяти (scan_progress) — отдельной инвалидации не требуется
        cache.clear()
        with progress_lock:
            scan_progress.update({'is_scanning': False, 'current_device': None, 'total_devices': 0, 'completed_devices': 0})
        return jsonify({'status': 'success', 'message': 'Кэш очищен'})
    except Exception:
        logger.error("Error in api_clear_cache", exc_info=True)
        return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG})

@app.route('/api/refresh')
@admin_required
def api_refresh():
    # admin_required: как и /api/force_refresh, ставит в очередь полную
    # live-перезагрузку по SSH (см. комментарий у api_force_refresh).
    device_id = request.args.get('device')
    normalized_id = normalize_device_id(device_id)
    if normalized_id and normalized_id in DEVICES:
        start_update_worker()  # GET-путь не проходит через api_start_update
        update_queue.put({'device_id': normalized_id, 'force_fresh': True, 'type': 'refresh'})
        invalidate_devices_cache()
        return jsonify({'status': 'success', 'message': 'Обновление запущено в фоне'})
    return jsonify({'status': 'error', 'message': 'Invalid device'})

@app.route('/api/refresh_onu')
@login_required
def api_refresh_onu():
    device_id = request.args.get('device')
    interface = request.args.get('interface')
    normalized_id = normalize_device_id(device_id)
    if not normalized_id or not interface or not validate_interface(interface):
        return jsonify({'status': 'error', 'message': 'Invalid parameters'})

    device_config = DEVICES.get(normalized_id)
    # defense-in-depth: device_config может отсутствовать (например, устройство
    # удалено между валидацией ID и этим моментом) — раньше здесь был KeyError,
    # который превращался в «500 Internal Server Error» от Flask.
    if not device_config:
        return jsonify({'status': 'error', 'message': 'Device not found'})
    ssh_client = BDCOMSSHClient(
device_config['hostname'], device_config['username'],
device_config['password'], device_config['enable_password'],
model=device_config.get('model', '3310')
)

    try:
        if not ssh_client.connect():
            return jsonify({'status': 'error', 'message': 'Failed to connect to device'})

        with get_db_session() as session_db:
            current_onu = session_db.query(ONU).filter_by(device_id=normalized_id, interface=interface, is_active=True).first()
            if not current_onu:
                return jsonify({'status': 'error', 'message': 'ONU not found in database'})

            onu_data = ssh_client.refresh_single_onu(interface)
            if 'error' in onu_data or not validate_onu_data(onu_data):
                return jsonify({'status': 'error', 'message': onu_data.get('error', 'Invalid ONU data received')})

            optical_power = onu_data.get('optical_power')
            client_macs = onu_data.get('client_macs', [])
            description = onu_data.get('description')

            if optical_power is not None:
                current_onu.optical_power = optical_power
                current_onu.is_enriched = True
            if description and description not in ['N/A', interface]:
                current_onu.description = description
            current_onu.client_macs_count = len(client_macs)
            current_onu.updated_at = datetime.now(timezone.utc)
            current_onu.last_seen = datetime.now(timezone.utc)
            current_onu.status = 'active' if optical_power is not None else 'off-line'
            current_onu.dereg_reason = 'N/A' if optical_power is not None else current_onu.dereg_reason

            session_db.query(ONUClientMAC).filter_by(onu_interface=f"{normalized_id}:{interface}").delete()
            for mac in client_macs:
                if mac.get('mac_address') and re.fullmatch(r'[a-zA-Z0-9]{4}\.[a-zA-Z0-9]{4}\.[a-zA-Z0-9]{4}', mac['mac_address']):
                    session_db.add(ONUClientMAC(
onu_interface=f"{normalized_id}:{interface}", vlan=mac.get('vlan', '1'),
mac_address=mac.get('mac_address'), normalized_mac=normalize_mac_address(mac['mac_address']),
type=mac.get('type', 'DYNAMIC'), port=mac.get('port', interface)
))
            session_db.commit()

        invalidate_devices_cache()
        return jsonify({'status': 'success', 'message': 'ONU data updated successfully', 'optical_power': optical_power, 'client_macs_count': len(client_macs), 'is_mcd': is_mcd(description)})
    except Exception:
        logger.error("api_onu_update_enrich failed", exc_info=True)
        return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG})
    finally:
        ssh_client.close()


@app.route('/api/status')
@login_required
def api_status():
    device_id = request.args.get('device')
    normalized_id = normalize_device_id(device_id)
    if not normalized_id:
        return jsonify({'status': 'error', 'message': 'Invalid device'})
    with get_db_session() as session_db:
        status = session_db.query(DeviceStatus).filter_by(device_id=normalized_id).first()
        if status:
            return jsonify({'status': 'success', 'is_enriched': status.enriched_onu_count > 0, 'is_online': status.is_online, 'onu_count': status.onu_count, 'last_update': status.last_successful_update.strftime('%Y-%m-%d %H:%M:%S') if status.last_successful_update else None})
    return jsonify({'status': 'success', 'is_enriched': False, 'is_online': False, 'onu_count': 0, 'last_update': None})

@app.route('/api/db/stats')
@login_required
def api_db_stats():
    return jsonify(get_cached_global_stats_memoized())

@app.route('/api/device_data/<device_id>')
@login_required
def api_device_data(device_id):
    normalized_id = normalize_device_id(device_id)
    if not normalized_id:
        return jsonify({'success': False, 'message': 'Invalid device identifier', 'error': 'Device not found'})
    with get_db_session() as session_db:
        data = get_cached_device_data(session_db, normalized_id, CACHE_TIMEOUT)
        if data:
            active_count = inactive_count = mcd_count = mcd_inactive_count = 0
            for onu in data.get('onu_info', []):
                if onu.get('optical_power') is not None:
                    active_count += 1
                else:
                    inactive_count += 1
                if onu.get('is_mcd'):
                    mcd_count += 1
                if onu.get('optical_power') is None:
                    mcd_inactive_count += 1
            return jsonify({'success': True, 'device_id': normalized_id, 'onu_count': len(data.get('onu_info', [])),
'active_count': active_count, 'inactive_count': inactive_count, 'signal_count': active_count,
'mcd_count': mcd_count, 'mcd_inactive_count': mcd_inactive_count,
'timestamp': data.get('timestamp', ''), 'enriched': data.get('enriched', False)})
    return jsonify({'success': False, 'message': 'No data available', 'error': 'Data not found in database'})

@app.route('/api/devices_data')
@login_required
def api_devices_data():
    try:
        devices_data = get_cached_devices_data()
        devices_stats = get_cached_devices_stats()
        simplified_data = {}
        for device_id, data in devices_data.items():
            device_config = DEVICES.get(device_id, {})
            simplified_data[device_id] = {'success': data.get('success', False), 'enriched': data.get('enriched', False),
'timestamp': data.get('timestamp', ''), 'name': device_config.get('name', device_id),
'ip': device_config.get('hostname', ''), 'stats': devices_stats.get(device_id, {})}
        return jsonify(simplified_data)
    except Exception as e:
        logger.error(f"Error in api_devices_data: {e}", exc_info=True)
        return jsonify({})

@app.route('/api/update_status')
@login_required
def api_update_status():
    try:
        return jsonify(get_cached_update_status())
    except Exception:
        return jsonify({})

@app.route('/api/scan_progress')
@login_required
def api_scan_progress():
    try:
        with progress_lock:
            progress_data = scan_progress.copy()
            progress_percent = int((progress_data['completed_devices'] / progress_data['total_devices']) * 100) if progress_data['total_devices'] > 0 else 0
            time_remaining = f"{int(progress_data['estimated_time_remaining'] // 60):02d}:{int(progress_data['estimated_time_remaining'] % 60):02d}" if progress_data['estimated_time_remaining'] else None
            return jsonify({'is_scanning': progress_data['is_scanning'], 'current_device': progress_data['current_device'],
'total_devices': progress_data['total_devices'], 'completed_devices': progress_data['completed_devices'],
'progress_percent': progress_percent, 'estimated_time_remaining': time_remaining})
    except Exception:
        return jsonify({'is_scanning': False})


@app.route('/api/export/<device_id>')
@login_required
def api_export_device(device_id):
    normalized_id = normalize_device_id(device_id)
    output = export_device_to_excel(normalized_id) if normalized_id else None
    if output:
        device_config = DEVICES.get(normalized_id, {})
        filename = f"{device_config.get('name', device_id)}_onu_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        return send_file(output, as_attachment=True, download_name=filename, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    return jsonify({'status': 'error', 'message': 'Нет данных для экспорта.'})

@app.route('/api/export/mcd_onus')
@login_required
def api_export_mcd_onus():
    output = export_mcd_onus_to_excel()
    if output:
        filename = f"mcd_onus_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        return send_file(output, as_attachment=True, download_name=filename, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    return jsonify({'status': 'error', 'message': 'Нет МКД-ONU для экспорта'})

@app.route('/api/export/inactive_onus')
@login_required
def api_export_inactive_onus():
    output = export_inactive_onus_to_excel()
    if output:
        filename = f"inactive_onus_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        return send_file(output, as_attachment=True, download_name=filename, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    return jsonify({'status': 'error', 'message': 'Нет отключенных ONU для экспорта'})

@app.route('/api/export/onu_list')
@login_required
def api_export_onu_list():
    filter_type = request.args.get('type', 'all')
    device_id = request.args.get('device')
    normalized_id = normalize_device_id(device_id) if device_id else None
    allowed_types = ['all', 'active', 'inactive', 'good_signal', 'warning_signal', 'bad_signal', 'single', 'mcd']
    if filter_type not in allowed_types:
        return jsonify({'status': 'error', 'message': f'Недопустимый тип: {filter_type}'})
    with get_db_session() as session_db:
        try:
            result = get_onu_list_by_filter(session_db, filter_type, normalized_id, limit=10000)
            onus = result.get('onus', [])
            if not onus:
                return jsonify({'status': 'error', 'message': 'Нет данных для экспорта'})
            df = build_onu_dataframe(onus, include_extended=True)
            if df is None:
                return jsonify({'status': 'error', 'message': 'Нет данных для экспорта'})
            sheet_name = f"ONU_{filter_type}"[:31]
            output = write_excel(df, sheet_name, '#D7E4BD')
            filter_names = {'all': 'все_ONU', 'active': 'активные', 'inactive': 'неактивные', 'good_signal': 'хороший_сигнал', 'warning_signal': 'предупреждение', 'bad_signal': 'плохой_сигнал', 'single': 'одиночные', 'mcd': 'МКД'}
            filename = f"onu_{filter_names.get(filter_type, filter_type)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            return send_file(output, as_attachment=True, download_name=filename, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        except Exception:
            logger.error("Error in api_export_onus", exc_info=True)
            return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG})


@app.route('/api/search')
@login_required
def api_search():
    query = sanitize_string(request.args.get('q', ''), max_length=100)
    if not query or len(query) < 2:
        return jsonify({'results': []})

    results = []
    seen_keys = set()
    contracts_by_onu = {}

    def _norm(s):
        return re.sub(r'[^a-z0-9]', '', str(s).lower()) if s else ''
    q_norm = _norm(query)

    def register_contract(device_id, interface, contract_number, main=False):
        if not contract_number:
            return
        entry = contracts_by_onu.setdefault((device_id, interface), {'main': None, 'extra': []})
        number = str(contract_number)
        if main and entry['main'] is None:
            entry['main'] = number
        elif number not in entry['extra'] and number != entry['main']:
            entry['extra'].append(number)

    def get_contracts_for_onu(onu):
        key = (onu.device_id, onu.interface)
        if key in contracts_by_onu:
            return contracts_by_onu[key]
        found = {'main': None, 'extra': []}

        links = session_db.query(ONUContract.contract_number, ONUContract.is_main).filter_by(
device_id=onu.device_id, interface=onu.interface).all()
        for cn, is_main in sorted(links, key=lambda x: (not x[1],)):
            if is_main and found['main'] is None:
                found['main'] = str(cn)
            elif str(cn) not in found['extra'] and str(cn) != found['main']:
                found['extra'].append(str(cn))

        full_iface = f"{onu.device_id}:{onu.interface}"
        client_macs = [cm.normalized_mac for cm in session_db.query(ONUClientMAC).filter_by(
onu_interface=full_iface).all() if cm.normalized_mac]

        candidates = set(client_macs)
        if onu.normalized_mac:
            candidates.add(onu.normalized_mac)
        if candidates:
            rows = session_db.query(Contract.contract_number).filter(
Contract.normalized_mac.in_(list(candidates))).distinct().limit(20).all()
            for (cn,) in rows:
                if cn and str(cn) not in found['extra'] and str(cn) != found['main']:
                    found['extra'].append(str(cn))
        contracts_by_onu[key] = found
        return found

    def contract_field(onu):
        data = get_contracts_for_onu(onu)
        if data['main']:
            return data['main']
        if data['extra']:
            shown = data['extra'][:3]
            more = len(data['extra']) - len(shown)
            return ', '.join(shown) + (f' +{more}' if more > 0 else '')
        return onu.contract if onu.contract and onu.contract != 'N/A' else None

    def add_result(onu, rtype, match_type, mac_display=None):
        key = (onu.device_id, onu.interface)
        if key in seen_keys:
            return False
        seen_keys.add(key)
        results.append({
'device_id': onu.device_id,
'device': onu.device_name,
'interface': safe_interface(onu.interface),
'mac': mac_display if mac_display is not None else (onu.mac or 'N/A'),
'description': onu.description if onu.description and onu.description != 'N/A' else 'N/A',
'contract': contract_field(onu),
'status': onu.status,
'type': rtype,
'optical_power': onu.optical_power,
'match_type': match_type,
'is_moved': onu.moved_to is not None or onu.moved_from is not None,
'moved_to': onu.moved_to,
'moved_from': onu.moved_from,
'is_mcd': is_mcd(onu.description),
})
        return True

    with get_db_session() as session_db:
        visible_filter = (ONU.is_active.is_(True)) | (ONU.is_configured.is_(True)) | (ONU.moved_to.isnot(None))


        normalized_query = normalize_mac_address(query)
        for onu in session_db.query(ONU).filter(ONU.mac != 'N/A', visible_filter).all():
            m = match_mac_query(onu.mac, query)
            if m:
                add_result(onu, 'onu_mac', 'full_mac' if m == 'full' else 'partial_mac')
            elif normalized_query and onu.normalized_mac == normalized_query:
                add_result(onu, 'onu_mac', 'full_mac')


        for onu in session_db.query(ONU).filter(ONU.description.ilike(like_pattern(query), escape=LIKE_ESCAPE), visible_filter).all():
            add_result(onu, 'onu_description', 'description')


        def _contract_hit(number):
            if not number:
                return False
            n = str(number).lower()
            return query.lower() in n or (q_norm and len(q_norm) >= 4 and q_norm in _norm(n))


        for onu in session_db.query(ONU).filter(ONU.contract.ilike(like_pattern(query), escape=LIKE_ESCAPE), visible_filter).all():
            register_contract(onu.device_id, onu.interface, onu.contract, main=True)
            add_result(onu, 'contract', 'contract')

        bound = session_db.query(ONUContract.device_id, ONUContract.interface,
ONUContract.contract_number, ONUContract.is_main).filter(
ONUContract.contract_number.ilike(like_pattern(query), escape=LIKE_ESCAPE)).distinct().all()
        for dev_id, iface, cn, is_main in bound:
            register_contract(dev_id, iface, cn, main=bool(is_main))
            onu = session_db.query(ONU).filter_by(device_id=dev_id, interface=iface).filter(visible_filter).first()
            if onu:
                add_result(onu, 'contract', 'contract')


        matched_contracts = list(session_db.query(Contract).filter(
(Contract.contract_number.ilike(like_pattern(query), escape=LIKE_ESCAPE)) |
(Contract.login.ilike(like_pattern(query), escape=LIKE_ESCAPE)) |
(Contract.ip_address.ilike(like_pattern(query), escape=LIKE_ESCAPE))
).limit(500).all())

        if q_norm and len(q_norm) >= 4:
            seen_cids = {c.id for c in matched_contracts}
            for c in session_db.query(Contract).limit(20000).all():
                if c.id not in seen_cids and _contract_hit(c.contract_number):
                    matched_contracts.append(c)
                    seen_cids.add(c.id)
        contract_macs = {c.normalized_mac for c in matched_contracts if c.normalized_mac}
        if contract_macs:

            mac_to_number = {}
            for c in matched_contracts:
                if c.normalized_mac:
                    mac_to_number.setdefault(c.normalized_mac, c.contract_number)
            for onu in session_db.query(ONU).filter(ONU.normalized_mac.in_(list(contract_macs)), visible_filter).all():
                register_contract(onu.device_id, onu.interface,
mac_to_number.get(onu.normalized_mac), main=True)
                add_result(onu, 'contract', 'contract')

            client_rows = session_db.query(ONUClientMAC.onu_interface, ONUClientMAC.normalized_mac).filter(
ONUClientMAC.normalized_mac.in_(list(contract_macs))).distinct().all()
            for onu_iface, cm_norm in client_rows:
                parts = (onu_iface or '').split(':', 1)
                if len(parts) != 2:
                    continue
                dev_id, iface = parts
                register_contract(dev_id, iface, mac_to_number.get(cm_norm), main=True)
                onu = session_db.query(ONU).filter_by(device_id=dev_id, interface=iface).filter(visible_filter).first()
                if onu:
                    add_result(onu, 'contract', 'contract')


        if is_hex_query(query) and len(re.sub(r'[^0-9a-fA-F]', '', query)) >= 4:
            client_macs = session_db.query(ONUClientMAC).filter(
ONUClientMAC.mac_address.ilike(like_pattern(query), escape=LIKE_ESCAPE)).all()
            for cmac in client_macs:
                parts = (cmac.onu_interface or '').split(':', 1)
                if len(parts) != 2:
                    continue
                dev_id, iface = parts
                onu = session_db.query(ONU).filter_by(device_id=dev_id, interface=iface).filter(visible_filter).first()
                if not onu:
                    continue
                key = (dev_id, iface)
                already_onu_row = any(r['device_id'] == dev_id and r['interface'] == iface and r['type'] in ('onu_mac',) for r in results)
                if key in seen_keys and not already_onu_row:

                    for r in results:
                        if r['device_id'] == dev_id and r['interface'] == iface:
                            r['client_mac_match'] = True
                            break
                    continue
                m = match_mac_query(cmac.mac_address, query) or 'partial'
                seen_keys.add(key)
                results.append({
'device_id': dev_id,
'device': onu.device_name,
'interface': safe_interface(iface),
'mac': cmac.mac_address,
'description': onu.description if onu.description and onu.description != 'N/A' else onu.interface,
'contract': contract_field(onu),
'status': onu.status,
'type': 'client_mac',
'optical_power': onu.optical_power,
'match_type': 'full_mac' if m == 'full' else 'partial_mac',
'is_moved': onu.moved_to is not None or onu.moved_from is not None,
'moved_to': onu.moved_to,
'moved_from': onu.moved_from,
'is_mcd': is_mcd(onu.description),
})


        def sort_key(result):
            match_type = result.get('match_type', '')
            result_type = result.get('type', '')
            if result_type == 'onu_mac' and match_type == 'full_mac':
                return 0
            elif result_type == 'onu_mac' and match_type == 'partial_mac':
                return 1
            elif result_type == 'client_mac' and match_type == 'full_mac':
                return 2
            elif result_type == 'client_mac' and match_type == 'partial_mac':
                return 3
            elif result_type == 'onu_description':
                return 4
            elif result_type == 'contract':
                return 5
            return 6

        results.sort(key=sort_key)


        mac_groups = {}
        for result in results:
            mac_groups.setdefault(result['mac'], []).append(result)
        for group in mac_groups.values():
            if len(group) > 1:
                for item in group:
                    item['has_duplicates'] = True
                    item['duplicate_count'] = len(group)

    return jsonify({'results': results[:100]})


@app.route('/api/update_onu_description', methods=['POST'])
@login_required
def api_update_onu_description():
    steps = []
    def add_step(text, status='done'):
        steps.append({'text': text, 'status': status})

    device_id = request.json.get('device')
    interface = request.json.get('interface')
    description = request.json.get('description', '')
    normalized_id = normalize_device_id(device_id)

    add_step('Проверка параметров')
    if not normalized_id or not interface or not validate_interface(interface):
        return jsonify({'status': 'error', 'message': 'Invalid parameters', 'steps': steps})

    description = sanitize_description(description, max_length=100)
    # Defense-in-depth: описание подставляется в SSH-команду 'description ...'
    # на OLT. sanitize_description вырезает управляющие символы и все
    # shell/CLI-спецсимволы whitelist-regexом (кириллица сохраняется —
    # quote_plus раньше превращал её в %D0%9C... в конфигурации устройства).
    # Пустое значение остаётся валидным (означает 'no description').

    device_config = DEVICES.get(normalized_id)
    if not device_config:
        return jsonify({'status': 'error', 'message': 'Device not found', 'steps': steps})

    ssh_client = BDCOMSSHClient(
device_config['hostname'], device_config['username'],
device_config['password'], device_config['enable_password'],
model=device_config.get('model', '3310')
)

    try:
        add_step('Подключение к OLT по SSH')
        if not ssh_client.connect():
            return jsonify({'status': 'error', 'message': 'Failed to connect to device', 'steps': steps})

        add_step('Вход в режим конфигурации и применение описания')
        if ssh_client.update_onu_description(interface, description):
            add_step('Сохранение конфигурации (write)')
            with get_db_session() as session_db:
                onu = session_db.query(ONU).filter_by(device_id=normalized_id, interface=interface).first()
                if onu:
                    onu.description = description if description else 'N/A'
                    onu.updated_at = datetime.now(timezone.utc)
                    session_db.commit()
            add_step('Обновление в базе данных')
            invalidate_devices_cache()
            return jsonify({
'status': 'success',
'message': 'Description updated successfully',
'is_mcd': is_mcd(description),
'steps': steps
})
        return jsonify({'status': 'error', 'message': 'Failed to update description on device.', 'steps': steps})
    except Exception:
        logger.error("api_update_onu_description failed", exc_info=True)
        return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG, 'steps': steps})
    finally:
        ssh_client.close()

@app.route('/api/delete_onu', methods=['POST'])
@admin_required
def api_delete_onu():
    steps = []
    def add_step(text, status='done'):
        steps.append({'text': text, 'status': status})

    device_id = request.json.get('device')
    interface = request.json.get('interface')
    normalized_id = normalize_device_id(device_id)

    add_step('Проверка параметров')
    if not normalized_id or not interface or not validate_interface(interface):
        return jsonify({'status': 'error', 'message': 'Invalid parameters', 'steps': steps})

    device_config = DEVICES.get(normalized_id)
    if not device_config:
        return jsonify({'status': 'error', 'message': 'Device not found', 'steps': steps})

    ssh_client = BDCOMSSHClient(
device_config['hostname'], device_config['username'],
device_config['password'], device_config['enable_password'],
model=device_config.get('model', '3310')
)

    try:
        add_step('Подключение к OLT по SSH')
        if not ssh_client.connect():
            return jsonify({'status': 'error', 'message': 'Failed to connect to device', 'steps': steps})

        add_step('Выполнение команды удаления ONU')
        if ssh_client.delete_onu(interface):
            add_step('Сохранение конфигурации (write)')
            with get_db_session() as session_db:
                onu = session_db.query(ONU).filter_by(device_id=normalized_id, interface=interface).first()
                if onu:
                    add_step('Удаление связанных записей в БД')
                    delete_onu_safely(
session_db, onu.id,
reason=f"Удалена администратором {session.get('username', 'unknown')} из {device_config['name']}"
)
            invalidate_devices_cache()
            return jsonify({
'status': 'success',
'message': 'ONU deleted successfully',
'steps': steps
})
        return jsonify({'status': 'error', 'message': 'Failed to delete ONU on device', 'steps': steps})
    except Exception:
        logger.error("api_delete_onu failed", exc_info=True)
        return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG, 'steps': steps})
    finally:
        ssh_client.close()

@app.route('/api/inactive_onus')
@login_required
def api_inactive_onus():
    with get_db_session() as session_db:
        inactive_onus = session_db.query(ONU).filter(ONU.optical_power.is_(None), ONU.is_active.is_(True)).all()
        results = []
        for onu in inactive_onus:
            bind_type = 'dynamic' if onu.description and ('dynamic' in onu.description.lower() or 'динам' in onu.description.lower()) else 'static'
            results.append({'device_id': onu.device_id, 'device': onu.device_name, 'interface': safe_interface(onu.interface), 'mac': onu.mac, 'description': onu.description or '', 'contract': onu.contract or '', 'status': onu.status or 'off-line', 'dereg_reason': onu.dereg_reason or '', 'vendor': onu.vendor or '', 'model': onu.model or '', 'optical_power': None, 'optical_status': 'unknown', 'bind_type': bind_type, 'client_macs_count': 0, 'timestamp': onu.last_seen.isoformat() if hasattr(onu, 'last_seen') and onu.last_seen else '', 'is_mcd': is_mcd(onu.description)})
    return jsonify({'inactive_onus': results, 'count': len(results)})

@app.route('/api/update_status/<device_id>')
@login_required
def api_update_status_single(device_id):
    try:
        worker = start_update_worker()
        if not worker:
            return jsonify({'status': 'error', 'message': 'Служба обновления недоступна', 'devices': {}})
        return jsonify(worker.get_update_status() if device_id == 'all' else worker.get_update_status(normalize_device_id(device_id)))
    except Exception:
        logger.error("api_update_status_single failed", exc_info=True)
        return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG, 'devices': {}})

@app.route('/api/start_update/<device_id>')
@login_required
def api_start_update(device_id):
    start_update_worker()
    if device_id == 'all':
        update_queue.put({'device_id': 'all', 'force_fresh': True, 'type': 'update'})
        invalidate_devices_cache()
        invalidate_update_status_cache()
        return jsonify({'status': 'success', 'message': 'Обновление всех устройств запущено в фоне'})
    else:
        normalized_id = normalize_device_id(device_id)
        if normalized_id:
            update_queue.put({'device_id': normalized_id, 'force_fresh': True, 'type': 'update'})
            invalidate_devices_cache()
            return jsonify({'status': 'success', 'message': 'Обновление устройства запущено в фоне'})
        return jsonify({'status': 'error', 'message': 'Неверный ID устройства'})


@app.route('/api/duplicate_macs')
@login_required
def api_duplicate_macs():
    with get_db_session() as session_db:
        try:
            return jsonify(find_duplicate_onus(session_db, limit=50))
        except Exception:
            logger.error("api_duplicate_macs failed", exc_info=True)
            return jsonify({'duplicates': [], 'total_duplicates': 0, 'total_macs_scanned': 0, 'error': _INTERNAL_ERROR_MSG})

@app.route('/api/onu_without_description')
@login_required
def api_onu_without_description():
    with get_db_session() as session_db:
        try:
            onus_without_desc = session_db.query(ONU).filter(((ONU.description == '') | (ONU.description.is_(None)) | (ONU.description == 'N/A') | (ONU.description == ONU.interface)), ONU.is_active.is_(True)).all()
            cmap = get_contracts_map_for_onus(session_db, [(o.device_id, o.interface) for o in onus_without_desc])
            results = [{'device_id': onu.device_id, 'device': onu.device_name, 'interface': safe_interface(onu.interface), 'mac': onu.mac, 'vendor': onu.vendor, 'model': onu.model, 'status': onu.status, 'optical_power': onu.optical_power, 'contract': cmap.get((onu.device_id, onu.interface)) or (onu.contract if onu.contract and onu.contract != 'N/A' else None), 'timestamp': onu.updated_at.strftime('%Y-%m-%d %H:%M:%S') if onu.updated_at else 'N/A'} for onu in onus_without_desc]
            results.sort(key=lambda x: (x['device'], x['interface']))
            return jsonify({'onus_without_description': results, 'total_count': len(results), 'message': f'Найдено {len(results)} ONU без описания'})
        except Exception:
            logger.error("api_onu_without_description failed", exc_info=True)
            return jsonify({'onus_without_description': [], 'total_count': 0, 'error': _INTERNAL_ERROR_MSG})

@app.route('/api/mcd_onus')
@login_required
def api_mcd_onus():
    device_id = request.args.get('device')
    normalized_id = normalize_device_id(device_id) if device_id else None
    with get_db_session() as session_db:
        try:
            return jsonify(get_mcd_onus(session_db, normalized_id))
        except Exception:
            logger.error("api_mcd_onus failed", exc_info=True)
            return jsonify({'mcd_onus': [], 'total_count': 0, 'error': _INTERNAL_ERROR_MSG})

@app.route('/api/onus_without_contract')
@login_required
def api_onus_without_contract():
    with get_db_session() as session_db:
        try:
            onus_without_contract = session_db.query(ONU).filter(((ONU.contract == '') | (ONU.contract.is_(None))), ONU.is_active.is_(True)).all()
            results = [{'device_id': onu.device_id, 'device': onu.device_name, 'interface': safe_interface(onu.interface), 'description': onu.description, 'status': onu.status, 'optical_power': onu.optical_power, 'vendor': onu.vendor, 'model': onu.model, 'timestamp': onu.updated_at.strftime('%Y-%m-%d %H:%M:%S') if onu.updated_at else 'N/A', 'is_mcd': is_mcd(onu.description)} for onu in onus_without_contract]
            results.sort(key=lambda x: (x['device'], x['interface']))
            return jsonify({'onus_without_contract': results, 'total_count': len(results), 'message': f'Найдено {len(results)} ONU без договора'})
        except Exception:
            logger.error("api_onus_without_contract failed", exc_info=True)
            return jsonify({'onus_without_contract': [], 'total_count': 0, 'error': _INTERNAL_ERROR_MSG})

@app.route('/api/onu_list')
@login_required
def api_onu_list():
    filter_type = request.args.get('type', 'all')
    device_id = request.args.get('device')
    normalized_id = normalize_device_id(device_id) if device_id else None
    allowed_types = ['all', 'active', 'inactive', 'good_signal', 'warning_signal', 'bad_signal', 'single', 'mcd']
    if filter_type not in allowed_types:
        return jsonify({'status': 'error', 'message': f'Недопустимый тип: {filter_type}'})
    with get_db_session() as session_db:
        try:
            return jsonify({'status': 'success', **get_onu_list_by_filter(session_db, filter_type, normalized_id)})
        except Exception:
            logger.error("Error in api_onu_list", exc_info=True)
            return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG, 'onus': [], 'total_count': 0})


@app.route('/settings')
@login_required
def settings():
    if session.get('role') != 'admin':
        flash('Недостаточно прав для доступа к настройкам', 'danger')
        return redirect(url_for('index'))
    return render_template('settings.html', UPDATE_CONFIG=UPDATE_CONFIG, BACKUP_CONFIG=BACKUP_CONFIG, TELEGRAM_CONFIG=TELEGRAM_CONFIG, DEVICES=DEVICES, username=session.get('username'), role=session.get('role'))


@app.route('/api/devices/list')
@admin_required
def api_devices_list():
    try:
        from sqlalchemy import func
        with get_db_session() as session_db:
            counts = dict(session_db.query(
ONU.device_id, func.count(ONU.id)
).group_by(ONU.device_id).all())
        result = []
        for dev_id, cfg in sorted(DEVICES.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0):
            result.append({
'id': dev_id,
'name': cfg.get('name', dev_id),
'hostname': cfg.get('hostname', ''),
'model': cfg.get('model', ''),
'description': cfg.get('description', ''),
'onu_count': counts.get(str(dev_id), 0),
})
        return jsonify({'status': 'success', 'devices': result,
'config_source': get_devices_source_info(),
'next_id': get_next_device_id()})
    except Exception:
        logger.error("Error in api_devices_list", exc_info=True)
        return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG}), 500

@app.route('/api/devices/next-id')
@admin_required
def api_devices_next_id():
    try:
        return jsonify({'status': 'success', 'next_id': get_next_device_id()})
    except Exception:
        logger.error("Error in api_devices_next_id", exc_info=True)
        return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG}), 500

@app.route('/api/devices/test', methods=['POST'])
@admin_required
def api_devices_test():
    try:
        data = request.json or {}
        hostname = sanitize_string(data.get('hostname', ''), max_length=100)
        username = data.get('username', 'admin')
        password = data.get('password', '')
        enable_password = data.get('enable_password', '')
        model = data.get('model', '3310')
        if not is_valid_hostname(hostname):
            return jsonify({'status': 'error', 'message': 'Некорректный hostname/IP'})
        result = test_device_connection(hostname, username, password,
enable_password, model)
        return jsonify({'status': 'success' if result['success'] else 'error',
'message': result['message']})
    except Exception:
        logger.error("api_devices_test failed", exc_info=True)
        return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG})

@app.route('/api/devices/add', methods=['POST'])
@admin_required
def api_devices_add():
    try:
        data = request.json or {}
        new_id = str(data.get('id', '')).strip()
        name = sanitize_string(data.get('name', ''), max_length=50)
        hostname = sanitize_string(data.get('hostname', ''), max_length=100)
        username = data.get('username', 'admin')
        password = data.get('password', '')
        enable_password = data.get('enable_password', '')
        description = sanitize_string(data.get('description', ''), max_length=100)
        model = data.get('model', '3310')
        test_connection = bool(data.get('test_connection', True))

        if not new_id:
            new_id = get_next_device_id()
        if not name:
            return jsonify({'status': 'error', 'message': 'Название устройства обязательно'})
        if not is_valid_hostname(hostname):
            return jsonify({'status': 'error', 'message': 'Некорректный hostname/IP'})
        if model not in ('3310', 'GP3600'):
            return jsonify({'status': 'error', 'message': "Модель должна быть '3310' или 'GP3600'"})


        if test_connection:
            conn = test_device_connection(hostname, username, password,
enable_password, model)
            if not conn['success']:
                return jsonify({'status': 'error',
'message': f"Устройство недоступно: {conn['message']}. "
f"Добавление отменено (можно снять галочку «проверять связь»)."})

        result = add_device(new_id, name, hostname, username, password,
enable_password, description, model)
        if result['success']:
            invalidate_devices_cache()
            invalidate_update_status_cache()

            try:
                with get_db_session() as session_db:
                    save_device_status(session_db, new_id, name, {'onu_info': []},
success=False, error_message='Ожидает первого обновления')
            except Exception as e:
                logger.warning(f"Не удалось создать DeviceStatus для {new_id}: {e}")
            logger.info(f"➕ Добавлено устройство: {name} ({hostname}) ID={new_id}")


            immediate_update = bool(data.get('immediate_update', True))
            if immediate_update:
                try:
                    update_queue.put({'device_id': new_id, 'force_fresh': True, 'type': 'update'})
                    message = (f"Устройство {name} (ID {new_id}) добавлено. "
f"Первый опрос запущен вне очереди — данные появятся через 1-2 минуты.")
                except Exception as e:
                    logger.warning(f"Не удалось поставить {new_id} в очередь: {e}")
                    message = result['message']
            else:
                message = result['message']
            return jsonify({'status': 'success', 'message': message,
'device_id': new_id, 'queued': immediate_update})
        return jsonify({'status': 'error', 'message': result['message']})
    except Exception as e:
        logger.error(f"Error in api_devices_add: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Ошибка добавления устройства. Подробности в логах сервера.'})

@app.route('/api/devices/delete', methods=['POST'])
@admin_required
def api_devices_delete():
    steps = []
    def add_step(text, status='done'):
        steps.append({'text': text, 'status': status})

    try:
        data = request.json or {}
        device_id = str(data.get('device_id', '')).strip()
        if not device_id:
            return jsonify({'status': 'error', 'message': 'Не указан device_id', 'steps': steps})

        device_config = DEVICES.get(device_id)
        if not device_config:
            return jsonify({'status': 'error',
'message': f'Устройство {device_id} не найдено в конфигурации',
'steps': steps})

        device_name = device_config.get('name', device_id)
        add_step(f'Устройство найдено: {device_name}')


        try:
            from config import get_devices_source_info as _get_src_info
            _src = _get_src_info()
            if not _src.get('overrides_exists'):
                add_step('devices_overrides.json ещё не создан — будет создан на шаге сохранения',
status='warning')
            else:
                add_step('Источник истины: devices_overrides.json (config.py не требует правки)')
        except Exception as _e:
            logger.warning(f'Не удалось получить информацию об источнике устройств: {_e}')


        with get_db_session() as session_db:
            add_step('Удаление всех связанных данных из базы')
            db_result = delete_device_completely(session_db, device_id)
            stats = db_result.get('stats', {})
            add_step(f"Удалено ONU: {stats.get('deleted_onus', 0)}, "
f"записей истории: {stats.get('history', 0)}, "
f"MAC-адресов: {stats.get('client_macs', 0)}")
            if stats.get('restored_onus'):
                add_step(f"Переехавшие ONU «возвращены» (стали как будто всегда были на месте): "
f"{len(stats['restored_onus'])} шт.")


        add_step('Удаление из конфигурации устройств')
        cfg_result = remove_device_from_config(device_id)
        if not cfg_result['success']:
            return jsonify({'status': 'error',
'message': f"Данные из БД удалены, но конфигурация не сохранена: {cfg_result['message']}",
'steps': steps})


        invalidate_devices_cache()
        invalidate_update_status_cache()
        try:
            with get_db_session() as session_db:
                refresh_db_device_names(session_db)
        except Exception as e:
            logger.warning(f"Не удалось обновить кэш имён устройств: {e}")

        logger.info(f"🗑️ Устройство {device_name} (ID {device_id}) полностью удалено из системы")
        return jsonify({
'status': 'success',
'message': f'BDCOM {device_name} полностью удалён из системы вместе со всеми данными',
'stats': stats,
'steps': steps
})
    except Exception as e:
        logger.error(f"Error in api_devices_delete: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Ошибка удаления устройства. Подробности в логах сервера.', 'steps': steps})

@app.route('/api/settings/update', methods=['POST'])
@admin_required
def api_update_settings():
    try:
        data = request.json
        if 'stats_update_interval' in data:
            UPDATE_CONFIG['stats_update_interval'] = int(data['stats_update_interval'])
        if 'device_cache_timeout' in data:
            UPDATE_CONFIG['device_cache_timeout'] = int(data['device_cache_timeout'])
        if 'background_update_interval' in data:
            UPDATE_CONFIG['background_update_interval'] = int(data['background_update_interval'])
        if 'contract_auto_bind_interval' in data:
            UPDATE_CONFIG['contract_auto_bind_interval'] = int(data['contract_auto_bind_interval'])
        if 'backup_times' in data:
            BACKUP_CONFIG['backup_times'] = data['backup_times']
        if 'config_backup_enabled' in data:
            BACKUP_CONFIG['config_backup_enabled'] = bool(data['config_backup_enabled'])
        if 'data_backup_enabled' in data:
            BACKUP_CONFIG['data_backup_enabled'] = bool(data['data_backup_enabled'])
        update_scheduler_jobs()
        return jsonify({'status': 'success', 'message': 'Настройки обновлены', 'config': {'update': UPDATE_CONFIG, 'backup': BACKUP_CONFIG}})
    except Exception:
        logger.error("Error in api_settings_update", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Ошибка обновления настроек. Проверьте корректность переданных значений.'})


@app.route('/contracts')
@login_required
def contracts_page():
    with get_db_session() as session_db:
        return render_template('contracts.html', contract_stats=get_contract_stats(session_db), global_stats=get_global_stats(session_db), username=session.get('username'), role=session.get('role'))

@app.route('/api/contracts/upload', methods=['POST'])
@admin_required
def api_upload_contracts():
    try:
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file part'})
        file = request.files['file']
        if file.filename == '' or not allowed_file(file.filename):
            return jsonify({'status': 'error', 'message': 'Invalid file'})

        delimiter = request.form.get('delimiter', ';')
        if delimiter not in [';', ',', '\t', '|']:
            delimiter = ';'

        filename = secure_filename(f"contracts_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        with get_db_session() as session_db:
            result = save_contracts_from_file(session_db, filepath, delimiter)
        invalidate_devices_cache()
        return jsonify({'status': 'success', 'message': 'Договоры успешно загружены и привязаны', 'result': result})
    except werkzeug.exceptions.RequestEntityTooLarge:
        return jsonify({'status': 'error', 'message': 'File too large'})
    except Exception:
        logger.error("Error in api_contracts_upload", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Ошибка загрузки файла. Проверьте формат и повторите попытку.'})

@app.route('/api/contracts/search')
@login_required
def api_search_contracts():
    search_query = sanitize_string(request.args.get('q', ''), max_length=100)
    limit = int(request.args.get('limit', 50))
    limit = min(max(limit, 1), 500)
    with get_db_session() as session_db:
        try:
            contracts = search_contracts(session_db, search_query, limit)
            return jsonify({'contracts': contracts, 'total_count': len(contracts), 'message': f'Найдено {len(contracts)} договоров'})
        except Exception:
            logger.error("api_search_contracts failed", exc_info=True)
            return jsonify({'contracts': [], 'total_count': 0, 'error': _INTERNAL_ERROR_MSG})

@app.route('/api/contracts/stats')
@login_required
def api_contract_stats():
    with get_db_session() as session_db:
        return jsonify(get_contract_stats(session_db))

@app.route('/api/contracts/bind', methods=['POST'])
@admin_required
def api_bind_contracts():
    with get_db_session() as session_db:
        try:
            updated_count = bind_contracts_to_onu(session_db)
            invalidate_devices_cache()
            return jsonify({'status': 'success', 'message': f'Привязано {updated_count} договоров к ONU', 'updated_count': updated_count})
        except Exception:
            logger.error("Error in api_bind_contracts", exc_info=True)
            return jsonify({'status': 'error', 'message': 'Ошибка привязки договоров. Подробности в логах сервера.'})

@app.route('/api/contracts/clear', methods=['POST'])
@admin_required
def api_clear_contracts():
    with get_db_session() as session_db:
        try:
            contracts_deleted = session_db.query(Contract).delete(synchronize_session=False)
            session_db.query(ONU).update({ONU.contract: None}, synchronize_session=False)
            session_db.commit()
            invalidate_devices_cache()
            return jsonify({'status': 'success', 'message': f'Очищено {contracts_deleted} договоров', 'deleted_count': contracts_deleted})
        except Exception:
            logger.error("Error in api_clear_contracts", exc_info=True)
            return jsonify({'status': 'error', 'message': 'Ошибка очистки договоров. Подробности в логах сервера.'})

@app.route('/api/onu_contracts')
@login_required
def api_onu_contracts():
    device_id = request.args.get('device')
    interface = request.args.get('interface')
    normalized_id = normalize_device_id(device_id)
    if not normalized_id or not interface or not validate_interface(interface):
        return jsonify({'status': 'error', 'message': 'Invalid parameters'})
    with get_db_session() as session_db:
        try:
            contracts = db_get_onu_contracts(session_db, normalized_id, interface)
            return jsonify({'status': 'success', 'device_id': normalized_id, 'interface': interface, 'contracts': contracts, 'total_count': len(contracts)})
        except Exception:
            logger.error("Error in api_onu_contracts", exc_info=True)
            return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG})

@app.route('/api/set_main_contract', methods=['POST'])
@admin_required
def api_set_main_contract():
    data = request.json
    device_id, interface, contract_number = data.get('device'), data.get('interface'), data.get('contract_number')
    normalized_id = normalize_device_id(device_id)
    if not normalized_id or not interface or not contract_number or not validate_interface(interface):
        return jsonify({'status': 'error', 'message': 'Invalid parameters'})
    contract_number = sanitize_string(contract_number, max_length=100)
    with get_db_session() as session_db:
        try:
            contract = session_db.query(Contract).filter_by(contract_number=contract_number).first()
            if not contract:
                return jsonify({'status': 'error', 'message': 'Contract not found'})
            onu_contract = session_db.query(ONUContract).filter_by(device_id=normalized_id, interface=interface, contract_number=contract_number).first()
            if not onu_contract:
                return jsonify({'status': 'error', 'message': 'Contract not linked to this ONU'})
            onu = session_db.query(ONU).filter_by(device_id=normalized_id, interface=interface, is_active=True).first()
            if onu:
                onu.contract = contract_number
                onu.updated_at = datetime.now(timezone.utc)
                session_db.commit()
                invalidate_devices_cache()
                return jsonify({'status': 'success', 'message': f'Main contract set to {contract_number}'})
            return jsonify({'status': 'error', 'message': 'ONU not found'})
        except Exception:
            logger.error("Error in api_set_main_contract", exc_info=True)
            return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG})

@app.route('/api/set_onu_contract', methods=['POST'])
@admin_required
def api_set_onu_contract():
    data = request.json
    device_id, interface, contract_number = data.get('device'), data.get('interface'), data.get('contract_number')
    if not all([device_id, interface, contract_number]):
        return jsonify({'status': 'error', 'message': 'Не все параметры указаны'})
    normalized_id = normalize_device_id(device_id)
    if not normalized_id or not validate_interface(interface):
        return jsonify({'status': 'error', 'message': 'Устройство или интерфейс не найдены'})
    contract_number = sanitize_string(contract_number, max_length=100)
    with get_db_session() as session_db:
        try:
            result = set_onu_contract(session_db, normalized_id, interface, contract_number)
            invalidate_devices_cache()
            return jsonify(result)
        except Exception:
            logger.error("Error in api_set_onu_contract", exc_info=True)
            return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG})


@app.route('/api/cleanup_moved_onu', methods=['POST'])
@admin_required
def api_cleanup_moved_onu():
    steps = []
    def add_step(text, status='done'):
        steps.append({'text': text, 'status': status})

    data = request.json
    device_id, interface = data.get('device'), data.get('interface')

    add_step('Проверка параметров')
    if not device_id or not interface or not validate_interface(interface):
        return jsonify({'status': 'error', 'message': 'Не указаны параметры или неверный интерфейс', 'steps': steps})

    normalized_id = normalize_device_id(device_id)
    if not normalized_id:
        return jsonify({'status': 'error', 'message': 'Устройство не найдено', 'steps': steps})

    device_config = DEVICES.get(normalized_id)
    if not device_config:
        return jsonify({'status': 'error', 'message': 'Устройство не найдено в конфигурации', 'steps': steps})


    logger.info(f"🗑️ Удаление переехавшей ONU {device_config['name']}:{interface}")
    ssh_client = BDCOMSSHClient(
device_config['hostname'], device_config['username'],
device_config['password'], device_config['enable_password'],
model=device_config.get('model', '3310')
)
    ssh_deleted = False
    ssh_error = None
    try:
        add_step('Подключение к старому OLT по SSH')
        if ssh_client.connect():
            add_step('Выполнение команды удаления ONU')
            if ssh_client.delete_onu(interface):
                logger.info("✅ ONU физически удалена через SSH")
                ssh_deleted = True
            else:
                logger.warning("⚠️ SSH delete_onu вернул False (возможно, уже удалена)")
                ssh_deleted = True
            add_step('Сохранение конфигурации (write)')
        else:
            ssh_error = f"Не удалось подключиться к {device_config['name']}"
            logger.error(f"❌ {ssh_error}")
    except Exception as e:
        # В лог — полная ошибка; клиенту — только тип (без путей/внутренностей).
        logger.error(f"❌ SSH delete error for {device_config['name']}:{interface}: {e}", exc_info=True)
        ssh_error = f"Ошибка SSH: {type(e).__name__}"
    finally:
        ssh_client.close()

    if not ssh_deleted:
        return jsonify({'status': 'error', 'message': f'Не удалось удалить ONU с OLT: {ssh_error}', 'steps': steps})


    with get_db_session() as session_db:
        try:
            add_step('Очистка статусов переезда в БД')
            result = cleanup_moved_onus(session_db, normalized_id, interface)
            add_step('Удаление связанных записей')
            invalidate_devices_cache()
            return jsonify({
'status': 'success' if result.get('success') else 'error',
'message': result.get('message', ''),
'moved_to': result.get('moved_to', ''),
'steps': steps
})
        except Exception:
            logger.error("Error in cleanup DB step", exc_info=True)
            return jsonify({'status': 'error', 'message': 'Ошибка БД при очистке. Подробности в логах сервера.', 'steps': steps})

@app.route('/api/moved_onus')
@login_required
def api_moved_onus():
    device_id = request.args.get('device')
    normalized_id = normalize_device_id(device_id) if device_id else None
    with get_db_session() as session_db:
        try:
            return jsonify(get_moved_onus(session_db, normalized_id))
        except Exception:
            return jsonify({'moved_onus': [], 'total_count': 0})

@app.route('/api/device_moved_onus/<device_id>')
@login_required
def api_device_moved_onus(device_id):
    normalized_id = normalize_device_id(device_id)
    if not normalized_id:
        return jsonify({'moved_onus': [], 'total_count': 0})
    with get_db_session() as session_db:
        return jsonify(get_moved_onus(session_db, normalized_id))


@app.route('/api/start_manual_scan')
@login_required
def api_start_manual_scan():
    try:
        worker = start_update_worker()
        if any(status.get('status') == 'in_progress' for status in worker.get_update_status().values()):
            return jsonify({'status': 'error', 'message': 'Обновление уже выполняется'})
        update_queue.put({'device_id': 'all', 'force_fresh': True, 'type': 'manual_scan'})
        invalidate_devices_cache()
        invalidate_update_status_cache()
        # прогресс хранится в памяти (scan_progress) — отдельной инвалидации не требуется
        return jsonify({'status': 'success', 'message': 'Сканирование запущено в фоне'})
    except Exception:
        logger.error("Error in api_scan_all", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Ошибка запуска сканирования. Подробности в логах сервера.'})

@app.route('/api/scan_device/<device_id>')
@login_required
def api_scan_single_device(device_id):
    normalized_id = normalize_device_id(device_id)
    if not normalized_id:
        return jsonify({'status': 'error', 'message': f'Устройство "{escape_html(device_id)}" не найдено'})
    update_queue.put({'device_id': normalized_id, 'force_fresh': True, 'type': 'device_scan'})
    invalidate_devices_cache()
    return jsonify({'status': 'success', 'message': f'Начато сканирование устройства {DEVICES[normalized_id]["name"]}'})

@app.route('/api/clear_app_cache')
@admin_required
def api_clear_app_cache():
    try:
        invalidate_devices_cache()
        invalidate_update_status_cache()
        # прогресс хранится в памяти (scan_progress) — отдельной инвалидации не требуется
        cache.clear()
        return jsonify({'status': 'success', 'message': 'Все кэши очищены'})
    except Exception:
        logger.error("Error in api_clear_app_cache", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Ошибка очистки кэша. Подробности в логах сервера.'})


@app.route('/api/telegram/test_notification')
@admin_required
def api_test_notification():
    try:
        device_id = request.args.get('device_id', '1')
        interface = request.args.get('interface', 'EPON0/1:1')
        if not validate_interface(interface):
            return jsonify({'status': 'error', 'message': 'Неверный формат интерфейса'})
        is_mcd_test = request.args.get('is_mcd', 'false').lower() == 'true'
        success = test_telegram_notification(device_id, interface, is_mcd=is_mcd_test)
        return jsonify({'status': 'success' if success else 'error', 'message': f'Тестовое уведомление {"отправлено" if success else "не отправлено"} для {device_id}:{interface}'})
    except Exception:
        logger.error("Error in api_test_notification", exc_info=True)
        return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG})

@app.route('/api/telegram/debug_status')
@admin_required
def api_telegram_debug_status():
    try:
        from sqlalchemy import func
        status = get_telegram_bot_status()
        with get_db_session() as session_db:
            sample_onus = session_db.query(ONU).filter(ONU.is_active.is_(True)).limit(5).all()
            onu_samples = [{'device': onu.device_name, 'interface': safe_interface(onu.interface), 'status': onu.status, 'dereg_reason': onu.dereg_reason, 'optical_power': onu.optical_power, 'is_mcd': is_mcd(onu.description)} for onu in sample_onus]
            status_stats = session_db.query(ONU.status, func.count(ONU.id).label('count')).filter(ONU.is_active.is_(True)).group_by(ONU.status).all()
            status_counts = {stat[0]: stat[1] for stat in status_stats if stat[0]}
        return jsonify({'status': 'success', 'telegram_bot': status, 'onu_samples': onu_samples, 'status_counts': status_counts, 'total_onus_tracked': len(telegram_bot.last_onu_statuses) if hasattr(telegram_bot, 'last_onu_statuses') else 0})
    except Exception:
        logger.error("Error in api_telegram_debug_status", exc_info=True)
        return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG})

@app.route('/api/telegram/test')
@admin_required
def api_telegram_test():
    try:
        success = send_test_telegram_message()
        return jsonify({'status': 'success' if success else 'error', 'message': 'Тестовое сообщение отправлено' if success else 'Не удалось отправить'})
    except Exception:
        logger.error("Error in api_telegram_test", exc_info=True)
        return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG})

@app.route('/api/telegram/status')
@admin_required
def api_telegram_status():
    try:
        return jsonify({'status': 'success', 'telegram_bot': get_telegram_bot_status()})
    except Exception:
        logger.error("Error in api_telegram_status", exc_info=True)
        return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG})

@app.route('/api/telegram/settings', methods=['GET', 'POST'])
@admin_required
def api_telegram_settings():
    try:
        if request.method == 'POST':
            data = request.json
            # Мутация TELEGRAM_CONFIG здесь, применение к живому боту —
            # целиком в telegram_bot.apply_telegram_settings (единая точка
            # hot-reload; раньше app.py присваивал атрибуты точечно и
            # check_interval/списки статусов/mcd_marker не применялись
            # до перезапуска).
            updates = {}
            for key in ('bot_token', 'chat_id', 'critical_chat_id', 'mcd_marker'):
                if key in data:
                    updates[key] = str(data[key]).strip()
                    TELEGRAM_CONFIG[key] = updates[key]
            for key in ('enabled', 'monitoring_enabled', 'notify_on_offline',
                        'notify_on_recovery', 'notify_mcd_separately', 'mcd_always_notify'):
                if key in data:
                    updates[key] = bool(data[key])
                    TELEGRAM_CONFIG[key] = updates[key]
            for key in ('critical_statuses', 'recovery_statuses'):
                if key in data:
                    value = [str(s).strip() for s in data[key] if str(s).strip()]
                    updates[key] = value
                    TELEGRAM_CONFIG[key] = value
            if 'check_interval' in data:
                try:
                    interval = max(30, int(data['check_interval']))
                except (TypeError, ValueError):
                    return jsonify({'status': 'error',
                                    'message': 'check_interval должен быть целым числом секунд'})
                updates['check_interval'] = interval
                TELEGRAM_CONFIG['check_interval'] = interval

            apply_telegram_settings(updates)

            if TELEGRAM_CONFIG['monitoring_enabled'] and not telegram_bot.running:
                start_telegram_monitoring()
            elif not TELEGRAM_CONFIG['monitoring_enabled'] and telegram_bot.running:
                stop_telegram_monitoring()

            return jsonify({'status': 'success', 'message': 'Настройки Telegram обновлены', 'config': TELEGRAM_CONFIG})
        return jsonify({'status': 'success', 'config': TELEGRAM_CONFIG})
    except Exception:
        logger.error("Error in api_telegram_settings", exc_info=True)
        return jsonify({'status': 'error', 'message': _INTERNAL_ERROR_MSG})

@app.route('/settings/telegram')
@admin_required
def telegram_settings():
    return render_template('telegram_settings.html', username=session.get('username'), role=session.get('role'))


def scheduled_hourly_update():
    logger.info("🕐 Starting scheduled hourly update (non-blocking)")
    update_queue.put({'device_id': 'all', 'force_fresh': True, 'type': 'scheduled'})

def auto_bind_contracts():
    logger.info("📝 Starting automatic contract binding")
    with get_db_session() as session_db:
        try:
            updated_count = bind_contracts_to_onu(session_db)
            logger.info(f"✅ Automatic contract binding completed: {updated_count} contracts bound")
            invalidate_devices_cache()
        except Exception as e:
            logger.error(f"💥 Error in automatic contract binding: {e}", exc_info=True)

def check_onu_changes():
    logger.info("🔍 Checking for ONU changes")
    with get_db_session() as session_db:
        try:
            one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
            stale_onus = session_db.query(ONU).filter(ONU.last_seen < one_hour_ago, ONU.is_active.is_(True)).all()
            if stale_onus:
                logger.info(f"Found {len(stale_onus)} stale ONUs")
                for onu in stale_onus:
                    logger.info(f"  Stale: {onu.device_name}:{onu.interface} (last seen: {onu.last_seen})")
        except Exception as e:
            logger.error(f"Error checking ONU changes: {e}", exc_info=True)

def cleanup_task():
    try:
        if datetime.now().hour == 3 and datetime.now().minute < 5:
            with get_db_session() as session_db:
                try:
                    cleanup_old_data(session_db, days_to_keep=7)
                    logger.info("Old data cleanup completed")
                    invalidate_devices_cache()
                except Exception as e:
                    logger.error(f"Error during data cleanup: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"Error in cleanup task: {e}", exc_info=True)

def initial_data_update():
    logger.info("Starting initial data update...")
    time.sleep(10)
    # Skip if no devices configured to avoid misleading logs.
    if not DEVICES:
        logger.warning("No devices to scan (DEVICES empty). Skipping initial update.")
        return
    logger.info(f"Queuing initial scan for {len(DEVICES)} device(s)...")
    update_queue.put({'device_id': 'all', 'force_fresh': True, 'type': 'initial'})

def update_scheduler_jobs():
    try:
        scheduler.remove_all_jobs()

        if BACKUP_CONFIG.get('config_backup_enabled', True):
            for backup_time in BACKUP_CONFIG.get('backup_times', ['15:35', '19:30']):
                hour, minute = backup_time.split(':')
                scheduler.add_job(save_all_running_configs, CronTrigger(hour=int(hour), minute=int(minute)), id=f'config_backup_{backup_time}')
                logger.info(f"Scheduled config backup at {backup_time}")

        if BACKUP_CONFIG.get('data_backup_enabled', True):
            scheduler.add_job(save_all_onu_data_excel, CronTrigger(hour=19, minute=30), id='data_backup')

        scheduler.add_job(scheduled_hourly_update, CronTrigger(minute=0), id='hourly_update')

        contract_interval = UPDATE_CONFIG.get('contract_auto_bind_interval', 3600)
        if contract_interval > 0:
            scheduler.add_job(auto_bind_contracts, IntervalTrigger(seconds=contract_interval), id='contract_binding')
            logger.info(f"Scheduled contract auto-binding every {contract_interval} seconds")

        onu_check_interval = UPDATE_CONFIG.get('onu_change_check_interval', 600)
        if onu_check_interval > 0:
            scheduler.add_job(check_onu_changes, IntervalTrigger(seconds=onu_check_interval), id='onu_check')
            logger.info(f"Scheduled ONU change check every {onu_check_interval} seconds")

        scheduler.add_job(cleanup_task, IntervalTrigger(minutes=5), id='cleanup')
    except Exception as e:
        logger.error(f"Error updating scheduler jobs: {e}", exc_info=True)

def initialize_application():
    logger.info("Initializing EPON Monitor application with APScheduler and async updates...")
    try:
        start_update_worker()
        update_scheduler_jobs()
        scheduler.start()

        # Log device count early so operators can confirm whether scanning will actually happen.
        if not DEVICES:
            logger.warning(
                "No devices configured (DEVICES is empty). Scanning will NOT occur. "
                "Add devices via web UI or set DEVICES_JSON environment variable."
            )
        else:
            logger.info(f"Devices configured: {len(DEVICES)} IDs: {list(DEVICES.keys())}")

        if TELEGRAM_CONFIG.get('enabled', False):
            if initialize_telegram_bot():
                start_telegram_monitoring()
                logger.info("Telegram bot monitoring started")
            else:
                logger.warning("Telegram bot initialization failed")
        else:
            logger.info("Telegram bot disabled in config")

        try:
            scheduler.add_job(cleanup_telegram_notifications, CronTrigger(hour=2, minute=30), id='telegram_notifications_cleanup')
            logger.info("Scheduled Telegram notifications cleanup at 02:30")
        except Exception as e:
            logger.error(f"Error scheduling Telegram cleanup: {e}", exc_info=True)

        threading.Thread(target=initial_data_update, daemon=True).start()
        logger.info("Application initialization completed with async updates")
    except Exception as e:
        logger.error(f"Error initializing application: {e}", exc_info=True)
        raise

def stop_background_tasks():
    logger.info("Stopping background tasks...")
    try:
        try:
            stop_telegram_monitoring()
        except Exception as e:
            logger.warning(f"Error stopping Telegram monitoring: {e}")

        if update_worker and update_worker.is_alive():
            update_worker.stop()
            logger.info("Update worker stopped")

        if scheduler.running:
            scheduler.shutdown(wait=False)
            logger.info("Scheduler stopped")

        thread_pool.shutdown(wait=False)
        logger.info("Thread pool shutdown")
        logger.info("All background tasks stopped")
    except Exception as e:
        logger.error(f"Error stopping background tasks: {e}", exc_info=True)


@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', message="Страница не найдена"), 404

# Регистрация after-exit должна идти после определения stop_background_tasks.
import atexit  # noqa: E402
atexit.register(stop_background_tasks)

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', message="Внутренняя ошибка сервера"), 500


if __name__ == '__main__':
    initialize_application()
    logger.info("Starting optimized EPON Monitor application with async updates")
    app.run(host='0.0.0.0', port=5200, threaded=True, debug=False, use_reloader=False)
