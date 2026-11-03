"""
Конфигурация EPON Monitor.

Все секреты (пароли MySQL, SSH-пароли устройств, токен Telegram-бота, пароли
пользователей) берутся из переменных окружения / файла .env и НИКОГДА не
хранятся в этом файле в открытом виде.

Хранение паролей:
  - USERS: только bcrypt-хэши (password_hash). Для генерации:
      python -c "from config import hash_password; print(hash_password('secret'))"
  - Совместимость: если у пользователя указан 'password' (устаревший вариант),
    вход всё равно возможен через pbkdf2-хэш werkzeug или постоянный тайминг-сравнение.

После редактирования DEVICES/настроек через веб-интерфейс изменения пишутся
в devices_overrides.json и settings_overrides.json и переживают рестарт.
"""

import os
import re
import json
import logging
import threading
from pathlib import Path

from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

try:
    import bcrypt
except ImportError:
    bcrypt = None

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
logger = logging.getLogger('EPON_Config')

_config_lock = threading.RLock()


def _env(name, default=None):
    return os.environ.get(name, default)


def _env_int(name, default):
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ('1', 'true', 'yes', 'on', 'да')


SECRET_KEY = _env('SECRET_KEY')
if not SECRET_KEY:
    SECRET_KEY = generate_password_hash('epon-monitor-insecure-dev-key')
    logger.warning(
        'SECRET_KEY не задан в окружении/.env — сгенерирован временный. '
        'Задайте SECRET_KEY в .env, чтобы сессии переживали рестарт!'
    )

SESSION_CONFIG = {
    'secret_key': SECRET_KEY,
    'permanent_session_lifetime': _env_int('SESSION_LIFETIME', 28800),
    'session_cookie_secure': _env_bool('SESSION_COOKIE_SECURE', False),
    'session_cookie_httponly': True,
    'session_cookie_samesite': _env('SESSION_COOKIE_SAMESITE', 'Lax'),
}

USERS = {}
for _entry in (_env('USERS', '') or '').split(','):
    _entry = _entry.strip()
    if not _entry or ':' not in _entry:
        continue
    _name, _rest = _entry.split(':', 1)
    if ':' in _rest:
        _pwd_or_hash, _role = _rest.rsplit(':', 1)
    else:
        _pwd_or_hash, _role = _rest, 'user'
    _role = _role.strip() or 'user'
    if _pwd_or_hash.startswith(('bcrypt$', '$2b$', '$2a$', 'pbkdf2:')):
        USERS[_name.strip()] = {'password_hash': _pwd_or_hash, 'role': _role}
    else:
        USERS[_name.strip()] = {
            'password_hash': generate_password_hash(_pwd_or_hash),
            'role': _role,
        }

_LEGACY_ROLE_MAP = {'admin': 'adminisp', 'support': 'support'}
for _legacy_user in ('admin', 'support'):
    _legacy_pwd = _env(f'{_legacy_user.upper()}_PASSWORD')
    if not _legacy_pwd:
        continue
    if _legacy_user in USERS:
        continue
    USERS[_legacy_user] = {
        'password_hash': generate_password_hash(_legacy_pwd),
        'role': _LEGACY_ROLE_MAP.get(_legacy_user, 'user'),
    }
    logger.warning(
        'Используется устаревшая переменная %s_PASSWORD — перенесите '
        'пользователя в USERS="имя:хэш:роль".', _legacy_user.upper())

if not USERS:
    logger.warning('Ни одного пользователя не настроено (задайте USERS в .env).')


def hash_password(password):
    """Рекомендуемый хэш пароля (bcrypt, если доступен, иначе pbkdf2)."""
    if bcrypt is not None:
        return 'bcrypt$' + bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt(rounds=12)
        ).decode('ascii')
    return generate_password_hash(password, method='pbkdf2:sha256:600000')


def verify_password(stored, password):
    """Проверка пароля по хэшу. Поддержка bcrypt$, pbkdf2-/scrypt-хешей werkzeug.

    Возвращает True/False; сравнение выполняется constant-time внутри библиотек.
    """
    if stored is None or password is None:
        return False
    stored = str(stored)
    password = str(password)
    try:
        if stored.startswith('bcrypt$'):
            if bcrypt is None:
                logger.error('bcrypt не установлен, невозможно проверить пароль')
                return False
            return bcrypt.checkpw(
                password.encode('utf-8'),
                stored[len('bcrypt$'):].encode('ascii')
            )
        if stored.startswith(('$2b$', '$2a$')):
            if bcrypt is None:
                return False
            return bcrypt.checkpw(password.encode('utf-8'), stored.encode('ascii'))
        if stored.startswith(('pbkdf2:', 'scrypt:', 'plain:')):
            return check_password_hash(stored, password)
        import hmac
        return hmac.compare_digest(stored, password)
    except Exception as e:
        logger.error(f'Ошибка проверки пароля: {e}')
        return False


DB_TYPE = (_env('DB_TYPE', 'mysql') or 'mysql').strip().lower()

MYSQL_CONFIG = {
    'type': DB_TYPE,
    'sqlite_path': _env('DB_SQLITE_PATH', str(BASE_DIR / 'epon_monitor_dev.sqlite3')),
    'host': _env('DB_HOST', 'localhost'),
    'port': _env_int('DB_PORT', 3306),
    'database': _env('DB_NAME', 'epon_monitor'),
    'username': _env('DB_USER', 'root'),
    'password': _env('DB_PASSWORD', ''),
    'charset': _env('DB_CHARSET', 'utf8mb4'),
    'echo': _env_bool('DB_ECHO', False),
    'pool_size': _env_int('DB_POOL_SIZE', 20),
    'max_overflow': _env_int('DB_MAX_OVERFLOW', 30),
    'pool_recycle': _env_int('DB_POOL_RECYCLE', 3600),
    # Схема версионируется Alembic (migrations/); init_db сам таблицы не создаёт.
    'alembic_managed': _env_bool('DB_ALEMBIC_MANAGED', True),
}

UPLOAD_CONFIG = {
    'upload_folder': _env('UPLOAD_FOLDER', str(BASE_DIR / 'uploads')),
    'max_file_size': _env_int('MAX_FILE_SIZE', 16777216),
    'allowed_extensions': {'xlsx', 'csv', 'txt'},
}

UPDATE_CONFIG = {
    'stats_update_interval': _env_int('STATS_UPDATE_INTERVAL', 30),
    'device_cache_timeout': _env_int('DEVICE_CACHE_TIMEOUT', 3600),
    'background_update_interval': _env_int('BACKGROUND_UPDATE_INTERVAL', 300),
    'contract_auto_bind_interval': _env_int('CONTRACT_BIND_INTERVAL', 3600),
    'onu_change_check_interval': _env_int('ONU_CHECK_INTERVAL', 600),
    'memoize_cache_timeout': _env_int('MEMOIZE_CACHE_TIMEOUT', 30),
    'status_cache_timeout': _env_int('STATUS_CACHE_TIMEOUT', 10),
    'global_stats_cache_timeout': _env_int('GLOBAL_STATS_CACHE_TIMEOUT', 60),
}

BACKUP_CONFIG = {
    'backup_directory': _env('BACKUP_DIR', 'BDCOM'),
    'config_backup_enabled': _env_bool('CONFIG_BACKUP_ENABLED', True),
    'data_backup_enabled': _env_bool('DATA_BACKUP_ENABLED', True),
    'max_backup_files': _env_int('MAX_BACKUP_FILES', 3000),
    'backup_times': [t.strip() for t in (_env('BACKUP_TIMES', '15:35,19:30')).split(',')
                     if t.strip()],
}

SSH_CONFIG = {
    # '' = netmiko default; 'reject' — строгая проверка host keys OLT.
    'host_keys_policy': _env('SSH_HOST_KEYS_POLICY', '') or None,
    'timeout': _env_int('SSH_TIMEOUT', 30),
    'port': _env_int('SSH_PORT', 22),
    'session_timeout': _env_int('SSH_SESSION_TIMEOUT', 60),
    'blocking_timeout': _env_int('SSH_BLOCKING_TIMEOUT', 15),
}

OPTICAL_CONFIG = {
    'good_threshold': _env_int('OPTICAL_GOOD_THRESHOLD', -25),
    'warning_threshold': _env_int('OPTICAL_WARNING_THRESHOLD', -27),
    'bad_threshold': _env_int('OPTICAL_BAD_THRESHOLD', -30),
}

TELEGRAM_CONFIG = {
    'bot_token': _env('TELEGRAM_BOT_TOKEN', ''),
    'chat_id': _env('TELEGRAM_CHAT_ID', ''),
    'critical_chat_id': _env('TELEGRAM_CRITICAL_CHAT_ID', ''),
    'enabled': _env_bool('TELEGRAM_ENABLED', False),
    'monitoring_enabled': _env_bool('TELEGRAM_MONITORING', False),
    'notify_on_offline': _env_bool('TELEGRAM_NOTIFY_OFFLINE', True),
    'notify_on_recovery': _env_bool('TELEGRAM_NOTIFY_RECOVERY', True),
    'notify_mcd_separately': _env_bool('TELEGRAM_NOTIFY_MCD_SEPARATELY', True),
    'mcd_always_notify': _env_bool('TELEGRAM_MCD_ALWAYS', True),
    'mcd_marker': _env('TELEGRAM_MCD_MARKER', '+'),
    'check_interval': _env_int('TELEGRAM_CHECK_INTERVAL', 360),
    'critical_statuses': [s.strip() for s in
                          _env('TELEGRAM_CRITICAL_STATUSES', 'wire-down,losi,los').split(',')
                          if s.strip()],
    'recovery_statuses': [s.strip() for s in
                          _env('TELEGRAM_RECOVERY_STATUSES', 'active,online').split(',')
                          if s.strip()],
}

VENDOR_CONFIG = {
    'BDCM': {'full_name': 'BDCOM', 'mac_prefix': '4092', 'description': 'BDCOM Technology'},
    'HWTC': {'full_name': 'Huawei', 'mac_prefix': '8c70', 'description': 'Huawei Technologies'},
    'ZTEG': {'full_name': 'ZTE', 'mac_prefix': '3417', 'description': 'ZTE Corporation'},
    'ALCL': {'full_name': 'Alcatel', 'mac_prefix': '00e0', 'description': 'Alcatel-Lucent'},
    'DASN': {'full_name': 'Dasann', 'mac_prefix': '0026', 'description': 'Dasann Networks'},
    'FTRO': {'full_name': 'Fiberhome', 'mac_prefix': '0012', 'description': 'Fiberhome Technologies'},
    'SCOM': {'full_name': 'Speedcom', 'mac_prefix': 'a0f4', 'description': 'Speedcom Technology'},
}

# Базовый список устройств берётся из окружения (DEVICES_JSON — JSON вида
# {"1": {"name": "...", "hostname": "...", ...}, ...}).
DEVICES_ENV_DEFAULT = {}
try:
    DEVICES_ENV_DEFAULT = json.loads(_env('DEVICES_JSON', '{}') or '{}')
except (json.JSONDecodeError, TypeError):
    logger.error('DEVICES_JSON содержит некорректный JSON — используется пустой список устройств')

OVERRIDES_FILE = BASE_DIR / 'devices_overrides.json'

DEVICES = {}


def _resolve_device_value(value):
    """Подстановка значений из окружения в формате '${VAR:default}'.

    Совместимость со старым devices_overrides.json, где пароли устройств
    хранились как ссылки на env-переменные (DEVICE_PASSWORD и т.п.).
    """
    if not isinstance(value, str):
        return value
    s = value.strip()
    if s.startswith('${') and s.endswith('}') and len(s) > 3:
        inner = s[2:-1]
        var, _, default = inner.partition(':')
        return os.environ.get(var, default) if var else default
    return value


def _normalize_device_entry(dev_id, entry):
    """Валидация/нормализация одной записи устройства."""
    if not isinstance(entry, dict):
        return None
    name = str(_resolve_device_value(entry.get('name', ''))).strip()
    hostname = str(_resolve_device_value(entry.get('hostname', ''))).strip()
    if not name or not re.fullmatch(r'[A-Za-z0-9._-]+', hostname):
        return None
    model = _resolve_device_value(entry.get('model', '3310'))
    if model not in ('3310', 'GP3600'):
        model = '3310'
    return {
        'name': name[:50],
        'hostname': hostname,
        'username': str(_resolve_device_value(entry.get('username', 'admin'))),
        'password': str(_resolve_device_value(entry.get('password', ''))),
        'enable_password': str(_resolve_device_value(entry.get('enable_password', ''))),
        'description': str(_resolve_device_value(entry.get('description', '')))[:100],
        'model': model,
    }


def _load_legacy_overrides(overrides):
    """Миграция старого формата devices_overrides.json.

    Legacy-формат: плоский JSON {id: {name, hostname, ...}} без обёртки
    {'devices': ..., 'deleted': ...}. Возвращает (devices_map, deleted_list).
    """
    if not isinstance(overrides, dict):
        return {}, []
    if 'devices' in overrides or 'deleted' in overrides:
        return overrides.get('devices') or {}, overrides.get('deleted') or []
    devices_map = {
        str(k): v for k, v in overrides.items()
        if str(k).isdigit() and isinstance(v, dict) and 'hostname' in v
    }
    if devices_map:
        logger.info(
            'Обнаружен devices_overrides.json в legacy-формате — будет '
            'конвертирован в новый формат при первом сохранении через UI.')
    return devices_map, []


def reload_devices():
    """DEVICES = env-дефолты + overrides (overrides имеют приоритет).

    Устройства, удалённые через UI (список 'deleted'), не возвращаются даже
    если они присутствуют в DEVICES_JSON окружения. Поддерживается как новый
    ({'devices': {...}, 'deleted': [...]}), так и legacy-формат overrides-файла.
    """
    with _config_lock:
        overrides = _read_json(OVERRIDES_FILE, default={}) or {}
        devices_map, deleted_list = _load_legacy_overrides(overrides)
        deleted = {str(d) for d in deleted_list}
        merged = {}
        for dev_id, entry in DEVICES_ENV_DEFAULT.items():
            if str(dev_id) in deleted:
                continue
            norm = _normalize_device_entry(dev_id, entry)
            if norm is None:
                continue
            merged[str(dev_id)] = norm
        for dev_id, entry in devices_map.items():
            if str(dev_id) in deleted:
                continue
            norm = _normalize_device_entry(dev_id, entry)
            if norm is None:
                continue
            merged[str(dev_id)] = norm
        globals()['DEVICES'] = merged
    return DEVICES


def _read_json(path, default=None):
    try:
        if Path(path).exists():
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f'Не удалось прочитать {path}: {e}')
    return default


def _write_json(path, data):
    tmp = Path(str(path) + '.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def get_devices_source_info():
    overrides = _read_json(OVERRIDES_FILE, default={})
    devices_map, _deleted = _load_legacy_overrides(overrides)
    return {
        'overrides_file': str(OVERRIDES_FILE),
        'overrides_exists': OVERRIDES_FILE.exists(),
        'override_count': len(devices_map),
        'env_count': len(DEVICES_ENV_DEFAULT),
        'total': len(DEVICES),
    }


def get_next_device_id():
    ids = [int(k) for k in DEVICES if str(k).isdigit()]
    return str(max(ids) + 1) if ids else '1'


def add_device(device_id, name, hostname, username, password='',
               enable_password='', description='', model='3310'):
    """Добавляет/обновляет устройство и сохраняет его в devices_overrides.json."""
    device_id = str(device_id).strip()
    if not re.fullmatch(r'\d+', device_id):
        return {'success': False, 'message': 'ID устройства должен быть числом'}
    if not re.fullmatch(r'[\d.]+', str(hostname)):
        return {'success': False, 'message': 'Некорректный hostname/IP'}
    if model not in ('3310', 'GP3600'):
        return {'success': False, 'message': "Модель должна быть '3310' или 'GP3600'"}
    entry = _normalize_device_entry(device_id, {
        'name': name,
        'hostname': hostname,
        'username': username,
        'password': password,
        'enable_password': enable_password,
        'description': description,
        'model': model,
    })
    if entry is None:
        return {'success': False, 'message': 'Некорректные данные устройства'}
    with _config_lock:
        overrides = _read_json(OVERRIDES_FILE, default={}) or {}
        devices_map = overrides.get('devices') or {}
        devices_map[device_id] = entry
        overrides['devices'] = devices_map
        try:
            _write_json(OVERRIDES_FILE, overrides)
        except OSError as e:
            return {'success': False, 'message': f'Не удалось сохранить конфиг: {e}'}
        DEVICES[device_id] = entry
    return {'success': True,
            'message': f'Устройство {entry["name"]} сохранено в {OVERRIDES_FILE.name}'}


def remove_device_from_config(device_id):
    device_id = str(device_id).strip()
    with _config_lock:
        overrides = _read_json(OVERRIDES_FILE, default={}) or {}
        devices_map = overrides.get('devices') or {}
        devices_map.pop(device_id, None)
        DEVICES_ENV_DEFAULT.pop(device_id, None)
        overrides['devices'] = devices_map
        deleted = overrides.setdefault('deleted', [])
        if device_id not in deleted:
            deleted.append(device_id)
        try:
            _write_json(OVERRIDES_FILE, overrides)
        except OSError as e:
            return {'success': False, 'message': f'Не удалось сохранить конфиг: {e}'}
        DEVICES.pop(device_id, None)
    return {'success': True, 'message': f'Устройство {device_id} удалено из конфигурации'}


def test_device_connection(hostname, username, password, enable_password, model='3310'):
    """Проверка доступности устройства по SSH (netmiko)."""
    try:
        from netmiko import ConnectHandler
        device_type = 'huawei' if model == 'GP3600' else 'dcn'
        conn = ConnectHandler(
            device_type=device_type,
            host=hostname,
            username=username,
            password=password,
            secret=enable_password or None,
            conn_timeout=10,
            timeout=15,
        )
        conn.find_prompt()
        conn.disconnect()
        return {'success': True, 'message': f'Соединение с {hostname} установлено'}
    except Exception as e:
        return {'success': False, 'message': f'{type(e).__name__}: {e}'}


reload_devices()
