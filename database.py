import os
import re
import logging
import datetime
import threading
from contextlib import contextmanager
import chardet
import pandas as pd
from sqlalchemy import (
create_engine, Column, Integer, String, Float, DateTime, Text,
Boolean, Index, BigInteger, func, distinct, case, and_
)
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session


@compiles(BigInteger, "sqlite")
@compiles(BigInteger, "postgresql")
def _bigint_as_integer(element, compiler, **kw):
    """BIGINT -> INTEGER для диалектов без нативного автосбрасываемого BIGINT PK.

    В SQLite автоинкремент работает только для «INTEGER PRIMARY KEY», поэтому
    схемы с BigInteger-PK не давали id при вставке (NOT NULL constraint failed).
    На MySQL тип остаётся нативным BIGINT.
    """
    return "INTEGER"

from sqlalchemy import inspect as sa_inspect  # noqa: E402


def like_pattern(term):
    """Безопасный LIKE-паттерн '%term%': экранирует спецсимволы подстановки.

    Без экранирования пользовательский '%'/'_' трактовались бы как wildcard'ы
    (поиск по '50%' находил все записи на '50...'). Escape-символ — backslash;
    при вызове .like()/.ilike() его нужно передавать явным параметром
    escape=LIKE_ESCAPE (SQLAlchemy не добавляет ESCAPE-фразу автоматически).
    """
    escaped = str(term).replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    return f'%{escaped}%'


def escape_prefix(term):
    """Экранирует спецсимволы LIKE в строке-префиксе (без добавления %).

    Для запросов вида "начинается с..." — column.like(escape_prefix(t) + '%',
    escape=LIKE_ESCAPE). Без экранирования пользовательский '%'/'_' трактовался
    бы как wildcard подстановки. Обратный слэш экранируется первым, чтобы не
    экранировать уже добавленные escape-символы.
    """
    return str(term).replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


LIKE_ESCAPE = '\\'


def mcd_like_pattern():
    """LIKE-паттерн для MCD-описаний: '<marker>%' из конфига с экранированием.

    Маркер берётся из TELEGRAM_CONFIG.mcd_marker (по умолчанию '+') и
    экранируется через escape_prefix, чтобы пользовательский '%'/'_' в
    значении env-переменной не превращался в SQL-wildcard.
    Использовать так: column.like(mcd_like_pattern(), escape=LIKE_ESCAPE).
    """
    return escape_prefix(TELEGRAM_CONFIG.get('mcd_marker', '+')) + '%'


from config import MYSQL_CONFIG, VENDOR_CONFIG, TELEGRAM_CONFIG, DEVICES  # noqa: E402

# Настройка logging выполняется централизованно в app.py setup_logging().
# basicConfig() на уровне модуля здесь запрещён: импорт database из любого
# скрипта молча конфигурировал бы корневой логгер всего процесса.
logger = logging.getLogger('EPON_Database')
Base = declarative_base()

# Общее безопасное сообщение для поля 'error' в возвратах функций БД:
# строки исключений драйверов (пути, хосты, фрагменты SQL) клиенту не
# отдаём — подробности пишутся только в лог с exc_info=True.
# app.py использует то же значение (INTERNAL_ERROR_MSG).
INTERNAL_ERROR_MSG = 'Внутренняя ошибка сервера. Обратитесь к администратору.'


def is_mcd(description):
    if not description or not isinstance(description, str):
        return False
    desc = description.strip()
    if not desc:
        return False
    marker = TELEGRAM_CONFIG.get('mcd_marker', '+')
    return desc[0] in ('+', '＋', marker)

def now_local():
    return datetime.datetime.now()


def bulk_delete_query(query):
    from sqlalchemy import delete as sa_delete
    stmt = sa_delete(query.column_descriptions[0]['entity'])
    crit = getattr(query, '_where_criteria', None)
    if crit:
        stmt = stmt.where(*crit)
    result = query.session.execute(stmt)
    return int(result.rowcount or 0)


_db_device_names_cache = {}


def refresh_db_device_names(session=None):
    """Build a device_id -> device_name map from the DB.

    If ``session`` is None, opens its own session from the shared pool and
    updates the module-level cache. Otherwise only reads via the given session
    (cache update is left to the outermost call).
    """
    global _db_device_names_cache
    try:
        if session is None:
            with get_db_session() as own_session:
                names = _collect_device_names(own_session)
            _db_device_names_cache = names
            return names

        names = _collect_device_names(session)
        _db_device_names_cache = names
        return names
    except Exception as e:
        logger.error(f"Error refreshing DB device names: {e}")
        return dict(_db_device_names_cache)


def _collect_device_names(session):
    names = {}
    rows = session.query(ONU.device_id, ONU.device_name).distinct().all()
    for dev_id, dev_name in rows:
        if dev_id and dev_name:
            names[str(dev_id)] = dev_name
    rows = session.query(DeviceStatus.device_id, DeviceStatus.device_name).distinct().all()
    for dev_id, dev_name in rows:
        if dev_id and dev_name:
            names.setdefault(str(dev_id), dev_name)
    return names


def get_device_name_by_id(device_id):
    if not device_id:
        return ''
    device_id_str = str(device_id)
    if device_id_str in DEVICES:
        return DEVICES[device_id_str].get('name', device_id_str)
    for _dev_id, config in DEVICES.items():
        if config.get('name') == device_id_str:
            return config.get('name', device_id_str)

    cached_name = _db_device_names_cache.get(device_id_str)
    if cached_name:
        return cached_name
    return device_id_str

def parse_moved_location(moved_location):
    if not moved_location:
        return None, None, ''
    parts = str(moved_location).split(':', 1)
    if len(parts) == 2:
        device_id = parts[0]
        interface = parts[1]
        device_name = get_device_name_by_id(device_id)
        return device_id, interface, device_name
    return moved_location, None, get_device_name_by_id(moved_location)


class DeviceStatus(Base):
    __tablename__ = 'device_status'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    device_id = Column(String(10), unique=True, nullable=False, index=True)
    device_name = Column(String(50), nullable=False, index=True)
    last_successful_update = Column(DateTime)
    onu_count = Column(Integer, default=0)
    active_onu_count = Column(Integer, default=0)
    inactive_onu_count = Column(Integer, default=0)
    enriched_onu_count = Column(Integer, default=0)
    error_message = Column(Text)
    is_online = Column(Boolean, default=False)
    updated_at = Column(DateTime, default=now_local, onupdate=now_local)
    __table_args__ = (
Index('idx_device_id', 'device_id'),
Index('idx_device_name', 'device_name'),
{'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
)

class ONU(Base):
    __tablename__ = 'onus'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    device_id = Column(String(10), nullable=False, index=True)
    device_name = Column(String(50), nullable=False, index=True)
    interface = Column(String(50), nullable=False, index=True)
    vendor = Column(String(50))
    model = Column(String(50))
    mac = Column(String(50), index=True)
    normalized_mac = Column(String(50), index=True)
    description = Column(Text)
    contract = Column(String(100), index=True)
    bind_type = Column(String(20))
    status = Column(String(20), index=True)
    dereg_reason = Column(String(50), index=True)
    optical_power = Column(Float)
    client_macs_count = Column(Integer, default=0)
    is_enriched = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True, index=True)
    moved_to = Column(String(100), nullable=True, index=True)
    moved_from = Column(String(100), nullable=True, index=True)
    moved_at = Column(DateTime, nullable=True)
    is_configured = Column(Boolean, default=True, index=True)
    last_seen = Column(DateTime, default=now_local)
    created_at = Column(DateTime, default=now_local)
    updated_at = Column(DateTime, default=now_local, onupdate=now_local)

    @property
    def is_mcd(self):
        return is_mcd(self.description)

    __table_args__ = (
Index('idx_device_interface', 'device_id', 'interface', unique=True,
mysql_length={'device_id': 10, 'interface': 50}),
Index('idx_device_mac', 'device_id', 'mac'),


Index('idx_onu_normalized_mac', 'normalized_mac'),
Index('idx_status_reason', 'status', 'dereg_reason'),
Index('idx_contract', 'contract'),
Index('idx_mac', 'mac'),
Index('idx_is_active', 'is_active'),
Index('idx_moved_to', 'moved_to'),
Index('idx_moved_from', 'moved_from'),
Index('idx_is_configured', 'is_configured'),
{'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
)

class ONUHistory(Base):
    __tablename__ = 'onu_history'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    onu_id = Column(BigInteger, nullable=True, index=True)
    device_id = Column(String(10), nullable=False, index=True)
    interface = Column(String(50), nullable=False, index=True)
    mac = Column(String(50), index=True)
    action = Column(String(20), nullable=False)
    old_device_id = Column(String(10))
    new_device_id = Column(String(10))
    old_interface = Column(String(50))
    new_interface = Column(String(50))
    details = Column(Text)
    created_at = Column(DateTime, default=now_local)
    __table_args__ = (
Index('idx_onu_history', 'device_id', 'interface', 'created_at'),
Index('idx_mac_history', 'mac', 'created_at'),
{'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
)

class ONUClientMAC(Base):
    __tablename__ = 'onu_client_macs'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    onu_interface = Column(String(100), nullable=False, index=True)
    vlan = Column(String(10))
    mac_address = Column(String(50), nullable=False, index=True)
    normalized_mac = Column(String(50), index=True)
    type = Column(String(10))
    port = Column(String(50))
    created_at = Column(DateTime, default=now_local)
    __table_args__ = (
Index('idx_onu_mac', 'onu_interface', 'mac_address', unique=True,
mysql_length={'onu_interface': 50, 'mac_address': 50}),
Index('idx_normalized_mac', 'normalized_mac'),
{'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
)

class ONUContract(Base):
    __tablename__ = 'onu_contracts'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    device_id = Column(String(10), nullable=False, index=True)
    interface = Column(String(50), nullable=False, index=True)
    contract_number = Column(String(100), nullable=False, index=True)
    is_main = Column(Boolean, default=False)
    created_at = Column(DateTime, default=now_local)
    __table_args__ = (
Index('idx_onu_contract', 'device_id', 'interface', 'contract_number', unique=True,
mysql_length={'device_id': 10, 'interface': 50, 'contract_number': 50}),
Index('idx_contract_onu', 'contract_number', 'device_id', 'interface'),
{'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
)

class Contract(Base):
    __tablename__ = 'contracts'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    contract_number = Column(String(100), nullable=False, index=True)
    login = Column(String(100))
    ip_address = Column(String(45))
    mac_address = Column(String(50), index=True)
    normalized_mac = Column(String(50), index=True)
    additional_info = Column(Text)
    uploaded_at = Column(DateTime, default=now_local)
    updated_at = Column(DateTime, default=now_local, onupdate=now_local)
    __table_args__ = (
Index('idx_contract_mac', 'contract_number', 'mac_address'),
Index('idx_full_search', 'contract_number', 'mac_address', 'login'),
{'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
)

class ONUState(Base):
    """Исторический снимок состояния ONU при каждом успешном опросе OLT.

    Таблица является источником временных рядов для страницы «Статистика»:
    уровень оптического сигнала, онлайн-статус, причина отключения.
    Одна строка на ONU (device_id+interface) на один цикл опроса.
    """
    __tablename__ = 'onu_state'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    device_id = Column(String(10), nullable=False, index=True)
    interface = Column(String(50), nullable=False, index=True)
    mac = Column(String(50))
    is_online = Column(Boolean, default=False, nullable=False)
    optical_power = Column(Float, nullable=True)
    status = Column(String(20))
    dereg_reason = Column(String(50))
    recorded_at = Column(DateTime, default=now_local, nullable=False, index=True)
    __table_args__ = (
        Index('idx_onu_state_lookup', 'device_id', 'interface', 'recorded_at'),
        Index('idx_onu_state_time', 'recorded_at'),
        {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
    )


class TelegramNotification(Base):
    __tablename__ = 'telegram_notifications'
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(10), nullable=False, index=True)
    interface = Column(String(50), nullable=False, index=True)
    onu_number = Column(Integer, nullable=False)
    status_type = Column(String(20), nullable=False, index=True)
    message_hash = Column(String(64), nullable=False, index=True)
    status_text = Column(Text, nullable=False)
    sent_at = Column(DateTime, default=now_local, index=True)
    is_active = Column(Boolean, default=True, index=True)
    description = Column(Text)
    __table_args__ = (
Index('idx_notification_lookup', 'device_id', 'interface', 'onu_number', 'status_type', 'is_active'),
Index('idx_message_hash', 'message_hash', 'is_active'),
Index('idx_sent_at', 'sent_at'),
{'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
)


def get_optical_status(optical_power):
    if optical_power is None:
        return 'unknown'
    if optical_power > -25:
        return 'good'
    elif optical_power >= -27:
        return 'warning'
    else:
        return 'bad'

_engine = None
_SessionFactory = None
_db_init_lock = threading.Lock()


def _build_connection_string():
    """Строим URL через sqlalchemy.engine.URL — пароль экранируется корректно.

    При DB_TYPE=sqlite возвращает None (engine строится отдельно, см. init_db).
    """
    if MYSQL_CONFIG.get('type') == 'sqlite':
        return None
    from sqlalchemy.engine import URL
    return URL.create(
        drivername='mysql+pymysql',
        username=MYSQL_CONFIG['username'],
        password=str(MYSQL_CONFIG['password']),
        host=MYSQL_CONFIG['host'],
        port=MYSQL_CONFIG['port'],
        database=MYSQL_CONFIG['database'],
        query={'charset': MYSQL_CONFIG['charset']},
    )


def init_db():
    """Инициализирует (или возвращает существующий) единый engine и сессию-фабрику.

    Раньше на каждый вызов get_db_session() создавался новый engine со своим
    пулом соединений, что приводило к утечке соединений MySQL. Теперь engine
    создается один раз (singleton) и переиспользуется.

    DB_TYPE=sqlite используется для разработки и тестов (без MySQL-сервера).
    """
    global _engine, _SessionFactory
    with _db_init_lock:
        if _SessionFactory is not None:
            return _SessionFactory
        try:
            is_sqlite = MYSQL_CONFIG.get('type') == 'sqlite'
            if is_sqlite:
                from sqlalchemy.pool import StaticPool
                _engine = create_engine(
                    f"sqlite:///{MYSQL_CONFIG['sqlite_path']}",
                    echo=MYSQL_CONFIG.get('echo', False),
                    connect_args={'check_same_thread': False},
                    poolclass=StaticPool,  # общая in-memory/файловая БД между потоками
                )
            else:
                _engine = create_engine(
                    _build_connection_string(),
                    echo=MYSQL_CONFIG.get('echo', False),
                    pool_size=MYSQL_CONFIG.get('pool_size', 20),
                    max_overflow=MYSQL_CONFIG.get('max_overflow', 30),
                    pool_recycle=MYSQL_CONFIG.get('pool_recycle', 3600),
                    pool_pre_ping=True,
                )
            if MYSQL_CONFIG.get('alembic_managed', True):
                # Схема управляется Alembic: создаём таблицы только на чистой БД,
                # существующую (legacy/production) схему помечаем точкой head,
                # чтобы не менять её через create_all.
                _ensure_schema_version(_engine)
            else:
                Base.metadata.create_all(_engine)
            _SessionFactory = scoped_session(sessionmaker(
                bind=_engine,
                autocommit=False,
                autoflush=False,
                expire_on_commit=False
            ))
            if is_sqlite:
                logger.info(f"SQLite database initialized at {MYSQL_CONFIG['sqlite_path']} (dev mode)")
            else:
                logger.info(f"MySQL database initialized on {MYSQL_CONFIG['host']}:{MYSQL_CONFIG['port']}/{MYSQL_CONFIG['database']}")
            return _SessionFactory
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise


def run_migrations():
    """Прогоняет Alembic-миграции до head (эквивалент `alembic upgrade head`).

    Предназначена для развёртываний без отдельного CLI-шага. URL подключения
    env.py берёт из config.py — здесь секретов нет. Ошибку пробрасываем:
    молча игнорировать рассинхрон схемы нельзя.
    """
    from alembic.command import upgrade
    from alembic.config import Config as AlembicConfig

    root_dir = os.path.dirname(os.path.abspath(__file__))
    cfg = AlembicConfig(os.path.join(root_dir, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(root_dir, "migrations"))
    upgrade(cfg, "head")
    logger.info("Alembic migrations applied to head")


def _ensure_schema_version(engine):
    """Приводит схему в соответствие с Alembic-head без разрушительных изменений.

    - Чистая БД (нет таблиц) -> выполняем миграции (создаём схемы + alembic_version).
    - Legacy-БД (таблицы есть, alembic_version нет) -> stamp head: фиксируем
      текущее состояние как baseline, данные и структуру не трогаем.
    - Иначе -> ничего не делаем (миграции уже применены или применяются вне).
    """
    from sqlalchemy import inspect as _inspect

    insp = _inspect(engine)
    db_tables = set(insp.get_table_names())
    if "alembic_version" in db_tables:
        return  # схема уже под управлением Alembic
    if not (db_tables - {"alembic_version"}):
        run_migrations()  # чистая БД — полный прогон миграций
    else:
        from alembic.script import ScriptDirectory
        from alembic.config import Config as AlembicConfig
        import os as _os
        root_dir = _os.path.dirname(_os.path.abspath(__file__))
        cfg = AlembicConfig(_os.path.join(root_dir, "alembic.ini"))
        cfg.set_main_option("script_location", _os.path.join(root_dir, "migrations"))
        head = ScriptDirectory.from_config(cfg).get_current_head()
        # alembic.command.stamp создаёт собственное подключение из env.py
        # (URL берётся из того же config.py) и записывает version_num=head.
        from alembic.command import stamp
        stamp(cfg, head, purge=False)
        logger.info(f"Legacy schema detected — stamped alembic_version at {head}")


@contextmanager
def get_db_session():
    """Контекст-менеджер сессии БД поверх ЕДИНОГО пула соединений."""
    Session = init_db()
    session = Session()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"DB error, rolled back: {e}")
        raise
    finally:
        session.close()

def normalize_mac_address(mac):
    if not mac or mac == 'N/A' or mac == '':
        return None
    try:
        mac_str = str(mac).strip()
        if ':' in mac_str:
            parts = mac_str.split(':')
            if len(parts) == 2:
                vendor_part = parts[0].upper()
                mac_part = parts[1].upper()
                vendor_found = None
                for vendor_key, vendor_info in VENDOR_CONFIG.items():
                    if vendor_part == vendor_key:
                        vendor_found = vendor_info
                        break
                if vendor_found:
                    normalized = f"{vendor_found['mac_prefix']}{mac_part.lower()}"
                    return normalized[:50]
                else:
                    clean_mac = re.sub(r'[^a-fA-F0-9]', '', mac_str).lower()
                    if len(clean_mac) == 12:
                        return clean_mac[:50]
                    elif len(clean_mac) > 12:
                        return clean_mac[-12:][:50]
                    elif len(clean_mac) > 0:
                        return clean_mac.zfill(12)[:50]
        clean_mac = re.sub(r'[^a-fA-F0-9]', '', mac_str).lower()
        if not clean_mac:
            return None
        if len(clean_mac) == 12:
            return clean_mac[:50]
        elif len(clean_mac) > 12:
            return clean_mac[-12:][:50]
        elif len(clean_mac) > 0:
            return clean_mac.zfill(12)[:50]
        return None
    except Exception as e:
        logger.error(f"Error normalizing MAC address {mac}: {e}")
        return None

def extract_mac_last_8_chars(mac):
    if not mac:
        return None
    try:
        clean_mac = re.sub(r'[^a-fA-F0-9]', '', str(mac)).lower()
        if len(clean_mac) >= 8:
            return clean_mac[-8:]
        return clean_mac
    except Exception as e:
        logger.error(f"Error extracting last 8 chars from MAC {mac}: {e}")
        return None

def is_hex_query(query):
    if not query:
        return False
    return bool(re.fullmatch(r'[0-9a-fA-F]+', query))

def normalize_search_digits(query):
    if not query:
        return None
    cleaned = re.sub(r'[\s.\-]+', '', str(query)).lower()
    return cleaned or None

def _mac_hex_body(mac_str):
    body = mac_str.split(':', 1)[1] if ':' in mac_str else mac_str
    return re.sub(r'[^0-9a-f]', '', body.lower())

def match_mac_query(onu_mac, query):
    if not onu_mac or not query:
        return None
    mac_str = str(onu_mac).strip().lower()
    q = str(query).strip().lower()


    if q == mac_str:
        return 'full'

    if ':' in mac_str and ':' not in q and q == mac_str.split(':', 1)[1]:
        return 'full'


    if not is_hex_query(q) or len(q) < 4:
        return None

    body = _mac_hex_body(mac_str)
    if body == q:
        return 'full'
    if body.endswith(q) or body.startswith(q) or q in body:
        return 'partial'

    return None


def save_device_status(session, device_id, device_name, data, success=True, error_message=None):
    try:
        status = session.query(DeviceStatus).filter_by(device_id=device_id).first()
        if not status:
            status = DeviceStatus(device_id=device_id, device_name=device_name)
            session.add(status)

        if success:
            status.last_successful_update = now_local()
            status.onu_count = len(data.get('onu_info', []))
            active_count = 0
            signal_count = 0
            for onu in data.get('onu_info', []):
                if onu.get('optical_power') is not None:
                    active_count += 1
                    signal_count += 1
            status.active_onu_count = active_count
            status.inactive_onu_count = status.onu_count - active_count
            status.enriched_onu_count = signal_count
            status.is_online = True
            status.error_message = None
        else:
            status.error_message = error_message
        status.updated_at = now_local()
        session.commit()
    except Exception as e:
        logger.error(f"Error saving device status for {device_name}: {e}")
        session.rollback()
        raise

def save_onu_data(session, device_id, device_name, onu_info):
    try:
        logger.info(f"Processing {len(onu_info)} ONUs for device {device_name}")

        existing_onus = session.query(ONU).filter(ONU.device_id == device_id).all()
        existing_onu_dict = {onu.interface: onu for onu in existing_onus}

        processed_count = 0
        new_onus = []
        moved_onus = []
        configured_interfaces = set()
        desc_sync_list = []

        def deactivate_old_onu(old_onu, new_device_id, new_interface, new_device_name):
            current_location = f"{new_device_id}:{new_interface}"
            if old_onu.moved_to != current_location:
                old_onu.moved_to = current_location
                old_onu.moved_at = now_local()
                old_onu.updated_at = now_local()
                old_onu.is_active = False
                old_onu.status = 'off-line'
                old_onu.dereg_reason = 'Moved to another OLT'
                old_onu.optical_power = None
                create_onu_history(
session, old_onu.id,
old_onu.device_id, old_onu.interface,
old_onu.mac, 'marked_moved',
new_device_id=new_device_id, new_interface=new_interface,
details=f"ONU переехала на {new_device_name}:{new_interface}"
)
                logger.info(f"🟡 Старая ONU {old_onu.device_name}:{old_onu.interface} помечена как уехавшая на {new_device_name}:{new_interface}")

        for onu_data in onu_info:
            try:
                interface = onu_data['interface']
                configured_interfaces.add(interface)
                mac = onu_data.get('mac') or onu_data.get('sn', 'N/A')
                normalized_mac = normalize_mac_address(mac)

                existing_onu_same_mac = None
                moved_from = None
                mark_current_as_moved_to = None
                is_current_active = onu_data.get('optical_power') is not None

                if normalized_mac:
                    existing_onu_same_mac = session.query(ONU).filter(
ONU.normalized_mac == normalized_mac,
ONU.device_id != device_id,
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).order_by(ONU.updated_at.desc()).first()

                    if existing_onu_same_mac:
                        is_existing_active = existing_onu_same_mac.optical_power is not None

                        if is_current_active and not is_existing_active:
                            moved_from = f"{existing_onu_same_mac.device_id}:{existing_onu_same_mac.interface}"
                        elif not is_current_active and is_existing_active:
                            mark_current_as_moved_to = f"{existing_onu_same_mac.device_id}:{existing_onu_same_mac.interface}"
                            moved_from = None
                        elif is_current_active and is_existing_active:
                            moved_from = f"{existing_onu_same_mac.device_id}:{existing_onu_same_mac.interface}"
                        else:
                            moved_from = f"{existing_onu_same_mac.device_id}:{existing_onu_same_mac.interface}"

                if interface in existing_onu_dict:
                    db_onu = existing_onu_dict[interface]

                    db_desc = (db_onu.description or '').strip()
                    dev_desc = (onu_data.get('description') or '').strip()
                    is_db_desc_valid = bool(db_desc) and db_desc != 'N/A' and db_desc != interface
                    is_dev_desc_valid = bool(dev_desc) and dev_desc != 'N/A' and dev_desc != interface


                    if is_dev_desc_valid and is_db_desc_valid and db_desc != dev_desc:
                        logger.info(f"🔄 OLT description changed for {interface}: '{db_desc}' -> '{dev_desc}' (Will update DB)")
                    elif is_db_desc_valid and not is_dev_desc_valid:
                        desc_sync_list.append({
'interface': interface,
'description': db_desc
})
                        logger.info(f"⬆️ Pushing DB description to OLT for {interface}: '{db_desc}'")

                    if mark_current_as_moved_to:
                        db_onu.moved_to = mark_current_as_moved_to
                        db_onu.moved_at = now_local()
                        db_onu.is_active = False
                        db_onu.is_configured = True
                        db_onu.status = 'off-line'
                        db_onu.dereg_reason = 'Moved to another OLT'
                        db_onu.optical_power = None
                        db_onu.updated_at = now_local()
                        create_onu_history(
session, db_onu.id, device_id, interface, db_onu.mac, 'marked_moved',
new_device_id=existing_onu_same_mac.device_id, new_interface=existing_onu_same_mac.interface,
details=f"ONU (ghost config) помечена как уехавшая на {existing_onu_same_mac.device_name}:{existing_onu_same_mac.interface}"
)
                        logger.info(f"🟡 Ghost ONU {device_name}:{interface} помечена как уехавшая на {existing_onu_same_mac.device_name}:{existing_onu_same_mac.interface}")
                        processed_count += 1
                        continue

                    if existing_onu_same_mac and moved_from:
                        deactivate_old_onu(existing_onu_same_mac, device_id, interface, device_name)

                    update_existing_onu(db_onu, onu_data, normalized_mac, moved_from=moved_from)
                    db_onu.is_configured = True
                    processed_count += 1
                else:
                    if mark_current_as_moved_to:
                        new_onu = create_new_onu_safe(
session, device_id, device_name, onu_data, normalized_mac,
moved_from=None
)
                        if new_onu:
                            new_onu.moved_to = mark_current_as_moved_to
                            new_onu.moved_at = now_local()
                            new_onu.is_active = False
                            new_onu.status = 'off-line'
                            new_onu.dereg_reason = 'Moved to another OLT'
                            new_onu.optical_power = None
                            create_onu_history(
session, new_onu.id, device_id, interface, new_onu.mac, 'marked_moved',
new_device_id=existing_onu_same_mac.device_id, new_interface=existing_onu_same_mac.interface,
details=f"ONU (ghost config) помечена как уехавшая на {existing_onu_same_mac.device_name}:{existing_onu_same_mac.interface}"
)
                        new_onus.append({'device': device_name, 'interface': interface, 'mac': mac})
                        processed_count += 1
                        continue

                    if existing_onu_same_mac and moved_from:
                        logger.info(f"ONU moved: {existing_onu_same_mac.device_name}:{existing_onu_same_mac.interface} -> {device_name}:{interface}")
                        deactivate_old_onu(existing_onu_same_mac, device_id, interface, device_name)
                        moved_onus.append({
'old_device': existing_onu_same_mac.device_name,
'new_device': device_name,
'mac': normalized_mac,
'old_interface': existing_onu_same_mac.interface,
'new_interface': interface
})
                        new_onu = create_new_onu_safe(
session, device_id, device_name, onu_data, normalized_mac,
moved_from=moved_from
)
                        if moved_from and new_onu and existing_onu_same_mac:
                            create_onu_history(
session, new_onu.id, device_id, interface, new_onu.mac, 'moved_to',
old_device_id=existing_onu_same_mac.device_id,
old_interface=existing_onu_same_mac.interface,
details=f"ONU переехала с {existing_onu_same_mac.device_name}:{existing_onu_same_mac.interface}"
)
                    else:
                        new_onu = create_new_onu_safe(session, device_id, device_name, onu_data, normalized_mac)
                        if new_onu:
                            new_onus.append({'device': device_name, 'interface': interface, 'mac': mac})
                    processed_count += 1
            except Exception as e:
                logger.error(f"Error processing ONU {device_name}:{onu_data.get('interface', 'unknown')}: {e}")
                continue

        for interface, onu in existing_onu_dict.items():
            if interface not in configured_interfaces and onu.is_configured:
                onu.is_active = False
                onu.is_configured = False
                onu.status = 'off-line'
                onu.dereg_reason = 'Removed from OLT'
                onu.optical_power = None
                onu.is_enriched = False
                onu.updated_at = now_local()
                create_onu_history(
session, onu.id, device_id, interface, onu.mac, 'unconfigured',
details=f"ONU удалена из конфигурации OLT {device_name} (не найдена в выводе)"
)

        # Временной ряд для страницы «Статистика»: снимок состояния каждой ONU
        # на текущий цикл опроса (сигнал, онлайн/офлайн, причина отключения).
        record_onu_state_samples(session, device_id, onu_info)

        session.commit()

        if new_onus:
            logger.info(f"New ONUs found on {device_name}: {len(new_onus)}")
        if moved_onus:
            logger.info(f"ONUs moved to {device_name}: {len(moved_onus)}")

        remaining_on_old = session.query(func.count(ONU.id)).filter(
ONU.device_id == device_id, ONU.is_configured.is_(True),
ONU.is_active.is_(True), ONU.moved_to.isnot(None)
).scalar() or 0

        if remaining_on_old > 0:
            logger.info(f"⚠️ {remaining_on_old} ONU on {device_name} are marked as moved but still configured on OLT")

        logger.info(f"Successfully processed {processed_count}/{len(onu_info)} ONU records for {device_name}")

        if processed_count > 0:
            update_mac_addresses_simple(session, device_id, device_name, onu_info)

        return {
'processed': processed_count, 'new': len(new_onus),
'moved': len(moved_onus), 'remaining_on_old': remaining_on_old,
'desc_sync': desc_sync_list
}

    except Exception as e:
        logger.error(f"Error saving ONU data for {device_name}: {e}")
        session.rollback()
        raise

def create_onu_history(session, onu_id, device_id, interface, mac, action,
old_device_id=None, new_device_id=None,
old_interface=None, new_interface=None, details=None):
    try:
        history = ONUHistory(
device_id=device_id, interface=interface, mac=mac, action=action,
old_device_id=old_device_id, new_device_id=new_device_id,
old_interface=old_interface, new_interface=new_interface,
details=details, created_at=now_local()
)
        session.add(history)
    except Exception as e:
        logger.error(f"Error creating ONU history: {e}")


# ===================== Временные ряды (страница «Статистика») =====================

SIGNAL_BINS = [
    # (метка, нижняя граница включительно или None, верхняя граница не включительно)
    ('до -20', None, -20.0),
    ('-20…-24', -20.0, -25.0),
    ('-25…-27', -25.0, -27.0),
    ('от -27', -27.0, None),
]


def _signal_bin_label(power):
    """Определяет диапазон сигнала для гистограммы (по порогам get_optical_status)."""
    if power is None:
        return None
    for label, lo, hi in SIGNAL_BINS:
        if lo is not None and power < lo:
            continue
        if hi is not None and power >= hi:
            continue
        return label
    return 'от -27'


def record_onu_state_samples(session, device_id, onu_info):
    """Пишет снимки состояния ONU в onu_state (временной ряд для статистики).

    Вызывается из save_onu_data после обработки всего списка ONU одного
    устройства. Ошибку записи ряда считаем некритичной: мониторинг текущего
    состояния не должен падать из-за истории.
    """
    try:
        ts = now_local()
        rows = []
        seen = set()
        for onu_data in onu_info:
            interface = onu_data.get('interface')
            if not interface or interface in seen:
                continue
            seen.add(interface)
            power = onu_data.get('optical_power')
            rows.append(ONUState(
                device_id=device_id,
                interface=interface,
                mac=(onu_data.get('mac') or '')[:50],
                is_online=power is not None,
                optical_power=power,
                status=(onu_data.get('status') or 'N/A')[:20],
                dereg_reason=(onu_data.get('dereg_reason') or 'N/A')[:50],
                recorded_at=ts,
            ))
        if rows:
            session.bulk_save_objects(rows)
    except Exception as e:
        logger.error(f"Error recording ONU state samples for {device_id}: {e}")


def get_signal_trend_series(session, device_id=None, days=7, max_onus=8):
    """Временной ряд среднего/минимального уровня сигнала по устройствам.

    Возвращает series: [{name, points: [[ts_iso, avg], ...]}, ...] — по одному
    ряду на OLT (или один общий ряд при device_id) + ряд худшего сигнала.
    Группировка по часам выполняется на Python (диалект-независимо).
    """
    try:
        since = now_local() - datetime.timedelta(days=days)
        rows = session.query(
            ONUState.device_id, ONUState.recorded_at,
            ONUState.optical_power
        ).filter(ONUState.recorded_at >= since, ONUState.optical_power.isnot(None)) \
         .order_by(ONUState.device_id, ONUState.recorded_at).limit(200000).all()

        by_device = {}   # did -> bucket -> [sum, n, min]
        worst = {}       # bucket -> min
        for did, ts, power in rows:
            if ts is None or power is None:
                continue
            bucket = ts.strftime('%Y-%m-%d %H:00')
            acc = by_device.setdefault(did, {}).setdefault(bucket, [0.0, 0, float('inf')])
            acc[0] += float(power)
            acc[1] += 1
            acc[2] = min(acc[2], float(power))
            prev = worst.get(bucket)
            if prev is None or float(power) < prev:
                worst[bucket] = round(float(power), 2)

        series = []
        for did in sorted(by_device)[:max_onus]:
            pts = [[b, round(v[0] / v[1], 2)] for b, v in sorted(by_device[did].items())]
            series.append({'name': f'{get_device_name_by_id(did)} (средний)', 'points': pts})
        if len(by_device) > 1 and worst:
            series.append({'name': 'Худший сигнал в сети (min)',
                           'points': [[b, worst[b]] for b in sorted(worst)]})
        return {'series': series, 'days': days}
    except Exception as e:
        logger.error(f"Error building signal trend series: {e}", exc_info=True)
        return {'series': [], 'days': days, 'error': INTERNAL_ERROR_MSG}


def get_availability_stats(session, days=7):
    """Аптайм по каждому устройству и суммарно за период (по снимкам onu_state).

    Точка данных = успешный опрос OLT; online_ratio = доля снимков с сигналом.
    """
    try:
        since = now_local() - datetime.timedelta(days=days)
        rows = session.query(
            ONUState.device_id,
            func.count(ONUState.id),
            func.sum(case((ONUState.is_online.is_(True), 1), else_=0)),
        ).filter(ONUState.recorded_at >= since).group_by(ONUState.device_id).all()

        devices = []
        tot_samples = tot_online = 0
        for did, total, online in rows:
            total = int(total or 0)
            online = int(online or 0)
            tot_samples += total
            tot_online += online
            devices.append({
                'device_id': did,
                'device': get_device_name_by_id(did),
                'samples': total,
                'online_samples': online,
                'uptime_pct': round(online / total * 100, 2) if total else None,
            })
        devices.sort(key=lambda d: (d['uptime_pct'] is None, d['uptime_pct']))
        return {
            'days': days,
            'devices': devices,
            'overall_uptime_pct': round(tot_online / tot_samples * 100, 2) if tot_samples else None,
            'total_samples': tot_samples,
        }
    except Exception as e:
        logger.error(f"Error computing availability stats: {e}", exc_info=True)
        return {'days': days, 'devices': [], 'overall_uptime_pct': None, 'total_samples': 0,
                'error': INTERNAL_ERROR_MSG}


def get_daily_availability(session, days=14):
    """Ежедневный аптайм сети (%) и количество онлайн-ONU по дням.

    Группировка по датам выполняется на Python — диалект-независимо
    (MySQL/SQLite), по аналогии с get_signal_trend_series.
    """
    try:
        since = (now_local() - datetime.timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
        rows = session.query(
            ONUState.recorded_at, ONUState.is_online
        ).filter(ONUState.recorded_at >= since).limit(500000).all()

        by_day = {}  # day -> [total, online]
        for ts, online in rows:
            if ts is None:
                continue
            day = ts.strftime('%Y-%m-%d')
            acc = by_day.setdefault(day, [0, 0])
            acc[0] += 1
            if online:
                acc[1] += 1

        labels, uptimes, online_counts = [], [], []
        for day in sorted(by_day):
            total, online = by_day[day]
            labels.append(day)
            uptimes.append(round(online / total * 100, 2) if total else None)
            online_counts.append(online)
        return {'labels': labels, 'uptime': uptimes, 'online': online_counts}
    except Exception as e:
        logger.error(f"Error computing daily availability: {e}", exc_info=True)
        return {'labels': [], 'uptime': [], 'online': [], 'error': INTERNAL_ERROR_MSG}


def get_outage_events(session, days=7, limit=300):
    """Последние события изменений состояния ONU (из onu_history).

    ДЕЙСТВУЮЩИЕ обрывы: последняя запись по ONU — down/unconfigured/marked_moved.
    ЗАКРЫТЫЕ: down-событие, после которого есть up-событие (считается длительность).
    """
    try:
        since = now_local() - datetime.timedelta(days=days)
        ev_down = ('down', 'unconfigured', 'marked_moved')
        ev_up = ('up', 'created', 'moved_to', 'restored')

        rows = session.query(
            ONUHistory.device_id, ONUHistory.interface, ONUHistory.action,
            ONUHistory.details, ONUHistory.created_at,
        ).filter(ONUHistory.created_at >= since).order_by(
            ONUHistory.device_id, ONUHistory.interface, ONUHistory.created_at
        ).limit(100000).all()

        last_action = {}
        open_pairs = set()
        events = []
        for did, iface, action, details, created in rows:
            key = (did, iface)
            prev_action, prev_time = last_action.get(key, (None, None))
            if action in ev_down and prev_action not in ev_down:
                # начало нового интервала недоступности (up -> down)
                open_pairs.add(key)
            elif action in ev_up and key in open_pairs:
                # конец интервала: считаем длительность обрыва
                open_pairs.discard(key)
                events.append({
                    'device_id': did, 'device': get_device_name_by_id(did),
                    'interface': iface,
                    'started_at': prev_time.strftime('%Y-%m-%d %H:%M') if prev_time else None,
                    'ended_at': created.strftime('%Y-%m-%d %H:%M') if created else None,
                    'duration_min': int((created - prev_time).total_seconds() // 60) if (prev_time and created) else None,
                    'state': 'closed', 'details': details, 'action': action,
                })
            last_action[key] = (action, created)

        now_ts = now_local()
        open_events = []
        for (did, iface), (action, created) in last_action.items():
            if (did, iface) in open_pairs:
                open_events.append({
                    'device_id': did, 'device': get_device_name_by_id(did),
                    'interface': iface,
                    'started_at': created.strftime('%Y-%m-%d %H:%M') if created else None,
                    'ended_at': None,
                    'duration_min': int((now_ts - created).total_seconds() // 60) if created else None,
                    'state': 'open', 'details': None, 'action': action,
                })

        all_events = open_events + events
        all_events.sort(key=lambda ev: ev['started_at'] or '', reverse=True)
        return {'events': all_events[:limit],
                'open_count': len(open_events),
                'closed_count': len(events),
                'days': days}
    except Exception as e:
        logger.error(f"Error computing outage events: {e}", exc_info=True)
        return {'events': [], 'open_count': 0, 'closed_count': 0, 'days': days,
                'error': INTERNAL_ERROR_MSG}


def get_degraded_onus(session, delta_threshold=3.0, days=7, min_current=-24.0, limit=200):
    """ONU с признаками деградации сигнала.

    Сигнал «упал» более чем на delta_threshold dB по сравнению с первым
    замером окна и при этом текущий уровень хуже min_current — кандидат на
    профилактику (грязная муфта, перегиб провода, старый передатчик).
    """
    try:
        since = now_local() - datetime.timedelta(days=days)

        # Первый и последний замер сигнала каждой ONU за окно — группировка на
        # Python (диалект-независимо), как в get_signal_trend_series.
        rows = session.query(
            ONUState.device_id, ONUState.interface,
            ONUState.recorded_at, ONUState.optical_power
        ).filter(ONUState.recorded_at >= since, ONUState.optical_power.isnot(None)) \
         .order_by(ONUState.device_id, ONUState.interface, ONUState.recorded_at) \
         .limit(500000).all()

        first_map, last_map = {}, {}
        for did, iface, ts, power in rows:
            key = (did, iface)
            if key not in first_map and power is not None:
                first_map[key] = float(power)
            if power is not None:
                last_map[key] = float(power)

        cur = session.query(ONU).filter(
            ONU.optical_power.isnot(None), ONU.is_configured.is_(True)
        ).all()

        # Единый стандарт строк ONU (договор из справочника привязок +
        # логин/IP клиента), к которому добавляются поля временного ряда.
        base_rows = _standardized_onu_rows(session, cur)
        power_by_key = {(o.device_id, o.interface): o.optical_power for o in cur}

        results = []
        for row in base_rows:
            key = (row['device_id'], row['interface'])
            power = power_by_key.get(key)
            first_power = first_map.get(key)
            if first_power is None or power is None:
                continue
            delta = float(first_power) - float(power)  # > 0 => сигнал ухудшился
            if delta >= delta_threshold and float(power) <= min_current:
                row['current_power'] = round(float(power), 2)
                row['first_power'] = round(float(first_power), 2)
                row['delta_db'] = round(delta, 2)
                row['optical_status'] = get_optical_status(power)
                results.append(row)
        results.sort(key=lambda r: r['delta_db'], reverse=True)
        return {'onus': results[:limit], 'total_count': len(results),
                'threshold_db': delta_threshold, 'days': days}
    except Exception as e:
        logger.error(f"Error computing degraded ONUs: {e}", exc_info=True)
        return {'onus': [], 'total_count': 0, 'days': days, 'error': INTERNAL_ERROR_MSG}


def get_signal_histogram(session, device_id=None):
    """Распределение уровней сигнала активных ONU по диапазонам (бинам)."""
    try:
        base = [(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))]
        if device_id:
            base.insert(0, ONU.device_id == device_id)
        good = session.query(func.count(ONU.id)).filter(*base, ONU.optical_power > -25).scalar() or 0
        warn = session.query(func.count(ONU.id)).filter(*base, ONU.optical_power <= -25,
                                                        ONU.optical_power >= -27).scalar() or 0
        bad = session.query(func.count(ONU.id)).filter(*base, ONU.optical_power < -27).scalar() or 0
        off = session.query(func.count(ONU.id)).filter(*base, ONU.optical_power.is_(None)).scalar() or 0
        return {'good': good, 'warning': warn, 'bad': bad, 'offline': off}
    except Exception as e:
        logger.error(f"Error computing signal histogram: {e}", exc_info=True)
        return {'good': 0, 'warning': 0, 'bad': 0, 'offline': 0, 'error': INTERNAL_ERROR_MSG}


def get_onu_state_history(session, device_id, interface, days=30, limit=5000):
    """Ряд состояния одной ONU (для графика на странице детали ONU)."""
    try:
        since = now_local() - datetime.timedelta(days=days)
        rows = session.query(
            ONUState.recorded_at, ONUState.optical_power, ONUState.is_online,
            ONUState.status, ONUState.dereg_reason
        ).filter(ONUState.device_id == device_id, ONUState.interface == interface,
                 ONUState.recorded_at >= since).order_by(ONUState.recorded_at).limit(limit).all()
        return {
            'points': [{
                'time': r[0].strftime('%Y-%m-%d %H:%M'),
                'power': r[1], 'is_online': bool(r[2]),
                'status': r[3], 'dereg_reason': r[4],
            } for r in rows],
            'device_id': device_id, 'interface': interface, 'days': days,
        }
    except Exception as e:
        logger.error(f"Error getting ONU state history: {e}", exc_info=True)
        return {'points': [], 'error': INTERNAL_ERROR_MSG}


def get_top_worst_onus(session, limit=15):
    """Таблица худших по сигналу активных ONU (для страницы статистики)."""
    try:
        onus = session.query(ONU).filter(
            ONU.optical_power.isnot(None),
            (ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
        ).order_by(ONU.optical_power.asc()).limit(limit).all()
        cmap = get_contracts_map_for_onus(session, [(o.device_id, o.interface) for o in onus])
        out = []
        for o in onus:
            out.append(_onu_row_dict(o, cmap))
        return {'onus': out}
    except Exception as e:
        logger.error(f"Error getting worst ONUs: {e}", exc_info=True)
        return {'onus': [], 'error': INTERNAL_ERROR_MSG}


def get_history_actions_summary(session, days=30):
    """Количество событий onu_history по типам действий за период."""
    try:
        since = now_local() - datetime.timedelta(days=days)
        rows = session.query(ONUHistory.action, func.count(ONUHistory.id)) \
            .filter(ONUHistory.created_at >= since) \
            .group_by(ONUHistory.action).all()
        return {'actions': [{'action': a, 'count': int(c)} for a, c in rows], 'days': days}
    except Exception as e:
        logger.error(f"Error summarizing history actions: {e}", exc_info=True)
        return {'actions': [], 'days': days, 'error': INTERNAL_ERROR_MSG}


def _onu_row_dict(onu, contracts_map=None):
    """Единый формат строки ONU для всех списков/выпадающих панелей UI.

    Обязательные поля: device_id, device, interface, mac, description, status,
    dereg_reason, optical_power, optical_status, contract (+login/ip из
    справочника договоров), vendor/model, client_macs_count, флаги МКД/переезда,
    last_seen. Все списки ONU в приложении строятся через эту функцию, чтобы
    везде выводилась одинаковая полная информация о клиенте.
    """
    key = (onu.device_id, onu.interface)
    contract = None
    if contracts_map:
        contract = contracts_map.get(key)
    if not contract:
        contract = onu.contract if onu.contract and onu.contract != 'N/A' else None
    moved_to_device_id, moved_to_iface, moved_to_device_name = parse_moved_location(onu.moved_to)
    moved_from_device_id, moved_from_iface, moved_from_device_name = parse_moved_location(onu.moved_from)
    return {
        'device_id': onu.device_id,
        'device': onu.device_name,
        'interface': onu.interface,
        'mac': onu.mac,
        'description': onu.description if onu.description and onu.description != 'N/A' else None,
        'contract': contract,
        'status': onu.status,
        'dereg_reason': onu.dereg_reason,
        'optical_power': onu.optical_power,
        'optical_status': get_optical_status(onu.optical_power),
        'vendor': onu.vendor, 'model': onu.model,
        'client_macs_count': onu.client_macs_count,
        'is_active': onu.is_active, 'is_configured': onu.is_configured,
        'is_mcd': is_mcd(onu.description),
        'is_moved': onu.moved_to is not None or onu.moved_from is not None,
        'is_moved_to': onu.moved_to is not None,
        'is_moved_from': onu.moved_from is not None,
        'moved_to': onu.moved_to, 'moved_from': onu.moved_from,
        'moved_at': onu.moved_at.strftime('%Y-%m-%d %H:%M:%S') if onu.moved_at else None,
        'moved_to_device_id': moved_to_device_id,
        'moved_to_device_name': moved_to_device_name,
        'moved_to_interface': moved_to_iface,
        'moved_from_device_id': moved_from_device_id,
        'moved_from_device_name': moved_from_device_name,
        'moved_from_interface': moved_from_iface,
        'last_seen': onu.last_seen.strftime('%Y-%m-%d %H:%M:%S') if onu.last_seen else None,
    }


def enrich_rows_with_contract_details(session, rows):
    """Дополняет строки ONU данными договора (логин/IP/доп.инфо) из справочника contracts.

    Номера договоров собираются из поля 'contract' И из 'extra_contracts'
    (список всех привязок), чтобы логин/IP были доступны для каждой привязки
    на странице детали ONU и в экспорте.
    """
    numbers = set()
    for r in rows:
        if r.get('contract'):
            for part in str(r['contract']).split(','):
                p = part.strip()
                if p:
                    numbers.add(p)
        for ec in (r.get('extra_contracts') or []):
            if ec:
                numbers.add(str(ec).strip())
    numbers.discard('')
    if not numbers:
        return rows
    info = {}
    try:
        crows = session.query(Contract.contract_number, Contract.login,
                              Contract.ip_address, Contract.additional_info) \
            .filter(Contract.contract_number.in_(list(numbers))).distinct().limit(5000).all()
        for cn, login, ip, addinfo in crows:
            if cn and cn not in info:
                info[cn] = {'login': login, 'ip': ip, 'additional_info': addinfo}
    except Exception as e:
        logger.error(f"Error enriching contract details: {e}")
    for r in rows:
        cn = str(r['contract']).split(',')[0].strip() if r.get('contract') else None
        d = info.get(cn) if cn else None
        r['contract_login'] = (d or {}).get('login')
        r['contract_ip'] = (d or {}).get('ip')
        # Полный набор данных по каждой привязке (для детали ONU и экспорта):
        # номер -> {login, ip, additional_info}
        all_numbers = []
        if cn:
            all_numbers.append(cn)
        if r.get('contract'):
            for part in str(r['contract']).split(','):
                p = part.strip()
                if p and p not in all_numbers:
                    all_numbers.append(p)
        for ec in (r.get('extra_contracts') or []):
            if ec and ec not in all_numbers:
                all_numbers.append(ec)
        r['contracts_details'] = {
            num: info[num] for num in all_numbers if num in info
        }
    return rows


def create_new_onu_safe(session, device_id, device_name, onu_data, normalized_mac=None, moved_from=None):
    try:
        mac_address = onu_data.get('mac') or onu_data.get('sn', 'N/A')
        optical_power = onu_data.get('optical_power')
        onu = ONU(
device_id=device_id, device_name=device_name,
interface=onu_data['interface'],
vendor=onu_data.get('vendor', 'N/A'),
model=onu_data.get('model', 'N/A'),
mac=mac_address, normalized_mac=normalized_mac,
description=onu_data.get('description', 'N/A'),
contract=None, bind_type=onu_data.get('bind_type', 'N/A'),
status=onu_data.get('status', 'N/A'),
dereg_reason=onu_data.get('dereg_reason', 'N/A'),
optical_power=optical_power,
client_macs_count=len(onu_data.get('client_macs', [])),
is_enriched=optical_power is not None,
is_active=True, is_configured=True,
moved_from=moved_from, moved_to=None,
last_seen=now_local(),
created_at=now_local(),
updated_at=now_local()
)
        if moved_from:
            onu.moved_at = now_local()
        session.add(onu)
        session.flush()

        details = f"ONU создана на {device_name}"
        if moved_from:
            old_device_id_part, old_interface = moved_from.split(':', 1)
            old_device = session.query(DeviceStatus).filter_by(device_id=old_device_id_part).first()
            old_device_name = old_device.device_name if old_device else old_device_id_part
            details = f"ONU переехала с {old_device_name}:{old_interface} на {device_name}:{onu_data['interface']}"

        create_onu_history(
session, onu.id, device_id, onu.interface, onu.mac,
'created' if not moved_from else 'moved_to', details=details
)
        return onu
    except Exception as e:
        if "Duplicate entry" in str(e) or "1062" in str(e):
            session.rollback()
            existing_onu = session.query(ONU).filter_by(
device_id=device_id, interface=onu_data['interface']
).first()
            if existing_onu:
                update_existing_onu(existing_onu, onu_data, normalized_mac, moved_from=None)
                return existing_onu
        else:
            raise

def update_existing_onu(onu, onu_data, normalized_mac=None, moved_from=None):
    if onu_data.get('vendor') and onu_data['vendor'] != 'N/A':
        onu.vendor = onu_data['vendor']
    if onu_data.get('model') and onu_data['model'] != 'N/A':
        onu.model = onu_data['model']

    mac_address = onu_data.get('mac') or onu_data.get('sn', 'N/A')
    if mac_address and mac_address != 'N/A':
        onu.mac = mac_address
    if normalized_mac:
        onu.normalized_mac = normalized_mac


    new_description = onu_data.get('description', 'N/A')
    if new_description and new_description != 'N/A' and new_description != onu.interface:
        current_desc = (onu.description or '').strip()
        if current_desc != new_description:
            onu.description = new_description
            logger.info(f"✅ DB description updated for {onu.interface}: '{current_desc}' -> '{new_description}'")
    elif (not new_description or new_description == 'N/A' or new_description == onu.interface):
        pass

    if onu_data.get('bind_type') and onu_data['bind_type'] != 'N/A':
        onu.bind_type = onu_data['bind_type']

    optical_power = onu_data.get('optical_power')
    onu.optical_power = optical_power

    if optical_power is not None:
        onu.status = 'active'
        onu.dereg_reason = 'N/A'
        onu.is_enriched = True
        onu.last_seen = now_local()
    else:
        new_status = onu_data.get('status')
        if new_status and new_status != 'N/A':
            onu.status = new_status
        new_reason = onu_data.get('dereg_reason')
        if new_reason and new_reason != 'N/A':
            onu.dereg_reason = new_reason
        onu.is_enriched = False

    insp = sa_inspect(onu)
    history_attr = insp.attrs.optical_power
    old_optical_power = history_attr.history[0][0] if history_attr.history[0] else None
    if old_optical_power is not None:
        onu.last_seen = now_local()


    if moved_from:
        if onu.moved_from != moved_from:
            onu.moved_from = moved_from
            onu.moved_at = now_local()
            logger.info(f"✅ ONU {onu.device_name}:{onu.interface} marked as moved_from={moved_from} (приехала с другого ОЛТ)")
        onu.moved_to = None
    else:

        if onu.moved_from:
            old_moved_from = onu.moved_from
            onu.moved_from = None
            onu.moved_at = None
            logger.info(f"✅ Очищен moved_from у {onu.device_name}:{onu.interface} (была привязка к {old_moved_from})")

    onu.client_macs_count = len(onu_data.get('client_macs', []))
    onu.updated_at = now_local()
    onu.is_active = True
    onu.is_configured = True

def update_mac_addresses_simple(session, device_id, device_name, onu_info):
    try:
        logger.info(f"Updating MAC addresses for {device_name}")
        interfaces = [f"{device_id}:{o['interface']}" for o in onu_info]
        if interfaces:
            bulk_delete_query(session.query(ONUClientMAC).filter(
ONUClientMAC.onu_interface.in_(interfaces)
))

        new_macs = []
        seen = set()
        for onu_data in onu_info:
            full_iface = f"{device_id}:{onu_data['interface']}"
            for mac_data in onu_data.get('client_macs', []):
                mac_address = mac_data.get('mac_address')
                if not mac_address:
                    continue
                normalized = normalize_mac_address(mac_address)
                if not normalized or normalized in seen:
                    continue
                seen.add(normalized)
                new_macs.append(ONUClientMAC(
onu_interface=full_iface,
vlan=mac_data.get('vlan', '1'),
mac_address=mac_address,
normalized_mac=normalized,
type=mac_data.get('type', 'DYNAMIC'),
port=mac_data.get('port', onu_data['interface']),
))

        if new_macs:
            session.bulk_save_objects(new_macs)
            session.commit()
            logger.info(f"Successfully updated MAC addresses for {device_name}: {len(new_macs)} MACs")
    except Exception as e:
        logger.error(f"Error updating MAC addresses for {device_name}: {e}")
        session.rollback()
        raise


def delete_onu_safely(session, onu_id, reason="Manual deletion"):
    try:
        onu = session.query(ONU).filter_by(id=onu_id).first()
        if not onu:
            return {'success': False, 'message': 'ONU не найдена'}

        device_name = onu.device_name
        interface = onu.interface
        mac = onu.mac
        device_id = onu.device_id

        create_onu_history(
session, onu_id, device_id, interface, mac, 'deleted',
details=f"ONU удалена: {reason}"
)

        full_interface = f"{device_id}:{interface}"
        deleted_macs = bulk_delete_query(session.query(ONUClientMAC).filter_by(
onu_interface=full_interface
))
        deleted_contracts = bulk_delete_query(session.query(ONUContract).filter_by(
device_id=device_id, interface=interface
))


        bulk_delete_query(session.query(ONU).filter_by(id=onu_id))
        session.commit()

        logger.info(f"✅ Safely deleted ONU {device_name}:{interface} (MAC: {mac}). "
f"Removed: {deleted_macs} MACs, {deleted_contracts} contracts. Reason: {reason}")

        return {
'success': True,
'message': f'ONU {device_name}:{interface} успешно удалена',
'deleted_macs': deleted_macs,
'deleted_contracts': deleted_contracts,
'reason': reason
}
    except Exception as e:
        logger.error(f"Error during safe deletion of ONU {onu_id}: {e}", exc_info=True)
        session.rollback()
        # Клиенту — generic; подробности (пути/Драйвер-интерналс) только в логе.
        return {'success': False, 'message': 'Ошибка удаления ONU. Подробности в логах сервера.'}

def cleanup_moved_onus(session, device_id, interface):
    try:


        onu = session.query(ONU).filter_by(device_id=device_id, interface=interface).first()
        if not onu:
            return {'success': False, 'message': 'ONU не найдена в базе данных'}

        if not onu.moved_to:
            return {'success': False, 'message': 'Эта ONU не помечена как переехавшая с этого ОЛТ'}

        moved_to = onu.moved_to
        moved_to_device_id, moved_to_iface, moved_to_device_name = parse_moved_location(moved_to)


        if moved_to_device_id and moved_to_iface:
            new_onu = session.query(ONU).filter_by(
device_id=moved_to_device_id, interface=moved_to_iface
).first()
            if new_onu:
                if new_onu.moved_from:
                    logger.info(f"✅ Очищен moved_from у новой ONU {moved_to_device_name}:{moved_to_iface} "
f"(была привязка к {device_id}:{interface})")
                new_onu.moved_from = None
                new_onu.moved_at = None
                new_onu.updated_at = now_local()
            else:
                logger.warning(f"⚠️ Новая ONU {moved_to_device_name}:{moved_to_iface} не найдена в БД")


        onu.is_configured = False
        onu.is_active = False
        onu.moved_to = None
        onu.moved_at = None
        onu.updated_at = now_local()

        create_onu_history(
session, onu.id, device_id, interface, onu.mac, 'deleted',
details=f"ONU удалена со старого OLT после переезда на {moved_to_device_name}:{moved_to_iface}"
)
        session.commit()

        logger.info(f"✅ ONU {device_id}:{interface} удалена со старого OLT, "
f"статус переезда очищен у обеих ONU")

        return {
'success': True,
'message': 'ONU удалена со старого OLT, статус переезда очищен',
'moved_to': f"{moved_to_device_name}:{moved_to_iface}"
}
    except Exception as e:
        logger.error(f"Error cleaning up moved ONU: {e}", exc_info=True)
        session.rollback()
        return {'success': False, 'message': 'Ошибка очистки статуса переезда. Подробности в логах сервера.'}


def delete_device_completely(session, device_id):
    try:
        device_id = str(device_id)
        stats = {}


        restored = []
        arrived_onus = session.query(ONU).filter(
ONU.device_id == device_id,
ONU.moved_from.isnot(None)
).all()
        for onu in arrived_onus:
            src_dev_id, _, _ = parse_moved_location(onu.moved_from)
            if not src_dev_id or str(src_dev_id) == device_id:
                continue


            onu.moved_from = None
            onu.moved_at = None
            onu.updated_at = now_local()
            restored.append(f"{onu.device_name}:{onu.interface} (была с {src_dev_id})")
        stats['restored_onus'] = restored


        session.flush()


        onus = session.query(ONU).filter(ONU.device_id == device_id).all()
        stats['onus'] = len(onus)


        deleted_history = bulk_delete_query(session.query(ONUHistory).filter(
(ONUHistory.device_id == device_id) |
(ONUHistory.old_device_id == device_id) |
(ONUHistory.new_device_id == device_id)
))
        stats['history'] = deleted_history


        deleted_notifications = bulk_delete_query(session.query(TelegramNotification).filter(
TelegramNotification.device_id == device_id
))
        stats['notifications'] = deleted_notifications


        deleted_contract_links = bulk_delete_query(session.query(ONUContract).filter(
ONUContract.device_id == device_id
))
        stats['onu_contracts'] = deleted_contract_links


        deleted_client_macs = bulk_delete_query(session.query(ONUClientMAC).filter(
ONUClientMAC.onu_interface.like(f"{device_id}:%")
))
        stats['client_macs'] = deleted_client_macs


        deleted_onus = bulk_delete_query(session.query(ONU).filter(
ONU.device_id == device_id
))
        stats['deleted_onus'] = deleted_onus


        deleted_status = bulk_delete_query(session.query(DeviceStatus).filter(
DeviceStatus.device_id == device_id
))
        stats['device_status'] = deleted_status


        dangling_to = session.query(ONU).filter(
ONU.device_id != device_id,
ONU.moved_to.like(f"{device_id}:%")
).all()
        for o in dangling_to:
            o.moved_to = None
            o.moved_at = None
            o.updated_at = now_local()
        dangling_from = session.query(ONU).filter(
ONU.device_id != device_id,
ONU.moved_from.like(f"{device_id}:%")
).all()
        for o in dangling_from:
            o.moved_from = None
            o.moved_at = None
            o.updated_at = now_local()
        session.flush()
        stats['cleaned_dangling'] = len(dangling_to) + len(dangling_from)

        session.commit()

        logger.info(
f"✅ Устройство {device_id} полностью удалено из БД: "
f"ONU={deleted_onus}, история={deleted_history}, MAC={deleted_client_macs}, "
f"договоры={deleted_contract_links}, уведомления={deleted_notifications}, "
f"возвращено переездов={len(restored)}"
)
        return {'success': True, 'stats': stats}
    except Exception as e:
        logger.error(f"Ошибка при полном удалении устройства {device_id}: {e}")
        session.rollback()
        raise


def get_cached_device_data(session, device_id, cache_timeout=3600):
    """Возвращает сохранённые данные устройства из БД.

    Возвращает None, если свежие данные не найдены — вызывающий код обязан
    выполнить live-опрос устройства. Порог свежести задаёт конфигурация
    UPDATE_CONFIG['device_cache_timeout'] (env DEVICE_CACHE_TIMEOUT), а не
    жёсткая единица часа: раньше здесь был независимый дефолт 3600s, из-за
    чего настройки кэша рассогласовывались между app.py и database.py.
    """
    try:
        status = session.query(DeviceStatus).filter_by(device_id=device_id).first()
        if not status:
            return None

        # Если статус обновлялся слишком давно, считаем данные несвежими и
        # заставляем живой опрос (даже для онлайн-устройства).
        if status.updated_at:
            age = (now_local() - status.updated_at).total_seconds()
            if age >= cache_timeout:
                logger.info(
                    f"Cached data for {device_id} is too old ({age:.0f}s >= "
                    f"{cache_timeout}s); forcing live refresh."
                )
                return None

        if status.last_successful_update:
            cache_age = (now_local() - status.last_successful_update).total_seconds()
            if cache_age >= cache_timeout and not status.is_online:
                logger.warning(f"Data for {device_id} is stale ({cache_age:.0f}s) and device is offline. "
f"Returning cached data anyway.")

        onus = session.query(ONU).filter(
ONU.device_id == device_id,
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).order_by(ONU.interface).all()

        if not onus:
            return None

        onu_interfaces = [f"{device_id}:{onu.interface}" for onu in onus]
        all_macs = session.query(ONUClientMAC).filter(
ONUClientMAC.onu_interface.in_(onu_interfaces)
).all()

        macs_by_interface = {}
        for mac in all_macs:
            macs_by_interface.setdefault(mac.onu_interface, []).append({
'vlan': mac.vlan, 'mac_address': mac.mac_address,
'normalized_mac': mac.normalized_mac,
'type': mac.type, 'port': mac.port,
})

        # Единый стандарт строки ONU (_onu_row_dict): включает договор из
        # справочника привязок ONUContract, статус сигнала, МКД/переезд —
        # ту же информацию, что и поиск/списки. Поля ниже дополняют стандарт
        # live-данными опроса (клиентские MAC, normalized_mac, bind_type).
        cmap = get_contracts_map_for_onus(session, [(o.device_id, o.interface) for o in onus])
        onu_info = [_onu_row_dict(o, cmap) for o in onus]
        # Договоры в списке устройства могут быть не в cmap (например, legacy-
        # договор прямо в ONU.contract); достраиваем details по всем номерам.
        missing_nums = set()
        for onu, row in zip(onus, onu_info):
            if row.get('contract') and not row.get('contract_login'):
                missing_nums.add(row['contract'])
        if missing_nums:
            details = {c.contract_number: c for c in session.query(Contract).filter(
                Contract.contract_number.in_(list(missing_nums))).all()}
            for row in onu_info:
                c = details.get(row.get('contract'))
                if c:
                    row['contract_login'] = c.login
                    row['contract_ip'] = c.ip_address
        for onu, row in zip(onus, onu_info):
            full_iface = f"{device_id}:{onu.interface}"
            row['normalized_mac'] = onu.normalized_mac
            row['bind_type'] = onu.bind_type
            row['client_macs'] = macs_by_interface.get(full_iface, [])
            row['is_active'] = onu.is_active
            row['device_id'] = onu.device_id
        enrich_rows_with_contract_details(session, onu_info)

        return {
'onu_info': onu_info,
'timestamp': status.last_successful_update.strftime('%Y-%m-%d %H:%M:%S') if status.last_successful_update else 'Нет данных',
'success': True,
'enriched': status.enriched_onu_count > 0
}
    except Exception as e:
        logger.error(f"Error getting cached data for device {device_id}: {e}")
        return None

def get_onu_event_history(session, device_id, interface, days=90, limit=500):
    """История событий одной ONU (onu_history): up/down/переезды/создание/удаление."""
    try:
        since = now_local() - datetime.timedelta(days=days)
        rows = session.query(
            ONUHistory.action, ONUHistory.details, ONUHistory.mac, ONUHistory.created_at
        ).filter(ONUHistory.device_id == device_id,
                 ONUHistory.interface == interface,
                 ONUHistory.created_at >= since) \
            .order_by(ONUHistory.created_at.desc()).limit(limit).all()
        return {'events': [{
            'action': a, 'details': d, 'mac': m,
            'created_at': ts.strftime('%Y-%m-%d %H:%M') if ts else None,
        } for a, d, m, ts in rows], 'device_id': device_id, 'interface': interface}
    except Exception as e:
        logger.error(f"Error getting ONU event history: {e}", exc_info=True)
        return {'events': [], 'error': INTERNAL_ERROR_MSG}


def cleanup_old_data(session, days_to_keep=7):
    try:
        cutoff_date = now_local() - datetime.timedelta(days=days_to_keep)
        bulk_delete_query(session.query(ONUHistory).filter(
ONUHistory.created_at < cutoff_date - datetime.timedelta(days=23)
))
        bulk_delete_query(session.query(ONUClientMAC).filter(
ONUClientMAC.created_at < cutoff_date
))
        # Ротация временного ряда onu_state: таблица растёт по строке на ONU
        # за каждый цикл опроса; глубже 90 дней ряд статистике не нужен.
        bulk_delete_query(session.query(ONUState).filter(
ONUState.recorded_at < now_local() - datetime.timedelta(days=90)
))
        session.commit()
    except Exception as e:
        logger.error(f"Error during data cleanup: {e}")
        session.rollback()

def get_device_stats(session, device_id):
    try:
        base_filter = (ONU.device_id == device_id) & ((ONU.is_active.is_(True)) | (ONU.is_configured.is_(True)))
        total_onus = session.query(func.count(ONU.id)).filter(base_filter).scalar() or 0
        active_onus = session.query(func.count(ONU.id)).filter(
ONU.device_id == device_id, ONU.optical_power.isnot(None),
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0
        signal_onus = active_onus
        inactive_onus = total_onus - active_onus

        with_contract = session.query(func.count(ONU.id)).filter(
ONU.device_id == device_id, ONU.contract.isnot(None), ONU.contract != '',
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0

        moved_onus = session.query(func.count(ONU.id)).filter(
ONU.device_id == device_id, ONU.moved_to.isnot(None)
).scalar() or 0

        configured_but_inactive = session.query(func.count(ONU.id)).filter(
ONU.device_id == device_id, ONU.is_configured.is_(True), ONU.optical_power.is_(None)
).scalar() or 0

        mcd_onus = session.query(func.count(ONU.id)).filter(
ONU.device_id == device_id,
ONU.description.isnot(None),
ONU.description.like(mcd_like_pattern(), escape=LIKE_ESCAPE),
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0

        mcd_active = session.query(func.count(ONU.id)).filter(
ONU.device_id == device_id,
ONU.description.isnot(None),
ONU.description.like(mcd_like_pattern(), escape=LIKE_ESCAPE),
ONU.optical_power.isnot(None),
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0

        good_signal = session.query(func.count(ONU.id)).filter(
ONU.device_id == device_id, ONU.optical_power > -25,
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0

        warning_signal = session.query(func.count(ONU.id)).filter(
ONU.device_id == device_id, ONU.optical_power <= -25, ONU.optical_power >= -27,
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0

        bad_signal = session.query(func.count(ONU.id)).filter(
ONU.device_id == device_id, ONU.optical_power < -27,
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0

        single_onus = total_onus - mcd_onus
        single_active = active_onus - mcd_active

        return {
'total': total_onus, 'active': active_onus, 'inactive': inactive_onus,
'signal': signal_onus, 'with_contract': with_contract,
'moved': moved_onus, 'configured_but_inactive': configured_but_inactive,
'mcd': mcd_onus, 'mcd_active': mcd_active,
'single': single_onus, 'single_active': single_active,
'good_signal': good_signal, 'warning_signal': warning_signal, 'bad_signal': bad_signal,
}
    except Exception as e:
        logger.error(f"Error getting device stats for {device_id}: {e}")
        return {
'total': 0, 'active': 0, 'inactive': 0, 'signal': 0,
'with_contract': 0, 'moved': 0, 'configured_but_inactive': 0,
'mcd': 0, 'mcd_active': 0, 'single': 0, 'single_active': 0,
'good_signal': 0, 'warning_signal': 0, 'bad_signal': 0,
}

def get_global_stats(session):
    try:
        total_devices = session.query(func.count(DeviceStatus.id)).scalar() or 0
        online_devices = session.query(func.count(DeviceStatus.id)).filter_by(is_online=True).scalar() or 0
        total_onus = session.query(func.count(ONU.id)).filter(
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0
        active_onus = session.query(func.count(ONU.id)).filter(
ONU.optical_power.isnot(None),
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0
        inactive_onus = total_onus - active_onus

        moved_onus = session.query(func.count(ONU.id)).filter(
ONU.moved_to.isnot(None)
).scalar() or 0

        with_contract = session.query(func.count(ONU.id)).filter(
ONU.contract.isnot(None), ONU.contract != '',
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0

        unique_contracts = session.query(func.count(distinct(Contract.contract_number))).scalar() or 0
        contracts_with_onu = session.query(func.count(distinct(ONU.contract))).filter(
ONU.contract.isnot(None), ONU.contract != '',
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0

        configured_onus = session.query(func.count(ONU.id)).filter(
ONU.is_configured.is_(True),
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0

        mcd_onus = session.query(func.count(ONU.id)).filter(
ONU.description.isnot(None),
ONU.description.like(mcd_like_pattern(), escape=LIKE_ESCAPE),
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0

        mcd_active = session.query(func.count(ONU.id)).filter(
ONU.description.isnot(None),
ONU.description.like(mcd_like_pattern(), escape=LIKE_ESCAPE),
ONU.optical_power.isnot(None),
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0

        mcd_inactive = mcd_onus - mcd_active

        good_signal = session.query(func.count(ONU.id)).filter(
ONU.optical_power > -25,
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0

        warning_signal = session.query(func.count(ONU.id)).filter(
ONU.optical_power <= -25, ONU.optical_power >= -27,
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0

        bad_signal = session.query(func.count(ONU.id)).filter(
ONU.optical_power < -27,
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0

        single_onus = total_onus - mcd_onus
        single_active = active_onus - mcd_active

        return {
'devices_total': total_devices, 'devices_online': online_devices,
'onus_total': total_onus, 'active_onus': active_onus,
'inactive_onus': inactive_onus, 'moved_onus': moved_onus,
'onus_with_contract': with_contract, 'contracts_total': unique_contracts,
'contracts_with_onu': contracts_with_onu, 'configured_onus': configured_onus,
'mcd_onus': mcd_onus, 'mcd_active': mcd_active, 'mcd_inactive': mcd_inactive,
'single_onus': single_onus, 'single_active': single_active,
'good_signal': good_signal, 'warning_signal': warning_signal, 'bad_signal': bad_signal,
}
    except Exception as e:
        logger.error(f"Error getting global stats: {e}")
        return {
'devices_total': 0, 'devices_online': 0, 'onus_total': 0,
'active_onus': 0, 'inactive_onus': 0, 'moved_onus': 0,
'onus_with_contract': 0, 'contracts_total': 0, 'contracts_with_onu': 0,
'configured_onus': 0, 'mcd_onus': 0, 'mcd_active': 0, 'mcd_inactive': 0,
'single_onus': 0, 'single_active': 0,
'good_signal': 0, 'warning_signal': 0, 'bad_signal': 0,
}


def save_contracts_from_file(session, file_path, delimiter=';'):
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read(100000)
            result = chardet.detect(raw_data)
            encoding = result['encoding']
            if encoding and ('windows' in encoding.lower() or '1251' in encoding):
                encoding = 'cp1251'
            elif not encoding:
                encoding = 'utf-8'

        df = pd.read_csv(file_path, delimiter=delimiter, encoding=encoding, on_bad_lines='skip')
        df.columns = [str(col).strip().replace('"', '') for col in df.columns]

        contract_col = None
        mac_col = None
        login_col = None
        ip_col = None

        for col in df.columns:
            col_lower = str(col).lower()
            if not contract_col and any(word in col_lower for word in ['договор', 'contract', 'pppoe', 'inet', 'лицевой']):
                contract_col = col
            if not mac_col and any(word in col_lower for word in ['mac-адрес', 'mac адрес', 'mac']):
                mac_col = col
            if not login_col and any(word in col_lower for word in ['login', 'логин']):
                login_col = col
            if not ip_col and any(word in col_lower for word in ['ip', 'адрес']):
                ip_col = col

        if not contract_col and len(df.columns) >= 1:
            contract_col = df.columns[0]
        if not mac_col and len(df.columns) >= 4:
            mac_col = df.columns[3]
        if not login_col and len(df.columns) >= 2:
            login_col = df.columns[1]
        if not ip_col and len(df.columns) >= 3:
            ip_col = df.columns[2]

        contracts_to_save = []
        seen_macs = set()
        skipped_count = 0

        for _idx, row in df.iterrows():
            try:
                contract = str(row[contract_col]).strip().replace('"', '') if not pd.isna(row[contract_col]) else ''
                mac = str(row[mac_col]).strip().replace('"', '') if not pd.isna(row[mac_col]) else ''
                login = str(row[login_col]).strip().replace('"', '') if login_col and not pd.isna(row[login_col]) else ''
                ip = str(row[ip_col]).strip().replace('"', '') if ip_col and not pd.isna(row[ip_col]) else ''

                if not contract or not mac:
                    skipped_count += 1
                    continue

                normalized_mac = normalize_mac_address(mac)
                if not normalized_mac:
                    skipped_count += 1
                    continue

                if normalized_mac in seen_macs:
                    skipped_count += 1
                    continue
                seen_macs.add(normalized_mac)

                additional_info = {}
                for col in df.columns:
                    if col not in [contract_col, mac_col, login_col, ip_col] and not pd.isna(row[col]):
                        additional_info[col] = str(row[col])

                contract_obj = Contract(
contract_number=contract, login=login, ip_address=ip,
mac_address=mac, normalized_mac=normalized_mac,
additional_info=str(additional_info) if additional_info else None
)
                contracts_to_save.append(contract_obj)
            except Exception:
                skipped_count += 1
                continue

        bulk_delete_query(session.query(Contract))
        session.commit()
        session.bulk_save_objects(contracts_to_save)
        session.commit()
        bind_contracts_to_onu(session)

        return {
'total_rows': len(df), 'saved_contracts': len(contracts_to_save),
'skipped_rows': skipped_count, 'unique_macs': len(seen_macs)
}
    except Exception as e:
        logger.error(f"Error saving contracts from file: {e}")
        session.rollback()
        raise

def bind_contracts_to_onu(session):
    try:

        contracts = session.query(Contract.normalized_mac, Contract.contract_number).all()
        if not contracts:
            return 0

        contract_dict = {}
        for normalized_mac, contract_number in contracts:
            if normalized_mac:
                contract_dict.setdefault(normalized_mac, []).append(contract_number)


        onus = session.query(ONU).filter(
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).all()

        updated_count = 0

        for onu in onus:
            onu_interface_full = f"{onu.device_id}:{onu.interface}"
            onu_is_mcd = is_mcd(onu.description)


            current_client_macs = session.query(ONUClientMAC).filter_by(
onu_interface=onu_interface_full
).all()

            active_contract_numbers = set()


            for cmac in current_client_macs:
                if cmac.normalized_mac and cmac.normalized_mac in contract_dict:
                    active_contract_numbers.update(contract_dict[cmac.normalized_mac])


            if not active_contract_numbers and onu.normalized_mac and onu.normalized_mac in contract_dict:
                active_contract_numbers.update(contract_dict[onu.normalized_mac])


            existing_db_contracts = session.query(ONUContract).filter_by(
device_id=onu.device_id,
interface=onu.interface
).all()
            existing_contract_numbers = {ec.contract_number for ec in existing_db_contracts}

            if onu_is_mcd:


                for c_num in active_contract_numbers:
                    if c_num not in existing_contract_numbers:
                        session.add(ONUContract(
device_id=onu.device_id,
interface=onu.interface,
contract_number=c_num,
is_main=False,
created_at=now_local()
))
                        updated_count += 1


                if not onu.contract and active_contract_numbers:
                    onu.contract = sorted(active_contract_numbers)[0]
                    onu.updated_at = now_local()

            else:


                if active_contract_numbers:

                    if active_contract_numbers != existing_contract_numbers:

                        bulk_delete_query(session.query(ONUContract).filter_by(
device_id=onu.device_id,
interface=onu.interface
))

                        is_first = True
                        for c_num in sorted(active_contract_numbers):
                            session.add(ONUContract(
device_id=onu.device_id,
interface=onu.interface,
contract_number=c_num,
is_main=is_first,
created_at=now_local()
))
                            is_first = False
                            updated_count += 1


                        new_main_contract = sorted(active_contract_numbers)[0]
                        if onu.contract != new_main_contract:
                            onu.contract = new_main_contract
                            onu.updated_at = now_local()
                else:


                    pass

        session.commit()
        return updated_count
    except Exception as e:
        logger.error(f"Error binding contracts to ONU: {e}")
        session.rollback()
        raise

def get_onu_contracts(session, device_id, interface):
    try:
        contracts = session.query(ONUContract).filter_by(
device_id=device_id, interface=interface
).all()
        contract_numbers = [contract.contract_number for contract in contracts]
        if contract_numbers:
            contract_details = session.query(Contract).filter(
Contract.contract_number.in_(contract_numbers)
).all()
            result = []
            for contract in contract_details:
                is_main = any(oc.contract_number == contract.contract_number and oc.is_main
for oc in contracts)
                result.append({
'contract_number': contract.contract_number,
'login': contract.login, 'ip_address': contract.ip_address,
'mac_address': contract.mac_address,
'uploaded_at': contract.uploaded_at.strftime('%Y-%m-%d %H:%M:%S') if contract.uploaded_at else None,
'additional_info': contract.additional_info,
'is_main': is_main
})
            return result
        return []
    except Exception as e:
        logger.error(f"Error getting ONU contracts: {e}")
        return []

def search_contracts(session, search_query, limit=50):
    try:
        query = session.query(Contract)
        if search_query:
            search_pattern = like_pattern(search_query)
            query = query.filter(
(Contract.contract_number.ilike(search_pattern, escape=LIKE_ESCAPE)) |
(Contract.mac_address.ilike(search_pattern, escape=LIKE_ESCAPE)) |
(Contract.login.ilike(search_pattern, escape=LIKE_ESCAPE)) |
(Contract.ip_address.ilike(search_pattern, escape=LIKE_ESCAPE))
)
        contracts = query.order_by(Contract.contract_number).limit(limit).all()

        result = []
        for contract in contracts:
            onus = []
            client_mac_onus = session.query(ONUClientMAC, ONU).join(
ONU, (ONU.device_id + ':' + ONU.interface) == ONUClientMAC.onu_interface
).filter(
ONUClientMAC.normalized_mac == contract.normalized_mac,
ONU.is_active.is_(True)
).all()
            for _client_mac, onu in client_mac_onus:
                onus.append({
'device': onu.device_name, 'interface': onu.interface,
'description': onu.description if onu.description and onu.description != 'N/A' else onu.interface,
'status': onu.status, 'optical_power': onu.optical_power,
'is_mcd': is_mcd(onu.description),
'is_moved_to': onu.moved_to is not None,
'is_moved_from': onu.moved_from is not None,
})

            normalized_onu_mac = normalize_mac_address(contract.mac_address)
            if normalized_onu_mac:
                direct_onus = session.query(ONU).filter(
ONU.normalized_mac == normalized_onu_mac,
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).all()
                for onu in direct_onus:
                    onus.append({
'device': onu.device_name, 'interface': onu.interface,
'description': onu.description if onu.description and onu.description != 'N/A' else onu.interface,
'status': onu.status, 'optical_power': onu.optical_power,
'is_moved': onu.moved_to is not None or onu.moved_from is not None,
'is_moved_to': onu.moved_to is not None,
'is_moved_from': onu.moved_from is not None,
'is_mcd': is_mcd(onu.description),
})

            result.append({
'contract_number': contract.contract_number,
'login': contract.login, 'ip_address': contract.ip_address,
'mac_address': contract.mac_address,
'uploaded_at': contract.uploaded_at.strftime('%Y-%m-%d %H:%M:%S') if contract.uploaded_at else None,
'onus': onus, 'onu_count': len(onus)
})
        return result
    except Exception as e:
        logger.error(f"Error searching contracts: {e}")
        return []

def get_contract_stats(session):
    try:
        total_contracts = session.query(func.count(Contract.id)).scalar() or 0
        contracts_with_onu = session.query(func.count(distinct(ONU.contract))).filter(
ONU.contract.isnot(None), ONU.contract != '',
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0
        onus_with_contract = session.query(func.count(ONU.id)).filter(
ONU.contract.isnot(None), ONU.contract != '',
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0
        total_onus = session.query(func.count(ONU.id)).filter(
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).scalar() or 0
        coverage_percentage = (onus_with_contract / total_onus * 100) if total_onus > 0 else 0
        return {
'total_contracts': total_contracts, 'contracts_with_onu': contracts_with_onu,
'onus_with_contract': onus_with_contract, 'total_onus': total_onus,
'coverage_percentage': round(coverage_percentage, 2)
}
    except Exception as e:
        logger.error(f"Error getting contract stats: {e}")
        return {
'total_contracts': 0, 'contracts_with_onu': 0,
'onus_with_contract': 0, 'total_onus': 0, 'coverage_percentage': 0
}

def set_onu_contract(session, device_id, interface, contract_number):
    try:
        onu = session.query(ONU).filter_by(
device_id=device_id, interface=interface, is_active=True
).first()
        if not onu:
            return {'success': False, 'message': 'ONU не найдена'}

        contract = session.query(Contract).filter_by(contract_number=contract_number).first()
        if not contract:
            contract = Contract(
contract_number=contract_number,
mac_address=onu.mac, normalized_mac=onu.normalized_mac
)
            session.add(contract)
            session.flush()

        onu_contract = session.query(ONUContract).filter_by(
device_id=device_id, interface=interface, contract_number=contract_number
).first()
        if not onu_contract:
            onu_contract = ONUContract(
device_id=device_id, interface=interface,
contract_number=contract_number, is_main=True
)
            session.add(onu_contract)
        else:
            onu_contract.is_main = True

        onu.contract = contract_number
        onu.updated_at = now_local()
        session.commit()

        return {
'success': True, 'message': f'Договор {contract_number} привязан к ONU',
'contract_number': contract_number
}
    except Exception as e:
        logger.error(f"Error setting ONU contract: {e}", exc_info=True)
        session.rollback()
        return {'success': False, 'message': 'Ошибка привязки договора. Подробности в логах сервера.'}


def get_contracts_map_for_onus(session, onu_keys):
    result = {}
    if not onu_keys:
        return result
    keys = list(set(onu_keys))
    key_set = set(keys)


    from sqlalchemy import tuple_
    links = session.query(
ONUContract.device_id, ONUContract.interface,
ONUContract.contract_number, ONUContract.is_main
).filter(tuple_(ONUContract.device_id, ONUContract.interface).in_(keys)).all()
    found = {k: {'main': None, 'extra': []} for k in keys}
    for did, iface, cn, is_main in links:
        key = (did, iface)
        if key not in found or not cn:
            continue
        cn = str(cn)
        if is_main and found[key]['main'] is None:
            found[key]['main'] = cn
        elif cn not in found[key]['extra'] and cn != found[key]['main']:
            found[key]['extra'].append(cn)


    client_rows = session.query(
ONUClientMAC.onu_interface, ONUClientMAC.normalized_mac
).filter(ONUClientMAC.onu_interface.in_(
[f"{d}:{i}" for d, i in keys]), ONUClientMAC.normalized_mac.isnot(None)
).distinct().limit(20000).all()
    candidates_by_key = {}
    iface_to_key = {f"{d}:{i}": (d, i) for d, i in keys}
    for full_iface, nmac in client_rows:
        k = iface_to_key.get(full_iface)
        if k is not None and nmac:
            candidates_by_key.setdefault(k, set()).add(nmac)

    onus_norm = session.query(ONU.device_id, ONU.interface, ONU.normalized_mac).filter(
tuple_(ONU.device_id, ONU.interface).in_(keys), ONU.normalized_mac.isnot(None)
).all()
    for did, iface, nmac in onus_norm:
        k = (did, iface)
        if k in key_set and nmac:
            candidates_by_key.setdefault(k, set()).add(nmac)

    all_candidates = set()
    for s in candidates_by_key.values():
        all_candidates.update(s)
    mac_to_contracts = {}
    if all_candidates:
        rows = session.query(
Contract.normalized_mac, Contract.contract_number
).filter(Contract.normalized_mac.in_(list(all_candidates))).distinct().limit(20000).all()
        for nmac, cn in rows:
            if nmac and cn:
                mac_to_contracts.setdefault(nmac, set()).add(str(cn))

    for k, cands in candidates_by_key.items():
        for nmac in cands:
            for cn in mac_to_contracts.get(nmac, ()):
                if cn not in found[k]['extra'] and cn != found[k]['main']:
                    found[k]['extra'].append(cn)


    for k in keys:
        data = found[k]
        if data['main']:
            result[k] = data['main']
        elif data['extra']:
            shown = data['extra'][:3]
            more = len(data['extra']) - len(shown)
            result[k] = ', '.join(shown) + (f' +{more}' if more > 0 else '')


    direct = session.query(ONU.device_id, ONU.interface, ONU.contract).filter(
tuple_(ONU.device_id, ONU.interface).in_(keys)).all()
    for did, iface, cn in direct:
        k = (did, iface)
        if k in key_set and not result.get(k) and cn and cn != 'N/A':
            result[k] = str(cn)
    return result


def find_duplicate_onus(session, limit=50):
    try:
        all_onus = session.query(ONU).filter(
ONU.mac != 'N/A',
ONU.mac.isnot(None),
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
).all()

        mac_groups = {}
        for onu in all_onus:
            if not onu.mac or onu.mac == 'N/A':
                continue
            last_8 = extract_mac_last_8_chars(onu.mac)
            if not last_8 or len(last_8) < 4:
                continue
            if last_8 not in mac_groups:
                mac_groups[last_8] = []

            _, _, moved_to_device_name = parse_moved_location(onu.moved_to)
            _, _, moved_from_device_name = parse_moved_location(onu.moved_from)

            mac_groups[last_8].append({
'device_id': onu.device_id,
'device': onu.device_name,
'interface': onu.interface,
'mac': onu.mac,
'normalized_mac': onu.normalized_mac,
'description': onu.description,
'contract': onu.contract,
'status': onu.status,
'optical_power': onu.optical_power,
'vendor': onu.vendor,
'model': onu.model,
'timestamp': onu.updated_at.strftime('%Y-%m-%d %H:%M:%S') if onu.updated_at else 'N/A',
'last_seen': onu.last_seen.strftime('%Y-%m-%d %H:%M:%S') if onu.last_seen else None,
'moved_to': onu.moved_to,
'moved_from': onu.moved_from,
'moved_to_device_name': moved_to_device_name,
'moved_from_device_name': moved_from_device_name,
'is_moved': onu.moved_to is not None or onu.moved_from is not None,
'is_moved_to': onu.moved_to is not None,
'is_moved_from': onu.moved_from is not None,
'is_configured': onu.is_configured,
'is_mcd': is_mcd(onu.description),
})

        duplicates = []
        for last_8, occurrences in mac_groups.items():
            if len(occurrences) < 2:
                continue
            unique_keys = {(occ['device_id'], occ['interface']) for occ in occurrences}
            if len(unique_keys) < 2:
                continue
            devices = {occ['device_id'] for occ in occurrences}
            is_moved = len(devices) > 1
            all_macs_in_group = list({occ['mac'] for occ in occurrences if occ['mac']})
            duplicates.append({
'mac_last_8': last_8,
'mac_example': occurrences[0]['mac'],
'all_macs': all_macs_in_group,
'occurrences': occurrences,
'count': len(occurrences),
'is_moved': is_moved,
'devices': list(devices)
})

        duplicates.sort(key=lambda x: x['count'], reverse=True)


        shown = duplicates[:limit]
        all_occ = [occ for dup in shown for occ in dup['occurrences']]
        try:
            cmap = get_contracts_map_for_onus(
session, [(o['device_id'], o['interface']) for o in all_occ])
            for occ in all_occ:
                occ['contract'] = cmap.get((occ['device_id'], occ['interface']))                    or (occ.get('contract') if occ.get('contract') and occ.get('contract') != 'N/A' else None)
        except Exception as e:
            logger.warning(f"Не удалось обогатить дубликаты договорами: {e}")

        return {
'duplicates': shown,
'total_duplicates': len(duplicates),
'total_macs_scanned': len(mac_groups),
'message': f'Найдено {len(duplicates)} дублирующихся MAC-адресов'
}
    except Exception as e:
        logger.error(f"Error searching for duplicate ONUs: {e}", exc_info=True)
        return {
'duplicates': [], 'total_duplicates': 0,
'total_macs_scanned': 0, 'error': INTERNAL_ERROR_MSG
}

def _standardized_onu_rows(session, onus):
    """Единый стандарт строк ONU для ВСЕХ списков/выпадающих панелей UI.

    Строка строится через _onu_row_dict (договор из справочника привязок
    ONUContract + статус сигнала + флаги МКД/переезда), затем обогащается
    данными договора (логин/IP/доп.инфо) через enrich_rows_with_contract_details.
    Любой список ONU в приложении обязан проходить через эту функцию, чтобы
    везде выводилась одинаковая полная информация о клиенте.
    """
    cmap = get_contracts_map_for_onus(session, [(o.device_id, o.interface) for o in onus])
    rows = [_onu_row_dict(o, cmap) for o in onus]
    enrich_rows_with_contract_details(session, rows)
    return rows


def get_inactive_onus(session):
    """Неактивные (offline) ONU в едином стандарте строк + тип привязки.

    Заменяет «сырую» сборку словарей в /api/inactive_onus: договор и данные
    клиента теперь доступны здесь так же, как в поиске и остальных списках.
    """
    try:
        onus = session.query(ONU).filter(
            ONU.optical_power.is_(None), ONU.is_active.is_(True)
        ).order_by(ONU.device_name, ONU.interface).all()
        results = _standardized_onu_rows(session, onus)
        for r in results:
            desc = (r.get('description') or '').lower()
            r['bind_type'] = 'dynamic' if ('dynamic' in desc or 'динам' in desc) else 'static'
        return {'inactive_onus': results, 'count': len(results)}
    except Exception as e:
        logger.error(f"Error getting inactive ONUs: {e}", exc_info=True)
        return {'inactive_onus': [], 'count': 0, 'error': INTERNAL_ERROR_MSG}


def get_onus_without_description(session):
    """ONU без описания в едином стандарте строк (для панели поиска)."""
    try:
        onus = session.query(ONU).filter(
            ((ONU.description == '') | (ONU.description.is_(None)) |
             (ONU.description == 'N/A') | (ONU.description == ONU.interface)),
            ONU.is_active.is_(True)
        ).order_by(ONU.device_name, ONU.interface).all()
        results = _standardized_onu_rows(session, onus)
        return {'onus_without_description': results, 'total_count': len(results),
                'message': f'Найдено {len(results)} ONU без описания'}
    except Exception as e:
        logger.error(f"Error getting ONUs without description: {e}", exc_info=True)
        return {'onus_without_description': [], 'total_count': 0, 'error': INTERNAL_ERROR_MSG}


def get_onus_without_contract(session):
    """ONU без договора в едином стандарте строк (для страницы договоров)."""
    try:
        onus = session.query(ONU).filter(
            ((ONU.contract == '') | (ONU.contract.is_(None))),
            ONU.is_active.is_(True)
        ).order_by(ONU.device_name, ONU.interface).all()
        results = _standardized_onu_rows(session, onus)
        # Договор мог быть только в справочнике привязок — считаем отсутствующим
        # тот, где нет ни основного номера, ни привязок ONUContract.
        results = [r for r in results if not r.get('contract')]
        return {'onus_without_contract': results, 'total_count': len(results),
                'message': f'Найдено {len(results)} ONU без договоров'}
    except Exception as e:
        logger.error(f"Error getting ONUs without contract: {e}", exc_info=True)
        return {'onus_without_contract': [], 'total_count': 0, 'error': INTERNAL_ERROR_MSG}


def get_onus_by_ids(session, ids):
    """Стандартизованные строки ONU по списку id (для групп дубликатов MAC)."""
    try:
        if not ids:
            return []
        onus = session.query(ONU).filter(ONU.id.in_(list(ids))).all()
        return _standardized_onu_rows(session, onus)
    except Exception as e:
        logger.error(f"Error getting standardized ONUs by ids: {e}", exc_info=True)
        return []


def get_moved_onus(session, device_id=None):
    try:
        query = session.query(ONU).filter(
            (ONU.moved_to.isnot(None)) | (ONU.moved_from.isnot(None))
        )
        if device_id:
            query = query.filter(ONU.device_id == device_id)
        moved_onus = query.order_by(ONU.device_name, ONU.interface).all()
        # Единый стандарт: _onu_row_dict уже содержит все поля переезда
        # (moved_to/from + device_id/name/interface, moved_at), договор и сигнал.
        results = _standardized_onu_rows(session, moved_onus)
        for r in results:
            r['is_moved_to'] = r['moved_to'] is not None
            r['is_moved_from'] = r['moved_from'] is not None
        return {'moved_onus': results, 'total_count': len(results)}
    except Exception as e:
        logger.error(f"Error getting move ONUs: {e}", exc_info=True)
        return {'moved_onus': [], 'total_count': 0}

def get_mcd_onus(session, device_id=None):
    try:
        query = session.query(ONU).filter(
            ONU.description.isnot(None),
            ONU.description.like(mcd_like_pattern(), escape=LIKE_ESCAPE),
            (ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
        )
        if device_id:
            query = query.filter(ONU.device_id == device_id)
        mcd_onus = query.order_by(ONU.device_name, ONU.interface).all()
        results = _standardized_onu_rows(session, mcd_onus)
        return {'mcd_onus': results, 'total_count': len(results)}
    except Exception as e:
        logger.error(f"Error getting MCD ONUs: {e}", exc_info=True)
        return {'mcd_onus': [], 'total_count': 0, 'error': INTERNAL_ERROR_MSG}

def get_onu_list_by_filter(session, filter_type, device_id=None, limit=1000):
    try:
        query = session.query(ONU).filter(
(ONU.is_active.is_(True)) | (ONU.is_configured.is_(True))
)
        if device_id:
            query = query.filter(ONU.device_id == device_id)

        if filter_type == 'active':
            query = query.filter(ONU.optical_power.isnot(None))
        elif filter_type == 'inactive':
            query = query.filter(ONU.optical_power.is_(None))
        elif filter_type == 'good_signal':
            query = query.filter(ONU.optical_power > -25)
        elif filter_type == 'warning_signal':
            query = query.filter(ONU.optical_power <= -25, ONU.optical_power >= -27)
        elif filter_type == 'bad_signal':
            query = query.filter(ONU.optical_power < -27)
        elif filter_type == 'single':
            query = query.filter(
(ONU.description.is_(None)) |
(~ONU.description.like(mcd_like_pattern(), escape=LIKE_ESCAPE))
)
        elif filter_type == 'mcd':
            query = query.filter(
ONU.description.isnot(None),
ONU.description.like(mcd_like_pattern(), escape=LIKE_ESCAPE)
)

        onus = query.order_by(ONU.device_name, ONU.interface).limit(limit).all()

        # Единый стандарт строки ONU + договор из справочника (как в поиске):
        results = _standardized_onu_rows(session, onus)

        return {'onus': results, 'total_count': len(results), 'filter_type': filter_type}
    except Exception as e:
        logger.error(f"Error getting ONU list by filter {filter_type}: {e}", exc_info=True)
        return {'onus': [], 'total_count': 0, 'error': INTERNAL_ERROR_MSG, 'filter_type': filter_type}
