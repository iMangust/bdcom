"""Окружение Alembic для EPON Monitor.

URL подключения берётся из config.py (env-переменные) — секреты не хранятся
в alembic.ini. Поддерживаются MySQL (прод) и SQLite (разработка/тесты).
"""
import logging
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from alembic import context

from sqlalchemy import engine_from_config, pool

from config import MYSQL_CONFIG
import database  # регистрирует все модели в Base.metadata

config = context.config

# Логирование Alembic настраивает ТОЛЬКО сам Alembic (logger 'alembic' -> stderr).
# Файловый вызов fileConfig(alembic.ini) убран навсегда: он всегда заменял
# НАСТРОЙКИ КОРНЕВОГО логгера (handlers/level из секции [logger_root]),
# затирая конфигурацию app.setup_logging() — и app.log пероставал писаться.
# Отключать существующие логгеры через disable_existing_loggers тоже нельзя:
# это глушило логгеры приложения (EPON_Monitor и др.), созданные до миграций.
logging.getLogger("alembic").setLevel(logging.INFO)

target_metadata = database.Base.metadata


def get_url():
    """Строит URL из MYSQL_CONFIG так же, как database.init_db()."""
    if MYSQL_CONFIG.get("type") == "sqlite":
        return f"sqlite:///{MYSQL_CONFIG['sqlite_path']}"
    from sqlalchemy.engine import URL
    return URL.create(
        drivername="mysql+pymysql",
        username=MYSQL_CONFIG["username"],
        password=str(MYSQL_CONFIG["password"]),
        host=MYSQL_CONFIG["host"],
        port=MYSQL_CONFIG["port"],
        database=MYSQL_CONFIG["database"],
        query={"charset": MYSQL_CONFIG["charset"]},
    )


def run_migrations_offline():
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
