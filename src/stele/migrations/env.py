# SPDX-License-Identifier: Apache-2.0
"""Alembic environment for the standalone Stele migration set.

Async (asyncpg) online migrations. The database URL is read from the
``STELE_DATABASE_URL`` environment variable (a ``postgresql+asyncpg://`` URL).
``target_metadata`` is Stele's own ``SteleBase.metadata`` — importing
``stele.models`` registers the 3 tables on it (for autogenerate; the baseline
itself is hand-authored).

CR-2026-150: this chain tracks its own progress in ``stele_alembic_version``,
not the default ``alembic_version``. A host that also runs its own migrations
against the same database (e.g. an engine consuming Stele as an editable
dependency) has its own alembic chain with its own ``alembic_version`` table;
without a distinct table name here, the two chains collide the moment either
one is run against the shared database — Stele's own ``alembic upgrade head``
would find the host's stamped revision and fail to locate it in Stele's
history. A distinct version table lets both chains be run independently
against one database. See README's "Consuming Stele alongside an existing
schema" note for the first-time-setup step this implies.
"""
from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from stele.base import Base as SteleBase
import stele.models  # noqa: F401 — register principals/webauthn_credentials/recovery_codes

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

_url = os.environ.get("STELE_DATABASE_URL")
if not _url:
    raise RuntimeError(
        "STELE_DATABASE_URL is not set (expected a postgresql+asyncpg:// URL)."
    )
config.set_main_option("sqlalchemy.url", _url)

target_metadata = SteleBase.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_table="stele_alembic_version",
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        version_table="stele_alembic_version",
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
