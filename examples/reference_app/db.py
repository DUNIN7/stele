"""Async database wiring for the reference app.

A single async engine + session factory. ``provide_db_session`` is what the app
injects into Stele's ``provide_db_session`` slot (and uses for its own composed
routes): a request-scoped ``AsyncSession``. The mounted Stele routes commit on
this session themselves; the composed signup/login routes own their own commits.
"""
from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def make_engine(database_url: str):
    return create_async_engine(database_url, future=True)


def make_session_factory(engine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


def make_provide_db_session(session_factory: async_sessionmaker[AsyncSession]):
    """Build the request-scoped session dependency the app wires into Stele's
    ``provide_db_session`` slot."""

    async def provide_db_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    return provide_db_session
