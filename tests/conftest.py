# SPDX-License-Identifier: Apache-2.0
"""Test fixtures for the Stele suite.

Shape:
  - One throwaway Postgres, read from ``STELE_DATABASE_URL`` (the same variable the
    migration env reads). The suite migrates it once and truncates between tests.
  - ``_migrated_database`` (session) runs ``alembic upgrade head`` once — the 3-table
    baseline (the migration is a sync subprocess, so it needs no event loop).
  - ``engine`` (session) is the async engine over the migrated DB; ``db`` (per-test)
    yields a session and TRUNCATEs the three tables on teardown for a clean slate.
  - ``fake_webauthn`` substitutes the two WebAuthn library-boundary verifies — the
    only calls a server-side test cannot make without a real authenticator.

The event loop is session-scoped (``asyncio_default_*_loop_scope = "session"`` in
pyproject), so the session-scoped engine and the per-test sessions share one loop.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_REPO_ROOT = Path(__file__).resolve().parents[1]
# FK-safe truncation order (children before parent).
_TABLES = ("recovery_codes", "webauthn_credentials", "principals")


def _require_database_url() -> str:
    url = os.environ.get("STELE_DATABASE_URL")
    if not url:
        raise RuntimeError(
            "STELE_DATABASE_URL must be set to a throwaway postgresql+asyncpg:// "
            "database for the test suite — the suite migrates it and truncates "
            "between tests, so point it at a disposable DB, never a real one."
        )
    return url


@pytest.fixture(scope="session")
def database_url() -> str:
    return _require_database_url()


@pytest.fixture(scope="session")
def _migrated_database(database_url: str) -> str:
    """Migrate-once: stand the 3-table baseline up against the throwaway DB."""
    env = {**os.environ, "STELE_DATABASE_URL": database_url}
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(_REPO_ROOT),
        env=env,
        check=True,
        capture_output=True,
    )
    return database_url


@pytest_asyncio.fixture(scope="session")
async def engine(_migrated_database: str):
    eng = create_async_engine(_migrated_database)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def db(engine) -> AsyncSession:
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        yield session
    # truncate-per-test: a clean slate for the next test.
    async with engine.begin() as conn:
        await conn.execute(
            text(f"TRUNCATE {', '.join(_TABLES)} RESTART IDENTITY CASCADE")
        )


@pytest.fixture
def fake_webauthn(monkeypatch):
    """Substitute the two WebAuthn library-boundary verifies (no authenticator in
    CI). Patches the canonical ``stele.webauthn`` functions — which the mounted
    enrollment ceremony also calls internally — and returns a small factory for the
    canned verified results. ``begin_registration`` / ``begin_authentication`` are
    NOT patched: they build options offline and need no authenticator.
    """
    from stele import webauthn as _wa

    class _FakeWebauthn:
        def registration(
            self,
            *,
            credential_id: bytes | None = None,
            public_key: bytes | None = None,
            sign_count: int = 0,
            transports=None,
        ) -> _wa.VerifiedCredentialData:
            result = _wa.VerifiedCredentialData(
                credential_id=credential_id or os.urandom(32),
                public_key=public_key or os.urandom(91),
                sign_count=sign_count,
                transports=transports,
            )
            monkeypatch.setattr(_wa, "verify_registration", lambda **kw: result)
            return result

        def assertion(
            self, *, credential_id: bytes, new_sign_count: int = 1
        ) -> _wa.VerifiedAssertionData:
            result = _wa.VerifiedAssertionData(
                credential_id=credential_id, new_sign_count=new_sign_count
            )
            monkeypatch.setattr(_wa, "verify_authentication", lambda **kw: result)
            return result

    return _FakeWebauthn()
