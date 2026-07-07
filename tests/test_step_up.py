"""TS-14 — unit tests for the step-up freshness slot (require_fresh_session,
_step_up_window). Constructs SessionPayload directly with a controlled
created_at (rather than issue_session, which stamps real wall-clock time) so
"stale" and "fresh" cases are deterministic, not timing-dependent.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pyotp
import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException

from stele.api import _step_up_window, require_fresh_session
from stele.registry import mint_principal
from stele.session import SessionPayload, encode_session
from stele.webauthn import VerifiedCredentialData

TEST_SECRET_KEY = Fernet.generate_key().decode()


def _canned_credential(sign_count: int = 0) -> VerifiedCredentialData:
    return VerifiedCredentialData(
        credential_id=os.urandom(32),
        public_key=os.urandom(91),
        sign_count=sign_count,
        transports=["internal"],
    )


async def _mint(db, name: str = "StepUp Tester"):
    person, codes = await mint_principal(
        display_name=name,
        totp_secret_plaintext=pyotp.random_base32(),
        passkey_credential=_canned_credential(),
        secret_key=TEST_SECRET_KEY,
        now=datetime.now(timezone.utc),
        db=db,
    )
    return person, codes


def _token_for(person_id, *, created_at: datetime) -> str:
    payload = SessionPayload(
        person_id=person_id, totp_verified=True,
        created_at=created_at, expires_at=created_at + timedelta(hours=1),
    )
    return encode_session(payload, secret_key=TEST_SECRET_KEY)


def test_step_up_window_default_is_900_seconds(monkeypatch):
    monkeypatch.delenv("STELE_STEP_UP_WINDOW_SECONDS", raising=False)
    assert _step_up_window() == timedelta(seconds=900)


async def test_require_fresh_session_accepts_recent_session(db):
    person, _ = await _mint(db)
    token = _token_for(person.id, created_at=datetime.now(timezone.utc))
    principal = await require_fresh_session(token=token, secret_key=TEST_SECRET_KEY, db=db)
    assert principal.id == person.id


async def test_require_fresh_session_rejects_stale_session(db):
    person, _ = await _mint(db)
    stale = datetime.now(timezone.utc) - timedelta(minutes=20)  # past the default 15-min window
    token = _token_for(person.id, created_at=stale)
    with pytest.raises(HTTPException) as excinfo:
        await require_fresh_session(token=token, secret_key=TEST_SECRET_KEY, db=db)
    assert excinfo.value.status_code == 403


async def test_require_fresh_session_window_is_configurable_wider(db, monkeypatch):
    """A session that would fail the default 15-min window passes under a
    wider STELE_STEP_UP_WINDOW_SECONDS."""
    monkeypatch.setenv("STELE_STEP_UP_WINDOW_SECONDS", "3600")
    person, _ = await _mint(db)
    stale = datetime.now(timezone.utc) - timedelta(minutes=20)
    token = _token_for(person.id, created_at=stale)
    principal = await require_fresh_session(token=token, secret_key=TEST_SECRET_KEY, db=db)
    assert principal.id == person.id


async def test_require_fresh_session_window_is_configurable_narrower(db, monkeypatch):
    """A session that would pass the default 15-min window fails under a
    narrower STELE_STEP_UP_WINDOW_SECONDS."""
    monkeypatch.setenv("STELE_STEP_UP_WINDOW_SECONDS", "5")
    person, _ = await _mint(db)
    slightly_old = datetime.now(timezone.utc) - timedelta(seconds=30)
    token = _token_for(person.id, created_at=slightly_old)
    with pytest.raises(HTTPException) as excinfo:
        await require_fresh_session(token=token, secret_key=TEST_SECRET_KEY, db=db)
    assert excinfo.value.status_code == 403
