# SPDX-License-Identifier: Apache-2.0
"""stele-cr-pre-publication-hardening-v0_1 — tests for the bundle's four
code-carrying items (TS-09, A-2, A-1, A-4). The three docs/pin-only items
(C-5, the starlette floor-pin, TS-18's warning) have no runtime behavior to
test.
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pyotp
import pytest
from cryptography.fernet import Fernet
from sqlalchemy.ext.asyncio import async_sessionmaker

from stele.api import _parse_step_up_window_seconds
from stele.person_totp import (
    PersonTotpCodeInvalid,
    begin_totp_rotation,
    confirm_totp_rotation,
)
from stele.registry import create_principal
from stele.webauthn import (
    PendingAddPasskeyStore,
    PendingLoginChallengeStore,
    WebauthnConfig,
    WebauthnConfigError,
    add_passkey_begin,
    login_challenge_begin,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "examples"))

TEST_SECRET_KEY = Fernet.generate_key().decode()
_CONFIG = WebauthnConfig(rp_id="localhost", rp_name="Test RP", rp_origin="http://localhost:8000")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# TS-09 — WebauthnConfig validates rp_id/rp_origin at construction
# ---------------------------------------------------------------------------
def test_webauthn_config_accepts_exact_host_match():
    config = WebauthnConfig(rp_id="localhost", rp_name="x", rp_origin="http://localhost:8000")
    assert config.rp_id == "localhost"


def test_webauthn_config_accepts_rp_id_as_registrable_suffix_of_origin_host():
    config = WebauthnConfig(rp_id="example.com", rp_name="x", rp_origin="https://login.example.com")
    assert config.rp_id == "example.com"


def test_webauthn_config_rejects_rp_id_unrelated_to_origin_host():
    with pytest.raises(WebauthnConfigError):
        WebauthnConfig(rp_id="evil.com", rp_name="x", rp_origin="https://example.com")


def test_webauthn_config_rejects_rp_id_more_specific_than_origin_host():
    # The inverse relationship is invalid too: rp_id may be a suffix of the
    # origin's host, never a MORE specific subdomain of it.
    with pytest.raises(WebauthnConfigError):
        WebauthnConfig(rp_id="login.example.com", rp_name="x", rp_origin="https://example.com")


def test_webauthn_config_rejects_malformed_rp_origin():
    with pytest.raises(WebauthnConfigError):
        WebauthnConfig(rp_id="example.com", rp_name="x", rp_origin="not-a-url")


def test_webauthn_config_rejects_non_http_scheme():
    with pytest.raises(WebauthnConfigError):
        WebauthnConfig(rp_id="example.com", rp_name="x", rp_origin="ftp://example.com")


# ---------------------------------------------------------------------------
# Multi-origin — one deployment reachable at more than one hostname
# ---------------------------------------------------------------------------
def test_webauthn_config_defaults_to_a_single_expected_origin():
    # The additive change must not alter single-origin behavior.
    config = WebauthnConfig(
        rp_id="example.com", rp_name="x", rp_origin="https://example.com"
    )
    assert config.additional_origins == ()
    assert config.expected_origins == ["https://example.com"]


def test_webauthn_config_accepts_additional_origins():
    config = WebauthnConfig(
        rp_id="dunin7.com",
        rp_name="x",
        rp_origin="https://app.dunin7.com",
        additional_origins=("https://loomworks-dev.dunin7.com",),
    )
    assert config.expected_origins == [
        "https://app.dunin7.com",
        "https://loomworks-dev.dunin7.com",
    ]


def test_webauthn_config_rejects_additional_origin_unrelated_to_rp_id():
    # The security property of the multi-origin change: an additional origin
    # is one the RP will accept assertions from, so it gets the identical
    # rp_id-suffix check. Without this, multi-origin support would be a hole
    # through which an unrelated host could be trusted.
    with pytest.raises(WebauthnConfigError):
        WebauthnConfig(
            rp_id="dunin7.com",
            rp_name="x",
            rp_origin="https://app.dunin7.com",
            additional_origins=("https://evil.com",),
        )


def test_webauthn_config_rejects_malformed_additional_origin():
    with pytest.raises(WebauthnConfigError):
        WebauthnConfig(
            rp_id="dunin7.com",
            rp_name="x",
            rp_origin="https://app.dunin7.com",
            additional_origins=("not-a-url",),
        )


def test_webauthn_config_validates_every_additional_origin_not_just_the_first():
    # A loop that stopped at the first entry would pass this silently.
    with pytest.raises(WebauthnConfigError):
        WebauthnConfig(
            rp_id="dunin7.com",
            rp_name="x",
            rp_origin="https://app.dunin7.com",
            additional_origins=(
                "https://loomworks-dev.dunin7.com",
                "https://evil.com",
            ),
        )


# ---------------------------------------------------------------------------
# A-2 — in-process pending stores sweep expired entries on every put()
# ---------------------------------------------------------------------------
async def test_login_challenge_store_sweeps_expired_entries_under_flooding():
    store = PendingLoginChallengeStore()
    long_ago = _now() - timedelta(hours=1)  # LOGIN_CHALLENGE_PENDING_TTL is 5 minutes
    for _ in range(50):
        await login_challenge_begin(config=_CONFIG, allow_credentials=None, now=long_ago, store=store)
    assert len(store._records) == 50  # nothing has put() since — no sweep has run yet

    await login_challenge_begin(config=_CONFIG, allow_credentials=None, now=_now(), store=store)
    assert len(store._records) == 1  # this put()'s sweep evicted all 50 stale entries


async def test_add_passkey_store_sweeps_expired_entries_under_flooding():
    store = PendingAddPasskeyStore()
    long_ago = _now() - timedelta(hours=1)  # ADD_PASSKEY_PENDING_TTL is 5 minutes
    for _ in range(50):
        await add_passkey_begin(
            person_id=uuid4(),
            person_display_name="Flood",
            person_email=None,
            config=_CONFIG,
            existing_credential_ids=[],
            now=long_ago,
            store=store,
        )
    assert len(store._records) == 50

    await add_passkey_begin(
        person_id=uuid4(),
        person_display_name="Fresh",
        person_email=None,
        config=_CONFIG,
        existing_credential_ids=[],
        now=_now(),
        store=store,
    )
    assert len(store._records) == 1


def test_reference_app_signup_pending_store_sweeps_expired_entries():
    from reference_app.main import _PendingStore, _SignupPending

    store = _PendingStore()
    long_ago = _now() - timedelta(hours=1)
    for i in range(50):
        store.put(
            f"su_{i}",
            _SignupPending(
                challenge=b"c", display_name="x", totp_secret="y", expires_at=long_ago
            ),
            now=long_ago - timedelta(seconds=1),
        )
    assert len(store._records) == 50

    store.put(
        "su_fresh",
        _SignupPending(
            challenge=b"c", display_name="x", totp_secret="y",
            expires_at=_now() + timedelta(minutes=5),
        ),
        now=_now(),
    )
    assert list(store._records) == ["su_fresh"]


# ---------------------------------------------------------------------------
# A-1 — confirm_totp_rotation's write is a race-safe atomic UPDATE
# ---------------------------------------------------------------------------
async def test_confirm_totp_rotation_race_only_one_wins(db, engine):
    """Two concurrent confirms of the same still-live rotation code must not
    both succeed. Independent AsyncSessions — a real DB-level race, mirroring
    TS-13's recovery-code race test (test_primitives.py).

    TS-13's test gets genuine interleaving for free: bcrypt.checkpw is a real
    CPU-bound stall between the read and the write, so both coroutines'
    reads reliably land before either write. confirm_totp_rotation has no
    comparably expensive step in between (verify_totp_step / Fernet
    encryption are both sub-millisecond) — plain asyncio.gather is NOT
    reliable here; empirically, one coroutine's whole read-verify-write-commit
    sequence completes before the other's SELECT is even dispatched, which
    would report the race as closed even against the unfixed fetch-then-mutate
    code (the second call's own fresh read would already see the first call's
    committed step, tripping the ordinary replay check rather than the atomic
    guard this test targets). A barrier gates each session's own UPDATE
    (identified by statement type, not call order) so both sessions'
    SELECTs are provably complete before either UPDATE is issued —
    manufacturing the same forced overlap bcrypt gives TS-13 for free.

    The barrier gates on the SELECT completing (not the UPDATE starting):
    it must work whether the write that follows is an ORM ``flush()`` (the
    pre-A-1 shape) or a Core ``update()`` (the fixed shape) — flush() never
    routes through ``Session.execute()``, so a gate keyed to an ``Update``
    statement would silently never fire against the old code and this test
    would pass for the wrong reason."""
    from sqlalchemy.sql import Select

    person = await create_principal(display_name="TOTP Race Tester", db=db)
    provisioning = await begin_totp_rotation(person_id=person.id, db=db)
    await db.commit()  # must be visible to session_a/session_b's own connections

    now = _now()
    code = pyotp.TOTP(provisioning.secret).at(now)

    factory = async_sessionmaker(engine, expire_on_commit=False)
    barrier = asyncio.Barrier(2)

    def _gate_after_reads(session):
        real_execute = session.execute

        async def _gated_execute(statement, *args, **kwargs):
            result = await real_execute(statement, *args, **kwargs)
            if isinstance(statement, Select):
                await asyncio.wait_for(barrier.wait(), timeout=5)
            return result

        session.execute = _gated_execute

    async def _confirm(session):
        _gate_after_reads(session)
        try:
            await confirm_totp_rotation(
                person_id=person.id, secret=provisioning.secret, code=code,
                secret_key=TEST_SECRET_KEY, now=now, db=session,
            )
        except PersonTotpCodeInvalid:
            await session.rollback()
            return False
        # Commit immediately: releases the row lock the winning UPDATE holds
        # so the other coroutine's blocked UPDATE can re-check and lose.
        await session.commit()
        return True

    async with factory() as session_a, factory() as session_b:
        results = await asyncio.gather(_confirm(session_a), _confirm(session_b))

    assert sorted(results) == [False, True]


async def test_confirm_totp_rotation_still_rejects_a_genuinely_bad_code(db):
    person = await create_principal(display_name="TOTP Bad Code Tester", db=db)
    provisioning = await begin_totp_rotation(person_id=person.id, db=db)
    await db.commit()
    with pytest.raises(PersonTotpCodeInvalid):
        await confirm_totp_rotation(
            person_id=person.id, secret=provisioning.secret, code="000000",
            secret_key=TEST_SECRET_KEY, now=_now(), db=db,
        )


# ---------------------------------------------------------------------------
# A-4 — STELE_STEP_UP_WINDOW_SECONDS is validated at startup/import
# ---------------------------------------------------------------------------
def test_parse_step_up_window_seconds_accepts_valid_value():
    assert _parse_step_up_window_seconds("3600") == 3600


def test_parse_step_up_window_seconds_rejects_non_integer():
    with pytest.raises(ValueError, match="integer number of seconds"):
        _parse_step_up_window_seconds("not-a-number")


@pytest.mark.parametrize("raw", ["0", "-5"])
def test_parse_step_up_window_seconds_rejects_non_positive(raw):
    with pytest.raises(ValueError, match="positive integer"):
        _parse_step_up_window_seconds(raw)


def test_stele_api_import_fails_loud_on_garbage_step_up_window_config():
    """A-4: a broken STELE_STEP_UP_WINDOW_SECONDS must fail at import (host
    boot, since mounting stele.api requires importing it) with a clear
    message, not surface as a bare 500 on the first step-up-gated request.
    A fresh subprocess so this doesn't disturb the already-imported
    stele.api module the rest of the suite relies on."""
    env = {**os.environ, "STELE_STEP_UP_WINDOW_SECONDS": "not-a-number"}
    result = subprocess.run(
        [sys.executable, "-c", "import stele.api"],
        cwd=str(_REPO_ROOT), env=env, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "STELE_STEP_UP_WINDOW_SECONDS" in result.stderr
