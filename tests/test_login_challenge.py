"""TS-06 — unit tests for the core login-challenge ceremony (PendingLoginChallengeStore,
login_challenge_begin, login_challenge_complete).

Pure orchestration, no DB: login_challenge_complete takes credential_public_key /
current_sign_count as caller-supplied values (mirroring verify_authentication's
existing contract), so these tests exercise the store + ceremony functions directly,
monkeypatching only the library-boundary verify_authentication.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from stele.webauthn import (
    LoginChallengeNotFound,
    PendingLoginChallengeStore,
    VerifiedAssertionData,
    WebauthnConfig,
    login_challenge_begin,
    login_challenge_complete,
)

_CONFIG = WebauthnConfig(rp_id="localhost", rp_name="Test RP", rp_origin="http://localhost:8000")


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def test_login_challenge_round_trip_is_single_use_on_success(monkeypatch):
    """A successful verify consumes the challenge — a second complete() call
    against the same login_id must fail as unknown, not succeed again."""
    import stele.webauthn as stele_webauthn

    store = PendingLoginChallengeStore()
    begin = await login_challenge_begin(
        config=_CONFIG, allow_credentials=None, now=_now(), store=store
    )

    monkeypatch.setattr(
        stele_webauthn,
        "verify_authentication",
        lambda **kw: VerifiedAssertionData(credential_id=b"cred", new_sign_count=1),
    )
    result = await login_challenge_complete(
        login_id=begin.login_id,
        credential={"id": "x", "rawId": "x", "response": {}, "type": "public-key"},
        config=_CONFIG,
        credential_public_key=b"pubkey",
        current_sign_count=0,
        now=_now(),
        store=store,
    )
    assert result.new_sign_count == 1

    with pytest.raises(LoginChallengeNotFound):
        await login_challenge_complete(
            login_id=begin.login_id,
            credential={"id": "x", "rawId": "x", "response": {}, "type": "public-key"},
            config=_CONFIG,
            credential_public_key=b"pubkey",
            current_sign_count=1,
            now=_now(),
            store=store,
        )


async def test_login_challenge_failed_verification_leaves_challenge_redeemable(monkeypatch):
    """Success-only consumption (TS-06 decision): a failed verify_authentication
    must NOT discard the pending record — the same login_id can be retried."""
    import stele.webauthn as stele_webauthn

    store = PendingLoginChallengeStore()
    begin = await login_challenge_begin(
        config=_CONFIG, allow_credentials=None, now=_now(), store=store
    )
    credential = {"id": "x", "rawId": "x", "response": {}, "type": "public-key"}

    def _raise(**kw):
        raise ValueError("assertion signature did not verify")

    monkeypatch.setattr(stele_webauthn, "verify_authentication", _raise)
    with pytest.raises(ValueError):
        await login_challenge_complete(
            login_id=begin.login_id,
            credential=credential,
            config=_CONFIG,
            credential_public_key=b"pubkey",
            current_sign_count=0,
            now=_now(),
            store=store,
        )

    # Retry against the SAME login_id, this time verification succeeds.
    monkeypatch.setattr(
        stele_webauthn,
        "verify_authentication",
        lambda **kw: VerifiedAssertionData(credential_id=b"cred", new_sign_count=1),
    )
    result = await login_challenge_complete(
        login_id=begin.login_id,
        credential=credential,
        config=_CONFIG,
        credential_public_key=b"pubkey",
        current_sign_count=0,
        now=_now(),
        store=store,
    )
    assert result.new_sign_count == 1


async def test_login_challenge_expired_is_rejected():
    store = PendingLoginChallengeStore()
    begin = await login_challenge_begin(
        config=_CONFIG, allow_credentials=None, now=_now(), store=store
    )
    past_ttl = _now() + timedelta(minutes=10)  # LOGIN_CHALLENGE_PENDING_TTL is 5 minutes
    with pytest.raises(LoginChallengeNotFound):
        await login_challenge_complete(
            login_id=begin.login_id,
            credential={"id": "x", "rawId": "x", "response": {}, "type": "public-key"},
            config=_CONFIG,
            credential_public_key=b"pubkey",
            current_sign_count=0,
            now=past_ttl,
            store=store,
        )


async def test_login_challenge_unknown_id_is_rejected():
    store = PendingLoginChallengeStore()
    with pytest.raises(LoginChallengeNotFound):
        await login_challenge_complete(
            login_id="login_does_not_exist",
            credential={"id": "x", "rawId": "x", "response": {}, "type": "public-key"},
            config=_CONFIG,
            credential_public_key=b"pubkey",
            current_sign_count=0,
            now=_now(),
            store=store,
        )
