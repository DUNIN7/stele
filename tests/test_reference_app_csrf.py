# SPDX-License-Identifier: Apache-2.0
"""TS-16 — CSRF (double-submit cookie) tests for the reference host's 7
state-changing routes: signup/begin, signup/complete, login/begin,
login/passkey, login/totp, login/recovery, logout.

Three of the seven never touch the DB (signup_begin, login_begin, logout), so
most cases here run against a bare ``app`` fixture pointed at the suite's
(unshared) throwaway DB. Only the rotation-on-success case needs ``mounted``
(same shape as test_roundtrip.py's fixture) to drive a real login/passkey call.
"""
from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pyotp
import pytest_asyncio
from cryptography.fernet import Fernet
from httpx import ASGITransport
from webauthn.helpers import bytes_to_base64url

import stele.webauthn as stele_webauthn
from stele.registry import mint_principal
from stele.webauthn import VerifiedAssertionData, VerifiedCredentialData

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "examples"))

_RP_ORIGIN = "http://localhost:8000"
_APP_SECRET_KEY = Fernet.generate_key().decode()
_CSRF_COOKIE = "stele_ref_csrf"
_CSRF_HEADER = "X-CSRF-Token"


@pytest_asyncio.fixture
async def app(database_url, _migrated_database, monkeypatch):
    """A built reference app pointed at the suite's throwaway DB — no engine
    sharing needed here, since every route this fixture backs (signup/begin,
    login/begin, logout) never touches the DB at all."""
    monkeypatch.setenv("STELE_DATABASE_URL", database_url)
    monkeypatch.setenv("STELE_SECRET_KEY", _APP_SECRET_KEY)
    monkeypatch.setenv("STELE_RP_ORIGIN", _RP_ORIGIN)
    import reference_app.main as refmain
    return refmain.build_app()


@pytest_asyncio.fixture
async def mounted(database_url, _migrated_database, engine, monkeypatch):
    """Same shape as test_roundtrip.py's fixture: the real app sharing the
    suite's engine, with the two WebAuthn library verifies stubbed."""
    monkeypatch.setenv("STELE_DATABASE_URL", database_url)
    monkeypatch.setenv("STELE_SECRET_KEY", _APP_SECRET_KEY)
    monkeypatch.setenv("STELE_RP_ORIGIN", _RP_ORIGIN)

    import reference_app.db as refdb
    monkeypatch.setattr(refdb, "make_engine", lambda url: engine)
    import reference_app.main as refmain
    monkeypatch.setattr(refmain, "make_engine", lambda url: engine)

    cid = os.urandom(32)
    monkeypatch.setattr(
        stele_webauthn,
        "verify_authentication",
        lambda **kw: VerifiedAssertionData(credential_id=cid, new_sign_count=1),
    )
    return refmain.build_app(), cid


def _credential(cid: bytes) -> dict:
    b64 = bytes_to_base64url(cid)
    return {"id": b64, "rawId": b64, "response": {}, "type": "public-key"}


async def test_index_mints_csrf_cookie(app):
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=_RP_ORIGIN) as client:
        r = await client.get("/")
        assert r.status_code == 200
        assert client.cookies.get(_CSRF_COOKIE)


async def test_signup_begin_rejects_missing_csrf_token(app):
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=_RP_ORIGIN) as client:
        r = await client.post("/auth/signup/begin", json={"display_name": "No CSRF"})
        assert r.status_code == 403


async def test_signup_begin_accepts_matching_cookie_and_header(app):
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=_RP_ORIGIN) as client:
        await client.get("/")  # mints the cookie, as a real browser page load would
        token = client.cookies.get(_CSRF_COOKIE)
        r = await client.post(
            "/auth/signup/begin",
            json={"display_name": "Has CSRF"},
            headers={_CSRF_HEADER: token},
        )
        assert r.status_code == 200, r.text


async def test_login_begin_rejects_mismatched_csrf_header(app):
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=_RP_ORIGIN) as client:
        await client.get("/")
        r = await client.post(
            "/auth/login/begin", headers={_CSRF_HEADER: "not-the-cookie-value"}
        )
        assert r.status_code == 403


async def test_logout_bearer_delivery_is_exempt_from_csrf(app):
    """A cross-site page cannot forge an Authorization header onto a request it
    triggers, so bearer-delivered calls are immune to CSRF by construction —
    the reference host exempts any request presenting Authorization: Bearer."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=_RP_ORIGIN) as client:
        r = await client.post("/auth/logout", headers={"Authorization": "Bearer whatever"})
        assert r.status_code == 200, r.text


async def test_logout_cookie_delivery_still_requires_csrf(app):
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=_RP_ORIGIN) as client:
        r = await client.post("/auth/logout")
        assert r.status_code == 403


async def test_logout_clears_both_session_and_csrf_cookies(app):
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=_RP_ORIGIN) as client:
        await client.get("/")
        token = client.cookies.get(_CSRF_COOKIE)
        r = await client.post("/auth/logout", headers={_CSRF_HEADER: token})
        assert r.status_code == 200, r.text
        assert _CSRF_COOKIE not in client.cookies


def test_build_app_warns_when_rp_origin_is_not_https(caplog, monkeypatch):
    """TS-16 step 1: build_app() logs a warning the moment it's configured
    against a non-https origin — no live DB connection needed to see it,
    since make_engine only constructs the (lazy) async engine."""
    monkeypatch.setenv("STELE_DATABASE_URL", "postgresql+asyncpg://unused/unused")
    monkeypatch.setenv("STELE_SECRET_KEY", _APP_SECRET_KEY)
    monkeypatch.setenv("STELE_RP_ORIGIN", "http://localhost:8000")
    import reference_app.main as refmain

    with caplog.at_level(logging.WARNING, logger="reference_app"):
        refmain.build_app()
    assert any("not https" in rec.message for rec in caplog.records)


async def test_csrf_cookie_rotates_on_successful_login(db, mounted):
    """TS-16: the token is reissued at the anonymous->partial-session boundary,
    not just minted once at page load — a pre-login token must not remain the
    live one after login/passkey succeeds."""
    app, cid = mounted
    await mint_principal(
        display_name="CSRF Rotate",
        totp_secret_plaintext=pyotp.random_base32(),
        passkey_credential=VerifiedCredentialData(
            credential_id=cid, public_key=os.urandom(91), sign_count=0, transports=["internal"]
        ),
        secret_key=_APP_SECRET_KEY,
        now=datetime.now(timezone.utc),
        db=db,
    )
    await db.commit()

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=_RP_ORIGIN) as client:
        await client.get("/")
        pre_login_token = client.cookies.get(_CSRF_COOKIE)

        login = (
            await client.post("/auth/login/begin", headers={_CSRF_HEADER: pre_login_token})
        ).json()
        r = await client.post(
            "/auth/login/passkey",
            json={"login_id": login["login_id"], "credential": _credential(cid)},
            headers={_CSRF_HEADER: pre_login_token},
        )
        assert r.status_code == 200, r.text
        assert client.cookies.get(_CSRF_COOKIE) != pre_login_token
