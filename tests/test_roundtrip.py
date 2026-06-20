"""P117-3 — one ASGI round-trip through the real mounted reference host.

Drives the §3 host-composed flow end-to-end (signup -> login by passkey+TOTP ->
mounted enrollment route -> recovery login -> logout) over httpx + ASGITransport
against the test Postgres. The app shares the suite's engine (the conftest ``engine``
fixture is injected into the app via ``make_engine``, so app and suite hit one DB),
and the two WebAuthn library verifies are stubbed in ``reference_app.main`` — the
module that binds them — since no authenticator exists in CI.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import httpx
import pyotp
import pytest_asyncio
from cryptography.fernet import Fernet
from httpx import ASGITransport
from webauthn.helpers import bytes_to_base64url

from stele.webauthn import VerifiedAssertionData, VerifiedCredentialData

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "examples"))

_RP_ORIGIN = "http://localhost:8000"
_APP_SECRET_KEY = Fernet.generate_key().decode()


@pytest_asyncio.fixture
async def mounted(database_url, _migrated_database, engine, monkeypatch):
    """Build the real reference app sharing the suite's engine (one DB), with the
    two WebAuthn verifies stubbed where the app binds them. Returns (app, credential_id)."""
    monkeypatch.setenv("STELE_DATABASE_URL", database_url)
    monkeypatch.setenv("STELE_SECRET_KEY", _APP_SECRET_KEY)
    monkeypatch.setenv("STELE_RP_ID", "localhost")
    monkeypatch.setenv("STELE_RP_NAME", "Stele Test RP")
    monkeypatch.setenv("STELE_RP_ORIGIN", _RP_ORIGIN)

    # Share the suite's engine: patch make_engine in db (for a first import) and in
    # main (which binds its own reference) so the whole app runs on one test engine.
    import reference_app.db as refdb
    monkeypatch.setattr(refdb, "make_engine", lambda url: engine)
    import reference_app.main as refmain
    monkeypatch.setattr(refmain, "make_engine", lambda url: engine)

    cid = os.urandom(32)
    monkeypatch.setattr(
        refmain,
        "verify_registration",
        lambda **kw: VerifiedCredentialData(
            credential_id=cid, public_key=os.urandom(91), sign_count=0, transports=["internal"]
        ),
    )
    monkeypatch.setattr(
        refmain,
        "verify_authentication",
        lambda **kw: VerifiedAssertionData(credential_id=cid, new_sign_count=1),
    )
    return refmain.build_app(), cid


def _credential(cid: bytes) -> dict:
    b64 = bytes_to_base64url(cid)
    return {"id": b64, "rawId": b64, "response": {}, "type": "public-key"}


async def test_full_round_trip(db, mounted):
    app, cid = mounted
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=_RP_ORIGIN) as client:
        # 1. signup begin -> registration challenge
        r = await client.post("/auth/signup/begin", json={"display_name": "Round Trip"})
        assert r.status_code == 200, r.text
        begin = r.json()
        assert "challenge" in begin["options"]
        signup_id = begin["signup_id"]
        totp_secret = begin["totp_secret"]

        # 2. signup complete (canned attestation) -> full session + recovery codes
        r = await client.post(
            "/auth/signup/complete",
            json={
                "signup_id": signup_id,
                "credential": _credential(cid),
                "totp_code": pyotp.TOTP(totp_secret).now(),
            },
        )
        assert r.status_code == 200, r.text
        done = r.json()
        assert len(done["recovery_codes"]) == 10
        recovery_code = done["recovery_codes"][0]
        who = (await client.get("/auth/whoami")).json()
        assert who["authenticated"] is True and who["totp_verified"] is True

        # 3. login begin -> discoverable (no allowCredentials in the options)
        r = await client.post("/auth/login/begin")
        assert r.status_code == 200, r.text
        login = r.json()
        assert not login["options"].get("allowCredentials")
        login_id = login["login_id"]

        # 4. login passkey -> partial session; a partial session cannot reach enrollment
        r = await client.post(
            "/auth/login/passkey",
            json={"login_id": login_id, "credential": _credential(cid)},
        )
        assert r.status_code == 200 and r.json()["next"] == "second-factor", r.text
        gated = await client.get("/me/security/passkeys")
        assert gated.status_code == 401, ("partial session must be gated", gated.status_code)

        # 5. login totp -> full session
        r = await client.post("/auth/login/totp", json={"code": pyotp.TOTP(totp_secret).now()})
        assert r.status_code == 200, r.text

        # 6. mounted enrollment route through stele.router with the full session
        r = await client.get("/me/security/passkeys")
        assert r.status_code == 200, r.text
        passkeys = r.json()
        assert len(passkeys) == 1

        # 7. recovery factor: a fresh login consuming a recovery code -> full session
        login_id_2 = (await client.post("/auth/login/begin")).json()["login_id"]
        await client.post(
            "/auth/login/passkey",
            json={"login_id": login_id_2, "credential": _credential(cid)},
        )
        r = await client.post("/auth/login/recovery", json={"code": recovery_code})
        assert r.status_code == 200, r.text
        who = (await client.get("/auth/whoami")).json()
        assert who["authenticated"] is True and who["totp_verified"] is True

        # 8. logout -> the session no longer resolves
        await client.post("/auth/logout")
        who = (await client.get("/auth/whoami")).json()
        assert who["authenticated"] is False


async def test_mounted_totp_rotate_issuer_is_rp_name(db, mounted):
    """The mounted /totp/rotate/begin route carries the host's WebauthnConfig.rp_name
    as the authenticator issuer — the seam end-to-end through the mount (not 'Stele',
    not a hardcoded brand)."""
    from urllib.parse import parse_qs, urlparse

    app, cid = mounted
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=_RP_ORIGIN) as client:
        begin = (await client.post("/auth/signup/begin", json={"display_name": "Rotate RP"})).json()
        await client.post(
            "/auth/signup/complete",
            json={
                "signup_id": begin["signup_id"],
                "credential": _credential(cid),
                "totp_code": pyotp.TOTP(begin["totp_secret"]).now(),
            },
        )
        r = await client.post("/me/security/totp/rotate/begin")
        assert r.status_code == 200, r.text
        uri = r.json()["provisioning_uri"]
        assert parse_qs(urlparse(uri).query)["issuer"][0] == "Stele Test RP"
