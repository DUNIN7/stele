# SPDX-License-Identifier: Apache-2.0
"""The Stele reference host — a minimal standalone FastAPI app.

What it demonstrates:
  - Mounting ``stele.router`` (the 8 credential-backed enrollment routes) with
    just two required providers: a DB session and a WebAuthn config. The
    passkey-enrollment ceremony is Stele's own, so the host supplies no ceremony.
  - Both delivery shapes over one Stele-minted token: a browser uses the session
    **cookie**; an agent sends ``Authorization: Bearer``. The single ``extract_token``
    override reads the cookie if present, else the bearer header.
  - Enrollment AND login. Enrollment is the mounted routes. Login is host
    composition over Stele primitives: passkey assertion → second factor
    (TOTP or a recovery code) → full session. Login-TOTP is composed here
    (kek_decrypt the secret, then pyotp verify) — Stele's surface does not grow.
  - Seed alignment: NO email as identity. Sign-in keys on credentials only; the app
    collects a display name, never an email, and never looks anyone up by email.
  - CSRF as a host responsibility (TS-16): a double-submit-cookie token gates every
    state-changing route reachable by cookie delivery. Stele mints no CSRF token of
    its own — same boundary as the session cookie itself (§ delivery, above).

This file is deliberately one module: a stranger reads it top to bottom and sees
exactly what a real mount takes.
"""
from __future__ import annotations

import json
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

import pyotp
from fastapi import Body, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn.helpers import base64url_to_bytes

import stele
from stele import credentials as credentials_registry
from stele import person_totp
from stele import recovery as recovery_codes
from stele.kek import EnvKeyEncryptionKeyProvider, kek_decrypt
from stele.registry import get_principal_by_id, mint_principal
from stele.session import issue_session, resolve_session
from stele.webauthn import (
    LoginChallengeNotFound,
    PendingLoginChallengeStore,
    WebauthnConfig,
    begin_registration,
    login_challenge_begin,
    login_challenge_complete,
    verify_registration,
)

from reference_app.config import load_settings
from reference_app.db import (
    make_engine,
    make_provide_db_session,
    make_session_factory,
)

_PENDING_TTL = timedelta(minutes=5)
_STATIC_DIR = Path(__file__).parent / "static"
_CSRF_HEADER = "X-CSRF-Token"

logger = logging.getLogger("reference_app")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Tiny in-process pending store for the signup-registration ceremony (a
# host-composed flow — no principal row exists yet to bind the challenge to,
# so it doesn't fit Stele's own login-challenge primitive). A single-process
# reference app; a real multi-process host would back this with Redis/Postgres.
# Login's pending challenge now uses Stele's own core PendingLoginChallengeStore
# (TS-06) instead of duplicating this shape.
# ---------------------------------------------------------------------------
@dataclass
class _SignupPending:
    challenge: bytes
    display_name: str
    totp_secret: str
    expires_at: datetime


class _PendingStore:
    def __init__(self) -> None:
        self._records: dict[str, Any] = {}

    def put(self, key: str, value: Any) -> None:
        self._records[key] = value

    def take(self, key: str, *, now: datetime) -> Any:
        record = self._records.pop(key, None)
        if record is None or record.expires_at <= now:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No such pending ceremony (unknown or expired).",
            )
        return record


def build_app() -> FastAPI:
    settings = load_settings()
    if not settings.rp_origin.startswith("https"):
        logger.warning(
            "STELE_RP_ORIGIN=%r is not https — the session and CSRF cookies will "
            "be set without the Secure flag. Fine for local development, never "
            "for a deployed host.",
            settings.rp_origin,
        )
    engine = make_engine(settings.database_url)
    session_factory = make_session_factory(engine)
    provide_db_session = make_provide_db_session(session_factory)
    webauthn_config = WebauthnConfig(
        rp_id=settings.rp_id, rp_name=settings.rp_name, rp_origin=settings.rp_origin
    )

    signup_pending = _PendingStore()
    login_challenge_store = PendingLoginChallengeStore()

    app = FastAPI(title="Stele reference host")

    # --- mount Stele's enrollment router -----------------------------------
    app.include_router(stele.router, prefix="/me/security")

    # The ONE delivery seam: cookie first (browser), then bearer (agent). Stele's
    # default extract_token is bearer-only; this override adds cookie support so a
    # single mount serves both shapes off the same Stele-minted token.
    async def extract_token(request: Request) -> Optional[str]:
        cookie = request.cookies.get(settings.cookie_name)
        if cookie:
            return cookie
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() == "bearer" and token:
            return token
        return None

    # The post-lift mount: two required slots + the delivery + secret. The
    # resolver stays Stele's default (it gates totp_verified — a partial session
    # cannot reach the enrollment routes). provide_person_email stays its None
    # default: no email as identity (seed alignment).
    app.dependency_overrides[stele.provide_db_session] = provide_db_session
    app.dependency_overrides[stele.provide_webauthn_config] = lambda: webauthn_config
    app.dependency_overrides[stele.provide_secret_key] = lambda: settings.secret_key
    app.dependency_overrides[stele.extract_token] = extract_token

    # The composed routes use the same request-scoped session dependency.
    db_dep = provide_db_session

    def _set_session_cookie(response: Response, token: str) -> None:
        response.set_cookie(
            key=settings.cookie_name,
            value=token,
            httponly=True,
            samesite="lax",
            secure=settings.rp_origin.startswith("https"),
            max_age=24 * 3600,
            path="/",
        )

    # --- CSRF (TS-16): double-submit cookie ---------------------------------
    # Stele mints no CSRF token — the same boundary as the session cookie itself
    # (docs § "Delivery: cookie or bearer, your choice"). Defense is the host's:
    # a non-HttpOnly cookie the page's own JS can read, echoed back as a header a
    # cross-site page cannot forge (same-origin policy blocks reading the cookie).
    def _issue_csrf_cookie(response: Response) -> None:
        response.set_cookie(
            key=settings.csrf_cookie_name,
            value=secrets.token_urlsafe(32),
            httponly=False,
            samesite="lax",
            secure=settings.rp_origin.startswith("https"),
            max_age=24 * 3600,
            path="/",
        )

    def _require_csrf(request: Request) -> None:
        """Gate for the 7 state-changing routes below. Only enforced for
        cookie-delivered calls — a caller presenting its own Authorization:
        Bearer header cannot be forged into doing so by a cross-site page, so
        bearer delivery is immune to CSRF by construction and is exempt."""
        header = request.headers.get("Authorization", "")
        scheme, _, _ = header.partition(" ")
        if scheme.lower() == "bearer":
            return
        cookie_token = request.cookies.get(settings.csrf_cookie_name)
        header_token = request.headers.get(_CSRF_HEADER)
        if not cookie_token or not header_token or not secrets.compare_digest(
            cookie_token, header_token
        ):
            raise HTTPException(status_code=403, detail="Missing or invalid CSRF token.")

    # =====================================================================
    # Signup — host composition over Stele primitives (create principal +
    # first passkey + TOTP + recovery codes). Two steps: begin issues the
    # WebAuthn challenge and a fresh TOTP secret; complete verifies both and
    # mints the account.
    # =====================================================================
    @app.post("/auth/signup/begin", dependencies=[Depends(_require_csrf)])
    async def signup_begin(display_name: str = Body(..., embed=True)) -> dict:
        if not display_name or not display_name.strip():
            raise HTTPException(status_code=400, detail="display_name is required.")
        challenge = begin_registration(
            config=webauthn_config,
            user_name=display_name,  # NOT an email — no email as identity
            user_display_name=display_name,
            exclude_credentials=None,
        )
        totp_secret = pyotp.random_base32()
        provisioning_uri = pyotp.TOTP(totp_secret).provisioning_uri(
            name=display_name, issuer_name=settings.rp_name
        )
        signup_id = f"su_{secrets.token_urlsafe(24)}"
        signup_pending.put(
            signup_id,
            _SignupPending(
                challenge=challenge.challenge,
                display_name=display_name,
                totp_secret=totp_secret,
                expires_at=_now() + _PENDING_TTL,
            ),
        )
        return {
            "signup_id": signup_id,
            "options": json.loads(challenge.options_json),
            "totp_secret": totp_secret,
            "totp_provisioning_uri": provisioning_uri,
        }

    @app.post("/auth/signup/complete", dependencies=[Depends(_require_csrf)])
    async def signup_complete(
        response: Response,
        signup_id: str = Body(...),
        credential: dict = Body(...),
        totp_code: str = Body(...),
        db: AsyncSession = Depends(db_dep),
    ) -> dict:
        pending = signup_pending.take(signup_id, now=_now())
        # TS-11: no PrincipalRow exists yet at this point, so there is no
        # last-accepted step to check against here — the step this verify
        # accepts is threaded into mint_principal below, which seeds it, so
        # this same code can't be replayed at the first login afterward.
        try:
            totp_step = person_totp.verify_totp_step(
                secret=pending.totp_secret, code=totp_code, last_step=None, now=_now(),
            )
        except person_totp.PersonTotpCodeInvalid:
            raise HTTPException(status_code=400, detail="Authenticator code did not verify.")
        verified = verify_registration(
            config=webauthn_config,
            credential=credential,
            expected_challenge=pending.challenge,
        )
        person, codes = await mint_principal(
            display_name=pending.display_name,
            totp_secret_plaintext=pending.totp_secret,
            totp_last_step=totp_step,
            passkey_credential=verified,
            secret_key=settings.secret_key,
            now=_now(),
            db=db,
        )
        await db.commit()
        _, token = issue_session(
            person_id=person.id, totp_verified=True,
            secret_key=settings.secret_key, now=_now(),
        )
        _set_session_cookie(response, token)
        _issue_csrf_cookie(response)  # rotate at the anonymous→authenticated boundary
        # recovery_codes shown exactly once; token returned so an agent caller can
        # use the bearer shape too.
        return {"person_id": str(person.id), "recovery_codes": codes, "session_token": token}

    # =====================================================================
    # Login — host composition. Passkey assertion (factor 1) → partial session;
    # then TOTP or a recovery code (factor 2) → full session.
    # =====================================================================
    @app.post("/auth/login/begin", dependencies=[Depends(_require_csrf)])
    async def login_begin() -> dict:
        result = await login_challenge_begin(
            config=webauthn_config,
            allow_credentials=None,
            now=_now(),
            store=login_challenge_store,
        )
        return {"login_id": result.login_id, "options": json.loads(result.options_json)}

    @app.post("/auth/login/passkey", dependencies=[Depends(_require_csrf)])
    async def login_passkey(
        response: Response,
        login_id: str = Body(...),
        credential: dict = Body(...),
        db: AsyncSession = Depends(db_dep),
    ) -> dict:
        raw = credential.get("rawId") or credential.get("id")
        if not raw:
            raise HTTPException(status_code=400, detail="Assertion missing credential id.")
        cred = await credentials_registry.get_credential_by_credential_id(
            credential_id=base64url_to_bytes(raw), db=db
        )
        if cred is None:
            raise HTTPException(status_code=401, detail="Unknown credential.")
        try:
            assertion = await login_challenge_complete(
                login_id=login_id,
                credential=credential,
                config=webauthn_config,
                credential_public_key=cred.public_key,
                current_sign_count=cred.sign_count,
                now=_now(),
                store=login_challenge_store,
            )
        except LoginChallengeNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        await credentials_registry.update_sign_count(
            credential_id=cred.credential_id, new_sign_count=assertion.new_sign_count, db=db
        )
        await db.commit()
        # Factor 1 done — issue a PARTIAL session (totp_verified=False). It carries
        # the person_id for factor 2 but cannot reach the gated enrollment routes.
        _, partial = issue_session(
            person_id=cred.person_id, totp_verified=False,
            secret_key=settings.secret_key, now=_now(),
        )
        _set_session_cookie(response, partial)
        _issue_csrf_cookie(response)  # rotate at the anonymous→partial-session boundary
        return {"next": "second-factor", "session_token": partial}

    async def _principal_id_from_partial(request: Request, db: AsyncSession) -> UUID:
        token = request.cookies.get(settings.cookie_name) or ""
        if not token:
            header = request.headers.get("Authorization", "")
            scheme, _, bearer = header.partition(" ")
            token = bearer if scheme.lower() == "bearer" else ""
        resolved = await resolve_session(token, secret_key=settings.secret_key, now=_now(), db=db)
        if resolved is None:
            raise HTTPException(status_code=401, detail="No partial session — begin login first.")
        return resolved.principal.id

    @app.post("/auth/login/totp", dependencies=[Depends(_require_csrf)])
    async def login_totp(
        request: Request,
        response: Response,
        code: str = Body(..., embed=True),
        db: AsyncSession = Depends(db_dep),
    ) -> dict:
        person_id = await _principal_id_from_partial(request, db)
        principal_row = (await get_principal_by_id(person_id=person_id, db=db))
        if principal_row is None:
            raise HTTPException(status_code=401, detail="Unknown principal.")
        # Login-TOTP is composed host-side (CR §0.5): decrypt the stored secret,
        # then verify the code via the shared person_totp.verify_totp_step
        # primitive (TS-11) — Stele owns no login route of its own.
        from stele.models import PrincipalRow
        from sqlalchemy import select
        row = (await db.execute(select(PrincipalRow).where(PrincipalRow.id == person_id))).scalar_one()
        if not row.totp_secret:
            raise HTTPException(status_code=400, detail="No authenticator enrolled.")
        secret = kek_decrypt(row.totp_secret, EnvKeyEncryptionKeyProvider(secret_key=settings.secret_key))
        try:
            step = person_totp.verify_totp_step(
                secret=secret, code=code, last_step=row.totp_last_step, now=_now(),
            )
        except person_totp.PersonTotpCodeInvalid:
            raise HTTPException(status_code=400, detail="Authenticator code did not verify.")
        row.totp_last_step = step
        await db.commit()
        _, token = issue_session(
            person_id=person_id, totp_verified=True,
            secret_key=settings.secret_key, now=_now(),
        )
        _set_session_cookie(response, token)
        _issue_csrf_cookie(response)  # rotate at the partial→full-session boundary
        return {"ok": True, "session_token": token}

    @app.post("/auth/login/recovery", dependencies=[Depends(_require_csrf)])
    async def login_recovery(
        request: Request,
        response: Response,
        code: str = Body(..., embed=True),
        db: AsyncSession = Depends(db_dep),
    ) -> dict:
        person_id = await _principal_id_from_partial(request, db)
        ok = await recovery_codes.verify_and_consume_recovery_code(
            person_id=person_id, code=code, db=db
        )
        await db.commit()
        if not ok:
            raise HTTPException(status_code=400, detail="Recovery code did not verify.")
        _, token = issue_session(
            person_id=person_id, totp_verified=True,
            secret_key=settings.secret_key, now=_now(),
        )
        _set_session_cookie(response, token)
        _issue_csrf_cookie(response)  # rotate at the partial→full-session boundary
        return {"ok": True, "session_token": token}

    @app.post("/auth/logout", dependencies=[Depends(_require_csrf)])
    async def logout(response: Response) -> dict:
        response.delete_cookie(key=settings.cookie_name, path="/")
        response.delete_cookie(key=settings.csrf_cookie_name, path="/")
        return {"ok": True}

    @app.get("/auth/whoami")
    async def whoami(request: Request, db: AsyncSession = Depends(db_dep)) -> dict:
        token = await extract_token(request)
        resolved = await resolve_session(token or "", secret_key=settings.secret_key, now=_now(), db=db)
        if resolved is None:
            return {"authenticated": False}
        return {
            "authenticated": True,
            "person_id": str(resolved.principal.id),
            "display_name": resolved.principal.display_name,
            "totp_verified": resolved.payload.totp_verified,
        }

    # --- the browser front -------------------------------------------------
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    @app.get("/")
    async def index() -> FileResponse:
        response = FileResponse(str(_STATIC_DIR / "index.html"))
        # Bootstraps the double-submit cookie before any mutating call: by the
        # time app.js fires its first POST, the CSRF cookie already exists to echo.
        _issue_csrf_cookie(response)
        return response

    return app


app = build_app()
