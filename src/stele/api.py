"""Stele's mountable primitive HTTP surface (Phase 7 P7-2, CR-2026-115).

A FastAPI ``APIRouter`` carrying the **direct-primitive** account-security
endpoints — passkey enrollment, recovery codes, TOTP rotation — generalized from
the engine's ``me_security`` router into a host-agnostic, mountable shape. A host
mounts it with ``include_router(stele.api.router, prefix=...)`` and supplies a
small, named set of dependencies (the injection contract below).

**The authorization boundary (stated, not silent).** This router ships
*authentication* primitives: it proves credential control and operates on the
authenticated principal's own credentials. It does **not** authorize — it does
not decide *what a principal may reach*. The host owns authorization; the seam is
``resolve_current_principal`` (the host supplies the resolver that carries its
policy gate). Stele resolves *who*; the host gates *what-here*.

**Session delivery is host-pluggable, not cookie-bound.** ``stele.session
.resolve_session`` takes a raw token and never reads a cookie. ``extract_token``
is the host's slot for *how* the token arrives (cookie for a UI, ``Authorization:
Bearer`` for an agent). The shipped default extracts a bearer token — a neutral,
non-cookie default the host overrides for cookie delivery. Stele takes no
delivery position.

**Mounting.** Override the injection slots via ``app.dependency_overrides`` (or
the override providers a future ``get_router(...)`` factory wires — §3). The slots
that have no safe default raise ``NotImplementedError`` until overridden, so a
half-wired mount fails loudly at request time rather than silently.
"""
from __future__ import annotations

from datetime import datetime, timezone
from json import loads as json_loads
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from stele import credentials as credentials_registry
from stele import person_totp
from stele import recovery as recovery_codes
from stele.kek import EnvKeyEncryptionKeyProvider
from stele.registry import Principal
from stele.session import resolve_session
from stele.webauthn import (
    PasskeyEnrollmentError,
    PasskeyEnrollmentNotFound,
    WebauthnConfig,
    add_passkey_begin,
    add_passkey_complete,
    pending_add_passkey_store,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ===========================================================================
# Injection slots — the SDK contract. Override via app.dependency_overrides.
#   - No-safe-default slots raise NotImplementedError until the host overrides.
#   - resolve_current_principal / extract_token / provide_secret_key /
#     provide_person_email ship usable defaults the reference app can run on.
# ===========================================================================


async def provide_db_session() -> AsyncSession:
    """Slot — the host yields a request-scoped ``AsyncSession``. No default."""
    raise NotImplementedError(
        "Mount stele.api: override provide_db_session to yield an AsyncSession."
    )


async def provide_secret_key() -> str:
    """Slot — the KEK/secret. Default reads Stele's own env (STELE_SECRET_KEY
    once §2 lands; the engine overrides this to inject its own secret)."""
    key = EnvKeyEncryptionKeyProvider().current_kek_material()
    if not key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No secret key configured for Stele's KEK.",
        )
    return key


async def provide_webauthn_config() -> WebauthnConfig:
    """Slot — the relying-party WebAuthn config. No default (host-specific rp_id
    / rp_origin)."""
    raise NotImplementedError(
        "Mount stele.api: override provide_webauthn_config to return a WebauthnConfig."
    )


async def extract_token(request: Request) -> Optional[str]:
    """Slot — how the session token arrives. Default: ``Authorization: Bearer``
    (neutral, non-cookie). Override for cookie delivery (a UI host)."""
    header = request.headers.get("Authorization")
    if header:
        scheme, _, token = header.partition(" ")
        if scheme.lower() == "bearer" and token:
            return token
    return None


async def resolve_current_principal(
    token: Optional[str] = Depends(extract_token),
    secret_key: str = Depends(provide_secret_key),
    db: AsyncSession = Depends(provide_db_session),
) -> Principal:
    """Stele's DEFAULT current-principal resolver — over the neutral
    ``resolve_session``. Gates a verified second factor (a partial session is not
    fully authenticated). The host OVERRIDES this whole slot to carry its own
    policy gate (its membership / account-status / host_account checks)."""
    resolved = await resolve_session(
        token or "", secret_key=secret_key, now=_now(), db=db
    )
    if resolved is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required (no valid session).",
        )
    if not resolved.payload.totp_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Second factor not verified.",
        )
    return resolved.principal


async def provide_person_email(
    principal: Principal = Depends(resolve_current_principal),
) -> Optional[str]:
    """Slot — the caller's email, used ONLY by passkeys/begin (the WebAuthn
    user.name). Narrow + optional: defaults to ``None`` so the router depends on
    no host_account view shape. A host that wants the email in the authenticator
    label overrides this to look it up for ``principal.id``."""
    return None


# ===========================================================================
# Request / response models (lifted from the engine's me_security shapes).
# ===========================================================================


class PasskeyBeginResponse(BaseModel):
    add_id: str = Field(..., title="Add id", description="Opaque handle for this in-progress passkey registration; send it back to complete.")
    options: dict[str, Any] = Field(..., title="Options", description="Passkey creation options for the browser's credential-create call.")


class PasskeyCompleteRequest(BaseModel):
    add_id: str = Field(..., title="Add id", description="The handle returned when registration began.")
    credential: dict[str, Any] = Field(..., title="Credential", description="The signed result of the browser's passkey-creation prompt.")
    display_name: Optional[str] = Field(None, title="Name", description="Optional label for this passkey.")


class PasskeyCompleteResponse(BaseModel):
    id: UUID = Field(..., title="Passkey id", description="The newly registered passkey's identifier.")


class PasskeyListItem(BaseModel):
    id: UUID = Field(..., title="Passkey id", description="Stable identifier for this passkey.")
    display_name: Optional[str] = Field(None, title="Name", description="The label given to this passkey, if any.")
    created_at: datetime = Field(..., title="Registered", description="When this passkey was registered.")
    transports: Optional[list[str]] = Field(None, title="Transports", description="How this authenticator connects, if reported.")


class PasskeyRevokeResponse(BaseModel):
    id: UUID = Field(..., title="Removed passkey id", description="The identifier of the passkey that was removed.")


class RecoveryCodesStatusResponse(BaseModel):
    unused_count: int = Field(..., title="Unused codes", description="How many recovery codes can still be used.")
    total: int = Field(..., title="Current set size", description="Codes in the current set (used + unused).")


class RecoveryCodesRegenerateResponse(BaseModel):
    codes: list[str] = Field(..., title="Recovery codes", description="A fresh set, shown exactly once; previous codes are revoked.")


class TotpRotateBeginResponse(BaseModel):
    secret: str = Field(..., title="New secret", description="The fresh base32 TOTP secret; the current secret is unchanged until confirm.")
    provisioning_uri: str = Field(..., title="Provisioning URI", description="The otpauth:// URL the UI renders as a QR code.")


class TotpRotateConfirmRequest(BaseModel):
    secret: str = Field(..., title="New secret", description="The secret returned by begin.")
    code: str = Field(..., title="Code", description="A current code from the new secret.")


class TotpRotateConfirmResponse(BaseModel):
    rotated: bool = Field(..., title="Rotated", description="True once the TOTP secret has been replaced.")


# ===========================================================================
# The mountable router — 8 credential-backed primitive routes. Resource-relative
# paths; the host chooses the mount prefix (e.g. include_router(router,
# prefix="/me/security")).
# ===========================================================================

router = APIRouter(tags=["stele-security"])


@router.post("/passkeys/begin", response_model=PasskeyBeginResponse, summary="Begin registering an additional passkey")
async def passkey_begin(
    principal: Principal = Depends(resolve_current_principal),
    person_email: Optional[str] = Depends(provide_person_email),
    db: AsyncSession = Depends(provide_db_session),
    config: WebauthnConfig = Depends(provide_webauthn_config),
) -> PasskeyBeginResponse:
    existing = await credentials_registry.list_credentials_for_person(
        person_id=principal.id, db=db
    )
    result = await add_passkey_begin(
        person_id=principal.id,
        person_display_name=principal.display_name,
        person_email=person_email,
        config=config,
        existing_credential_ids=[c.credential_id for c in existing],
        now=_now(),
    )
    return PasskeyBeginResponse(add_id=result.add_id, options=json_loads(result.options_json))


@router.post("/passkeys/complete", response_model=PasskeyCompleteResponse, summary="Finish registering an additional passkey")
async def passkey_complete(
    body: PasskeyCompleteRequest,
    principal: Principal = Depends(resolve_current_principal),
    db: AsyncSession = Depends(provide_db_session),
    config: WebauthnConfig = Depends(provide_webauthn_config),
) -> PasskeyCompleteResponse:
    now = _now()
    # Security-critical bind: the add_id is a capability token, but persisting a
    # credential must depend on the token AND the session — a leaked add_id can
    # never bind a passkey to the wrong account. The ceremony's pending store is
    # Stele-internal (post-P7-3 lift); the router reaches it directly.
    try:
        pending = pending_add_passkey_store.get(body.add_id, now=now)
    except PasskeyEnrollmentNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if pending.person_id != principal.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This passkey registration belongs to a different account.",
        )
    try:
        new_id = await add_passkey_complete(
            add_id=body.add_id,
            credential=body.credential,
            config=config,
            db=db,
            now=now,
            display_name=body.display_name,
        )
    except PasskeyEnrollmentNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PasskeyEnrollmentError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    await db.commit()
    return PasskeyCompleteResponse(id=new_id)


@router.get("/passkeys", response_model=list[PasskeyListItem], summary="List my registered passkeys")
async def passkey_list(
    principal: Principal = Depends(resolve_current_principal),
    db: AsyncSession = Depends(provide_db_session),
) -> list[PasskeyListItem]:
    creds = await credentials_registry.list_credentials_for_person(person_id=principal.id, db=db)
    return [
        PasskeyListItem(id=c.id, display_name=c.display_name, created_at=c.created_at, transports=c.transports)
        for c in creds
    ]


@router.delete("/passkeys/{passkey_id}", response_model=PasskeyRevokeResponse, summary="Remove one of my passkeys")
async def passkey_revoke(
    passkey_id: UUID,
    principal: Principal = Depends(resolve_current_principal),
    db: AsyncSession = Depends(provide_db_session),
) -> PasskeyRevokeResponse:
    creds = await credentials_registry.list_credentials_for_person(person_id=principal.id, db=db)
    target = next((c for c in creds if c.id == passkey_id), None)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such passkey on this account.")
    try:
        await credentials_registry.remove_credential(
            person_id=principal.id, credential_id=target.credential_id, db=db
        )
    except credentials_registry.LastPasskeyError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await db.commit()
    return PasskeyRevokeResponse(id=passkey_id)


@router.post("/recovery-codes/regenerate", response_model=RecoveryCodesRegenerateResponse, summary="Regenerate my recovery codes")
async def recovery_codes_regenerate(
    principal: Principal = Depends(resolve_current_principal),
    db: AsyncSession = Depends(provide_db_session),
) -> RecoveryCodesRegenerateResponse:
    fresh = await recovery_codes.regenerate_recovery_codes(person_id=principal.id, db=db)
    await db.commit()
    return RecoveryCodesRegenerateResponse(codes=fresh)


@router.get("/recovery-codes", response_model=RecoveryCodesStatusResponse, summary="My recovery-code status")
async def recovery_codes_status(
    principal: Principal = Depends(resolve_current_principal),
    db: AsyncSession = Depends(provide_db_session),
) -> RecoveryCodesStatusResponse:
    unused = await recovery_codes.count_unused_recovery_codes(person_id=principal.id, db=db)
    total = await recovery_codes.count_active_recovery_codes(person_id=principal.id, db=db)
    return RecoveryCodesStatusResponse(unused_count=unused, total=total)


@router.post("/totp/rotate/begin", response_model=TotpRotateBeginResponse, summary="Begin rotating my authenticator")
async def totp_rotate_begin(
    principal: Principal = Depends(resolve_current_principal),
    db: AsyncSession = Depends(provide_db_session),
) -> TotpRotateBeginResponse:
    result = await person_totp.begin_totp_rotation(person_id=principal.id, db=db)
    return TotpRotateBeginResponse(secret=result.secret, provisioning_uri=result.provisioning_uri)


@router.post("/totp/rotate/confirm", response_model=TotpRotateConfirmResponse, summary="Confirm my new authenticator")
async def totp_rotate_confirm(
    body: TotpRotateConfirmRequest,
    principal: Principal = Depends(resolve_current_principal),
    db: AsyncSession = Depends(provide_db_session),
    secret_key: str = Depends(provide_secret_key),
) -> TotpRotateConfirmResponse:
    try:
        await person_totp.confirm_totp_rotation(
            person_id=principal.id, secret=body.secret, code=body.code, secret_key=secret_key, db=db
        )
    except person_totp.PersonTotpCodeInvalid as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    await db.commit()
    return TotpRotateConfirmResponse(rotated=True)
