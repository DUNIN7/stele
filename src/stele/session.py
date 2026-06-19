"""Person-scoped session model (Phase 14 §7.5).

A session is a Fernet-encrypted JSON payload — signature and integrity
are both provided by Fernet's AEAD construction. The cookie value IS
the Fernet token; no server-side state is required to validate.

The payload carries:
- person_id: the authenticated person.
- totp_verified: True after the second factor verifies; the auth
  middleware refuses requests carrying partial sessions on protected
  routes.
- created_at / expires_at: lifecycle timestamps.

A separate cookie is used for the partial session (the value of the
intermediate token issued by /auth/login/complete). Step 5 does not
re-issue it; the partial session lives in PartialSessionStore and the
client passes the token in JSON body to /totp-verify or /recovery.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from cryptography.fernet import InvalidToken
from sqlalchemy.ext.asyncio import AsyncSession

from loomworks.credentials.envelope import kek_multifernet
from loomworks.credentials.kek import EnvKeyEncryptionKeyProvider
from loomworks.stele.registry import (
    Principal,
    get_principal_by_id,
)

DEFAULT_SESSION_TTL = timedelta(hours=24)
COOKIE_NAME = "loomworks_session"


class SessionInvalid(Exception):
    """The session cookie is missing, malformed, expired, or tampered."""


@dataclass(frozen=True)
class SessionPayload:
    person_id: UUID
    totp_verified: bool
    created_at: datetime
    expires_at: datetime


def encode_session(payload: SessionPayload, *, secret_key: str) -> str:
    """Serialize and encrypt the payload. The result is the cookie value.

    Encrypted under the KEK MultiFernet (CR-2026-102 Level A): writes use the
    current key; decode tries all keys, so a key rotation does not invalidate
    live sessions. Sessions are stateless cookies — never the DEK envelope."""
    body = json.dumps(
        {
            "person_id": str(payload.person_id),
            "totp_verified": payload.totp_verified,
            "created_at": payload.created_at.isoformat(),
            "expires_at": payload.expires_at.isoformat(),
        }
    )
    return (
        kek_multifernet(EnvKeyEncryptionKeyProvider(secret_key=secret_key))
        .encrypt(body.encode())
        .decode()
    )


def decode_session(
    token: str, *, secret_key: str, now: datetime
) -> SessionPayload:
    """Decrypt + validate the cookie. Raises SessionInvalid on any
    failure (bad MAC, malformed, expired)."""
    if not token:
        raise SessionInvalid("session cookie missing")
    try:
        body = kek_multifernet(
            EnvKeyEncryptionKeyProvider(secret_key=secret_key)
        ).decrypt(token.encode())
    except InvalidToken as exc:
        raise SessionInvalid("session token is malformed or tampered") from exc
    try:
        data = json.loads(body)
        payload = SessionPayload(
            person_id=UUID(data["person_id"]),
            totp_verified=bool(data["totp_verified"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise SessionInvalid("session payload shape is invalid") from exc

    if payload.expires_at <= now:
        raise SessionInvalid("session has expired")
    return payload


def issue_session(
    *,
    person_id: UUID,
    totp_verified: bool,
    secret_key: str,
    now: datetime,
    ttl: Optional[timedelta] = None,
) -> tuple[SessionPayload, str]:
    """Build a fresh SessionPayload + the corresponding cookie token."""
    ttl = ttl or DEFAULT_SESSION_TTL
    payload = SessionPayload(
        person_id=person_id,
        totp_verified=totp_verified,
        created_at=now,
        expires_at=now + ttl,
    )
    return payload, encode_session(payload, secret_key=secret_key)


@dataclass(frozen=True)
class ResolvedSession:
    """The result of resolving a session token (CR-2026-106, Phase 3).

    Carries the principal and the decoded payload, so the host can
    apply its own policy (the second-factor gate) off ``payload.totp_verified``
    without re-decoding. ``resolve_session`` reports what it found; the host
    decides what to do with it.

    Step 3.7 (CR-2026-110): the transitional ``person`` field (the retired
    ``Person`` shim) was dropped; only ``principal`` remains.
    """

    principal: Principal
    payload: SessionPayload


async def resolve_session(
    token: str, *, secret_key: str, now: datetime, db: AsyncSession
) -> "ResolvedSession | None":
    """Resolve a session token to its principal + payload — the
    host-agnostic "who is this session?" primitive realizing the
    integration design's ``session.resolve`` (CR-2026-106, Phase 3).

    Decodes the token and loads the principal. Returns a ``ResolvedSession``
    (carrying the ``Principal`` and the decoded ``SessionPayload``) on success,
    or ``None`` if the token is missing/malformed/expired/tampered or the
    principal no longer exists.

    Contract boundary: this primitive NEVER raises ``HTTPException`` and
    NEVER propagates :class:`SessionInvalid` (it catches it and reports
    ``None``). It does NOT apply the ``totp_verified`` gate — it only
    *carries* ``payload.totp_verified`` so the host wrapper can decide
    whether an unverified second factor is acceptable. Raise-vs-tolerate
    and the second-factor policy stay host-side.
    """
    try:
        payload = decode_session(token, secret_key=secret_key, now=now)
    except SessionInvalid:
        return None
    principal = await get_principal_by_id(
        person_id=payload.person_id, db=db
    )
    if principal is None:
        return None
    return ResolvedSession(principal=principal, payload=payload)
