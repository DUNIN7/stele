"""Persistence layer for webauthn_credentials.

Pure CRUD against the WebauthnCredentialRow ORM. The cryptographic
ceremony lives in `stele.webauthn`; this module never touches the
WebAuthn library.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from stele.models import WebauthnCredentialRow


class LastPasskeyError(Exception):
    """Refused: removing this credential would leave the person with no
    passkey, and so no way to start a login. Raised by
    :func:`remove_credential`; the HTTP layer maps it to a 4xx conflict."""


@dataclass(frozen=True)
class WebauthnCredential:
    """Read-side view of a webauthn_credentials row. Public key included
    because the auth flow needs it to verify assertions; consumers must
    not surface it past the substrate boundary."""

    id: UUID
    person_id: UUID
    credential_id: bytes
    public_key: bytes
    sign_count: int
    transports: Optional[list[str]]
    display_name: Optional[str]
    created_at: datetime


def _row_to_credential(row: WebauthnCredentialRow) -> WebauthnCredential:
    return WebauthnCredential(
        id=row.id,
        person_id=row.person_id,
        credential_id=row.credential_id,
        public_key=row.public_key,
        sign_count=row.sign_count,
        transports=list(row.transports) if row.transports else None,
        display_name=row.display_name,
        created_at=row.created_at,
    )


async def add_credential(
    *,
    person_id: UUID,
    credential_id: bytes,
    public_key: bytes,
    sign_count: int = 0,
    transports: Optional[list[str]] = None,
    display_name: Optional[str] = None,
    db: AsyncSession,
) -> WebauthnCredential:
    """Insert a credential row. The credential_id is unique across the
    table (DB constraint); attempting to add a duplicate raises an
    integrity error from SQLAlchemy."""
    row = WebauthnCredentialRow(
        id=uuid.uuid4(),
        person_id=person_id,
        credential_id=credential_id,
        public_key=public_key,
        sign_count=sign_count,
        transports=list(transports) if transports else None,
        display_name=display_name,
    )
    db.add(row)
    await db.flush()
    await db.refresh(row)
    return _row_to_credential(row)


async def list_credentials_for_person(
    *,
    person_id: UUID,
    db: AsyncSession,
) -> list[WebauthnCredential]:
    """Return every credential bound to a person, oldest first."""
    result = await db.execute(
        select(WebauthnCredentialRow)
        .where(WebauthnCredentialRow.person_id == person_id)
        .order_by(WebauthnCredentialRow.created_at)
    )
    rows = result.scalars().all()
    return [_row_to_credential(r) for r in rows]


async def get_credential_by_credential_id(
    *,
    credential_id: bytes,
    db: AsyncSession,
) -> WebauthnCredential | None:
    """Resolve a credential by its WebAuthn credential id (the bytes the
    authenticator returns). Returns None when no match — login flow
    treats that as authentication failure."""
    result = await db.execute(
        select(WebauthnCredentialRow).where(
            WebauthnCredentialRow.credential_id == credential_id
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        return None
    return _row_to_credential(row)


async def update_sign_count(
    *,
    credential_id: bytes,
    new_sign_count: int,
    db: AsyncSession,
) -> None:
    """Persist the new sign_count after a successful authentication.

    A non-monotonic sign_count is a possible cloned-authenticator
    signal; the auth flow checks that before calling this. This helper
    blindly writes the value supplied — the policy decision lives one
    layer up.
    """
    result = await db.execute(
        select(WebauthnCredentialRow).where(
            WebauthnCredentialRow.credential_id == credential_id
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        return
    row.sign_count = new_sign_count
    await db.flush()


async def remove_credential(
    *,
    person_id: UUID,
    credential_id: bytes,
    db: AsyncSession,
) -> bool:
    """Hard-delete a person's passkey by its WebAuthn credential id.

    Returns True if a row was deleted, False if no matching credential
    exists for this person. Commits nothing — the caller owns the
    transaction boundary, matching :func:`update_sign_count`.

    Refuses with :class:`LastPasskeyError` when the credential is the
    person's only passkey (see the guard below). The guard lives here, with
    the removal, so a caller that bypasses the HTTP route still hits it.

    This is the module's first delete; it follows the same
    fetch-then-mutate-then-flush precedent as the writers above.
    """
    row = (
        await db.execute(
            select(WebauthnCredentialRow).where(
                WebauthnCredentialRow.person_id == person_id,
                WebauthnCredentialRow.credential_id == credential_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return False

    # Last-passkey guard — counts PASSKEYS ONLY; TOTP is NOT a fallback.
    # In the real login flow the passkey assertion mints the partial session
    # and TOTP/recovery is layered on top, so a person with zero passkeys
    # cannot sign in at all (no org-SSO exists today). Hence we refuse on the
    # last passkey unconditionally, without consulting totp_secret. When
    # org-SSO lands, widen this to "last passkey AND no SSO binding".
    existing = await list_credentials_for_person(person_id=person_id, db=db)
    if len(existing) == 1:
        raise LastPasskeyError(
            "Cannot remove the only passkey; the account would have no way in."
        )

    await db.delete(row)
    await db.flush()
    return True
