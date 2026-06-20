"""Principal creation and lookup.

The ``Principal`` identity view and create/get helpers; the substrate's
primary identity surface. No credentials are touched here — passkeys, TOTP,
and recovery codes are added via their own modules. This module is the
persistence layer; the host orchestrates the full sign-up flow over it.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from stele.kek import EnvKeyEncryptionKeyProvider, kek_encrypt
from stele import credentials as credentials_registry
from stele import recovery as recovery_codes
from stele.models import PrincipalRow


class Principal(BaseModel):
    """Pure-principal read view.

    The identity surface of a principal — id, name, and the auth lifecycle
    timestamps — and **nothing host-side**. It maps from ``PrincipalRow`` and
    carries no lifecycle/policy/comms columns (those are a host concern). It
    never carries credentials — ``totp_secret`` is row-only and is deliberately
    absent here (the no-credentials invariant).
    """

    model_config = ConfigDict(frozen=True, from_attributes=True)

    id: UUID
    display_name: str
    first_login_at: Optional[datetime] = None
    last_presence_proof_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


def _row_to_principal(row: PrincipalRow) -> Principal:
    return Principal.model_validate(row)


async def create_principal(
    *,
    display_name: str,
    db: AsyncSession,
) -> Principal:
    """Create a principal record.

    display_name is required (and must be non-empty). Mints the identity
    row only — no host columns (email/mobile and the like are a host concern,
    set host-side; Stele touches no host data).

    Does not create credentials. The signup orchestration adds passkeys,
    TOTP, and recovery codes after the row exists.
    """
    if not display_name or not display_name.strip():
        raise ValueError("display_name must be non-empty")

    row = PrincipalRow(
        id=uuid.uuid4(),
        display_name=display_name,
    )
    db.add(row)
    await db.flush()
    await db.refresh(row)

    # `create_principal` is a bare credential-less mint (no passkey, TOTP,
    # recovery, or onboarding) — account setup is a host concern. It is kept
    # separate from `mint_principal` (the full-credential production mint);
    # they share only this row.
    return Principal.model_validate(row)


async def mint_principal(
    *,
    display_name: str,
    totp_secret_plaintext: str,
    passkey_credential,
    recovery_codes_count: int = recovery_codes.DEFAULT_CODE_COUNT,
    secret_key: str,
    now: datetime,
    db: AsyncSession,
) -> tuple[PrincipalRow, list[str]]:
    """Mint a full principal — the production sign-up primitive.

    Encrypt the TOTP secret, mint the principal row (principal columns only —
    host columns like onboarded-state/email/mobile are set host-side by the
    caller), add the WebAuthn passkey, and generate + store the recovery codes.
    Returns the row and the plaintext recovery codes (shown once).

    It does NOT seed saved filters, create any membership/org/personal
    engagement or credit, or issue a session — those are host concerns. It
    commits NOTHING; the host owns the transaction boundary and commits the
    mint phase.
    """
    totp_secret_enc = kek_encrypt(
        totp_secret_plaintext,
        EnvKeyEncryptionKeyProvider(secret_key=secret_key),
    )
    person = PrincipalRow(
        display_name=display_name,
        totp_secret=totp_secret_enc,
        first_login_at=now,  # signup is the first login
    )
    db.add(person)
    await db.flush()
    await db.refresh(person)

    await credentials_registry.add_credential(
        person_id=person.id,
        credential_id=passkey_credential.credential_id,
        public_key=passkey_credential.public_key,
        sign_count=passkey_credential.sign_count,
        transports=passkey_credential.transports,
        db=db,
    )

    plaintext_codes = recovery_codes.generate_recovery_codes(
        count=recovery_codes_count
    )
    await recovery_codes.store_recovery_codes(
        person_id=person.id, codes=plaintext_codes, db=db
    )

    return person, plaintext_codes


async def get_principal_by_id(
    *,
    person_id: UUID,
    db: AsyncSession,
) -> Principal | None:
    """Resolve a principal by id. Returns None if not found."""
    result = await db.execute(
        select(PrincipalRow).where(PrincipalRow.id == person_id)
    )
    row = result.scalar_one_or_none()
    if row is None:
        return None
    return Principal.model_validate(row)
