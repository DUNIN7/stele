"""Principal creation and lookup (Phase 14).

The ``Principal`` identity view and create/get helpers; the substrate's
primary identity surface. No credentials are touched here — passkeys, TOTP,
and recovery codes are added via dedicated endpoints (Steps 3, 5).

The signup orchestration (Step 3) coordinates the full flow; this
module is the persistence layer.
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
    """Pure-principal read view (Phase 6b, CR-2026-110).

    The identity surface of a principal — id, name, and the auth lifecycle
    timestamps — and **nothing host-side**. This is the view standalone Stele
    ships: it maps from ``PrincipalRow`` (Stele's own Base) and carries no
    lifecycle/policy/comms columns (those live on the host ``HostAccount``
    view). It never carries credentials — ``totp_secret`` is row-only and is
    deliberately absent here (the no-credentials invariant, governed by
    ``test_person_pydantic_does_not_carry_totp_secret``).

    Step 3.7 (CR-2026-110): the transitional ``Person`` shim has been retired
    and collapsed into this view. The collapse was superset-safe — ``Person``
    was the strict subset ``{id, display_name, created_at, updated_at}``;
    ``Principal`` adds the two ``Optional`` auth-lifecycle timestamps below,
    which no reader reads off the view, so the ``Person → Principal`` swap
    added fields without changing any consumer's behaviour.
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
    row only. CR-2026-111 C2: email/mobile (host columns) were removed from
    this Stele mint — they live on ``host_account`` and are set host-side,
    never by Stele (the boundary: stele/ touches no host data).

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

    # NOTE (CR-2026-107 Phase 4 §2.1): the system saved-filter seed that
    # used to live here (`seed_system_defined_filters`) was relocated to
    # the host `onboard` operation, where account setup belongs. This
    # leaves `create_principal` a bare credential-less mint (no passkey, TOTP,
    # recovery, or onboarding). It is kept separate from `mint_principal`
    # (the full-credential production mint) — they share only this row.
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
    """Mint a full principal — the Stele production sign-up primitive
    (CR-2026-107, Phase 4 §2.1).

    A verbatim relocation of the principal-creation work that lived inline
    at ``signup.py:255-284``: encrypt the TOTP secret, mint the ``PersonRow``
    (principal columns only — CR-2026-111 C2 stripped the host columns;
    onboarded-state + email/mobile are host_account, set host-side by the
    caller), add the WebAuthn passkey, and generate + store the recovery
    codes. Returns the row and the plaintext recovery codes (shown once).

    It does NOT seed saved filters, create any membership/org/personal
    engagement or credit, or issue a session — those are the host
    ``onboard`` phase. It commits NOTHING; the host owns the transaction
    boundary and commits the mint phase.
    """
    totp_secret_enc = kek_encrypt(
        totp_secret_plaintext,
        EnvKeyEncryptionKeyProvider(secret_key=secret_key),
    )
    person = PrincipalRow(
        display_name=display_name,
        totp_secret=totp_secret_enc,
        first_login_at=now,  # signup IS the first login (CR §13.3)
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
    """Resolve a principal by id. Returns None if not found.

    Step 3.7 (CR-2026-110): the former ``get_person_by_id`` and
    ``get_principal_and_person_by_id`` collapsed into this single resolver
    once the ``Person`` shim retired — both projected the same identity off
    one ``PersonRow`` load; the session resolver no longer needs a twin view.
    """
    result = await db.execute(
        select(PrincipalRow).where(PrincipalRow.id == person_id)
    )
    row = result.scalar_one_or_none()
    if row is None:
        return None
    return Principal.model_validate(row)
