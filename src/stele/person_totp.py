"""Person-scoped TOTP re-provisioning (rotate).

The crypto path matches the one ``registry.mint_principal`` uses for a
principal's first secret: KEK-direct via
``stele.kek.kek_encrypt(secret, EnvKeyEncryptionKeyProvider(...))`` — a bare
Fernet token under the KEK, no per-scope DEK (Stele has one secret scope, so it
ships no ``data_encryption_keys`` table).

This is a deliberate ROTATE: the person already has a secret and is replacing
it. The new secret is generated at ``begin`` and held by the caller until
``confirm`` verifies a live code against it — only then is the live column
overwritten, so a failed confirm leaves the old secret intact.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID

import pyotp
from pyotp.utils import strings_equal
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from stele.kek import EnvKeyEncryptionKeyProvider, kek_encrypt
from stele.models import PrincipalRow


class PersonTotpCodeInvalid(Exception):
    """The supplied code did not verify, or verified but at a time-step
    already accepted (a replay) — the rotate is refused and the person's
    existing secret is left untouched."""


@dataclass(frozen=True)
class PersonTotpProvisioning:
    """One-shot ``begin`` result. ``secret`` is the new plaintext TOTP secret
    the caller holds until ``confirm``; ``provisioning_uri`` is the otpauth://
    URL the UI renders as a QR code. Neither is written to the live column."""

    secret: str
    provisioning_uri: str


async def begin_totp_rotation(
    *,
    person_id: UUID,
    db: AsyncSession,
    issuer_name: str = "Stele",
) -> PersonTotpProvisioning:
    """Generate a fresh TOTP secret + provisioning URI for a person WITHOUT
    writing the live ``totp_secret`` column. The caller holds the secret until
    :func:`confirm_totp_rotation` verifies a code against it.

    ``issuer_name`` is the label the authenticator app shows for the account; it
    defaults to ``"Stele"`` and a host passes its own (e.g. the WebAuthn
    relying-party name) so the issuer reflects the host, not Stele.

    Raises:
        ValueError: the person row does not exist.
    """
    row = (
        await db.execute(select(PrincipalRow).where(PrincipalRow.id == person_id))
    ).scalar_one_or_none()
    if row is None:
        raise ValueError(f"person {person_id} not found")

    secret = pyotp.random_base32()
    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
        name=row.display_name, issuer_name=issuer_name
    )
    return PersonTotpProvisioning(secret=secret, provisioning_uri=provisioning_uri)


def verify_totp_step(
    *,
    secret: str,
    code: str,
    last_step: Optional[int],
    now: datetime,
    valid_window: int = 1,
) -> int:
    """Verify ``code`` against ``secret`` within the drift window and reject a
    replay — a step already accepted (``<= last_step``). Returns the step to
    persist as the caller's new last-accepted step.

    Pure — no DB access. Time-step indices are a function of wall-clock time
    only, not of which secret validated them, so ``last_step`` is meaningful
    across a secret rotation, not just within one secret's lifetime. The
    caller holds whatever row carries the last-accepted step and persists the
    returned value onto it; this is the one shared primitive all three
    TOTP-verify call sites (rotation-confirm, signup, login) go through.

    Raises:
        PersonTotpCodeInvalid: the code did not verify against any step in
            the window, or verified but at a step already accepted.
    """
    totp = pyotp.TOTP(secret)
    base_step = totp.timecode(now)
    for offset in range(-valid_window, valid_window + 1):
        step = base_step + offset
        if strings_equal(str(code), totp.generate_otp(step)):
            if last_step is not None and step <= last_step:
                raise PersonTotpCodeInvalid("Invalid code. Try again.")
            return step
    raise PersonTotpCodeInvalid("Invalid code. Try again.")


async def confirm_totp_rotation(
    *,
    person_id: UUID,
    secret: str,
    code: str,
    secret_key: str,
    now: datetime,
    db: AsyncSession,
) -> None:
    """Verify ``code`` against the freshly-generated (still un-stored) ``secret``
    and, on success, encrypt and write it to the person's ``totp_secret``
    column — the rotate. Commits nothing; the caller owns the transaction
    boundary (matching ``credentials.add_credential`` / ``update_sign_count``).

    The verify sits HERE, at the primitive layer, not in the route. On a bad
    code — or a code replaying an already-accepted step — nothing is written
    and the person's existing secret stays intact.

    Raises:
        ValueError: the secret is not base32, or the person row is missing.
        PersonTotpCodeInvalid: the code did not verify, or replayed a step
            already accepted (no write either way).
    """
    if not secret or not isinstance(secret, str):
        raise ValueError("secret must be a non-empty base32 string")
    # Reject a malformed client secret before it reaches pyotp.
    if not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in secret):
        raise ValueError("secret must be base32 (A-Z 2-7)")

    row = (
        await db.execute(select(PrincipalRow).where(PrincipalRow.id == person_id))
    ).scalar_one_or_none()
    if row is None:
        raise ValueError(f"person {person_id} not found")

    step = verify_totp_step(
        secret=secret, code=code, last_step=row.totp_last_step, now=now
    )

    row.totp_secret = kek_encrypt(
        secret, EnvKeyEncryptionKeyProvider(secret_key=secret_key)
    )
    row.totp_last_step = step
    row.updated_at = now
    await db.flush()
