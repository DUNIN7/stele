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
from datetime import datetime, timezone
from uuid import UUID

import pyotp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from stele.kek import EnvKeyEncryptionKeyProvider, kek_encrypt
from stele.models import PrincipalRow


class PersonTotpCodeInvalid(Exception):
    """The supplied code did not verify against the new secret; the rotate is
    refused and the person's existing secret is left untouched."""


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


async def confirm_totp_rotation(
    *,
    person_id: UUID,
    secret: str,
    code: str,
    secret_key: str,
    db: AsyncSession,
) -> None:
    """Verify ``code`` against the freshly-generated (still un-stored) ``secret``
    and, on success, encrypt and write it to the person's ``totp_secret``
    column — the rotate. Commits nothing; the caller owns the transaction
    boundary (matching ``credentials.add_credential`` / ``update_sign_count``).

    The verify sits HERE, at the primitive layer, not in the route. On a bad
    code nothing is written and the person's existing secret stays intact.

    Raises:
        ValueError: the secret is not base32, or the person row is missing.
        PersonTotpCodeInvalid: the code did not verify (no write).
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

    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        raise PersonTotpCodeInvalid("Invalid code. Try again.")

    row.totp_secret = kek_encrypt(
        secret, EnvKeyEncryptionKeyProvider(secret_key=secret_key)
    )
    row.updated_at = datetime.now(timezone.utc)
    await db.flush()
