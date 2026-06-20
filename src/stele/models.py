"""Stele identity row models.

Holds **only** ``SteleBase`` (``stele.base``) rows — the tables a standalone
Stele ships, with no host row and no outward foreign key:

- ``PrincipalRow`` -> ``principals`` (the Stele-owned identity table), and
- the two credential rows ``WebauthnCredentialRow`` -> ``webauthn_credentials``
  and ``RecoveryCodeRow`` -> ``recovery_codes``, whose ``person_id`` foreign keys
  point *inward* at ``principals.id`` (intra-Stele).

No ORM ``relationship()`` is used; all links are string-target foreign keys, and
no foreign key crosses out of Stele.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Integer,
    LargeBinary,
    Text,
    TIMESTAMP,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from stele.base import Base as SteleBase


class PrincipalRow(SteleBase):
    """The Stele-owned principal — identity + auth columns only.

    The standalone identity row: it carries the 7 principal columns, and the 2
    credential foreign keys point *inward* at its ``id``. It carries no
    lifecycle/policy/comms columns — those are a host concern, kept on the host
    side at the same ``id``.
    """

    __tablename__ = "principals"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    display_name: Mapped[str] = mapped_column(Text(), nullable=False)
    totp_secret: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)
    first_login_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    last_presence_proof_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )


class WebauthnCredentialRow(SteleBase):
    """Registered WebAuthn credential (passkey) for a principal."""

    __tablename__ = "webauthn_credentials"
    __table_args__ = (
        UniqueConstraint(
            "credential_id", name="uq_webauthn_credentials_credential_id"
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    person_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("principals.id"),
        nullable=False,
    )
    credential_id: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    sign_count: Mapped[int] = mapped_column(
        Integer(), nullable=False, server_default=text("0")
    )
    transports: Mapped[Optional[list]] = mapped_column(JSONB(), nullable=True)
    display_name: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )


class RecoveryCodeRow(SteleBase):
    """Single-use recovery code (bcrypt-hashed) for a principal."""

    __tablename__ = "recovery_codes"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    person_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("principals.id"),
        nullable=False,
    )
    code_hash: Mapped[str] = mapped_column(Text(), nullable=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    # Set when a code is rotated out by regenerate — distinct from used_at,
    # which records redemption at sign-in. A code is valid only when BOTH are
    # NULL; "redeemed" and "rotated out" are different facts, both preserved.
    invalidated_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
