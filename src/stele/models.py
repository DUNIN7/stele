"""Stele identity row models (CR-2026-104 Phase 1; CR-2026-109 Phase 6).

Holds **only** ``SteleBase`` (``loomworks.stele.base``) rows now — the tables a
standalone Stele ships, with no host row and no outward foreign key:

- ``PrincipalRow`` -> ``principals`` (the Stele-owned identity table), and
- the two credential rows ``WebauthnCredentialRow`` -> ``webauthn_credentials``
  and ``RecoveryCodeRow`` -> ``recovery_codes``, whose ``person_id`` foreign keys
  point *inward* at ``principals.id`` (intra-Stele).

CR-2026-112 (CR-C) emptied the host side out of this module: the former
``PersonRow`` identity class was reduced to a persons-table FK-target stub and
``HostAccountRow`` was relocated, both to ``persons/models.py`` on the shared
``loomworks.identity_base`` Base, where the host-FK tables live. This module no
longer imports that Base -- it is the Phase-7 precondition (Stele models stand
alone on ``SteleBase``).

``principals`` is created by migration 0085, seeded from the existing ``persons``
rows. Since CR-C (migration 0090) ``principals`` is the identity **write-source**
and ``persons`` is the reverse mirror (an ``AFTER INSERT OR UPDATE`` trigger on
``principals`` keeps ``persons`` in sync) -- still standing only for CR-B's
host-FK retarget. No ORM ``relationship()`` is used; all links are string-target
foreign keys, and no FK crosses the persons/Stele boundary at the ORM level.
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

from loomworks.stele.base import Base as SteleBase


class PrincipalRow(SteleBase):
    """The Stele-owned principal — identity + auth columns only (Phase 6).

    The standalone identity row (CR-2026-109, D1 = own-its-own-table): it
    carries the 7 principal columns, and the 2 identity foreign keys point
    *inward* at its ``id``. During the expand window these columns are also
    still present on ``persons`` and kept in sync by the migration-0085 mirror
    trigger; principal reads resolve from here. ``host_account`` (the
    lifecycle/policy columns) is the host-side sibling at the same ``id``.
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
