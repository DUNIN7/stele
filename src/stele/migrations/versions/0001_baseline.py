# SPDX-License-Identifier: Apache-2.0
"""baseline — Stele 3-table schema (principals, webauthn_credentials, recovery_codes)

The consolidated baseline. One revision, ``down_revision = None``, building the
settled Stele schema directly against a fresh database. The detail beyond the ORM
models: the per-person indexes ``idx_*_person`` are migration-only and absent from
``__table_args__``; ``webauthn_credentials``/``recovery_codes``.id carry
``gen_random_uuid()`` server defaults while ``principals.id`` does not — all
reproduced here.

There is no expand/contract scaffolding: no host seed, no mirror triggers, no host
foreign keys. Stele encrypts its one secret scope (``totp_secret``) KEK-direct, so
there is **no ``data_encryption_keys`` table**. Three tables only.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-06-19
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # principals — the 7 identity/auth columns. id has NO server default (the
    # ORM supplies uuid.uuid4 app-side).
    op.create_table(
        "principals",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("totp_secret", sa.Text(), nullable=True),
        sa.Column("first_login_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_presence_proof_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.TIMESTAMP(timezone=True),
            nullable=False, server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at", sa.TIMESTAMP(timezone=True),
            nullable=False, server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="principals_pkey"),
    )

    # webauthn_credentials — passkeys. id default gen_random_uuid() (0029 shape).
    op.create_table(
        "webauthn_credentials",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True),
            nullable=False, server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("person_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("credential_id", sa.LargeBinary(), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("transports", postgresql.JSONB(), nullable=True),
        sa.Column("display_name", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.TIMESTAMP(timezone=True),
            nullable=False, server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="webauthn_credentials_pkey"),
        sa.ForeignKeyConstraint(
            ["person_id"], ["principals.id"],
            name="webauthn_credentials_person_id_fkey",
        ),
        sa.UniqueConstraint(
            "credential_id", name="uq_webauthn_credentials_credential_id"
        ),
    )
    op.create_index(
        "idx_webauthn_credentials_person", "webauthn_credentials", ["person_id"]
    )

    # recovery_codes — bcrypt-hashed single-use codes. id default gen_random_uuid().
    op.create_table(
        "recovery_codes",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True),
            nullable=False, server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("person_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("code_hash", sa.Text(), nullable=False),
        sa.Column("used_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.TIMESTAMP(timezone=True),
            nullable=False, server_default=sa.text("now()"),
        ),
        sa.Column("invalidated_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="recovery_codes_pkey"),
        sa.ForeignKeyConstraint(
            ["person_id"], ["principals.id"],
            name="recovery_codes_person_id_fkey",
        ),
    )
    op.create_index(
        "idx_recovery_codes_person", "recovery_codes", ["person_id"]
    )


def downgrade() -> None:
    op.drop_index("idx_recovery_codes_person", table_name="recovery_codes")
    op.drop_table("recovery_codes")
    op.drop_index(
        "idx_webauthn_credentials_person", table_name="webauthn_credentials"
    )
    op.drop_table("webauthn_credentials")
    op.drop_table("principals")
