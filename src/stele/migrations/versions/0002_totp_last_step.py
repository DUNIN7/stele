# SPDX-License-Identifier: Apache-2.0
"""totp last step — persist last-accepted TOTP time-step per principal (TS-11 replay protection)

Adds ``principals.totp_last_step`` (nullable integer). Stele has one TOTP
secret per principal, so replay-state lives directly on ``principals`` rather
than a side table — the same pattern ``totp_secret`` itself already follows.
Time-step indices are a pure function of wall-clock time, not of which secret
validated them, so this single column also guards against replay across a
rotation, not just within one secret's lifetime.

Revision ID: 0002_totp_last_step
Revises: 0001_baseline
Create Date: 2026-07-06
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0002_totp_last_step"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "principals",
        sa.Column("totp_last_step", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("principals", "totp_last_step")
