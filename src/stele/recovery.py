"""Recovery codes — generation, hashing, and single-use verification.

Ten codes per person, eight characters each. The alphabet is uppercase
letters and digits with the visually ambiguous characters removed
(O, 0, I, 1, L) so codes copied from a screen don't fail to disambiguate.

Codes are stored as bcrypt hashes; the plaintext is returned exactly
once (at signup, or when regenerated) and never again — there is no view
path. Each code can be used once — verify sets `used_at` and rejects
subsequent attempts with the same code, atomically: consumption is a
single conditional UPDATE, not a fetch-then-mutate, so two concurrent
redemptions of the same code cannot both succeed (TS-13). Regenerate
rotates the set: the prior codes are soft-invalidated (`invalidated_at`)
so they stop redeeming, and a fresh set is issued. A code is valid only
when both `used_at` and `invalidated_at` are NULL.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timezone
from uuid import UUID

import bcrypt
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from stele.models import RecoveryCodeRow

ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # 31 chars; no O, 0, I, 1, L
CODE_LENGTH = 8
DEFAULT_CODE_COUNT = 10


def generate_recovery_codes(*, count: int = DEFAULT_CODE_COUNT) -> list[str]:
    """Return `count` fresh recovery codes — uppercase + digit only,
    visually unambiguous."""
    return [_generate_one() for _ in range(count)]


def _generate_one() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))


def hash_recovery_code(code: str) -> str:
    """Return a bcrypt hash for a plaintext recovery code.

    Uses the bcrypt default cost (12). bcrypt is sized for human
    passwords; recovery codes have ~40 bits of entropy here, well
    inside the bound where bcrypt is appropriate.
    """
    return bcrypt.hashpw(code.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


async def store_recovery_codes(
    *,
    person_id: UUID,
    codes: list[str],
    db: AsyncSession,
) -> None:
    """Persist bcrypt hashes for each code under the person.

    The plaintext list is the caller's responsibility to surface to the
    user — once this returns, only the hashes survive.
    """
    for code in codes:
        db.add(
            RecoveryCodeRow(
                person_id=person_id,
                code_hash=hash_recovery_code(code),
            )
        )
    await db.flush()


async def verify_and_consume_recovery_code(
    *,
    person_id: UUID,
    code: str,
    db: AsyncSession,
) -> bool:
    """Match `code` against the person's *valid* recovery hashes; on a
    match, atomically mark `used_at` and return True. Returns False if no
    valid code matches (already consumed, rotated out, or never issued).

    Valid = not yet redeemed AND not rotated out (``used_at IS NULL AND
    invalidated_at IS NULL``). The ``invalidated_at`` filter is what makes
    regenerate actually revoke: a rotated-out code can no longer be redeemed
    here — and this is the only place redemption happens.

    TS-13: the bcrypt loop below identifies *which* row matches, but does
    not itself consume it — two concurrent requests presenting the same
    valid code could both pass this SELECT and its bcrypt check before
    either writes. Consumption is a single conditional ``UPDATE ... WHERE
    id = :id AND used_at IS NULL AND invalidated_at IS NULL RETURNING id``
    against the one matched row; if it returns no row, a concurrent request
    already won the race and this one is rejected as already-used."""
    result = await db.execute(
        select(RecoveryCodeRow).where(
            RecoveryCodeRow.person_id == person_id,
            RecoveryCodeRow.used_at.is_(None),
            RecoveryCodeRow.invalidated_at.is_(None),
        )
    )
    rows = result.scalars().all()

    code_bytes = code.encode("utf-8")
    for row in rows:
        try:
            matched = bcrypt.checkpw(code_bytes, row.code_hash.encode("utf-8"))
        except ValueError:
            # Malformed hash — skip; treat as no match.
            continue
        if not matched:
            continue

        consumed = await db.execute(
            update(RecoveryCodeRow)
            .where(
                RecoveryCodeRow.id == row.id,
                RecoveryCodeRow.used_at.is_(None),
                RecoveryCodeRow.invalidated_at.is_(None),
            )
            .values(used_at=datetime.now(timezone.utc))
            .returning(RecoveryCodeRow.id)
        )
        return consumed.first() is not None
    return False


async def regenerate_recovery_codes(
    *,
    person_id: UUID,
    db: AsyncSession,
) -> list[str]:
    """Rotate a person's recovery codes in one transaction; return the fresh
    plaintext set (surfaced to the user exactly once).

    Soft-invalidates every currently-valid code (``used_at IS NULL AND
    invalidated_at IS NULL``) by stamping ``invalidated_at``, then issues a
    fresh ``DEFAULT_CODE_COUNT`` set. The invalidation and the inserts share
    the caller's transaction, so a mid-rotation failure rolls back to the
    prior set — never zero valid codes, never both sets live.

    Revocation is what ``invalidated_at`` buys: ``verify_and_consume_recovery_code``
    excludes invalidated codes, so the old set stops redeeming the moment this
    commits. The old rows are kept (not deleted) for the audit trail.
    """
    now = datetime.now(timezone.utc)
    await db.execute(
        update(RecoveryCodeRow)
        .where(
            RecoveryCodeRow.person_id == person_id,
            RecoveryCodeRow.used_at.is_(None),
            RecoveryCodeRow.invalidated_at.is_(None),
        )
        .values(invalidated_at=now)
    )
    fresh = generate_recovery_codes()
    await store_recovery_codes(person_id=person_id, codes=fresh, db=db)
    return fresh


async def count_unused_recovery_codes(
    *,
    person_id: UUID,
    db: AsyncSession,
) -> int:
    """How many codes the person can still redeem — valid means neither used
    nor rotated out (``used_at IS NULL AND invalidated_at IS NULL``)."""
    result = await db.execute(
        select(func.count())
        .select_from(RecoveryCodeRow)
        .where(
            RecoveryCodeRow.person_id == person_id,
            RecoveryCodeRow.used_at.is_(None),
            RecoveryCodeRow.invalidated_at.is_(None),
        )
    )
    return int(result.scalar_one())


async def count_active_recovery_codes(
    *,
    person_id: UUID,
    db: AsyncSession,
) -> int:
    """The size of the person's current set — issued and not rotated out
    (used + unused, ``invalidated_at IS NULL``), so unused/total reads as
    "N of M remaining"."""
    result = await db.execute(
        select(func.count())
        .select_from(RecoveryCodeRow)
        .where(
            RecoveryCodeRow.person_id == person_id,
            RecoveryCodeRow.invalidated_at.is_(None),
        )
    )
    return int(result.scalar_one())
