"""P117-1 smoke — the test plumbing is green: migration ran, the db fixture works,
the async/session-loop wiring resolves end-to-end against a real Postgres."""
from __future__ import annotations

from sqlalchemy import text

from stele.registry import create_principal, get_principal_by_id


async def test_migration_built_the_three_tables(db):
    tables = (
        await db.execute(
            text(
                "select tablename from pg_tables "
                "where schemaname = 'public' order by 1"
            )
        )
    ).scalars().all()
    assert {"principals", "webauthn_credentials", "recovery_codes"} <= set(tables)


async def test_db_fixture_round_trips_a_principal(db):
    created = await create_principal(display_name="Smoke Tester", db=db)
    await db.commit()
    read_back = await get_principal_by_id(person_id=created.id, db=db)
    assert read_back is not None
    assert read_back.display_name == "Smoke Tester"
