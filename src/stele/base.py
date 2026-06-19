"""Stele's own ``DeclarativeBase`` — the standalone identity ``MetaData``.

Stele extraction Phase 6 (CR-2026-109, Option B). This is the base the
principal-side rows move onto: ``principals`` and the credential row models
(``webauthn_credentials``, ``recovery_codes``), whose foreign keys point
*inward* at ``principals.id`` (intra-Stele). It is the physical realisation
of D1 = own-its-own-table — the standalone repository's identity tables live
on *this* ``MetaData``, owned by Stele alone, with no host row registered on
it and no foreign key crossing out to the host.

It is the counterpart to ``loomworks.identity_base`` (the interim shared base
from Branch 1, Phase 1): that base is owned by neither module and imported by
both; *this* base is owned by Stele. As the physical
``persons -> principals + host-account`` split lands, the principal-side rows
move from the shared base onto this one, and the host rows (``persons`` and
the governance tables) stay on the shared base — which becomes the host base.

Mirrors the engine's per-subsystem convention (each subsystem declares its own
independent ``DeclarativeBase``); the shared ``identity_base`` was the one
documented exception, scoped to the extraction. This base ends that exception
on the Stele side.

Scaffold only at Step 1.2: nothing is mapped onto it yet. The principal
mapping and the credential-model moves land together at Step 1.3 alongside
migration 0085 (Option B — ORM mapping and physical table arrive in the same
step, so the ORM never declares a table the migrated schema lacks).
"""
from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Stele's own ``DeclarativeBase`` for the standalone identity tables.

    Independent ``MetaData``. The principal-side rows (``principals`` and the
    credential models) are registered here from Step 1.3; no host row is ever
    registered on it, so ``Base.metadata`` describes exactly the tables a
    standalone Stele ships.
    """
