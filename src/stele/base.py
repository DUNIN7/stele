"""Stele's own ``DeclarativeBase`` — the standalone identity ``MetaData``.

This is the base the principal-side rows are mapped onto: ``principals`` and the
credential row models (``webauthn_credentials``, ``recovery_codes``), whose
foreign keys point *inward* at ``principals.id`` (intra-Stele). The identity
tables live on *this* ``MetaData``, owned by Stele alone, with no host row
registered on it and no foreign key crossing out to a host — so
``Base.metadata`` describes exactly the tables a standalone Stele ships.
"""
from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Stele's own ``DeclarativeBase`` for the standalone identity tables.

    Independent ``MetaData``. The principal-side rows (``principals`` and the
    credential models) are registered here; no host row is ever registered on
    it, so ``Base.metadata`` describes exactly the tables a standalone Stele
    ships.
    """
