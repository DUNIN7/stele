# SPDX-License-Identifier: Apache-2.0
"""Reference-app settings — read from the environment (the ``.env`` the config
generator scaffolds; see ``examples/generate_env.py``).

The full env floor a real Stele mount needs:
  - STELE_SECRET_KEY      the KEK (a Fernet key) — encrypts session tokens + the
                          TOTP secret at rest. Generate a fresh one; never ship a
                          placeholder.
  - STELE_RP_ID           the WebAuthn Relying-Party id (the registrable domain,
                          e.g. "localhost"). MUST match the serving origin's host.
  - STELE_RP_NAME         the human-readable RP name shown by the authenticator.
  - STELE_RP_ORIGIN       the exact serving origin (scheme + host + port, e.g.
                          "http://localhost:8000"). The browser refuses the
                          ceremony if this does not match where the page is served.
  - STELE_DATABASE_URL    postgresql+asyncpg://… — a real Postgres (Stele's models
                          use JSONB / bytea, so SQLite is not viable).
  - STELE_SECRET_KEYS_PREVIOUS   optional, comma-separated older KEKs kept
                          decrypt-readable across a rotation.

Note the cookie name is the reference app's OWN choice (below) — Stele's
``issue_session`` is mint-only and the router sets no cookie, so delivery
(including the cookie name) is wholly the host's. An adopter never inherits
Stele's internal cookie-name constant.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    secret_key: str
    rp_id: str
    rp_name: str
    rp_origin: str
    database_url: str
    # The reference app names its own session cookie. This is the §1.6 point made
    # concrete: the host owns delivery, so the host owns the cookie name.
    cookie_name: str = "stele_ref_session"
    # TS-16: the double-submit CSRF token cookie — also the host's own choice,
    # same boundary as cookie_name above. Non-HttpOnly by design (the page's own
    # JS must be able to read it back into a header).
    csrf_cookie_name: str = "stele_ref_csrf"


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"{name} is not set. Copy the generated .env (python examples/generate_env.py) "
            f"and fill it, then `set -a; . ./.env; set +a` before starting the app."
        )
    return value


def load_settings() -> Settings:
    return Settings(
        secret_key=_require("STELE_SECRET_KEY"),
        rp_id=os.environ.get("STELE_RP_ID", "localhost"),
        rp_name=os.environ.get("STELE_RP_NAME", "Stele Reference App"),
        rp_origin=os.environ.get("STELE_RP_ORIGIN", "http://localhost:8000"),
        database_url=_require("STELE_DATABASE_URL"),
    )
