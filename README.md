# Stele

A standalone identity & authentication substrate: **principals** (UUID identity),
**WebAuthn passkeys**, **TOTP**, and **recovery codes**. No host framework
dependency — Stele is a library of primitives plus its own database schema.

> **Status:** P7-1 packaging floor (CR-2026-114). This is the library + its
> independently-runnable migration set. The SDK surface and mountable router are
> P7-2; the reference app and full docs are P7-3.

## What's here

- `src/stele/` — the 9 core modules (`base`, `models`, `credentials`, `recovery`,
  `registry`, `session`, `person_totp`, `webauthn`) plus `kek` (the KEK-direct
  crypto floor). No `data_encryption_keys` table — Stele encrypts its one secret
  scope (the TOTP secret) KEK-direct.
- `migrations/` — an Alembic root with a single consolidated baseline that builds
  the three tables (`principals`, `webauthn_credentials`, `recovery_codes`)
  against a fresh database.

## Clone-and-run (the done-bar)

```sh
pip install -e .
export LOOMWORKS_SECRET_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
export STELE_DATABASE_URL="postgresql+asyncpg://USER@localhost:5432/YOUR_DB"
alembic upgrade head
```

The three tables build with zero residual DUNIN7/Loomworks dependency.

---

DUNIN7 — Done In Seven LLC — Miami, Florida
