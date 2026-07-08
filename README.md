# Stele

A sign-in system you can drop into your own app — passkeys and authenticator
codes instead of passwords, with no email address anywhere in how it
identifies people.

**New here?**
- **Building with an AI coding agent?** Tell it to read [`AGENTS.md`](AGENTS.md) — everything it needs to wire Stele in correctly, including what not to do.
- **Just want to try it, no coding?** Follow [`examples/README.md`](examples/README.md) — about 10 minutes, no experience needed.
- **Rebranding the sign-up/sign-in pages for your own app?** See [`docs/stele-how-it-works-v0_1.html`](docs/stele-how-it-works-v0_1.html) — what's actually happening during sign-up and sign-in, and exactly what's safe to restyle.
- **Evaluating Stele as a developer?** Keep reading below.

---

A standalone identity & authentication substrate: **principals** (UUID identity),
**WebAuthn passkeys**, **TOTP**, and **recovery codes**. No host framework
dependency — Stele is a library of primitives, a mountable router, and its own
database schema. Mount it into your FastAPI app; it proves *who* a caller is and
leaves *what they may reach* to you.

> **Status:** Standalone, mountable, and tested. The core primitives, the
> mountable router + SDK, and the runnable reference host all ship. A real test
> suite (`tests/`) runs against a throwaway Postgres in CI on every push. Two
> internal security review passes have been completed and their findings
> resolved — see [`CHANGELOG.md`](CHANGELOG.md) for the full history.
> Library metadata is `0.3.0`; the current tag is `v0.3.0`.

## What's here

- `src/stele/` — the core modules (`base`, `models`, `credentials`, `recovery`,
  `registry`, `session`, `person_totp`, `webauthn`, `api`) plus `kek` (the
  KEK-direct crypto floor). No `data_encryption_keys` table — Stele encrypts its
  one secret scope (the TOTP secret) KEK-direct. `import stele` pulls no web
  framework; only touching `stele.router` loads FastAPI.
- `src/stele/migrations/` — an Alembic root, packaged inside `src/stele` (TS-22)
  so it ships with the installed wheel. The baseline revision builds the three
  tables (`principals`, `webauthn_credentials`, `recovery_codes`); later
  revisions evolve the schema (e.g. `principals.totp_last_step`, TS-11 replay
  protection) against a fresh database. Postgres required (the schema uses
  `JSONB` and `bytea`); SQLite is not an option.
- `examples/` — a runnable reference host: the whole mount in one readable module
  (`reference_app/main.py`), the browser WebAuthn ceremony, a config generator,
  a throwaway-Postgres compose file, and a walkthrough README.
- `docs/` — the mount-contract adopter guide: the two slots, the
  authentication-not-authorization boundary, the discoverable sign-in
  commitment, narrated from the reference host.
- `tests/` — the suite: primitive units + a mounted reference-host round-trip,
  run in CI against a Postgres service.
- `AGENTS.md` — integration recipe for coding agents mounting Stele on someone
  else's behalf: hard constraints, required env vars, the mount pattern, what
  Stele deliberately doesn't do.

## Mounting Stele

```python
from fastapi import FastAPI
import stele

app = FastAPI()
app.include_router(stele.router, prefix="/me/security")

app.dependency_overrides[stele.provide_db_session] = my_db_session      # required
app.dependency_overrides[stele.provide_webauthn_config] = my_rp_config  # required
```

Two slots are required (`provide_db_session`, `provide_webauthn_config`) and fail
loudly until you supply them. The rest have working defaults — including
`resolve_current_principal`, the one seam where you add **your** authorization
policy. The full contract is in [`docs/stele-mount-contract-v0_1.md`](docs/stele-mount-contract-v0_1.md).

## Clone-and-run (the done-bar)

```sh
pip install -e .
export STELE_SECRET_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
export STELE_DATABASE_URL="postgresql+asyncpg://USER@localhost:5432/YOUR_DB"
alembic upgrade head
```

The three tables build against a fresh database with no external dependency.

### Consuming Stele alongside an existing schema

Stele's migration chain tracks its own progress in `stele_alembic_version` (CR-2026-150),
distinct from the default `alembic_version` — so it can run independently of a
host's own migration chain against the same database. But if the host's own
migrations already created Stele's tables (e.g. an engine that owned
`principals` before adopting Stele, or otherwise pre-built Stele's schema
through its own chain), Stele's `0001_baseline` will try to create tables
that already exist and fail. In that case, stamp the baseline instead of
running it, then upgrade forward for anything after it:

```sh
alembic stamp 0001_baseline
alembic upgrade head
```

A genuinely fresh database (nothing built yet, by either chain) doesn't need
this — a plain `alembic upgrade head` from a clean start works as shown above.

To run the reference host end-to-end (Postgres, config, the browser ceremony),
follow [`examples/README.md`](examples/README.md). To run the tests:

```sh
pip install -e ".[test]"
export STELE_DATABASE_URL="postgresql+asyncpg://USER@localhost:5432/YOUR_TEST_DB"
pytest
```

## Release history

See [`CHANGELOG.md`](CHANGELOG.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).

---

DUNIN7 — Done In Seven LLC — Miami, Florida
Marvin Percival — marvinp@dunin7.com
