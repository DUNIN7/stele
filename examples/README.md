# Stele reference host

A minimal standalone FastAPI app that **mounts `stele.router`** and **composes
signup + login** over Stele's primitives. It is the clone-and-run-and-*use* proof
for Phase 7: a stranger stands up Postgres, runs Stele's baseline migration, fills
a generated `.env`, starts this app, and **registers a real passkey in a browser**
that round-trips through `stele.router`.

This is host code — not part of the `stele` package. It shows, in one readable
module (`reference_app/main.py`), exactly what a real mount takes.

## What it demonstrates

- **The post-lift mount** — `stele.router`'s 8 enrollment routes with only **two
  required providers**: a DB session and a WebAuthn config. The passkey-enrollment
  ceremony is Stele's own (lifted at P7-3), so the host supplies no ceremony.
- **Both delivery shapes** over one Stele-minted token — a browser uses the session
  **cookie**; an agent sends `Authorization: Bearer`. One `extract_token` override
  serves both.
- **Enrollment AND login** — enrollment is the mounted routes; login is host
  composition (passkey assertion → TOTP or recovery code → full session).
  Login-TOTP is composed here (decrypt the secret, then verify) — Stele's surface
  does not grow.
- **Seed alignment** — **no email as identity.** Sign-in keys on credentials only.
  The app collects a display name, never an email, and never looks anyone up by one.

## Run it

Prerequisites: Python 3.12, the `stele` package installed (e.g. `uv pip install -e
..` from this `examples/` directory, or `pip install -e ..`), plus `uvicorn`.

1. **Generate a `.env`** (fresh secret + fields to fill):

   ```sh
   python generate_env.py > .env
   ```

   Fill `STELE_RP_ID` / `STELE_RP_NAME` / `STELE_RP_ORIGIN` / `STELE_DATABASE_URL`.
   For a local run the generated defaults already work with the Postgres below.

2. **Start Postgres** (throwaway):

   ```sh
   docker compose up -d
   # → postgresql+asyncpg://stele:stele@localhost:5433/stele_ref
   ```

   (No Docker? Point `STELE_DATABASE_URL` at any reachable Postgres database.)

3. **Run Stele's baseline migration** against that database:

   ```sh
   cd ..                       # the stele repo root (has alembic.ini)
   STELE_DATABASE_URL=postgresql+asyncpg://stele:stele@localhost:5433/stele_ref \
     alembic upgrade head
   cd examples
   ```

4. **Start the app**:

   ```sh
   set -a; . ./.env; set +a
   uvicorn reference_app.main:app --reload --port 8000
   ```

5. **Open** `http://localhost:8000`, sign up (register a passkey + scan the TOTP
   QR), then sign out and log back in. The passkey round-trips through
   `stele.router`'s ceremony.

## The one thing strangers get wrong: RP origin must match

The browser refuses the WebAuthn ceremony unless `STELE_RP_ID` is the host of the
page's origin and `STELE_RP_ORIGIN` is the **exact** origin you serve from. Serve
at `http://localhost:8000` → `STELE_RP_ID=localhost`, `STELE_RP_ORIGIN=http://localhost:8000`.
A mismatch is the most common first failure.

## The cookie name is the host's

This app names its own session cookie (`stele_ref_session`, in `config.py`). Stele's
`issue_session` is mint-only and the router sets no cookie, so delivery — including
the cookie name — is wholly the host's. An adopter never inherits a Stele cookie
name.
