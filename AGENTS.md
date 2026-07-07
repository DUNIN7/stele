# AGENTS.md — Integrating Stele

Stele is a standalone authentication library (passkeys, TOTP, recovery codes). It authenticates principals; it never authorizes. Identity is a system-assigned UUID — never an email address. Mount it into an existing FastAPI application.

## Hard constraints — do not violate

- **Never add an email or username field for sign-in.** Stele's login is the WebAuthn discoverable flow: the browser offers registered passkeys, the user picks one, no identifier is typed. Adding an email field reintroduces identity-by-attribute and breaks the substrate's core commitment.
- **Postgres only.** The schema uses `JSONB` and `bytea`. SQLite is not supported.
- **In-process pending-challenge stores are single-worker.** If deploying with multiple workers/processes, this needs a shared backing store — not built by default. Single-worker deployments are unaffected.

## Install

```
pip install -e "path/to/stele"
```

Or once published to PyPI: `pip install stele` (check the repo's current publication status).

## Required environment variables

- `STELE_SECRET_KEY` — a Fernet key. Generate with:
  `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
- `STELE_DATABASE_URL` — a `postgresql+asyncpg://` URL.
- `STELE_RP_ID`, `STELE_RP_NAME`, `STELE_RP_ORIGIN` — WebAuthn relying-party config. `rp_id` must be a valid registrable-domain suffix of `rp_origin`'s host (enforced at mount time — a mismatch raises immediately).

## Database setup

```
alembic upgrade head
```

Run from the installed package's root (where `alembic.ini` lives) with `STELE_DATABASE_URL` set. Creates `principals`, `webauthn_credentials`, `recovery_codes`.

## Mounting — the two mandatory slots

```python
from stele import router, provide_db_session, provide_webauthn_config, WebauthnConfig

app.dependency_overrides[provide_db_session] = your_db_session_dependency
app.dependency_overrides[provide_webauthn_config] = lambda: WebauthnConfig(
    rp_id="yourapp.com",
    rp_name="Your App",
    rp_origin="https://yourapp.com",
)
app.include_router(router, prefix="/auth")
```

Both slots are mandatory and fail loudly if unsupplied. Everything else (`resolve_current_principal`, `extract_token`, `provide_secret_key`, `provide_person_email`) has a working default — override only if you need different behavior.

## What Stele does not do (by design — don't build around this as a bug)

- **No authorization.** Stele confirms who someone is; your application decides what they can do. Do not expect a permissions or roles system from Stele.
- **No email-based password reset.** There is no email tied to identity. If a user loses every passkey, every recovery code, and their authenticator, that identity is unrecoverable by design.
- **No per-session revocation yet.** Sessions expire on a TTL; there's no way to kill one specific stolen session early today.
- **No built-in rate limiting yet** on authentication attempts.

## Full reference

- `docs/stele-mount-contract-v0_1.md` — the authoritative mount contract (all slots, all defaults, the full boundary).
- `examples/reference_app/` — a complete, runnable host application demonstrating every flow (signup, login, recovery, credential rotation).
- `CHANGELOG.md` — what's been fixed, what's a documented limitation.
