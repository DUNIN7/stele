# Stele mount contract — the adopter's guide — v0.1

**Version.** 0.1
**Date.** 2026-06-19
**Status.** The mount contract for an adopter of the standalone Stele package, written down. What each slot is, what you supply, where the boundary sits. Adopter-facing.
**Render-type.** Standard. HTML primary, Markdown source alongside.

---

## Plain-language summary

Stele is a standalone identity substrate: principals (a UUID identity), WebAuthn passkeys, TOTP, and recovery codes, with a KEK-encrypted secret floor and its own three-table migration. You mount its eight credential-management routes into your own FastAPI app and supply **two** things — a database session and a WebAuthn relying-party config. Everything else has a working default. Stele proves *who* a caller is; your app decides *what they may reach*. A runnable reference host lives at `stele/examples/`; this document is that host narrated.

## What Stele draws a line around: authentication, not authorization

Stele **authenticates** — it resolves who a caller is and operates on that caller's own credentials (their passkeys, their recovery codes, their authenticator). It does **not authorize** — it never decides what a principal may reach in *your* system. That decision is yours, and the seam is one slot: `resolve_current_principal`. Stele ships a default resolver that checks the session is valid and the second factor verified; you override it to add your own policy (membership, account status, whatever your app gates on). A router that assumed one host's authorization could not be mounted in another — so Stele assumes none.

## The mount, in one paragraph

```python
from fastapi import FastAPI
import stele

app = FastAPI()
app.include_router(stele.router, prefix="/me/security")
app.dependency_overrides[stele.provide_db_session] = my_db_session     # required
app.dependency_overrides[stele.provide_webauthn_config] = my_rp_config  # required
```

`stele.router` carries eight routes — register/list/remove passkeys, regenerate/check recovery codes, rotate the authenticator. `import stele` pulls no web framework; only touching `stele.router` loads FastAPI. You choose the mount prefix.

## The slots you wire

Override a slot through FastAPI's `dependency_overrides`, keyed on the slot object itself.

| Slot | Required? | What you supply |
|---|---|---|
| `provide_db_session` | **Required** | Yields a request-scoped `AsyncSession` against your Postgres. Raises until supplied. |
| `provide_webauthn_config` | **Required** | Returns `WebauthnConfig(rp_id, rp_name, rp_origin)` — your relying party. Raises until supplied. |
| `resolve_current_principal` | Optional | Default checks the session + second factor. Override to carry **your** authorization policy. |
| `require_fresh_session` | Optional | Default checks the same as `resolve_current_principal`, **plus** rejects if the second factor was verified more than `STELE_STEP_UP_WINDOW_SECONDS` ago (default 900s / 15 min). Gates six sensitive-mutation routes — see below. Override to change the window, or your own step-up policy. |
| `extract_token` | Optional | Default reads `Authorization: Bearer`. Override for cookie delivery (see below). |
| `provide_secret_key` | Optional | Default reads `STELE_SECRET_KEY` from the environment. Override to inject your KEK another way. |
| `provide_person_email` | Optional | Default `None`. Override only to put an email in the authenticator label — Stele never uses it as identity. |

Only the two required slots have no safe default — and they **fail loudly** (a clear error at request time) if you forget them, rather than silently doing the wrong thing. There is **no ceremony slot**: the passkey-enrollment ceremony is Stele's own, so you supply none.

A minimal `provide_db_session`:

```python
from sqlalchemy.ext.asyncio import async_sessionmaker
session_factory = async_sessionmaker(engine, expire_on_commit=False)

async def my_db_session():
    async with session_factory() as session:
        yield session
```

A minimal `provide_webauthn_config`:

```python
from stele.webauthn import WebauthnConfig
def my_rp_config():
    return WebauthnConfig(rp_id="localhost", rp_name="My App", rp_origin="http://localhost:8000")
```

## Step-up: recent-second-factor required for sensitive mutations

A session authenticated at any point up to its full lifetime (24 hours by default) can otherwise call any mounted route — including credential-changing ones. `require_fresh_session` closes that gap: it gates six mutation routes that change what can sign in as this principal — `passkeys/begin`, `passkeys/complete`, `DELETE passkeys/{id}`, `recovery-codes/regenerate`, `totp/rotate/begin`, `totp/rotate/confirm` — and additionally rejects the request if the second factor was verified more than `STELE_STEP_UP_WINDOW_SECONDS` ago (default 900 seconds / 15 minutes), read from the session's `created_at`. Read-only routes (`GET passkeys`, `GET recovery-codes`) and `provide_person_email` (a lookup, not a mutation) stay on the plain `resolve_current_principal` gate.

This is a **freshness window**, not a re-entry-of-credential ceremony — it does not ask the caller to re-type a TOTP code or re-assert a passkey. If your app needs that heavier guarantee, override `require_fresh_session` with your own dependency.

## Delivery: cookie or bearer, your choice

Stele mints session tokens; it does **not** set cookies. `issue_session` returns you the token and nothing else — how it reaches the browser is yours to decide. The shipped `extract_token` default reads an `Authorization: Bearer` header (the neutral, agent-friendly shape). For a browser app, override it to read your cookie — and you can serve both shapes at once:

```python
async def extract_token(request):
    cookie = request.cookies.get("my_session")     # browser
    if cookie:
        return cookie
    header = request.headers.get("Authorization", "")  # agent
    scheme, _, token = header.partition(" ")
    return token if scheme.lower() == "bearer" and token else None
```

The **cookie name is yours.** Stele exports none for you to inherit — you name your own, set it from the token Stele mints, and read it back in `extract_token`. The reference host names its cookie `stele_ref_session`.

## The minimal mount, walked

This is the reference host at `stele/examples/`, narrated. It is copy-runnable.

1. **Install** Stele and `uvicorn` into your environment.
2. **Generate config** — `python examples/generate_env.py > .env`. The generator emits a real, freshly generated `STELE_SECRET_KEY` (never ship a placeholder) plus the fields to fill: `STELE_RP_ID`, `STELE_RP_NAME`, `STELE_RP_ORIGIN`, `STELE_DATABASE_URL`.
3. **Stand up Postgres** — `docker compose up -d` brings up a throwaway one. (Stele's tables use `JSONB` and `bytea`; SQLite is not an option.)
4. **Run the migration** — `alembic upgrade head` from the Stele repo root creates the three tables.
5. **Start the app** — load the `.env`, then `uvicorn reference_app.main:app --port 8000`.
6. **Open** `http://localhost:8000`, register a passkey with a real authenticator, scan the TOTP secret, and you are signed in. Sign out and sign back in — the passkey round-trips through `stele.router`.

The reference host composes the marquee flows itself (signup and login are *yours* to orchestrate — Stele ships the primitives, not the policy): passkey assertion → second factor (a TOTP code or a recovery code) → a full session. Login-TOTP it composes by decrypting the stored secret and verifying the code — Stele's surface stays the credential-management routes plus the primitives, and does not grow a login of its own.

## The one thing that trips everyone: RP origin must match

The browser refuses a WebAuthn ceremony unless your relying-party config matches where the page is served. `STELE_RP_ID` is the registrable domain — the **host** of the origin, e.g. `localhost`. `STELE_RP_ORIGIN` is the **exact** origin — scheme, host, and port, e.g. `http://localhost:8000`. Serve the page from a different origin than you configured and the ceremony fails before it starts. This is the most common first-run failure; check it first.

## No email as identity

Stele keys sign-in on credentials — passkeys, the authenticator, recovery codes — never on an email address. There is no email lookup and no email-based recovery reset. If your app collects an email at all, it is a contact channel, not an identity, and Stele never reads it (`provide_person_email` exists only to label an authenticator, and defaults to none). Build your signup and login the same way the reference host does, and you will not reintroduce email-as-identity by habit.

**There is no "remember ID" field — and there should not be one.** Sign-in runs the WebAuthn *discoverable* flow: the browser offers every passkey registered for your relying party and the user picks one. The authenticator holds the identity, so the user types no email, username, or account id before the assertion — and identity is resolved afterward by the credential they chose. `begin_authentication` defaults to exactly this (it sends no `allowCredentials`), and the reference host's login asks for nothing but the passkey, then a second factor. An email, username, or "remember ID" box at sign-in would reintroduce identity-by-attribute — the very thing the discoverable flow removes. Do not add one by habit.

## Where the code is

The runnable reference host — the source of every example above — is `stele/examples/` in the Stele repository: `reference_app/main.py` (the whole mount in one readable module), `reference_app/static/` (the browser ceremony), `generate_env.py` (the config generator), `docker-compose.yml`, and a `README` that walks the run.

---

DUNIN7 — Done In Seven LLC — Miami, Florida
Stele mount contract — the adopter's guide — v0.1 — 2026-06-19
