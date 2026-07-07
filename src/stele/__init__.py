"""Stele — a standalone identity & authentication substrate.

Principals (UUID identity), WebAuthn passkeys, TOTP, and recovery codes, with a
KEK-direct secret floor and an independently-runnable migration set. This is the
package's public SDK surface: the primitives below, plus a **mountable FastAPI
router** at ``stele.router``.

## The primitives (always available — no web framework needed)

Identity / session / credential / recovery / TOTP / WebAuthn / KEK operations are
re-exported at the top level, e.g. ``stele.mint_principal``, ``stele.Principal``,
``stele.issue_session``, ``stele.resolve_session``, ``stele.list_credentials_for_person``.
The ORM rows and ``Base`` (for the migration set) are here too. Importing ``stele``
or any submodule pulls **no web framework** — only the data/crypto deps.

## The mountable router (``stele.router`` — pulls FastAPI lazily)

``stele.router`` and the injection slots are imported lazily on first access, so a
library/ORM-only consumer never loads FastAPI. A host mounts the 8 credential-backed
primitive routes (passkey enrollment, recovery codes, TOTP rotation) like this::

    from fastapi import FastAPI
    import stele

    app = FastAPI()
    app.include_router(stele.router, prefix="/me/security")

    # --- the injection contract (override via FastAPI dependency_overrides) ---
    # Required (no safe default — raise until supplied):
    app.dependency_overrides[stele.provide_db_session]      = my_db_session_dep
    app.dependency_overrides[stele.provide_webauthn_config] = my_webauthn_config_dep
    # Override to carry YOUR policy gate (the default only checks the session + 2FA):
    app.dependency_overrides[stele.resolve_current_principal] = my_principal_resolver
    # Optional:
    app.dependency_overrides[stele.extract_token]        = my_cookie_extractor   # cookie delivery
    app.dependency_overrides[stele.provide_secret_key]   = my_secret_key_dep     # inject your KEK
    app.dependency_overrides[stele.provide_person_email] = my_email_lookup        # passkeys/begin only

**The authorization boundary:** Stele *authenticates* (resolves *who*, operates on
the principal's own credentials). The host *authorizes* (*what-here*) — the
``resolve_current_principal`` slot is where the host injects its policy. A mountable
router that assumed a specific host's authorization would not be mountable elsewhere.

The injection contract has **2 required slots** (``provide_db_session``,
``provide_webauthn_config``) and 5 optional/defaulted slots. The passkey-enrollment
ceremony is Stele's own (in ``stele.webauthn``) — no host ceremony callables to
supply. The reference app under ``examples/`` shows a complete, runnable mount.
"""
from __future__ import annotations

# --- primitives (eager; no web framework) -----------------------------------
from stele.base import Base
from stele.models import PrincipalRow, RecoveryCodeRow, WebauthnCredentialRow
from stele.registry import (
    Principal,
    create_principal,
    get_principal_by_id,
    mint_principal,
)
from stele.session import (
    ResolvedSession,
    SessionInvalid,
    SessionPayload,
    decode_session,
    encode_session,
    issue_session,
    resolve_session,
)
from stele.credentials import (
    LastPasskeyError,
    WebauthnCredential,
    add_credential,
    get_credential_by_credential_id,
    list_credentials_for_person,
    remove_credential,
    update_sign_count,
)
from stele.recovery import (
    count_active_recovery_codes,
    count_unused_recovery_codes,
    generate_recovery_codes,
    hash_recovery_code,
    regenerate_recovery_codes,
    store_recovery_codes,
    verify_and_consume_recovery_code,
)
from stele.person_totp import (
    PersonTotpCodeInvalid,
    PersonTotpProvisioning,
    begin_totp_rotation,
    confirm_totp_rotation,
)
from stele.webauthn import (
    AddPasskeyBeginResult,
    AuthenticationChallenge,
    LoginChallengeBeginResult,
    LoginChallengeNotFound,
    PasskeyEnrollmentError,
    PasskeyEnrollmentNotFound,
    PendingAddPasskeyStore,
    PendingLoginChallengeStore,
    RegistrationChallenge,
    VerifiedAssertionData,
    VerifiedCredentialData,
    WebauthnConfig,
    add_passkey_begin,
    add_passkey_complete,
    begin_authentication,
    begin_registration,
    login_challenge_begin,
    login_challenge_complete,
    verify_authentication,
    verify_registration,
)
from stele.kek import (
    EnvKeyEncryptionKeyProvider,
    KeyEncryptionKeyProvider,
    KeyEncryptionKeyUnavailableError,
    kek_decrypt,
    kek_encrypt,
    kek_multifernet,
    kek_provider,
)

# --- the mountable router + injection slots (lazy: pulls FastAPI on access) ---
# Exposed via PEP 562 module __getattr__ so importing stele (or any primitive)
# never requires FastAPI; only touching stele.router does.
_LAZY_API = {
    "router",
    "resolve_current_principal",
    "extract_token",
    "provide_secret_key",
    "provide_db_session",
    "provide_webauthn_config",
    "provide_person_email",
}


def __getattr__(name: str):
    if name in _LAZY_API:
        from stele import api as _api

        return getattr(_api, name)
    raise AttributeError(f"module 'stele' has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + list(_LAZY_API))


__all__ = [
    # identity
    "Principal", "mint_principal", "create_principal", "get_principal_by_id",
    # session
    "issue_session", "resolve_session", "decode_session", "encode_session",
    "ResolvedSession", "SessionPayload", "SessionInvalid",
    # credentials
    "WebauthnCredential", "list_credentials_for_person", "add_credential",
    "remove_credential", "get_credential_by_credential_id", "update_sign_count",
    "LastPasskeyError",
    # recovery
    "regenerate_recovery_codes", "count_unused_recovery_codes",
    "count_active_recovery_codes", "verify_and_consume_recovery_code",
    "generate_recovery_codes", "hash_recovery_code", "store_recovery_codes",
    # totp
    "begin_totp_rotation", "confirm_totp_rotation", "PersonTotpCodeInvalid",
    "PersonTotpProvisioning",
    # webauthn (+ the add-passkey enrollment ceremony)
    "WebauthnConfig", "begin_registration", "verify_registration",
    "begin_authentication", "verify_authentication", "RegistrationChallenge",
    "AuthenticationChallenge", "VerifiedCredentialData", "VerifiedAssertionData",
    "add_passkey_begin", "add_passkey_complete", "AddPasskeyBeginResult",
    "PendingAddPasskeyStore", "PasskeyEnrollmentNotFound", "PasskeyEnrollmentError",
    "login_challenge_begin", "login_challenge_complete", "LoginChallengeBeginResult",
    "PendingLoginChallengeStore", "LoginChallengeNotFound",
    # kek / crypto
    "EnvKeyEncryptionKeyProvider", "KeyEncryptionKeyProvider",
    "KeyEncryptionKeyUnavailableError", "kek_encrypt", "kek_decrypt",
    "kek_multifernet", "kek_provider",
    # ORM / migration
    "Base", "PrincipalRow", "WebauthnCredentialRow", "RecoveryCodeRow",
    # mountable router + injection contract (lazy)
    "router", "resolve_current_principal", "extract_token", "provide_secret_key",
    "provide_db_session", "provide_webauthn_config", "provide_person_email",
]
