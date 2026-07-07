"""WebAuthn registration and authentication helpers.

Thin wrappers around the `webauthn` library. Stele does not implement
WebAuthn cryptographic operations directly; this module isolates the
library boundary so the rest of the package deals with plain dataclasses
(`RegistrationChallenge`, `VerifiedCredentialData`) and orchestration code
can be tested without exercising the real ceremony.

The verify entry points (`verify_registration`, `verify_authentication`)
are exposed as module-level callables so tests can monkeypatch them to
return canned VerifiedRegistration / VerifiedAuthentication objects
without having to drive a real authenticator.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from webauthn import (
    generate_authentication_options as _gen_auth_options,
    generate_registration_options as _gen_registration_options,
    options_to_json as _options_to_json,
    verify_authentication_response as _verify_authentication_response,
    verify_registration_response as _verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from stele import credentials as credentials_registry


@dataclass(frozen=True)
class WebauthnConfig:
    """Relying-party configuration. Built once from settings at app
    startup; passed explicitly to every helper for testability."""

    rp_id: str
    rp_name: str
    rp_origin: str


@dataclass(frozen=True)
class RegistrationChallenge:
    """Server-side state for a pending registration ceremony.

    `user_handle` is the WebAuthn user.id — a 16-byte opaque value the
    authenticator stores alongside the credential. We generate it
    fresh per ceremony so it's not tied to any database identifier."""

    challenge: bytes
    user_handle: bytes
    options_json: str


@dataclass(frozen=True)
class VerifiedCredentialData:
    """Extract of a successful registration: the fields we persist to
    `webauthn_credentials`. Transports are reported by the authenticator
    in the registration response and we forward them to the client at
    auth time so the right authenticator is picked."""

    credential_id: bytes
    public_key: bytes
    sign_count: int
    transports: Optional[list[str]] = None


@dataclass(frozen=True)
class AuthenticationChallenge:
    """Server-side state for a pending authentication ceremony."""

    challenge: bytes
    options_json: str


@dataclass(frozen=True)
class VerifiedAssertionData:
    """Extract of a successful authentication: just enough to update
    sign_count on the matching credential and identify which credential
    answered."""

    credential_id: bytes
    new_sign_count: int


def begin_registration(
    *,
    config: WebauthnConfig,
    user_name: str,
    user_display_name: str,
    exclude_credentials: list[bytes] | None = None,
) -> RegistrationChallenge:
    """Build PublicKeyCredentialCreationOptions for a new passkey.

    `user_name` is the human-readable handle the authenticator may show
    (typically email or display_name); `user_display_name` is the
    longer label. `exclude_credentials` is the list of credential ids
    already registered for this person — passing them avoids a second
    registration of the same authenticator on the same account.
    """
    user_handle = os.urandom(16)
    excluded = (
        [
            PublicKeyCredentialDescriptor(id=cid)
            for cid in exclude_credentials
        ]
        if exclude_credentials
        else None
    )
    options = _gen_registration_options(
        rp_id=config.rp_id,
        rp_name=config.rp_name,
        user_id=user_handle,
        user_name=user_name,
        user_display_name=user_display_name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        exclude_credentials=excluded,
    )
    return RegistrationChallenge(
        challenge=options.challenge,
        user_handle=user_handle,
        options_json=_options_to_json(options),
    )


def verify_registration(
    *,
    config: WebauthnConfig,
    credential: dict[str, Any],
    expected_challenge: bytes,
) -> VerifiedCredentialData:
    """Verify the attestation response from `navigator.credentials.create()`.

    Wraps `webauthn.verify_registration_response`. Tests monkeypatch
    this module-level function to return a canned VerifiedCredentialData
    without exercising the real cryptographic verifier.
    """
    verified = _verify_registration_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id=config.rp_id,
        expected_origin=config.rp_origin,
    )
    transports = _extract_transports(credential)
    return VerifiedCredentialData(
        credential_id=verified.credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        transports=transports,
    )


def begin_authentication(
    *,
    config: WebauthnConfig,
    allow_credentials: list[bytes] | None = None,
) -> AuthenticationChallenge:
    """Build PublicKeyCredentialRequestOptions for sign-in.

    With no `allow_credentials` the browser presents every passkey
    bound to the RP id (discoverable / resident-key flow). With a list,
    the browser narrows to those credentials only — appropriate when
    the caller has hinted a specific person.
    """
    descriptors = (
        [
            PublicKeyCredentialDescriptor(id=cid)
            for cid in allow_credentials
        ]
        if allow_credentials
        else None
    )
    options = _gen_auth_options(
        rp_id=config.rp_id,
        allow_credentials=descriptors,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return AuthenticationChallenge(
        challenge=options.challenge,
        options_json=_options_to_json(options),
    )


def verify_authentication(
    *,
    config: WebauthnConfig,
    credential: dict[str, Any],
    expected_challenge: bytes,
    credential_public_key: bytes,
    current_sign_count: int,
) -> VerifiedAssertionData:
    """Verify the assertion response from `navigator.credentials.get()`.

    Returns the identified credential id and the new sign_count the
    caller should persist back to the credential row. Tests monkeypatch
    this function to return a canned result.
    """
    verified = _verify_authentication_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id=config.rp_id,
        expected_origin=config.rp_origin,
        credential_public_key=credential_public_key,
        credential_current_sign_count=current_sign_count,
    )
    return VerifiedAssertionData(
        credential_id=verified.credential_id,
        new_sign_count=verified.new_sign_count,
    )


def _extract_transports(credential: dict[str, Any]) -> Optional[list[str]]:
    """Pull the authenticator-reported transports off a registration
    response, if present. Defensive — many authenticators omit it."""
    response = credential.get("response") if isinstance(credential, dict) else None
    if not isinstance(response, dict):
        return None
    transports = response.get("transports")
    if not transports:
        return None
    if isinstance(transports, list) and all(isinstance(t, str) for t in transports):
        return list(transports)
    return None


# ===========================================================================
# Add-passkey enrollment ceremony. An already-signed-in person registers an
# additional passkey: ``add_passkey_begin`` issues the WebAuthn challenge and
# parks the pending state; ``add_passkey_complete`` verifies the attestation and
# persists the new credential. It is a thin orchestration over this module's own
# ``begin_registration`` / ``verify_registration`` plus
# ``stele.credentials.add_credential`` — so its companion pending store lives
# here too. No host concepts cross: ``person_id`` is the principal id.
# ===========================================================================

ADD_PASSKEY_PENDING_TTL = timedelta(minutes=5)


class PasskeyEnrollmentNotFound(Exception):
    """An unknown or expired add-passkey handle. The mount maps this to 404."""


class PasskeyEnrollmentError(Exception):
    """An add-passkey verification failure. The mount maps this to 400."""


@dataclass
class _PendingAddPasskey:
    """In-flight add-passkey ceremony state. ``person_id`` is the principal id —
    identity-only, no host concepts; the mount binds it against the
    authenticated caller before persisting."""

    person_id: UUID
    challenge: bytes
    user_handle: bytes
    options_json: str
    expires_at: datetime


@dataclass(frozen=True)
class AddPasskeyBeginResult:
    add_id: str
    options_json: str


class PendingAddPasskeyStore:
    """In-process pending store for the add-passkey ceremony. A single process
    holds one; a future multi-process host swaps a database-backed
    implementation behind the same shape."""

    def __init__(self) -> None:
        self._records: dict[str, _PendingAddPasskey] = {}

    def put(self, add_id: str, record: _PendingAddPasskey) -> None:
        self._records[add_id] = record

    def get(self, add_id: str, *, now: datetime) -> _PendingAddPasskey:
        record = self._records.get(add_id)
        if record is None:
            raise PasskeyEnrollmentNotFound(f"No pending add-passkey {add_id}")
        if record.expires_at <= now:
            self._records.pop(add_id, None)
            raise PasskeyEnrollmentNotFound(
                f"Pending add-passkey {add_id} has expired"
            )
        return record

    def discard(self, add_id: str) -> None:
        self._records.pop(add_id, None)


# The ceremony's Stele-internal pending store. The mountable router
# (``stele.api``) reaches this singleton directly; a host driving the ceremony
# outside the router may pass its own store instance via the ``store`` kwarg.
pending_add_passkey_store = PendingAddPasskeyStore()


async def add_passkey_begin(
    *,
    person_id: UUID,
    person_display_name: str,
    person_email: Optional[str],
    config: WebauthnConfig,
    existing_credential_ids: list[bytes],
    now: datetime,
    store: PendingAddPasskeyStore | None = None,
) -> AddPasskeyBeginResult:
    """Begin a registration ceremony for an additional passkey on an
    already-signed-in person. ``existing_credential_ids`` populates the WebAuthn
    excludeCredentials list so the same authenticator cannot register twice on
    the same person. Defaults to the module pending store."""
    store = store if store is not None else pending_add_passkey_store
    challenge = begin_registration(
        config=config,
        user_name=person_email or person_display_name,
        user_display_name=person_display_name,
        exclude_credentials=existing_credential_ids,
    )
    add_id = f"add_{secrets.token_urlsafe(24)}"
    store.put(
        add_id,
        _PendingAddPasskey(
            person_id=person_id,
            challenge=challenge.challenge,
            user_handle=challenge.user_handle,
            options_json=challenge.options_json,
            expires_at=now + ADD_PASSKEY_PENDING_TTL,
        ),
    )
    return AddPasskeyBeginResult(add_id=add_id, options_json=challenge.options_json)


async def add_passkey_complete(
    *,
    add_id: str,
    credential: dict,
    config: WebauthnConfig,
    db: AsyncSession,
    now: datetime,
    display_name: Optional[str] = None,
    store: PendingAddPasskeyStore | None = None,
) -> UUID:
    """Verify the attestation and persist the new credential bound to the
    in-flight person. Returns the new credential's id. Defaults to the module
    pending store."""
    store = store if store is not None else pending_add_passkey_store
    record = store.get(add_id, now=now)
    verified = verify_registration(
        config=config,
        credential=credential,
        expected_challenge=record.challenge,
    )
    new_credential = await credentials_registry.add_credential(
        person_id=record.person_id,
        credential_id=verified.credential_id,
        public_key=verified.public_key,
        sign_count=verified.sign_count,
        transports=verified.transports,
        display_name=display_name,
        db=db,
    )
    store.discard(add_id)
    return new_credential.id


# ===========================================================================
# Login-challenge ceremony. TS-06: the passkey-assertion (login) flow was the
# one ceremony Stele defined the pure primitives for (``begin_authentication``,
# ``verify_authentication``) but shipped no pending-challenge store for — every
# host had to reinvent one. ``login_challenge_begin`` issues the WebAuthn
# request options and parks the pending state; ``login_challenge_complete``
# retrieves it and verifies the assertion. Named ``login_challenge_*`` (not
# ``login_*``) to avoid colliding with a host's own login route names. Mirrors
# the add-passkey ceremony's shape exactly, including its pending store lives
# here too. Unlike ``add_passkey_complete``, this does not perform the
# credential lookup itself — ``credential_public_key``/``current_sign_count``
# are supplied by the caller, matching ``verify_authentication``'s existing
# contract (the assertion can name any enrolled credential; only the caller
# knows which one it resolved).
# ===========================================================================

LOGIN_CHALLENGE_PENDING_TTL = timedelta(minutes=5)


class LoginChallengeNotFound(Exception):
    """An unknown or expired login-challenge handle. The mount/host maps this
    to 404."""


@dataclass
class _PendingLoginChallenge:
    """In-flight login (authentication) ceremony state."""

    challenge: bytes
    expires_at: datetime


@dataclass(frozen=True)
class LoginChallengeBeginResult:
    login_id: str
    options_json: str


class PendingLoginChallengeStore:
    """In-process pending store for the login-challenge ceremony. A single
    process holds one; a future multi-process host swaps a database-backed
    implementation behind the same shape."""

    def __init__(self) -> None:
        self._records: dict[str, _PendingLoginChallenge] = {}

    def put(self, login_id: str, record: _PendingLoginChallenge) -> None:
        self._records[login_id] = record

    def get(self, login_id: str, *, now: datetime) -> _PendingLoginChallenge:
        record = self._records.get(login_id)
        if record is None:
            raise LoginChallengeNotFound(f"No pending login challenge {login_id}")
        if record.expires_at <= now:
            self._records.pop(login_id, None)
            raise LoginChallengeNotFound(
                f"Pending login challenge {login_id} has expired"
            )
        return record

    def discard(self, login_id: str) -> None:
        self._records.pop(login_id, None)


# The ceremony's Stele-internal pending store. A host driving the ceremony
# may pass its own store instance via the ``store`` kwarg instead.
pending_login_challenge_store = PendingLoginChallengeStore()


async def login_challenge_begin(
    *,
    config: WebauthnConfig,
    allow_credentials: list[bytes] | None = None,
    now: datetime,
    store: PendingLoginChallengeStore | None = None,
) -> LoginChallengeBeginResult:
    """Begin a login (authentication) ceremony. Defaults to the module
    pending store."""
    store = store if store is not None else pending_login_challenge_store
    challenge = begin_authentication(config=config, allow_credentials=allow_credentials)
    login_id = f"login_{secrets.token_urlsafe(24)}"
    store.put(
        login_id,
        _PendingLoginChallenge(
            challenge=challenge.challenge,
            expires_at=now + LOGIN_CHALLENGE_PENDING_TTL,
        ),
    )
    return LoginChallengeBeginResult(login_id=login_id, options_json=challenge.options_json)


async def login_challenge_complete(
    *,
    login_id: str,
    credential: dict[str, Any],
    config: WebauthnConfig,
    credential_public_key: bytes,
    current_sign_count: int,
    now: datetime,
    store: PendingLoginChallengeStore | None = None,
) -> VerifiedAssertionData:
    """Verify the assertion response against the pending login challenge.

    Consumption is success-only: ``discard`` is only reached after
    ``verify_authentication`` succeeds, so a failed verification (wrong
    authenticator, dismissed prompt, transient error) leaves the challenge
    redeemable until it expires — matching ``add_passkey_complete``. Defaults
    to the module pending store.
    """
    store = store if store is not None else pending_login_challenge_store
    record = store.get(login_id, now=now)
    verified = verify_authentication(
        config=config,
        credential=credential,
        expected_challenge=record.challenge,
        credential_public_key=credential_public_key,
        current_sign_count=current_sign_count,
    )
    store.discard(login_id)
    return verified
