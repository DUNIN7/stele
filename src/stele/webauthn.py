"""WebAuthn registration and authentication helpers (Phase 14).

Thin wrappers around the Duo `webauthn` library. The substrate does
not implement WebAuthn cryptographic operations directly; this module
isolates the library boundary so the rest of the codebase deals with
plain dataclasses (`RegistrationOptions`, `VerifiedCredentialData`)
and orchestration code can be tested without exercising the real
ceremony.

The verify entry points (`verify_registration`, `verify_authentication`)
are exposed as module-level callables so tests can monkeypatch them to
return canned VerifiedRegistration / VerifiedAuthentication objects
without having to drive a real authenticator.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional

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
