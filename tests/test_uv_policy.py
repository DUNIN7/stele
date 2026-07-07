"""TS-08 — unit tests for UV (user verification) policy threading.

``WebauthnConfig.user_verification`` (default ``PREFERRED``) drives both
ceremonies: ``begin_registration``/``begin_authentication`` request it in the
options sent to the browser, and ``verify_registration``/``verify_authentication``
enforce it server-side by passing ``require_user_verification`` to the
underlying library only when the policy is ``REQUIRED`` — the library itself
defaults that flag to ``False`` regardless of what was requested, so without
this threading a stolen authenticator satisfying only user-presence (a touch,
no PIN/biometric) would still verify. Pure unit tests: ``begin_*`` build
options offline; ``verify_*`` are exercised by monkeypatching the
library-boundary functions to capture the kwargs they were called with.
"""
from __future__ import annotations

import json

import pytest

from stele.webauthn import (
    WebauthnConfig,
    begin_authentication,
    begin_registration,
    verify_authentication,
    verify_registration,
)
from webauthn.helpers.structs import UserVerificationRequirement

_PREFERRED_CONFIG = WebauthnConfig(
    rp_id="localhost", rp_name="Test RP", rp_origin="http://localhost:8000"
)
_REQUIRED_CONFIG = WebauthnConfig(
    rp_id="localhost",
    rp_name="Test RP",
    rp_origin="http://localhost:8000",
    user_verification=UserVerificationRequirement.REQUIRED,
)


def test_webauthn_config_user_verification_defaults_to_preferred():
    assert _PREFERRED_CONFIG.user_verification == UserVerificationRequirement.PREFERRED


def test_begin_registration_requests_configured_uv_policy():
    preferred = begin_registration(
        config=_PREFERRED_CONFIG, user_name="a@example.com", user_display_name="A"
    )
    required = begin_registration(
        config=_REQUIRED_CONFIG, user_name="a@example.com", user_display_name="A"
    )
    assert (
        json.loads(preferred.options_json)["authenticatorSelection"]["userVerification"]
        == "preferred"
    )
    assert (
        json.loads(required.options_json)["authenticatorSelection"]["userVerification"]
        == "required"
    )


def test_begin_authentication_requests_configured_uv_policy():
    preferred = begin_authentication(config=_PREFERRED_CONFIG)
    required = begin_authentication(config=_REQUIRED_CONFIG)
    assert json.loads(preferred.options_json)["userVerification"] == "preferred"
    assert json.loads(required.options_json)["userVerification"] == "required"


def test_verify_registration_does_not_require_uv_when_preferred(monkeypatch):
    import stele.webauthn as stele_webauthn

    captured = {}

    def _fake_verify(**kw):
        captured.update(kw)

        class _Result:
            credential_id = b"cred"
            credential_public_key = b"pubkey"
            sign_count = 0

        return _Result()

    monkeypatch.setattr(stele_webauthn, "_verify_registration_response", _fake_verify)
    verify_registration(
        config=_PREFERRED_CONFIG,
        credential={"id": "x", "rawId": "x", "response": {}, "type": "public-key"},
        expected_challenge=b"challenge",
    )
    assert captured["require_user_verification"] is False


def test_verify_registration_requires_uv_when_required(monkeypatch):
    import stele.webauthn as stele_webauthn

    captured = {}

    def _fake_verify(**kw):
        captured.update(kw)

        class _Result:
            credential_id = b"cred"
            credential_public_key = b"pubkey"
            sign_count = 0

        return _Result()

    monkeypatch.setattr(stele_webauthn, "_verify_registration_response", _fake_verify)
    verify_registration(
        config=_REQUIRED_CONFIG,
        credential={"id": "x", "rawId": "x", "response": {}, "type": "public-key"},
        expected_challenge=b"challenge",
    )
    assert captured["require_user_verification"] is True


def test_verify_authentication_does_not_require_uv_when_preferred(monkeypatch):
    import stele.webauthn as stele_webauthn

    captured = {}

    def _fake_verify(**kw):
        captured.update(kw)

        class _Result:
            credential_id = b"cred"
            new_sign_count = 1

        return _Result()

    monkeypatch.setattr(stele_webauthn, "_verify_authentication_response", _fake_verify)
    verify_authentication(
        config=_PREFERRED_CONFIG,
        credential={"id": "x", "rawId": "x", "response": {}, "type": "public-key"},
        expected_challenge=b"challenge",
        credential_public_key=b"pubkey",
        current_sign_count=0,
    )
    assert captured["require_user_verification"] is False


def test_verify_authentication_requires_uv_when_required(monkeypatch):
    import stele.webauthn as stele_webauthn

    captured = {}

    def _fake_verify(**kw):
        captured.update(kw)

        class _Result:
            credential_id = b"cred"
            new_sign_count = 1

        return _Result()

    monkeypatch.setattr(stele_webauthn, "_verify_authentication_response", _fake_verify)
    verify_authentication(
        config=_REQUIRED_CONFIG,
        credential={"id": "x", "rawId": "x", "response": {}, "type": "public-key"},
        expected_challenge=b"challenge",
        credential_public_key=b"pubkey",
        current_sign_count=0,
    )
    assert captured["require_user_verification"] is True
