"""Stele — the identity module (CR-2026-103, Phase 0).

A host-agnostic, in-process-first / service-ready boundary for identity:
credentials (passkeys, TOTP, recovery codes), the WebAuthn ceremony, and
session encode/decode. Phase 0 stands up this empty package; the zero
external-caller identity pieces currently in ``persons/`` move in next.
The key-encryption key (KEK) does NOT live here — it stays shared infra
in ``credentials/`` and Stele references it.
"""
