"""KEK (key-encryption key) — Stele's standalone crypto floor.

Lifted and slimmed from the engine's ``loomworks.credentials.kek`` +
``loomworks.credentials.envelope`` (P7-1, CR-2026-114). Stele has exactly one
secret scope — the principal ``totp_secret`` — plus the session token, both
encrypted **KEK-direct** (Level A): the KEK is a Fernet ``MultiFernet``; writes
encrypt under the first (current) key, decrypt tries all (so an old key kept in
``previous`` still reads existing ciphertext during a rotation).

The engine's envelope / per-scope-DEK machinery (Level B — the
``data_encryption_keys`` table) is **not** lifted. At one secret scope it is
complexity without payoff, so Stele ships no DEK table. (Reclaimable if Stele
later grows a second secret kind: re-introduce the envelope then.)

KEK material is read from the environment (``STELE_SECRET_KEY``, with
``STELE_SECRET_KEYS_PREVIOUS`` for rotation) **only** when a ``secret_key`` is not
injected; every Stele call site injects an explicit ``secret_key``, so this env
read is a standalone fallback. (P7-2 §2 renamed the fallback key from the engine's
``LOOMWORKS_SECRET_KEY`` to this STELE-native name; the rename is strictly
internal — the engine reads its own ``LOOMWORKS_SECRET_KEY`` via its own provider
and injects it, never firing this fallback, so no engine deployment env changes.)
"""
from __future__ import annotations

import hashlib
import os
from typing import Protocol, runtime_checkable

from cryptography.fernet import Fernet, MultiFernet


class KeyEncryptionKeyUnavailableError(RuntimeError):
    """No KEK material is configured."""


@runtime_checkable
class KeyEncryptionKeyProvider(Protocol):
    """Source of KEK material. A host may swap the implementation (e.g. a
    KMS-backed provider) without touching callers."""

    def current_kek_material(self) -> str: ...
    def current_kek(self) -> str: ...
    def all_keks(self) -> list[str]: ...
    def kek_id(self) -> str: ...


class EnvKeyEncryptionKeyProvider:
    """Environment-backed KEK provider.

    ``secret_key`` may be injected (tests / host overrides); otherwise the live
    ``STELE_SECRET_KEY`` env value is read on every call. ``previous_keys``
    are older KEKs kept decrypt-readable during a rotation: ``all_keks`` returns
    ``[current, *previous]`` (current first). Injected for tests; otherwise read
    from ``STELE_SECRET_KEYS_PREVIOUS`` (comma-separated). Empty ⇒
    ``all_keks() == [current]``.
    """

    def __init__(
        self,
        secret_key: str | None = None,
        previous_keys: list[str] | None = None,
    ) -> None:
        self._secret_key = secret_key
        self._previous_keys = previous_keys

    def current_kek_material(self) -> str:
        if self._secret_key is not None:
            return self._secret_key
        return os.environ.get("STELE_SECRET_KEY", "") or ""

    def current_kek(self) -> str:
        key = self.current_kek_material()
        if not key:
            raise KeyEncryptionKeyUnavailableError(
                "No KEK material configured (STELE_SECRET_KEY is empty)."
            )
        return key

    def _previous(self) -> list[str]:
        if self._previous_keys is not None:
            return [k for k in self._previous_keys if k]
        raw = os.environ.get("STELE_SECRET_KEYS_PREVIOUS", "") or ""
        return [k.strip() for k in raw.split(",") if k.strip()]

    def all_keks(self) -> list[str]:
        keks: list[str] = []
        current = self.current_kek_material()
        if current:
            keks.append(current)
        for k in self._previous():
            if k and k not in keks:
                keks.append(k)
        return keks

    def kek_id(self) -> str:
        return hashlib.sha256(self.current_kek().encode()).hexdigest()[:16]


_default_provider: KeyEncryptionKeyProvider = EnvKeyEncryptionKeyProvider()


def kek_provider() -> KeyEncryptionKeyProvider:
    """The active KEK provider (environment-backed by default)."""
    return _default_provider


def _resolve(provider: KeyEncryptionKeyProvider | None) -> KeyEncryptionKeyProvider:
    return provider if provider is not None else kek_provider()


def kek_multifernet(provider: KeyEncryptionKeyProvider | None = None) -> MultiFernet:
    """Build the KEK as a ``MultiFernet`` over the provider's ordered key set
    (Level A). Encrypt uses the first (current) key; decrypt tries all."""
    keks = _resolve(provider).all_keks()
    if not keks:
        raise KeyEncryptionKeyUnavailableError(
            "No KEK material configured; cannot build the KEK MultiFernet."
        )
    return MultiFernet([Fernet(k.encode()) for k in keks])


def kek_encrypt(plaintext: str, provider: KeyEncryptionKeyProvider | None = None) -> str:
    """KEK-direct (Level A) encrypt — the ``totp_secret`` at-rest path in Stele.
    Encrypt under the current KEK; the returned token is a bare Fernet token
    (no envelope prefix)."""
    return kek_multifernet(provider).encrypt(plaintext.encode()).decode()


def kek_decrypt(token: str, provider: KeyEncryptionKeyProvider | None = None) -> str:
    """KEK-direct decrypt — ``MultiFernet`` tries all keys (rotation-safe)."""
    return kek_multifernet(provider).decrypt(token.encode()).decode()
