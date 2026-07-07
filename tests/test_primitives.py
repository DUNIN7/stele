"""P117-2 — primitive unit tests for session, recovery, TOTP, credentials.

Pure surfaces (session encode/decode/issue) run in-memory; async surfaces run
against the throwaway Postgres via the ``db`` fixture. Principals are created via
the real registry — ``mint_principal`` for the "a minted principal exists with a
passkey" case (resolve_session), ``create_principal`` for the clean-slate cases
(recovery / TOTP / credentials) where an auto-minted passkey + recovery set would
confound the very counts under test. Passkey credentials are built from canned
``VerifiedCredentialData`` (the fake_webauthn shape) — storage needs no authenticator.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import bcrypt
import pyotp
import pytest
from cryptography.fernet import Fernet

from stele import credentials, recovery
from stele.credentials import LastPasskeyError
from stele.kek import EnvKeyEncryptionKeyProvider, kek_decrypt
from stele.models import PrincipalRow
from stele.person_totp import (
    PersonTotpCodeInvalid,
    begin_totp_rotation,
    confirm_totp_rotation,
    verify_totp_step,
)
from stele.registry import create_principal, mint_principal
from stele.session import (
    SessionInvalid,
    SessionPayload,
    decode_session,
    encode_session,
    issue_session,
    resolve_session,
)
from stele.webauthn import VerifiedCredentialData

TEST_SECRET_KEY = Fernet.generate_key().decode()


def _canned_credential(sign_count: int = 0) -> VerifiedCredentialData:
    return VerifiedCredentialData(
        credential_id=os.urandom(32),
        public_key=os.urandom(91),
        sign_count=sign_count,
        transports=["internal"],
    )


async def _mint(db, name: str = "Tester"):
    person, codes = await mint_principal(
        display_name=name,
        totp_secret_plaintext=pyotp.random_base32(),
        passkey_credential=_canned_credential(),
        secret_key=TEST_SECRET_KEY,
        now=datetime.now(timezone.utc),
        db=db,
    )
    return person, codes


# ---------------------------------------------------------------------------
# session.py — pure (no db)
# ---------------------------------------------------------------------------
def test_encode_decode_round_trip():
    now = datetime.now(timezone.utc)
    pid = uuid4()
    payload = SessionPayload(
        person_id=pid, totp_verified=True,
        created_at=now, expires_at=now + timedelta(hours=1),
    )
    token = encode_session(payload, secret_key=TEST_SECRET_KEY)
    decoded = decode_session(token, secret_key=TEST_SECRET_KEY, now=now)
    assert decoded.person_id == pid
    assert decoded.totp_verified is True


def test_decode_rejects_tampered_token():
    now = datetime.now(timezone.utc)
    payload = SessionPayload(
        person_id=uuid4(), totp_verified=False,
        created_at=now, expires_at=now + timedelta(hours=1),
    )
    token = encode_session(payload, secret_key=TEST_SECRET_KEY)
    tampered = token[:12] + ("A" if token[12] != "A" else "B") + token[13:]
    with pytest.raises(SessionInvalid):
        decode_session(tampered, secret_key=TEST_SECRET_KEY, now=now)


def test_decode_rejects_expired_token():
    past = datetime(2020, 1, 1, tzinfo=timezone.utc)
    payload = SessionPayload(
        person_id=uuid4(), totp_verified=True,
        created_at=past, expires_at=past + timedelta(hours=1),
    )
    token = encode_session(payload, secret_key=TEST_SECRET_KEY)
    with pytest.raises(SessionInvalid):
        decode_session(token, secret_key=TEST_SECRET_KEY, now=datetime.now(timezone.utc))


def test_issue_session_threads_totp_verified():
    now = datetime.now(timezone.utc)
    pid = uuid4()
    payload, token = issue_session(
        person_id=pid, totp_verified=False, secret_key=TEST_SECRET_KEY, now=now
    )
    assert payload.person_id == pid
    assert payload.totp_verified is False
    assert decode_session(token, secret_key=TEST_SECRET_KEY, now=now).totp_verified is False
    payload_true, _ = issue_session(
        person_id=pid, totp_verified=True, secret_key=TEST_SECRET_KEY, now=now
    )
    assert payload_true.totp_verified is True


# ---------------------------------------------------------------------------
# session.py — resolve_session (async, db)
# ---------------------------------------------------------------------------
async def test_resolve_session_for_minted_principal(db):
    now = datetime.now(timezone.utc)
    person, _ = await _mint(db, "Resolve Tester")
    _, token = issue_session(
        person_id=person.id, totp_verified=True, secret_key=TEST_SECRET_KEY, now=now
    )
    resolved = await resolve_session(token, secret_key=TEST_SECRET_KEY, now=now, db=db)
    assert resolved is not None
    assert resolved.principal.id == person.id
    assert resolved.payload.totp_verified is True


async def test_resolve_session_none_for_invalid_token(db):
    now = datetime.now(timezone.utc)
    assert await resolve_session(
        "not-a-valid-token", secret_key=TEST_SECRET_KEY, now=now, db=db
    ) is None


# ---------------------------------------------------------------------------
# recovery.py
# ---------------------------------------------------------------------------
def test_generate_recovery_codes_shape():
    codes = recovery.generate_recovery_codes()
    assert len(codes) == recovery.DEFAULT_CODE_COUNT
    assert all(len(c) == recovery.CODE_LENGTH for c in codes)
    assert len(set(codes)) == len(codes)
    assert all(ch in recovery.ALPHABET for c in codes for ch in c)


def test_hash_recovery_code_verifies_round_trip_not_stable_string():
    # NOTE (vs the P117-2 plan's "stable for the same input"): hash_recovery_code
    # is bcrypt-salted, so two hashes of the same code are DIFFERENT strings.
    # Stability is the verify round-trip, tested here; the per-call salt is asserted.
    code = "ABCD2345"
    digest = recovery.hash_recovery_code(code)
    assert bcrypt.checkpw(code.encode(), digest.encode())
    assert not bcrypt.checkpw("WRONG234".encode(), digest.encode())
    assert recovery.hash_recovery_code(code) != digest


async def test_store_then_counts_reflect_set(db):
    person = await create_principal(display_name="Recovery Tester", db=db)
    codes = recovery.generate_recovery_codes()
    await recovery.store_recovery_codes(person_id=person.id, codes=codes, db=db)
    assert await recovery.count_active_recovery_codes(person_id=person.id, db=db) == recovery.DEFAULT_CODE_COUNT
    assert await recovery.count_unused_recovery_codes(person_id=person.id, db=db) == recovery.DEFAULT_CODE_COUNT


async def test_verify_and_consume_is_single_use(db):
    person = await create_principal(display_name="Consume Tester", db=db)
    codes = recovery.generate_recovery_codes()
    await recovery.store_recovery_codes(person_id=person.id, codes=codes, db=db)
    assert await recovery.verify_and_consume_recovery_code(person_id=person.id, code=codes[0], db=db) is True
    assert await recovery.count_unused_recovery_codes(person_id=person.id, db=db) == recovery.DEFAULT_CODE_COUNT - 1
    assert await recovery.verify_and_consume_recovery_code(person_id=person.id, code=codes[0], db=db) is False
    assert await recovery.verify_and_consume_recovery_code(person_id=person.id, code="WRONGCOD", db=db) is False


async def test_regenerate_replaces_the_set(db):
    person = await create_principal(display_name="Regen Tester", db=db)
    old = recovery.generate_recovery_codes()
    await recovery.store_recovery_codes(person_id=person.id, codes=old, db=db)
    fresh = await recovery.regenerate_recovery_codes(person_id=person.id, db=db)
    assert len(fresh) == recovery.DEFAULT_CODE_COUNT
    assert set(fresh).isdisjoint(set(old))
    assert await recovery.count_active_recovery_codes(person_id=person.id, db=db) == recovery.DEFAULT_CODE_COUNT
    assert await recovery.verify_and_consume_recovery_code(person_id=person.id, code=old[0], db=db) is False
    assert await recovery.verify_and_consume_recovery_code(person_id=person.id, code=fresh[0], db=db) is True


# ---------------------------------------------------------------------------
# person_totp.py (async, db)
# ---------------------------------------------------------------------------
def _issuer_of(provisioning_uri: str) -> str:
    return parse_qs(urlparse(provisioning_uri).query)["issuer"][0]


async def test_begin_totp_rotation_returns_provisioning(db):
    person = await create_principal(display_name="TOTP Begin", db=db)
    prov = await begin_totp_rotation(person_id=person.id, db=db)
    assert prov.secret
    assert prov.provisioning_uri.startswith("otpauth://")


async def test_begin_totp_rotation_default_issuer_is_stele(db):
    person = await create_principal(display_name="Issuer Default", db=db)
    prov = await begin_totp_rotation(person_id=person.id, db=db)
    assert _issuer_of(prov.provisioning_uri) == "Stele"


async def test_begin_totp_rotation_honors_issuer_override(db):
    person = await create_principal(display_name="Issuer Override", db=db)
    prov = await begin_totp_rotation(person_id=person.id, db=db, issuer_name="My App")
    assert _issuer_of(prov.provisioning_uri) == "My App"


async def test_confirm_totp_rotation_good_code_writes_secret(db):
    person = await create_principal(display_name="TOTP Confirm", db=db)
    prov = await begin_totp_rotation(person_id=person.id, db=db)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    code = pyotp.TOTP(prov.secret).at(now)
    await confirm_totp_rotation(
        person_id=person.id, secret=prov.secret, code=code,
        secret_key=TEST_SECRET_KEY, now=now, db=db,
    )
    row = await db.get(PrincipalRow, person.id)
    assert row.totp_secret is not None
    decrypted = kek_decrypt(row.totp_secret, EnvKeyEncryptionKeyProvider(secret_key=TEST_SECRET_KEY))
    assert decrypted == prov.secret
    assert row.totp_last_step == pyotp.TOTP(prov.secret).timecode(now)


async def test_confirm_totp_rotation_bad_code_raises(db):
    person = await create_principal(display_name="TOTP Bad", db=db)
    prov = await begin_totp_rotation(person_id=person.id, db=db)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    current = pyotp.TOTP(prov.secret).at(now)
    wrong = "000000" if current != "000000" else "111111"
    with pytest.raises(PersonTotpCodeInvalid):
        await confirm_totp_rotation(
            person_id=person.id, secret=prov.secret, code=wrong,
            secret_key=TEST_SECRET_KEY, now=now, db=db,
        )


async def test_confirm_totp_rotation_rejects_replayed_code(db):
    """TS-11: the same code, submitted twice, must not rotate twice — the
    second confirm replays an already-accepted step."""
    person = await create_principal(display_name="TOTP Replay", db=db)
    prov = await begin_totp_rotation(person_id=person.id, db=db)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    code = pyotp.TOTP(prov.secret).at(now)
    await confirm_totp_rotation(
        person_id=person.id, secret=prov.secret, code=code,
        secret_key=TEST_SECRET_KEY, now=now, db=db,
    )
    with pytest.raises(PersonTotpCodeInvalid):
        await confirm_totp_rotation(
            person_id=person.id, secret=prov.secret, code=code,
            secret_key=TEST_SECRET_KEY, now=now, db=db,
        )


# ---------------------------------------------------------------------------
# person_totp.verify_totp_step (pure, sync — no DB)
# ---------------------------------------------------------------------------
def test_verify_totp_step_accepts_fresh_code_and_returns_step():
    secret = pyotp.random_base32()
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    code = pyotp.TOTP(secret).at(now)
    step = verify_totp_step(secret=secret, code=code, last_step=None, now=now)
    assert step == pyotp.TOTP(secret).timecode(now)


def test_verify_totp_step_rejects_replay_of_same_step():
    secret = pyotp.random_base32()
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    code = pyotp.TOTP(secret).at(now)
    step = verify_totp_step(secret=secret, code=code, last_step=None, now=now)
    with pytest.raises(PersonTotpCodeInvalid):
        verify_totp_step(secret=secret, code=code, last_step=step, now=now)


def test_verify_totp_step_accepts_later_step_after_replay_rejected():
    secret = pyotp.random_base32()
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    first_code = pyotp.TOTP(secret).at(now)
    first_step = verify_totp_step(secret=secret, code=first_code, last_step=None, now=now)

    later = now + timedelta(seconds=31)  # > one interval: guaranteed next step
    later_code = pyotp.TOTP(secret).at(later)
    later_step = verify_totp_step(
        secret=secret, code=later_code, last_step=first_step, now=later
    )
    assert later_step > first_step


# ---------------------------------------------------------------------------
# credentials.py (async, db)
# ---------------------------------------------------------------------------
async def test_add_then_get_credential(db):
    person = await create_principal(display_name="Cred Tester", db=db)
    cid = os.urandom(32)
    await credentials.add_credential(
        person_id=person.id, credential_id=cid, public_key=os.urandom(91),
        sign_count=0, transports=["internal"], db=db,
    )
    got = await credentials.get_credential_by_credential_id(credential_id=cid, db=db)
    assert got is not None
    assert got.person_id == person.id
    assert got.credential_id == cid
    assert await credentials.get_credential_by_credential_id(credential_id=os.urandom(32), db=db) is None


async def test_list_credentials_reflects_adds(db):
    person = await create_principal(display_name="List Tester", db=db)
    for _ in range(3):
        await credentials.add_credential(
            person_id=person.id, credential_id=os.urandom(32),
            public_key=os.urandom(91), db=db,
        )
    creds = await credentials.list_credentials_for_person(person_id=person.id, db=db)
    assert len(creds) == 3


async def test_update_sign_count_persists(db):
    person = await create_principal(display_name="SignCount Tester", db=db)
    cid = os.urandom(32)
    await credentials.add_credential(
        person_id=person.id, credential_id=cid, public_key=os.urandom(91),
        sign_count=0, db=db,
    )
    await credentials.update_sign_count(credential_id=cid, new_sign_count=7, db=db)
    got = await credentials.get_credential_by_credential_id(credential_id=cid, db=db)
    assert got.sign_count == 7


async def test_remove_credential_and_last_passkey_guard(db):
    person = await create_principal(display_name="Remove Tester", db=db)
    cid1, cid2 = os.urandom(32), os.urandom(32)
    await credentials.add_credential(
        person_id=person.id, credential_id=cid1, public_key=os.urandom(91), db=db
    )
    with pytest.raises(LastPasskeyError):
        await credentials.remove_credential(person_id=person.id, credential_id=cid1, db=db)
    await credentials.add_credential(
        person_id=person.id, credential_id=cid2, public_key=os.urandom(91), db=db
    )
    assert await credentials.remove_credential(person_id=person.id, credential_id=cid2, db=db) is True
    remaining = await credentials.list_credentials_for_person(person_id=person.id, db=db)
    assert len(remaining) == 1
