## v0.3.0 — 2026-07-07

### Added
- Fail-loud validation of rp_id/rp_origin at WebAuthnConfig construction
  (rejects a misconfigured relying-party setup instead of accepting it
  silently)
- Sweep of expired entries from in-process pending-challenge stores
  (closes an unauthenticated memory-exhaustion path)
- Atomic update for TOTP replay-guard state (closes a narrow
  concurrent-submission race on a still-live code)
- Startup-time validation of the step-up freshness window configuration
  (fails at boot with a clear error, not per-request)

### Fixed
- generate_env.py now quotes all generated .env values (a value
  containing a space previously failed to load silently)
- Stale migrations-layout description in README corrected
- Explicit starlette version floor pinned (previously transitive-only)

### Security
This release is the second internal security review pass — an
adversarial review of the fixes shipped in v0.2.0, rather than new
ground. It found and closed four real gaps in that prior work, including
one (the WebAuthn relying-party validation) that had never been checked
by either review pass before this one.

## v0.2.0 — 2026-07-06

### Added
- Apache-2.0 license (LICENSE, SPDX headers on all source files, PEP 639 project metadata)
- TOTP replay protection — per-principal tracking of the last accepted authenticator code
- Atomic recovery-code redemption — closes a narrow concurrent-redemption race
- Native login-challenge storage, shipped in core (previously left entirely to the host)
- Configurable step-up freshness check on sensitive account operations (passkey add/remove, recovery-code regeneration, authenticator rotation)
- Configurable WebAuthn user-verification policy (PREFERRED by default; hosts may opt into REQUIRED)
- CSRF defense-in-depth in the reference application, plus a startup warning for insecure cookie configuration

### Fixed
- Database migrations now ship inside the installable package (previously present in the source distribution only, absent from the wheel)

### Security
This release closes out a full internal security review of the authentication substrate. Findings and fixes covered session handling, credential storage, WebAuthn ceremony state, and the reference application's cookie posture. No exploit was found in production use; this was a proactive hardening pass ahead of public release.

## v0.1.0 — 2026-06-21

### Added
- Initial standalone extraction from the Loomworks engine
- Test suite and CI
- Reference host application demonstrating passkey, TOTP, and recovery-code flows

### Fixed
- README corrected for standalone installation (environment variable naming)

## Known limitations

- Pending-challenge and login-challenge stores are in-process only (single-worker). A multi-process deployment should back these with a shared store; the seam for this is planned but not yet built.
- Rate limiting / lockout on repeated authentication attempts is planned, not yet implemented.
- Immediate session revocation is planned, not yet implemented — sessions currently expire on a configurable TTL, not on demand.
