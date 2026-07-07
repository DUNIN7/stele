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
