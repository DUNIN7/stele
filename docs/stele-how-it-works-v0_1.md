# Stele — How It Works & Making It Yours — v0.1

**Version.** v0.1
**Date.** 2026-07-07
**Audience.** Anyone building an app with Stele — especially if you're working through an AI coding agent rather than writing code by hand.

---

## What happens when someone signs up

No email, no password, no username. Here's what actually occurs, step by step:

1. **They type a display name** — just a label, like "Ada." Not used to look them up, ever.
2. **Their device creates a passkey.** This is a unique cryptographic key pair, generated on their phone or laptop, locked to your website specifically. It can't be copied, guessed, or reused on a different site — even a perfect fake copy of your site couldn't trick it into working.
3. **They set up a second factor.** A QR code appears; they scan it with an authenticator app (Google Authenticator, Authy, 1Password — any of these). That app now generates a fresh 6-digit code every 30 seconds, which they enter once to confirm the link worked.
4. **They receive 10 recovery codes.** A one-time safety net — if they ever lose their passkey and their phone at once, one of these codes gets them back in.

That's it. No password was ever created, typed, or stored anywhere.

## What happens when someone signs in

1. **They click "sign in."** Nothing to type yet.
2. **Their browser offers the passkey it already has for your site.** Not a list of accounts — just theirs, because it's the only one that matches your site's identity.
3. **They approve it** — Face ID, Touch ID, a fingerprint, or their phone's screen lock. This proves *they* are physically present with *that* device.
4. **They enter their 6-digit authenticator code** (or a recovery code, if needed) as the second factor.
5. **They're in.**

## Why this matters for your app

- **There's no password database to leak.** The single most common cause of account breaches simply doesn't exist in your system.
- **No email tied to identity** means no email-based account takeover, and no "forgot password" flow to secure (there isn't one).
- **Phishing-resistant by construction** — a fake copy of your login page can't extract a working credential, because the passkey is cryptographically bound to your real site's address.
- **This is the same technology banks and Google use** for their own passwordless sign-in — you get it by mounting one library, not building a security team's worth of infrastructure.

---

## Making the sign-up and sign-in pages yours

The pages you see when you run the demo (`examples/reference_app/`) are a **starting point**, not a fixed design. You're expected to reskin them completely — different colors, your logo, your own words, your own layout.

### What's safe to change — everything visual

Open `examples/reference_app/static/index.html`. Freely change:
- All the CSS in the `<style>` block — colors, fonts, spacing, your brand's look.
- The wording — "Sign up," "Register a passkey," any of the instructional text.
- The overall page layout, header, logo, footer — wrap the existing sections in your own page design.

### What must NOT change — a handful of exact names

The file `app.js` finds specific pieces of the page by an exact internal name (an `id` attribute) and wires real functionality to them. As long as these exact names stay on *some* element, you can restyle everything around them however you like:

```
signup-name, signup-btn, signup-totp, signup-qr, signup-secret, signup-code, signup-finish-btn, signup-codes, recovery-codes, login-btn, login-2fa, login-code, login-totp-btn, login-recovery, login-recovery-btn, account-section, whoami, list-btn, add-passkey-btn, logout-btn, passkey-list, log
```

Also leave alone: the two `<script>` tags at the bottom of the page (`qrcode.js` and `app.js`), and everything inside `app.js` itself — that file contains the actual cryptographic conversation with the browser's passkey system. It has nothing to do with appearance.

### A concrete example

**Before (the demo's plain version):**
```html
<button id="signup-btn">Register a passkey</button>
```

**After (rebranded — same button, new look):**
```html
<button id="signup-btn" class="brand-primary-btn">
  Create my account →
</button>
```

Same `id`, so `app.js` still finds it and still works exactly the same. Everything about how it looks and reads is now yours.

### If you're working with an AI coding agent

Tell it something like:

> "Restyle the sign-up and sign-in pages in `examples/reference_app/static/index.html` to match my brand — [describe your colors, logo, tone]. Keep every element's `id` attribute exactly as it is, and don't modify `app.js` or `qrcode.js` at all."

That one instruction gives your agent everything it needs to reskin the pages safely. For the deeper technical integration — mounting Stele into your *own* application rather than just restyling the demo — point your agent at `AGENTS.md` in the repo root.

---

## Where to go next

- **Restyling this demo for your brand?** You're already reading the right document.
- **Mounting Stele into your own application from scratch?** Tell your AI agent to read `AGENTS.md`.
- **Want the full technical contract** — every slot, every default, every override point? See `docs/stele-mount-contract-v0_1.md`.

---

DUNIN7 — Done In Seven LLC — Miami, Florida
Marvin Percival — marvinp@dunin7.com
Stele — How It Works & Making It Yours — v0.1 — 2026-07-07
