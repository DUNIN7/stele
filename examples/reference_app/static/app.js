// The browser half of the Stele reference host (P7-3 §3). Drives the real
// navigator.credentials ceremony against the mounted stele.router + the host's
// composed signup/login routes. No framework — the smallest correct front.
//
// WebAuthn options arrive as JSON with base64url-encoded byte fields; the browser
// needs ArrayBuffers. The result comes back as ArrayBuffers; the server (py_webauthn)
// needs base64url. These two coercions are the whole trick.

"use strict";

const logEl = document.getElementById("log");
function log(msg) {
  logEl.textContent += (typeof msg === "string" ? msg : JSON.stringify(msg, null, 2)) + "\n";
}

// --- base64url <-> ArrayBuffer -------------------------------------------
function b64urlToBuf(s) {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// --- coerce server options -> PublicKeyCredential*Options ----------------
function coerceCreateOptions(options) {
  options.challenge = b64urlToBuf(options.challenge);
  options.user.id = b64urlToBuf(options.user.id);
  if (options.excludeCredentials)
    for (const c of options.excludeCredentials) c.id = b64urlToBuf(c.id);
  return options;
}
function coerceGetOptions(options) {
  options.challenge = b64urlToBuf(options.challenge);
  if (options.allowCredentials)
    for (const c of options.allowCredentials) c.id = b64urlToBuf(c.id);
  return options;
}

// --- serialize credential result -> JSON py_webauthn expects -------------
function serializeRegistration(cred) {
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64url(cred.response.clientDataJSON),
      attestationObject: bufToB64url(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : [],
    },
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
}
function serializeAssertion(cred) {
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64url(cred.response.clientDataJSON),
      authenticatorData: bufToB64url(cred.response.authenticatorData),
      signature: bufToB64url(cred.response.signature),
      userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null,
    },
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
}

// TS-16: the double-submit CSRF cookie is minted on page load (GET /, non-HttpOnly
// on purpose) — read it back here and echo it as a header on every mutating call.
function csrfToken() {
  const match = document.cookie.match(/(?:^|; )stele_ref_csrf=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : null;
}

async function postJSON(url, body) {
  const headers = { "Content-Type": "application/json" };
  const token = csrfToken();
  if (token) headers["X-CSRF-Token"] = token;
  const r = await fetch(url, {
    method: "POST",
    headers,
    credentials: "same-origin", // carry the session cookie
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || `${url} → ${r.status}`);
  return data;
}

// --- signup ---------------------------------------------------------------
let _signupId = null;
document.getElementById("signup-btn").onclick = async () => {
  try {
    const name = document.getElementById("signup-name").value.trim();
    if (!name) return log("Enter a display name first.");
    const begin = await postJSON("/auth/signup/begin", { display_name: name });
    _signupId = begin.signup_id;
    const cred = await navigator.credentials.create({ publicKey: coerceCreateOptions(begin.options) });
    window._pendingRegistration = serializeRegistration(cred);
    document.getElementById("signup-secret").textContent = begin.totp_secret;
    const qrEl = document.getElementById("signup-qr");
    qrEl.innerHTML = "";
    new QRCode(qrEl, { text: begin.totp_provisioning_uri, width: 200, height: 200 });
    document.getElementById("signup-totp").classList.remove("hidden");
    log("Passkey created. Scan the QR code with your authenticator app, then finish.");
  } catch (e) { log("signup begin failed: " + e.message); }
};
document.getElementById("signup-finish-btn").onclick = async () => {
  try {
    const code = document.getElementById("signup-code").value.trim();
    const done = await postJSON("/auth/signup/complete", {
      signup_id: _signupId, credential: window._pendingRegistration, totp_code: code,
    });
    const ol = document.getElementById("recovery-codes");
    ol.innerHTML = "";
    for (const c of done.recovery_codes) { const li = document.createElement("li"); li.textContent = c; ol.appendChild(li); }
    document.getElementById("signup-codes").classList.remove("hidden");
    log("Signed up. You are logged in.");
    await refreshWhoami();
  } catch (e) { log("signup complete failed: " + e.message); }
};

// --- login ----------------------------------------------------------------
let _loginId = null;
document.getElementById("login-btn").onclick = async () => {
  try {
    const begin = await postJSON("/auth/login/begin");
    _loginId = begin.login_id;
    const cred = await navigator.credentials.get({ publicKey: coerceGetOptions(begin.options) });
    await postJSON("/auth/login/passkey", { login_id: _loginId, credential: serializeAssertion(cred) });
    document.getElementById("login-2fa").classList.remove("hidden");
    log("Passkey verified. Enter your second factor.");
  } catch (e) { log("login begin failed: " + e.message); }
};
document.getElementById("login-totp-btn").onclick = async () => {
  try {
    await postJSON("/auth/login/totp", { code: document.getElementById("login-code").value.trim() });
    log("Second factor verified. Logged in.");
    await refreshWhoami();
  } catch (e) { log("totp failed: " + e.message); }
};
document.getElementById("login-recovery-btn").onclick = async () => {
  try {
    await postJSON("/auth/login/recovery", { code: document.getElementById("login-recovery").value.trim() });
    log("Recovery code accepted. Logged in.");
    await refreshWhoami();
  } catch (e) { log("recovery failed: " + e.message); }
};

// --- account (mounted enrollment routes) ----------------------------------
document.getElementById("list-btn").onclick = async () => {
  try {
    const r = await fetch("/me/security/passkeys", { credentials: "same-origin" });
    const list = await r.json();
    if (!r.ok) throw new Error(list.detail || r.status);
    const ul = document.getElementById("passkey-list");
    ul.innerHTML = "";
    for (const p of list) { const li = document.createElement("li"); li.textContent = `${p.display_name || "(unnamed)"} — ${p.id}`; ul.appendChild(li); }
    log(`You have ${list.length} passkey(s).`);
  } catch (e) { log("list failed: " + e.message); }
};
document.getElementById("add-passkey-btn").onclick = async () => {
  try {
    // The mounted Stele ceremony — no host ceremony code, just the routes.
    const begin = await postJSON("/me/security/passkeys/begin");
    const cred = await navigator.credentials.create({ publicKey: coerceCreateOptions(begin.options) });
    await postJSON("/me/security/passkeys/complete", { add_id: begin.add_id, credential: serializeRegistration(cred) });
    log("Added another passkey via stele.router.");
  } catch (e) { log("add passkey failed: " + e.message); }
};
document.getElementById("logout-btn").onclick = async () => {
  await postJSON("/auth/logout");
  log("Signed out.");
  await refreshWhoami();
};

async function refreshWhoami() {
  const r = await fetch("/auth/whoami", { credentials: "same-origin" });
  const who = await r.json();
  const acct = document.getElementById("account-section");
  if (who.authenticated && who.totp_verified) {
    acct.classList.remove("hidden");
    document.getElementById("whoami").textContent = `Signed in as ${who.display_name} (${who.person_id}).`;
  } else {
    acct.classList.add("hidden");
  }
}
refreshWhoami();
