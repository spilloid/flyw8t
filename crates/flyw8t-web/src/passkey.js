// Passkeys (ADR-0014): runs the WebAuthn ceremony for the form on this page, then posts the form. The browser and the
// key do the cryptography; this only converts between base64url and bytes. The server checks everything it is sent.
"use strict";
(() => {
  const form = document.getElementById("webauthn");
  const status = document.getElementById("webauthn-status");
  if (!form || !status) return;
  if (!window.PublicKeyCredential) {
    status.textContent = "This browser does not support passkeys.";
    return;
  }
  const b64 = (buf) =>
    btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const bytes = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const set = (name, value) => { form.elements.namedItem(name).value = value; };
  let busy = false;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (busy || !form.reportValidity()) return;
    busy = true;
    const { mode, publicKey: o } = JSON.parse(form.dataset.options);
    o.challenge = bytes(o.challenge);
    if (o.user) o.user.id = bytes(o.user.id);
    for (const c of o.excludeCredentials || []) c.id = bytes(c.id);
    for (const c of o.allowCredentials || []) c.id = bytes(c.id);
    status.textContent = "Waiting for your passkey…";
    try {
      const cred = mode === "create"
        ? await navigator.credentials.create({ publicKey: o })
        : await navigator.credentials.get({ publicKey: o });
      const r = cred.response;
      set("client_data_json", b64(r.clientDataJSON));
      if (mode === "create") {
        set("attestation_object", b64(r.attestationObject));
      } else {
        set("credential_id", b64(cred.rawId));
        set("authenticator_data", b64(r.authenticatorData));
        set("signature", b64(r.signature));
      }
      status.textContent = "Checking…";
      form.submit();
    } catch (err) {
      busy = false;
      status.textContent = err && err.name === "NotAllowedError"
        ? "Cancelled, or no passkey was allowed. Try again."
        : `That did not work: ${err && err.message}`;
    }
  });
  // Ready: the button starts disabled so that the form cannot be posted without the ceremony.
  form.querySelector("button[type=submit]").disabled = false;
})();
