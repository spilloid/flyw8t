# Company standards in flyw8t

Adoption of corporate-strategy `standards/STD-*.md`, as of 2026-10-29.

| Standard | Status | Where / why |
|---|---|---|
| STD-001 Orchestrated, adversarially-reviewed development | adopted | `CLAUDE.md` routing; [dev-process.md](dev-process.md) log. One cross-family review round (Codex gpt-6.1-sol) on the core; attended support not yet reviewed. |
| STD-002 PR template | adopted | `.github/PULL_REQUEST_TEMPLATE.md`, checked by the `standards` CI job. |
| STD-003 Documentation freshness | adopted | README states the Cargo workspace version and `CHANGELOG.md`'s latest entry matches it, both checked in CI; dated quarantine list in `CLAUDE.md`. |
| STD-004 Identity architecture | adopted (partial) | Local accounts, TOTP, passkeys and prefixed scoped bearer tokens (`fw8_`, hashed, revocable) are built; **OIDC remains open**, required by roadmap 0.7 before the 0.8 feature freeze. Devices have a separate Ed25519 plane (ADR-0002) that cannot satisfy user checks, and vice versa. |
| STD-005 Agent-facing surface | partial | API authorization and tenancy match the console; token scopes only narrow; unattended create needs an idempotency key; collisions return 409 without leaking the other request. Diagnostics are C1. No MCP server; signed script execution/approvals follow ADR-0015 and the 0.3 remediation gate, with independent review required. |
| STD-006 Secret handling | adopted (a, b) | (a) no deployment secrets committed; `.env` is git-ignored, `.env.example` holds placeholders, stated in `SECURITY.md`. (b) passwords Argon2id; session, API and enrollment tokens and support invitations SHA-256 only, shown once with `Cache-Control: no-store`; device private keys never leave devices. |
| STD-007 Repo metadata | adopted | MIT `LICENSE` (`Joseph Spillers`); `CHANGELOG.md`. AI attribution: none, per the operator's standing preference. |
| STD-008 UI capture & overflow validation | adopted, **mechanism deviates** | `crates/flyw8t-server/tests/ui_capture.rs` drives headless Chrome over DevTools from Rust (as PortGlass does): 16 pages × 3 widths × 2 themes, failing on horizontal overflow or browser errors; plus `support_browser.rs` for the attended-support flow. Wired into CI. `standards/check.sh` looks for `docs/scripts/capture-*.mjs` and will not detect this shape. |
