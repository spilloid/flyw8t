## What changed

<!-- What problem does this solve, and for whom? Link the issue or ADR if there is one. -->

## How it was checked

- [ ] `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace -- --include-ignored` against PostgreSQL (`FLYW8T_TEST_DATABASE_URL`)
- [ ] Touches the job lifecycle, protocol, journal, gateway or auth: reviewed adversarially per `CLAUDE.md` routing and logged in `docs/dev-process.md`; the model test still passes with `PROPTEST_CASES=5000`
- [ ] Touches the console: `ui_capture` passes and the screenshots were looked at
- [ ] No new path executes anything outside the action catalog; no new query skips organization scoping
- [ ] Nothing logs or returns a secret (passwords, tokens, keys); new secrets are write-only and hashed
- [ ] Docs, `CHANGELOG.md` and `docs/acceptance-tests.md` updated in this change if behavior changed
- [ ] Only synthetic data: test organizations, loopback and TEST-NET addresses, throwaway identities; no real customer devices, hostnames or credentials

## Evidence

<!-- Logs, screenshots, or a short reproduction. -->
