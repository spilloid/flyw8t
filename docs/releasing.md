# Releasing

1. `main` is green in CI.
2. `CHANGELOG.md` has a section `## X.Y.Z — YYYY-MM-DD (...)` for the version, merged to `main` through a PR.
3. Tag the merge commit and push the tag: `git tag -a vX.Y.Z -m "flyw8t X.Y.Z" <sha> && git push origin vX.Y.Z`.
4. `.github/workflows/release.yml` builds `flyw8t-server` and `flyw8t-agent` for Windows (MSVC) and Linux (GNU), writes `SHA256SUMS`, and publishes a GitHub **pre-release** with that CHANGELOG section as its notes. It fails if the section is missing.
5. Check the release page: every asset is present and the sums match a local `sha256sum`.

Every release is a pre-release while `docs/threat-model.md` lists blocking open items. Do not describe a release as production-ready.

## Code signing

Windows binaries (`flyw8t-server.exe`, `flyw8t-agent.exe`) are Authenticode-signed in `release.yml` with the company's Azure Artifact Signing account (corporate-strategy D-0047), through `.github/actions/sign-release`. That action signs, adds an RFC 3161 timestamp (the signing certificates last only three days), and then fails the release unless every `.exe` verifies against the expected signer. A tag therefore cannot publish an unsigned Windows binary. Linux binaries are covered by `SHA256SUMS` only.

The job signs in with GitHub OIDC; no signing secret is stored. The `release` environment holds the settings and may deploy only from `main` and `v*` tags.

**One-time setup:** run `scripts/setup-signing.ps1` as the Azure subscription owner. Then run the **Signing check** workflow (`gh workflow run signing-check.yml`), which builds, signs and verifies without publishing anything. Do this before the next tag.

To check a downloaded release yourself: `./scripts/verify-signature.ps1 -Files flyw8t-agent-*.exe -ExpectedSubject "CN=Joseph Spillers"`.
