# Releasing

1. `main` is green in CI.
2. `CHANGELOG.md` has a section `## X.Y.Z — YYYY-MM-DD (...)` for the version, merged to `main` through a PR.
3. Tag the merge commit and push the tag: `git tag -a vX.Y.Z -m "flyw8t X.Y.Z" <sha> && git push origin vX.Y.Z`.
4. `.github/workflows/release.yml` builds `flyw8t-server` and `flyw8t-agent` for Windows (MSVC) and Linux (GNU), writes `SHA256SUMS`, and publishes a GitHub **pre-release** with that CHANGELOG section as its notes. It fails if the section is missing.
5. Check the release page: every asset is present and the sums match a local `sha256sum`.

Every release is a pre-release while `docs/threat-model.md` lists blocking open items. Binaries are **not code-signed** until Authenticode signing is set up (roadmap 0.2). Do not describe a release as production-ready.
