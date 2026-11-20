# Releasing

1. In the release PR, set the workspace version in `Cargo.toml`, refresh `Cargo.lock`, update the version in `README.md`, and date the `## X.Y.Z — YYYY-MM-DD (...)` section in `CHANGELOG.md`. Merge the PR to `main`.
2. Check that CI passed on the merge commit. Run `gh workflow run signing-check.yml --ref main`, confirm the run used that same SHA, and wait for it to pass. Use its `signed-binaries` artifact for the Windows browser launch check below. The artifact expires after one day.
3. After the checks pass, tag that commit with `git tag -a vX.Y.Z -m "flyw8t X.Y.Z" <sha>` and push with `git push origin vX.Y.Z`.
4. The release workflow publishes a GitHub **pre-release** with the version's changelog section as its notes. Download all seven binaries and `SHA256SUMS` into an empty directory. Confirm the asset names and run `sha256sum -c SHA256SUMS` there. Expect seven successful checks.

   | Platform | Binaries |
   | --- | --- |
   | Windows x64 (MSVC) | `flyw8t-server`, `flyw8t-agent`, `flyw8t-mcp`, `flyw8t-technician` |
   | Linux x64 (GNU) | `flyw8t-server`, `flyw8t-agent`, `flyw8t-mcp` |

   Filenames include the tag and Rust target triple. Windows filenames end in `.exe`.
5. Check the digest of `ghcr.io/spilloid/flyw8t-server:X.Y.Z` in the release notes and pin deployments to that digest. The image is unsigned. A new package on GitHub starts **private**. Give deployments a pull credential or make the package public once in its package settings.

Every release is a pre-release while `docs/threat-model.md` lists blocking open items. Do not describe a release as production-ready.

## Code signing

Both the signing check and the release workflow use `.github/actions/sign-release` and the company's Azure Artifact Signing account (corporate-strategy D-0047). The action Authenticode-signs all four Windows executables, adds an RFC 3161 timestamp and checks each signature. Timestamping keeps signatures verifiable after the three-day signing certificate expires. Configure `SIGNING_EXPECTED_SUBJECT` to verify the publisher as well. Linux binaries are covered by `SHA256SUMS` only.

The job signs in with GitHub OIDC; no signing secret is stored. The `release` environment holds the settings and may deploy only from `main` and `v*` tags.

For initial Azure setup, run `scripts/setup-signing.ps1` as the subscription owner. To verify a downloaded set of Windows binaries in PowerShell, run the following from the release checkout with the four executables in `dist`.

```powershell
./scripts/verify-signature.ps1 -Files (Get-ChildItem ./dist -Filter '*.exe').FullName -ExpectedSubject "CN=Joseph Spillers"
```

## Windows browser launch check

1. Sign in with a clean Windows user account. Place the signed technician executable in the directory where it will stay. Launch it and select **Browser links → Enable for this Windows user**. Close the app.
2. Sign in to the candidate web console and open a Windows device. Under **Open in Flyw8t Technician**, try **Help someone**, **Unattended console**, and **Windows sign-in**. Accept the browser's external-app prompt if shown. For each link, confirm that the app shows the intended computer and mode and waits for a click on **Find sessions**, **Check console**, or **Connect**. Close the app between checks.
3. Remove the registration from **Browser links**, close the app, and repeat the browser launch. Confirm that Windows no longer opens that copy of the technician app. Record the candidate SHA, Windows and browser versions, and result.

The executable also accepts `--register-protocol` and `--unregister-protocol` for per-user setup from a deployment script.
