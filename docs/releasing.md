# Releasing

1. In the release PR, set the workspace version in `Cargo.toml`, refresh `Cargo.lock`, update the version in `README.md`, and date the `## X.Y.Z — YYYY-MM-DD (...)` section in `CHANGELOG.md`. Merge the PR to `main`.
2. Check that CI passed on the merge commit. Run `gh workflow run signing-check.yml --ref main`, confirm the run used that same SHA, and wait for it to pass. Use its `signed-binaries` artifact for the Windows browser launch check below. The artifact expires after one day.
3. After the checks pass, tag that commit with `git tag -a vX.Y.Z -m "flyw8t X.Y.Z" <sha>` and push with `git push origin vX.Y.Z`.
4. The release workflow publishes a GitHub **pre-release** with the version's changelog section as its notes. Download all nine binaries and `SHA256SUMS` into an empty directory. Confirm the asset names and run `sha256sum -c SHA256SUMS` there. Expect nine successful checks.

   | Platform | Binaries |
   | --- | --- |
   | Windows x64 (MSVC) | `flyw8t-server`, `flyw8t-agent`, `flyw8t-mcp`, `flyw8t-sign`, `flyw8t-technician` |
   | Linux x64 (GNU) | `flyw8t-server`, `flyw8t-agent`, `flyw8t-mcp`, `flyw8t-sign` |

   Filenames include the tag and Rust target triple. Windows filenames end in `.exe`.
5. Check the digest of `ghcr.io/spilloid/flyw8t-server:X.Y.Z` in the release notes and pin deployments to that digest. The image is unsigned. A new package on GitHub starts **private**. Give deployments a pull credential or make the package public once in its package settings.

Every release is a pre-release while `docs/threat-model.md` lists blocking open items. Do not describe a release as production-ready.

## Compose upgrade rehearsal

The container CI job tests fresh deployment, MFA sign-in and database recovery. It also upgrades the published 0.2.0 container to the candidate on the same disposable PostgreSQL database. The upgrade checks the migration history, signs in through MFA and opens an organization created before the upgrade. It then restores the original snapshot and boots the published 0.2.0 image. Recovery checks the original account and organization and confirms that a record created after the snapshot is absent.

Run the rehearsal on a Linux x64 Docker host from the candidate checkout.

```sh
docker build -f deploy/compose/Dockerfile -t flyw8t-server:ci .
node scripts/compose-smoke.mjs --upgrade-from-0.2.0
```

The script uses the digest in the 0.2.0 release notes. It creates a unique Compose project with disposable credentials and a loopback-only server port. PostgreSQL is reachable only within the project network. [Flyw8t 0.2.0 release](https://github.com/spilloid/flyw8t/releases/tag/v0.2.0)

## Code signing

Both the signing check and the release workflow use `.github/actions/sign-release` and the company's Azure Artifact Signing account (corporate-strategy D-0047). The action verifies the Authenticode signature, RFC 3161 timestamp, and exact publisher on each Windows executable. Set `SIGNING_EXPECTED_SUBJECT` to the certificate's publisher name, the same name with a `CN=` prefix, or the complete subject. Timestamping keeps signatures verifiable after the three-day signing certificate expires. Linux binaries are covered by `SHA256SUMS` only.

The job signs in with GitHub OIDC; no signing secret is stored. The `release` environment holds the settings and may deploy only from `main` and `v*` tags.

For initial Azure setup, run `scripts/setup-signing.ps1` as the subscription owner. To verify a downloaded set of Windows binaries in PowerShell, run the following from the release checkout with the five executables in `dist`.

```powershell
./scripts/verify-signature.ps1 -Files (Get-ChildItem ./dist -Filter '*.exe').FullName -ExpectedSubject "CN=Joseph Spillers"
```

## Staged Windows update manifest

When preparing an update manifest for publication, use the final timestamped Authenticode executable. From the staging directory, verify the manifest and the exact same executable with the release key obtained through the independent trust channel. Supply the intended tag's numeric version.

```sh
flyw8t-sign update verify --public-key "$FLYW8T_RELEASE_PUBLIC_KEY" --release-version 0.3.0 \
  --artifact flyw8t-agent-v0.3.0-x86_64-pc-windows-msvc.exe
```

The command prints the verified artifact name, byte count and SHA-256. Compare the digest with the upload bytes and retain Authenticode verification for that artifact. The tag workflow builds and signs its own executables. Generate a fresh manifest after any rebuild or change to the Authenticode signature.

## Windows browser launch check

The signing rehearsal runs this acceptance check on a second fresh Windows runner.
It downloads the signing job's executables, verifies them, starts the candidate
console on loopback and exercises the links in a new Chrome profile. Use the same
sequence for a hands-on check or to investigate a failed automatic run.

The same signing rehearsal checks the downloaded setup file and the clipboard
against the reviewed template. It enrolls its disposable Windows runner in a
loopback console using the signed agent and the downloaded file. If runner policy
refuses the file before the enrollment prompt, it exercises the verified clipboard
commands under the existing policy.
It checks the Windows service status and the device's live row. It also runs
the generated Intune detection scripts against that signed installation for the
matching site and for another site before removing the trial service. The
rehearsal uses disposable Windows runners.

1. Sign in with a clean Windows user account. Place the signed technician executable in the directory where it will stay. Launch it and select **Browser links → Enable for this Windows user**. Close the app.
2. Sign in to the candidate web console and open a Windows device. Under **Connect**, try **Open physical desktop** and **Sign in with RDP**. Expand **Technician and connection options** to try **Help a Windows session through Technician** and **Open direct SSH**. Accept the browser's external-app prompt if shown. For each link, confirm that the app shows the intended computer and mode and waits for the technician to continue. Close the app between checks.
3. Remove the registration from **Browser links**, close the app, and repeat the browser launch. Confirm that Windows no longer opens that copy of the technician app. Record the candidate SHA, Windows and browser versions, and result.

The executable also accepts `--register-protocol` and `--unregister-protocol` for per-user setup from a deployment script.

## Signed Intune bundle rehearsal

The signing check downloads the signed agent onto a clean Windows runner and verifies its publisher. A loopback console generates a site-specific Intune bundle using that exact executable. The test unpacks the bundle, installs as LocalSystem, runs the bundled detector and uninstall command, and retries with the spent one-use package. It checks the installed bytes, site, device ID, key, and token use count.

Complete the Intune pilot in an authorized tenant with the published candidate. Record the app upload, the assignment to a pilot device, and the managed results for installation, detection, and uninstall. Keep enrollment bundles out of the evidence archive because they contain a credential.
