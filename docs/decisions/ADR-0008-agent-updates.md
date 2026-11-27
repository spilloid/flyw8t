# ADR-0008: No agent auto-update until updates are signed

**Status:** accepted · **Date:** 2026-10-29

**Default policy confirmed by the operator:** 2026-11-26.

## Decision

The agent has **no update mechanism** in 0.1. Administrators install and upgrade agents. Auto-update ships only with all of:

1. A release manifest signed with an Ed25519 key held **outside** the flyw8t server (a release-signing key, as PortGlass's updater uses; `portglass-core::update` is the reference). A compromised flyw8t server must not be able to push a binary.
2. Authenticode-signed Windows binaries (Azure Artifact Signing, as netviz, PortGlass and tuldMi already do), checked by the agent before replacing itself.
3. Version monotonicity (no downgrade unless explicitly allowed by a signed manifest), staged rollout by organization, and automatic rollback if the new agent fails to reconnect within a bound.
4. The update is itself a job with a lifecycle and evidence: success means "the device reconnected and reported the new version", not "the download finished".

## Preparing a signed release manifest

`flyw8t-sign update keygen` creates a passphrase-protected release key and prints its Ed25519 public key in hex. Keep the private key offline and distribute the public key through a trusted channel. Script trust keys and agent release keys use separate key files.

Use the original Windows x64 agent from the release build after verifying its Authenticode publisher, timestamp and version. The manifest signs the numeric release version, artifact size and SHA-256 under a domain dedicated to the Windows x64 agent. The signer and verifier check that the manifest version matches the version embedded in the executable. Store the manifest beside the original executable in release staging.

```sh
flyw8t-sign update keygen --out release.key
flyw8t-sign update sign --key release.key --version 0.3.0 \
  --artifact flyw8t-agent-v0.3.0-x86_64-pc-windows-msvc.exe
flyw8t-sign update verify --public-key "$FLYW8T_RELEASE_PUBLIC_KEY" --release-version 0.3.0 \
  --artifact flyw8t-agent-v0.3.0-x86_64-pc-windows-msvc.exe
```

Both signing and verification use `flyw8t-agent-windows-x64-update.json` by default. Use `--release-version` to verify a staged pair before publication. The release version should come from the intended tag and the public key from the trusted channel used to distribute it. This mode checks the exact signed version, filename, embedded build version and artifact bytes. Use `--current-version` to check that a candidate is newer than an installed version. Authenticode verification remains part of release qualification.

Published 0.2.0 Windows binaries remain usable as manual installers. Update candidates need the embedded build version, which those binaries predate. The offline verifier accepts `--current-version 0.2.0` when evaluating a newer compatible candidate. Endpoints on 0.2.0 need a managed bootstrap before they can receive automatic updates.

Run `update-trust pin` as Administrator after enrollment. Supply the verification key from the offline signer through your trusted channel. The pin lives in the protected default Windows agent state directory. The first successfully stored key is the pin. Repeating it succeeds, and a request to pin a different key returns an error. Use `update-trust status` to inspect the local pin.

On the Windows x64 agent, `update-check` verifies an update against the running agent's version, the pinned release key, the signed byte count and SHA-256, and Windows Authenticode. The candidate must be a plain Windows x64 release executable with the Flyw8t publisher and a trusted timestamp. The command holds the candidate open for read sharing through both checks. It reports the verified version and which release key source it used.

```powershell
flyw8t-agent update-trust pin --public-key $env:FLYW8T_RELEASE_PUBLIC_KEY
flyw8t-agent update-trust status
flyw8t-agent update-check --manifest flyw8t-agent-windows-x64-update.json --artifact flyw8t-agent-v0.3.1-x86_64-pc-windows-msvc.exe
```

For an offline diagnostic, `update-check --public-key KEY` uses the explicitly supplied key for that invocation. The saved pin applies when the argument is omitted.

The updater still needs manifest delivery and Windows service replacement and recovery.

## Fleet policy

When the signed updater ships, automatic updates are enabled by default for enrolled agents that support it. An eligible agent receives the approved release as its rollout cohort opens and the device checks in. Its enrollment and job journal carry forward. An update waits for active jobs and technician sessions to finish before restarting the agent.

Expose **Automatic agent updates** to administrators at the organization and device levels. A device can opt out or inherit the organization setting. Turning updates off for the organization pauses its whole fleet. An explicit opt-out persists across reconnects and upgrades, and policy changes appear in audit history. This also lets an administrator keep an Intune-managed fleet on its own update schedule.

The console now saves those preferences. Organizations default to enabled. Devices default to following their organization. A fleet pause takes precedence and preserves device opt-outs when the fleet resumes. Changes appear in the Audit log and in the affected devices' Activity views. The settings are available before the signed updater can install releases.

Start with a small Windows canary after the 0.2.0 sprint. Verify a signed upgrade through reconnect on a real enrolled PC, then exercise a broken release and confirm rollback preserves the same enrollment. Include a device with updates turned off and an offline device that rejoins later. Show the installed version and update result in Device Activity. Older agents need a managed upgrade to a build that contains the updater before they become eligible.

## Why

A remote-execution product's update channel is its most powerful attack path (threat T9). Shipping it unsigned "for now" would quietly make a server compromise into an arbitrary-code fleet compromise.
