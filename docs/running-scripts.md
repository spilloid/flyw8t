# Running scripts: from no trust to a signed C3 run

This is the operator's path through ADR-0015 as built in steps 2 to 4. Nothing here relies on the server being honest. Every check that matters runs on your own machine (`flyw8t-sign`) or on the device (`flyw8t-agent`).

## 1. The trust root (once per deployment)

Download `flyw8t-sign` for your signing workstation from the GitHub release and verify its checksum. On Windows, verify the timestamped publisher signature as well. Keep the signing workstation separate from the server.

On a machine you trust, not the server:

```text
flyw8t-sign keygen --out root.key
```

Keep a second copy of `root.key`, and its passphrase, somewhere else. If every copy is lost, every agent has to be re-enrolled.

In the console, go to **Administration → Script trust**. The page shows the relying-party id and origin of this console. To include a passkey of yours, download its signer entry from there.

```text
flyw8t-sign draft-genesis --key root.key --person "Your Name" --rp-id <rp id> --origin <origin> [--signer passkey-signer.json] --out draft.json
flyw8t-sign genesis --key root.key --draft draft.json --out genesis.json
```

`genesis` shows everything it is about to sign, asks you to type `yes`, and prints the **trust fingerprint** (`sha256:…`). Keep the fingerprint in your own notes and install scripts. Agents pin your copy, never the console's.

Paste `genesis.json` on the Script trust page. Sudo mode is required.

## 2. Pin agents

New agents, as Administrator:

```text
flyw8t-agent enroll --server https://… --token … --trust sha256:… --org <organization id>
```

Take the organization id from your own records, not from the console. If the fingerprint does not verify, or the server enrolls the device into a different organization, nothing is saved on the device.

Agents enrolled before this, as Administrator, with the service stopped:

```text
sc stop flyw8t-agent
flyw8t-agent trust pin sha256:… --org <organization id>
sc start flyw8t-agent
```

`flyw8t-agent trust status` shows what an agent holds, and `flyw8t-agent status` shows its **device key id**. On your signing machine, list each device you will sign runs for:

```text
flyw8t-sign device add --name "dev box" --key-id sha256:…
```

## 3. Approve a revision

On the revision's page, download the **approval request**. Review the script file itself, then:

```text
flyw8t-sign approve --key root.key --request approval-request.json --source reviewed.ps1 --out approval.json
```

The tool refuses if the file you reviewed is not the revision's source. Paste `approval.json` on the revision page. Sudo mode is required.

## 4. Run it

On the device page, choose **Run an approved script →**, pick the revision, fill in any asked values and start the run. For a non-secret input bound to a custom field, Flyw8t starts at the level specified by the revision and falls back through less specific levels to the field default. A device-level binding looks for device, site, company, and global values in that order. Flyw8t stores the resolved values with the job so later changes to the fields cannot change a queued run.

The installed Windows service normally runs approved scripts as LocalSystem (`NT AUTHORITY\SYSTEM`). A foreground agent uses its own Windows account. The job outcome shows the account class the agent observed on PowerShell's primary token. Older results and unavailable observations carry no account evidence. The result contains only the account class.

- **C0 and C1:** the job is eligible for dispatch immediately. Select a delivery window to allow dispatch when an offline device reconnects. The window governs delivery and the execution timeout governs the run after it starts.
- **C2 and C3:** the job waits for a run signature. Open **sign and upload it**, download `run-request.json`, then:

```text
flyw8t-sign authorize --key root.key --request run-request.json --out run-signature.json
```

The tool checks the revision, its approvals, the values and the device against its own chain and device list, then shows everything it signs. A C3 signature is valid for 15 minutes. Paste `run-signature.json` on the job page to authorize dispatch. The delivery window ends no later than the run signature's expiration.

## A reboot

A script that reboots the machine should schedule the reboot and exit, so that its success is reported before the machine goes down:

```powershell
param([string]$Delay)
shutdown.exe /r /t $Delay /c "flyw8t: signed C3 reboot"
```

Declare it with parameters `Delay = "60"` and risk class C3.

## Validation

The trust-chain/approval integration suite requires PostgreSQL on either platform; the real PowerShell integration suite requires PostgreSQL and Windows. With a disposable database configured, run `cargo test -p flyw8t-server --test trust -- --ignored` and, on Windows, `cargo test -p flyw8t-server --test script_runs -- --ignored`. Default Windows CI has no database and must skip both database suites. Linux's `--include-ignored` must run the cross-platform trust suite while excluding the Windows-only script runner suite. Successful compilation or skipping does not establish execution coverage or security review.

Windows CI also records a cold-start diagnostic (`scripts/diagnose-powershell-startup.ps1`): fresh synthetic subprocesses compare the original module order, System-only, System-first, and explicit Windows module imports. It runs after the real tests, including on failure, so the probe cannot warm up the interpreter to make those tests pass. Stage markers distinguish engine startup, first cmdlet/module loading and stdin EOF. Each subprocess gets a fresh application-data folder, but shared filesystem/security caches can warm between probes; ordered timings are observations, not controlled causal proof or release-gate results. The native tests still use real Job Objects and enforce the original execution deadlines. The wrapper resets its module search to the two absolute protected locations and imports its own Utility/Management dependencies by absolute Windows manifest path; approved scripts may explicitly import their reviewed dependencies. Stalled stdin must remain cancellable and bounded by the execution timeout.

The Windows runner checks the owner and permissions of its state, run and per-job directories. It creates new run directories with protected permissions and rejects reparse points and pre-existing job directories. Run its Windows tests from an elevated account so that they can create the same protected state directory as the service. The integration test checks both successful runs and refusal when the run directory allows access to ordinary Users.

## Schedule an approved revision

From the device’s **Run an approved script** page, choose **Schedule this revision** on a C0 or C1 PowerShell revision. Enter the first date and time in UTC, choose one time, daily or weekly, and set a delivery window and execution timeout. Daily and weekly schedules keep the same UTC time. The schedule stores the exact revision and snapshots the provided values and resolved non-secret custom fields when you save it. Create a new schedule to change the revision or those values.

At each due time the server checks the schedule creator’s current role and organization access, the device credential, and the trust list and revision approval. The agent independently verifies the same signed approval before execution. C2 and C3 still require an individual run signature and appear in the on-demand flow.

Open **Script schedules** to see upcoming and recently stopped schedules, missed and blocked occurrences, and links to the normal job record. An offline device can receive each queued occurrence whose delivery window remains open. A wider window can leave several occurrences ready to run on reconnect. A missed window produces a history entry. A revoked approval or lost creator access stops the future schedule at the next in-window occurrence. Cancelling a schedule stops future occurrences. The job page controls any work that has already queued.

The agent retries persisting the exact result after a transient journal-write failure. A process exit before persistence can leave the outcome unknown. The original job cannot run again. The full script execution implementation still requires independent security review.

## Not built yet

- Passkey signing in the browser, for approvals and run signatures. Use `flyw8t-sign`.
- Secure delivery of secret script parameters.
- Linux and macOS runners. The agent runs PowerShell on Windows only.
- Drafting list changes in the console. Edit the head into the next version and sign it with `flyw8t-sign sign-list`.
- Device limits are set in `policy.json` in the state folder (`{"max_risk": "C3", "timeout_ceiling_secs": 3600}`), not with an enrollment flag yet.
