# Running scripts: from no trust to a signed C3 run

This is the operator's path through ADR-0015 as built in steps 2 to 4. Nothing here relies on the server being honest. Every check that matters runs on your own machine (`flyw8t-sign`) or on the device (`flyw8t-agent`).

## 1. The trust root (once per deployment)

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

On the device page, choose **Run an approved script →**, pick the revision, fill in any asked values and start the run.

- **C0 and C1:** the run is sent at once.
- **C2 and C3:** the job waits for a run signature. Open **sign and upload it**, download `run-request.json`, then:

```text
flyw8t-sign authorize --key root.key --request run-request.json --out run-signature.json
```

The tool checks the revision, its approvals, the values and the device against its own chain and device list, then shows everything it signs. A C3 signature is valid for 15 minutes. Paste `run-signature.json` on the job page, and the agent runs the script.

## A reboot

A script that reboots the machine should schedule the reboot and exit, so that its success is reported before the machine goes down:

```powershell
param([string]$Delay)
shutdown.exe /r /t $Delay /c "flyw8t: signed C3 reboot"
```

Declare it with parameters `Delay = "60"` and risk class C3.

## Not built yet

- Passkey signing in the browser, for approvals and run signatures. Use `flyw8t-sign`.
- Parameters bound to custom fields, and secret parameters. Runs offer constants and asked values only.
- Linux and macOS runners. The agent runs PowerShell on Windows only.
- Drafting list changes in the console. Edit the head into the next version and sign it with `flyw8t-sign sign-list`.
- Device limits are set in `policy.json` in the state folder (`{"max_risk": "C3", "timeout_ceiling_secs": 3600}`), not with an enrollment flag yet.
