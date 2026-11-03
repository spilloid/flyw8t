# ADR-0014: Scripts and custom fields: editable, revisioned, role-controlled, signed to run

**Status:** accepted (2026-11-02; operator answered the open questions the same day) · builds on the 0.6 roadmap entry, [threat model T10](../threat-model.md) and [ADR-0005](ADR-0005-job-lifecycle.md) · sets the direction for [ADR-0007](ADR-0007-extension-runtime.md)

## Context

The operator wants arbitrary scripts that technicians can run against workstations across tenants:

- **Scripts:** easy to see, tweak and modify in the console; controlled by role; every change revisioned.
- **Variables:** scripts read values that are **global**, **tenant** (organization) or **device** specific. These values are user-defined fields that technicians see and edit, controlled by role and revisioned too. Their definitions control where a field may be set, and can require one to be set, for example "every client must set a backup share".
- **Editor:** a minimal editor that shows basic errors was nice in Datto and NinjaOne, but not needed. N-able's upload-only is annoying but not painful. Adopting a third-party code editor is a risk the operator would rather not take, and building one is complexity they don't want.

The threat model's line does not move: **a compromised server must not become fleet-wide code execution** (T10). Today the agent's compiled catalog enforces that. Scripts replace the catalog with content written in the console, so something else has to hold that line.

## Decision

### 1. Scripts are a library of revisions; only an approved revision runs

- A **script** belongs to one organization or is **global**. It has a name, a language (PowerShell first; then bash and Python), a risk class, and declared parameters.
- Every save creates a new **revision** with its author, time and a hash of its content (source, language, parameters, risk class). Revisions are never edited or deleted, so the console can show who changed what, with a diff.
- A revision is a **draft** until someone allowed to publish **approves** it (section 3). Only approved revisions run. Approving revision 7 does not approve revision 8.
- **Risk classes** follow STD-005:
  - **C0**, read-only;
  - **C1**, bounded and reversible;
  - **C2**, consequential: each run needs a second person's approval;
  - **C3**, irreversible: run interactively only, one device at a time.

### 2. Editing: a plain text box, with checks done by the server

The script page has a plain, resizable, monospace text box (spellcheck off), plus upload and download, so an external editor round-trips easily. A few lines of our own script make Tab insert a tab; nothing else is added to the page.

On save, the **server** checks the revision and shows problems with line numbers next to the text box:

- **Syntax:**
  - PowerShell is parsed with `Parser.ParseInput`, which never runs it;
  - bash is checked with `bash -n`;
  - Python is checked with `compile()`.
  
  The checkers run in an isolated worker with no network or credentials and with resource limits. If a checker isn't available, the page says so rather than claiming the script is fine.
- **Variables:** every `{{…}}` reference must name a defined field or a declared parameter. If a required field is unset for some organizations, the page says which ones.
- **Size and encoding:** UTF-8, at most 256 KiB, line endings normalized.

Syntax that passes proves nothing about safety; the page says so too.

*Not chosen, for now:* a bundled code editor such as CodeMirror or Monaco. It would bring supply-chain and maintenance cost, and it could alter a draft or misrepresent what a reviewer is approving. Monaco also does not support mobile browsers. Reconsider once people ask for it, as a layer over the text box that keeps working without it. (Codex `gpt-6.1-sol` reached the same recommendation independently; 2026-11-02.)

### 3. Approval is a signature the server cannot forge

Approving a revision means **signing its hash with a passkey or security key in the approver's browser (WebAuthn)**. The agent verifies that signature before running anything.

The agent trusts only approvers on a **trust list rooted in a key it pinned at enrollment**. The list is signed. Changing it (adding or removing an approver) needs a signature from a key already on it, so the server can distribute the list but cannot add itself to it.

So a compromised server can only replay revisions that real people approved, to devices in the scopes the agent allows. It cannot create new ones.

The approval screen shows the exact source, the parameters and the hash being signed. For C2 scripts, a second approver signs each run, not only the revision.

**Sudo mode.** Approving is a fresh passkey or security-key ceremony at the moment of approval: a signed-in session, a password or a TOTP code is never enough on its own, however recent. The same step-up (a fresh WebAuthn assertion, valid for a few minutes) also guards the other changes that widen what can run: editing the trust list, defining or archiving custom fields, and changing users' roles. People without a usable passkey approve with the offline signing tool instead.

### 4. Custom fields: definitions, scoped values, revisioned

A **field definition** has:

- a key, label and type: text, number, yes/no, choice, or **secret**;
- where it **may be set**: global, organization, site, device;
- where it **must be set**, for example "required for every organization";
- an optional default and validation (a pattern, or a list of choices);
- who may **edit** values and who may **see** them. Secret values are never shown after entry; they are only sent to the agent at run time.

Each value belongs to one scope. Every change is a new row recording who, when and the previous value (masked for secrets), so a value's history is visible and can be restored.

**Resolution** for a device: device value, else its site's value, else organization value, else global value, else the default. The device page shows the resolved value and where it came from.

**Required fields:** organizations and devices missing a required value are listed on their pages and on an admin page. A script that uses such a field **does not run** on the affected devices. The run's confirmation page names them first.

### 5. Values reach scripts as data, never as script text

A script declares parameters. Each one takes a value from:

- a field (`{{device.asset_tag}}`, `{{org.backup_share}}`, `{{global.support_email}}`);
- a constant;
- something the technician types when running it.

The agent passes the values as data:

- PowerShell gets named parameters;
- bash and Python get environment variables and a JSON file;
- secrets are passed on standard input.

Values are never substituted into the source, so a crafted value cannot turn a signed script into different code. Secret values are redacted from captured output and from logs.

### 6. Who can do what

New permissions, granted per organization like the existing ones:

| Permission | Default roles |
|---|---|
| `ViewScripts` | admin, technician |
| `EditScripts` (drafts only; global scripts too) | admin, technician |
| `PublishScripts` (approve a revision; needs a registered security key) | admin |
| `RunScripts` (by risk class: technicians C0–C1, C2 with a second approval) | admin, technician |
| `ManageFields` (definitions) | admin |
| `EditFieldValues` (per field, per scope) | admin; technician where the field allows |

API tokens get `scripts:run` only, scoped like `jobs:run`. Editing and approving stay browser-only. Custom roles are a later step; the permissions above are written so a custom role can be any subset of them.

### 7. On the agent

- **Before anything else:** verify the approval signature and the trust list, and recheck the device's own policy. A device can refuse classes, for example "no C2 or above".
- **Before running:** check the interpreter is there, and repeat the syntax check with the real one.
- **Running:**
  - as SYSTEM on Windows, root elsewhere;
  - in a Windows Job Object, so a timeout ends the whole process tree;
  - output is capped as it is today.
- **Afterwards:** results flow through the existing job lifecycle (ADR-0005). Nothing retries on its own; a run can target many devices as a batch, like diagnostics.

## Alternatives considered

- **Upload-only scripts:** no simpler security-wise, and needlessly slow for small fixes.
- **Approval by a server-held key:** a compromised server could approve its own scripts. Rejected; this is T10.
- **An offline signing tool (CLI) instead of WebAuthn:** this works and is the fallback for people without a security key. It is slower to use, so it isn't the default.
- **Substituting variables into script text:** the usual RMM approach and the usual injection bug. Rejected.

## Consequences and costs

- **Approvers need a security key or passkey:** platform passkeys work, and YubiKeys cost about $50 each. This needs the operator's decision (see Open questions).
- **The server image grows:** PowerShell on Linux adds roughly 70 MB to the container for syntax checks, so it is an optional component.
- **The agent learns to verify WebAuthn signatures:** ECDSA P-256 over the revision hash. The verification code is small; it needs its own tests and review.

## Build order

1. **Done (2026-11-02).** **Custom fields:** definitions, scoped values with history, required-field reporting, and resolved values on device and organization pages. This executes nothing and is useful on its own. **Done (2026-11-03):** sites as a level between organization and device (migration 0009; a site value also meets a device requirement for the devices in that site).
2. **Done (2026-11-02).** **Script library:** drafts, revisions, diffs, server-side checks, upload and download. This executes nothing. As built: a script's language is fixed when it is created; the revision hash also covers the script's id; drafts with problems are saved and their problems shown (approval will refuse them); file upload loads the file into the text box to review before saving, so it needs JavaScript (pasting works without). Checker processes run with an empty environment, a time limit and capped output, but **not yet without network access**: that is left to the deployment (for example a container with no egress) until the isolated worker exists.
3. **Trust list and approval:** WebAuthn registration for approvers, sudo mode, the signed trust list, pinning at enrollment, and approving revisions.
4. **Running scripts:** agent verification, parameters as data, Job Objects, single runs, then batches. PowerShell first.
5. **Schedules:** recurring runs per organization, site or tag, then policies that pass down from organization to device.

## Operator decisions (2026-11-02)

1. **Approvers and keys:** yes: approvers use a passkey or security key, with the offline signing tool as the fallback, and approval is a sudo-mode step (section 3).
2. **Global scripts:** technicians may draft and edit global scripts; only those who can publish approve them.
3. **Sites as a scope:** yes: field values can be set per site, between organization and device.
