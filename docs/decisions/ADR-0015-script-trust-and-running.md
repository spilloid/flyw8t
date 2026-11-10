# ADR-0015: Script trust and running: a pinned, signed trust list; approvals and runs the server cannot forge

**Status:** proposed (2026-11-10; revised after a Codex `gpt-6.1-sol` design review, dev-process row 37) · refines [ADR-0014](ADR-0014-scripts-and-custom-fields.md) sections 3 and 7 (build steps 3 and 4) · holds the line of [threat model T10](../threat-model.md) · uses the job lifecycle of [ADR-0005](ADR-0005-job-lifecycle.md)

## Context

ADR-0014 decided that scripts run only when real people have approved them, with signatures the server cannot forge, checked by the agent against a trust list "rooted in a key it pinned at enrollment". It did not say what the list is, how it changes, what exactly is signed, or how the agent runs what it has verified. This ADR does, so the code in build steps 3 and 4 has one design to follow and one design to review.

**What is protected, exactly.** A server or database compromised **after** the people involved signed must not be able to:

- run anything nobody approved;
- run a C2 or C3 script without a fresh signature for that run on that device;
- change who may approve.

Two things are **not** protected, and the design says so rather than pretend:

- **A signing key that is stolen and usable** (the device, plus its PIN or biometric) is SYSTEM on every device in its scope. A risk class is the approver's promise about what a script does, and the agent cannot check it. So a stolen key can approve anything as C0 and run it with no further signature.
- **A server compromised while someone signs in the browser** can show one thing and have the browser sign another. Passkeys sign a hash, and the page that shows what the hash means comes from the server. `flyw8t-sign` closes this gap for anyone who uses it, because it computes and shows everything it signs from what is on the signer's own machine.

The operator decided on 2026-11-10:

1. The trust root is an **offline root key** (made with `flyw8t-sign`, kept on paper or a USB stick) together with the operator's passkey, both in the first list.
2. A reboot is a **C3** script: the person running it signs each run, one device at a time. That works for a single operator.
3. Removing a signer from the list **invalidates everything that signer approved**.
4. Agents enrolled before the trust list existed **refuse scripts until pinned locally** (`flyw8t-agent trust pin`) or re-enrolled.

## Decision

### 1. Signers

A **signer** is one key belonging to one person:

- **passkey:** a WebAuthn credential (ES256, P-256), already registered with the console (#28). It signs in a browser.
- **offline:** an Ed25519 key in a passphrase-protected file, used with `flyw8t-sign` on any machine. It signs on the command line, after showing everything it signs.

Each signer entry holds:

- its **key id**: SHA-256 of its public key, recomputed by every verifier, never taken from the entry;
- its public key, and for a passkey, its credential id;
- the **person** it belongs to, as an id and a display name. A key's person never changes; moving a key to another person means removing it, and that is permanent (section 2);
- **may approve up to**: the highest risk class it may approve revisions and sign runs for (`none`, `C0` … `C3`);
- **scope**: every organization, or a listed set of organization ids;
- **role**: `signer`, `list admin` or `root`. A root is also a list admin. Only offline keys may be roots.

A person may hold several keys. The agent never sees users, roles or permissions from the server's database. It sees only this list.

### 2. The trust list is a signed chain

A **trust list** version holds:

- the **deployment id**: random, fixed at the first version, and part of every signed statement, so nothing signed for one flyw8t deployment is accepted by another;
- its **version number**, and the **hash of the previous version**. The first version (genesis) has no previous version;
- the WebAuthn **relying-party id** and the **allowed origins** (the console's public URL), which passkey signatures must match;
- the **threshold**: how many different people among the list admins must sign the next version;
- the **signers**;
- **removed keys**: the id of every key ever removed;
- **revoked revisions**: content hashes that no longer run, whoever approved them;
- when it was made.

A version's hash covers these fields only, not its signatures. **Every version must be valid on its own:**

- at least one root;
- a threshold of at least 1, and no more than the number of different people who are list admins;
- no key id or credential id appearing twice;
- no signer whose key id is among the removed keys.

**The first version (genesis)** is signed by at least its own threshold of its list admins, all different people, and by every root in it. Its hash is the deployment's **trust fingerprint**, written `sha256:` followed by 64 hex digits. It never changes for the life of the deployment.

**A later version is accepted only if all of the following hold:**

- it has the next version number;
- it names the hash of the version the agent **currently holds**: the agent extends only its own head and never steps back;
- it keeps the deployment id;
- it is signed by at least the **previous** version's threshold of that version's list admins, counted as **different people**;
- if it adds, removes or changes the role of any list admin or root, or changes the threshold, a **root of the previous version** has also signed;
- its removed keys and revoked revisions are **supersets** of the previous version's. Removal and revocation are permanent: a removed key is never valid again, even if a later version lists it, and a revoked revision never runs again.

So the server can store and hand out the chain, but it cannot extend it or wind it back, and no one key below a root can take over the list.

**Defaults at genesis:**

- the offline key is the root and the only list admin, with a threshold of 1;
- the operator's passkey is a signer that may approve up to C3 in every organization.

A stolen passkey together with the server can then approve scripts until the key is removed. That is serious (see Context), but it cannot add keys, protect itself from removal, or touch the list. The operator may make passkeys list admins, and raise the threshold once there are two people; changes like these always need the root as well.

**Recovery:**

- **Lost passkey:** the root signs a version that removes it and adds the new one.
- **Lost root, with the root's backup copy:** use the copy. Keep the offline key in two places.
- **Lost root and every copy:** agents must be re-enrolled with a new genesis. That is the price of a root the server cannot replace.

### 3. Pinning

**Where the fingerprint comes from.** `flyw8t-sign genesis` prints it, on the operator's own machine. The operator keeps it in their install scripts or notes. The console shows it too, for convenience, but a compromised console can show a different one, so the console's copy is not the authority.

**At genesis**, `flyw8t-sign` shows every signer's key id and person. The passkey entry's public key reaches it through the server, from when the passkey was registered. So the operator confirms the passkey before signing: the console's passkey page shows the same key id, read when they last signed in with it. This is a governance step the tool cannot do for them, and the ADR says so.

**Enrollment.** `enroll --server … --token … --trust sha256:… --org <organization id>` works like this:

1. The agent fetches the chain from the server.
2. It checks that the genesis hashes to the given fingerprint, and verifies every later step.
3. It stores the head version and the fingerprint.
4. It stores the organization id it was given **on the command line**, and checks that it matches what the server enrolled it into.

A wrong fingerprint or a different organization stops enrollment before the device key is registered.

**Agents enrolled without `--trust`** (every agent today) run the built-in actions as before and refuse every script. To pin one, run this as Administrator on the device:

```text
flyw8t-agent trust pin sha256:… --org <organization id>
```

It fetches and verifies the chain the same way. No list is ever trusted only because the server sent it (operator decision 4).

**The device's identity in signatures** is the SHA-256 of its device public key (its **device key id**), not the id the server assigned it. The server could give two machines the same id; it cannot give them the same private key. The console shows the device key id on the device page. `flyw8t-agent status` shows it on the device.

**The pin, the head version, the organization and the spent-run record** all live in the protected state folder (SYSTEM and Administrators only, as `enroll` made it). So nothing that is not already an administrator on the machine can change them. A script running as SYSTEM can. That is the first point under "not protected" in Context, and why removal cannot repair a device a malicious script has already run on.

**Updates.** The agent reports the version it holds. When the server has newer versions, it sends the ones after it. The agent verifies each step, and stores the new head durably before acting on anything that depends on it. A version that does not verify is refused and reported. **Nothing the console shows about versions is trustworthy** under a compromised server. On the device, `flyw8t-agent trust status` shows the fingerprint, version, head hash and organization.

### 4. What is signed

Every signature is over a **statement**. A statement's hash is SHA-256 over a domain string naming its kind, then its fields in a fixed order. The building blocks:

- every value is preceded by a one-byte type tag;
- byte strings and text are an 8-byte big-endian length, then the bytes (text as UTF-8);
- integers are 8 bytes, big-endian; a boolean is one byte, 0 or 1;
- UUIDs and hashes are written as byte strings (length, then 16 or 32 bytes);
- times are whole seconds since the Unix epoch;
- enumerations (risk class, role, signer kind, scope kind) are a fixed small integer each;
- an optional value is a 0 byte, or a 1 byte and the value;
- a list is an 8-byte count, then its items in ascending order of their encoding. Duplicates are refused.

The agent re-encodes from the values it parsed, never from bytes it was sent, and unknown fields are refused. One encoder in `flyw8t-protocol`, used by the server, the agent and `flyw8t-sign`, has fixed test vectors. The exact grammar is written down with those vectors in build step 2.

The **revision content hash** is kept exactly as it is stored today (ADR-0014 build step 2). It covers the script id, language, risk class, parameter declarations and source.

| Statement | Domain | Fields |
|---|---|---|
| Trust list | `flyw8t trust list v1` | the fields of section 2 |
| Revision approval | `flyw8t revision approval v1` | deployment id, script id, revision number, revision content hash, risk class, language, script scope (an organization id, or global), approved at, signer key id |
| Run authorization | `flyw8t run authorization v1` | deployment id, job id, device key ids, revision content hash, parameter commitment, timeout, not before, expires at, signer key id |

**The parameter commitment** is SHA-256 over `flyw8t run values v1`, then a random 32-byte salt made for the run, then each declared parameter's name and value, sorted by name. The salt travels with the job. It means a guessable secret cannot be found by trying values against a signature someone has copied.

**How each kind of signer signs a statement hash:**

- **Passkey:** the hash is the WebAuthn **challenge**. The assertion signs `authenticatorData || SHA-256(clientDataJSON)`, and `clientDataJSON` carries the challenge. The agent checks:
  - the `clientDataJSON` is valid JSON with exactly one of each field it reads;
  - its type is `webauthn.get`;
  - its challenge is the base64url of the statement hash;
  - its origin is one of the allowed origins of the list version that verifies the signature;
  - `crossOrigin` is absent or false, and there is no `topOrigin`;
  - the authenticator data carries the SHA-256 of that version's rp id, with user-present and **user-verified** set;
  - the ES256 signature verifies under the signer's key.

  The signature counter is not used: synced passkeys report 0. All of this extends `flyw8t_protocol::webauthn`, which the server already uses for sudo mode.
- **Offline:** Ed25519 over `flyw8t offline signature v1\0` followed by the statement hash.

### 5. What the agent checks

**The checks.** The first failure refuses the job (`NotAccepted`, with the reason), and nothing runs:

1. **Pinned:** the agent holds a pinned, verified head, and the job's deployment id is that list's.
2. **Revision:** recompute the content hash from the revision sent, and check it is not revoked. The revision's own fields (script id, number, language, risk class) are what every later step compares against.
3. **Approval:** at least one revision approval whose every field matches: the deployment, the script id, revision number, content hash, risk class and language, and a script scope that is global or exactly the agent's pinned organization. Its signer must:
   - be in the head list and not removed;
   - be allowed to approve at least this class;
   - have a scope that includes the agent's organization;
   - have a signature that verifies.
4. **Run authorization**, for C2 and C3:
   - **The signer passes the same tests as in step 3.**
   - **The authorization names:** this deployment, the job id, this device's key id, the content hash, and a parameter commitment that matches the values and salt sent.
   - **Its timeout is the one the agent will use,** and it is no longer than the device's ceiling.
   - **Its window:** not before is no later than now, and expires at is after now. The window is at most 15 minutes for C3 and 24 hours for C2.
   - **For C2:** its signer is a **different person** from every approver the agent relied on in step 3.
   - **For C3:** it names **exactly one** device key id. The same person may have approved the revision.
5. **Device policy:** the class is at or below the device's own limit. The limit is set at enrollment (`--max-risk`, default C3) and changed only on the device. So is the timeout ceiling (default 1 hour).
6. **Parameters:**
   - The signed declarations parse **without a single problem**, using the server's own parser, moved into `flyw8t-protocol`.
   - Every declared parameter has exactly one value, and no name appears twice, ignoring case, across both the plain values and the secrets.
   - A constant equals its declared value.
   - A parameter declared `secret` arrives only among the secrets, and a parameter not declared `secret` never does. Secret-ness is part of the signed declarations: the server refuses to bind a secret field to a parameter not declared `secret`.
   - Values are strings, at most 4 KiB each and 64 KiB in all.

**When the checks run.** They run when the offer arrives, so a bad job is refused at once. They run **again immediately before launch**, under the same lock as trust updates, so a removal or revocation that arrives while a job waits stops it. A job already running is not stopped by a later removal; the console says so.

**Spending a run authorization.** The agent records it as spent **before** anything of the job runs, including the parse, and only once the record is on disk. The key is deployment, device key and job id. Writing the record uses `MoveFileEx` with write-through, the open item from `docs/reliability.md`.

- If the record cannot be written, or the store cannot be read, nothing runs.
- A record is never given back, whatever happens to the job afterwards.
- The store is not the job journal: the journal drops old entries by count, and a flood of jobs must not let a signed run be replayed.
- Records are kept until their authorization has expired, plus a margin of one day.

**Time.** The agent keeps a durable **high-water mark**: the latest time it has seen. If the clock reads earlier than the mark, by more than a small tolerance, it refuses every run that needs an authorization until the clock passes the mark again. That stops a clock wound back from reviving a pruned record.

### 6. Running

PowerShell first (Windows PowerShell 5.1, which every supported Windows has). `pwsh`, bash and Python follow the same shape later.

**The job folder.**

- `run\<job id>` in the default state folder, created **new**: if it already exists, the job fails.
- Before it is used, its parent is checked as `enroll` checks the state folder: owner, protected permissions, no reparse points.
- The script, wrapper and values are written with create-new semantics, and the job fails if any of them already exists.
- The script is UTF-8 **with a byte-order mark**: Windows PowerShell 5.1 reads files without one in the legacy code page.
- The folder is removed after the job, refusing to follow reparse points.

**The interpreter.** `powershell.exe` from the System folder, as the known-folder API reports it, never from `PATH`. The command line is `-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <wrapper>`. The execution-policy setting applies to this process only, and does not turn off AMSI or Defender.

**The wrapper** is fixed, compiled into the agent, and reviewed as part of it. It does the following, in order:

1. It reads the plain values from the job folder as UTF-8 (`-Encoding UTF8`), and the secrets from standard input as UTF-8. Both are JSON objects of strings only: anything else stops the job.
2. It parses the script with `[Parser]::ParseFile`. The parse runs **inside the containment**, after the run authorization is spent. Parsing can resolve `using module` statements and load what they name, so it is not inert, and it is never run outside a job that is allowed to run.
3. It requires the script's `param()` block to declare **exactly** the signed parameter names, as plain parameters. Positional binding is not used, and a script without a `param()` block receives no values.
4. It builds a hashtable and calls the script with `& $script @values`.

Splatting a hashtable binds by name, so a value such as `-Force` stays a value. Nothing is ever written into the source or onto a command line.

**The environment.**

- A minimal set of variables: `SystemRoot`, `windir`, `ComSpec`, `PATH` of the System folders, and `TEMP` and `TMP` pointing at the job folder.
- `PSModulePath` lists only the System and Program Files module folders, which only administrators can change.
- Nothing from the agent's own environment is passed on.

**What approval cannot cover: what a script loads.** A script that loads code from somewhere a non-administrator can write hands that person SYSTEM. That covers dot-sourcing a file from a user folder, importing a module from a writable path, and downloading code. Script authors must load only from administrator-only locations. The approval page warns about each such reference it can see, and the warning is a heuristic.

**Containment.**

- The process is created **inside** a Job Object (`PROC_THREAD_ATTRIBUTE_JOB_LIST`, Windows 10 and later). There is no moment when it runs outside the job.
- The job object has kill-on-close and no breakaway, and its handle is not inheritable.
- Only the standard-stream pipes are inherited.
- A timeout or a cancel terminates the job object, so the whole process tree goes, and cleanup waits for it to empty.
- Output is captured and capped as for diagnostics today.

**Redaction.**

- Secret values are removed from output **as it is captured**, before it reaches the journal, a log or the server. Removal works across chunk boundaries and on overlapping secrets.
- Types that carry secrets print as `[redacted]` in debug output.
- This is a best effort: a script that transforms a secret (base64, say) defeats it. PowerShell's own logging, if an administrator turned on script-block or transcription logging, can record values.

**Results** are reported through the existing lifecycle (ADR-0005): exit code, output, timed out, cancelled, or **interrupted**. A script that reboots the machine before it exits gets "interrupted". So a script meant to reboot should schedule it (`shutdown /r /t 30`) and exit 0, and its success is reported before the machine goes down. Nothing retries on its own. A cancel or timeout can leave the script's work half done, and the result says the outcome is partial.

### 7. Delivery

- **Capabilities:** the agent states what it supports when it authenticates (`capabilities: ["scripts.v1"]`). The server never offers a script to an agent that did not say so, so older agents never receive a message they do not understand.
- **`ScriptOffer`** is a new message. It carries:
  - the job id, the timeout and the deployment id;
  - the full revision and its approvals;
  - the run authorization, if any, and the salt;
  - the plain values, and the secrets.

  Secret-bearing fields have types that never print their contents. The built-in catalog's `JobOffer` is unchanged.
- **`TrustUpdate`** is a new message. It carries the versions after the one the agent reported holding.
- **The connection** is the existing authenticated, TLS-only WebSocket. Nothing in this ADR relies on it for integrity. Secrets rely on it for confidentiality, as they do today.

### 8. In the console

- **Trust page** (administrators, sudo mode):
  - **Genesis:** the server drafts the first list: the deployment id, the rp id and origin from the public URL, and the operator's passkey. `flyw8t-sign genesis` shows it in plain words, signs it with the root, and prints the fingerprint. The signature is uploaded, and the server verifies it before publishing.
  - **Later changes:** drafted the same way and signed by list admins. A passkey list admin may sign in the browser. A change that needs the root is signed with `flyw8t-sign`.
  - The page shows the chain, every signer, every removed key, and each device's reported version. The reported versions are useful, but not proof (section 3).
- **Approving a revision** (`PublishScripts`, sudo mode):
  - **In the browser:** the page shows the source, the parameter declarations, the risk class, warnings about what the script loads, and the statement hash. Then comes a WebAuthn ceremony whose challenge is that hash.
  - **With `flyw8t-sign approve`:** the approver gives it the **file they reviewed**, and it computes the content hash itself.
  - **On the server:** every approval is verified as the agent would verify it before it is stored, so a bad one is refused at once rather than on every device.
- **Running:** the device page gets "Run script". Choose an approved revision and enter the asked values.
  - For C2 and C3 a run-authorization ceremony follows. Its page shows the device (name and key id), the script, every plain value, and the version of each secret field ("set", and when it was last changed).
  - `flyw8t-sign authorize` does the same from a downloaded run request, and prints what it signs.
  - C3 is offered for one device at a time only.

### 9. What a compromised server can still do (and cannot)

Assuming nobody signs anything in a browser while the server is compromised (otherwise see Context):

**Can:**

- run an **approved C0 or C1** revision on any device in the approver's scope, as often as it likes, with any values for field-bound and asked parameters. It cannot change constants or swap a secret parameter for a plain one;
- choose the timeout for C0 and C1 runs, up to the device's ceiling, and cancel any run partway;
- **freeze** a device: withhold trust updates, so it keeps trusting a signer who has since been removed, and keeps running a revision since revoked. The same goes for enrollment: a new agent can be handed an old but valid head. Nothing on the server side detects this; `flyw8t-agent trust status` on the device does. Expiring lists are the remedy, and they are deferred (section 10);
- refuse to deliver jobs or results, and fabricate what the console shows about results and history. Availability and the console's own record are not protected;
- enroll a device into the wrong organization, if the person enrolling copies `--org` from the compromised console.

**Cannot:**

- run anything nobody approved;
- run a revoked revision on a device that has received the revocation;
- run a C2 or C3 script without a fresh run signature for that device's key, those values and that timeout, or run one twice;
- add, restore or protect a signer;
- extend or wind back the chain on a device;
- move a device to another deployment.

Script authors must therefore treat **asked and field-bound values as untrusted input**: a C1 script that deletes a path it is given is as dangerous as its parameter.

### 10. Not now

- **Lists that expire**, the remedy for freeze. They need people to re-sign on a schedule, and with one operator that cost is not worth it. Reconsider when there are two or more people.
- **Requiring the root for C0 and C1 approvals.** That would make a stolen passkey worth much less. It is cheap to add later, as an option per signer.
- **Signing the server's identity:** the separate pinning ADR, still to come. This ADR does not depend on it.
- **Linux and macOS runners, bash and Python:** the same checks, with process groups or cgroups instead of Job Objects.
- **Batches of C0 and C1 runs**, which follow single runs, as ADR-0014 says.
- **Schedules:** ADR-0014 build step 5.

## Alternatives considered

- **Trust the first list the server sends (TOFU):** convenient, but a server compromised before that moment owns the fleet. Rejected, by operator decision 4.
- **A root the server holds, or a key in a cloud KMS:** the server could approve for itself. Rejected (T10).
- **Passkey list admins by default:** convenient, but one stolen synced passkey and the server could rewrite who approves. Kept as an option, and even then the root must sign any change to list admins.
- **JSON canonicalization (JCS) for statements:** the typed, length-prefixed encoding follows what `content_hash` already does, is shorter to implement correctly, and leaves no question about number formats.
- **Signing each run for every class:** safest, but it would make even read-only C0 scripts a ceremony every time. Risk classes put that cost where it buys something. Context states what that leaves open.
- **Substituting values into the source:** rejected in ADR-0014. Here even the wrapper binds named parameters only.

## Consequences and costs

- **A new crate, `flyw8t-sign`:** a small CLI with `keygen` (a passphrase-protected key file), `show`, `genesis`, `sign-list`, `approve` and `authorize`. It shares the statement code with the agent.
- **The agent grows:** chain verification, approval and run checks, the spent-run store and time high-water mark, and the PowerShell runner in a Job Object. All of it needs tests that prove each check can fail, mutation runs, and a top-tier cross-family review before merge.
- **Every existing agent needs `trust pin`,** or re-enrollment, before it can run scripts. Built-in actions are unaffected.
- **Changing the console's public URL** changes its rp id, and existing passkeys can no longer sign. The root signs a version with the new origin and new passkeys.

## Build order

1. **This ADR,** reviewed by a second model family before any code. Round 1: dev-process row 37.
2. **Protocol and signing tool:**
   - statements, with the exact encoding grammar and test vectors;
   - chain verification, with the rules of section 2;
   - offline signatures;
   - the parameter parser, moved into `flyw8t-protocol` and extended with `secret`;
   - `flyw8t-sign`.
3. **Server and pinning:**
   - the trust page and genesis;
   - approvals, by passkey and offline;
   - enrollment with `--trust` and `--org`, and `trust pin` and `trust status`;
   - trust updates.
4. **Running:**
   - the agent's checks, spent-run store, high-water mark and runner;
   - `ScriptOffer`;
   - the console's run flow for C0 to C3.

   **Acceptance:** an approved C3 script, signed for the run, reboots the development machine. The agent reports success before the reboot, and reconnects after it.
