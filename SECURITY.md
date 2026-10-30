# Security policy

flyw8t is remote-execution infrastructure: a vulnerability can mean control of every enrolled endpoint. Please report suspected vulnerabilities privately.

## Reporting

Use GitHub's **private vulnerability reporting** on this repository (Security → Report a vulnerability), or email the maintainer at the address on the GitHub profile. Do not open a public issue. Expect an acknowledgement within three working days.

Please include the version or commit, a description, and a reproduction against **synthetic data** (test organizations, loopback or TEST-NET addresses). Never send real customer data.

## Supported versions

flyw8t is pre-1.0 and **not production-ready** (see `docs/threat-model.md` § Open items: no OIDC yet, unsigned binaries, attended support not yet independently reviewed). Fixes land on `main`.

## Design commitments

- No arbitrary command execution: endpoints run only a compiled-in, validated, read-only action catalog, and the agent enforces it independently of the server.
- Device private keys never leave devices. Passwords are Argon2id. Every other secret (sessions, API tokens, enrollment tokens, support invitations) is stored only as a SHA-256 digest and shown once.
- Tenancy comes from enrollment tokens, never from what a device says.
- History (`job_events`, `audit_events`, `support_events`) is append-only, enforced by the database.
- Plaintext is refused to any non-loopback host, by both agent and server.

## Deployment secrets

This repository contains **no deployment secrets**. `deploy/compose/.env.example` is a template with placeholder values; the real `.env` is git-ignored. Production secrets belong in your own secret store or a SOPS-encrypted overlay outside this repository.
