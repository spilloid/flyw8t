# ADR-0008: No agent auto-update until updates are signed

**Status:** accepted · **Date:** 2026-10-29

## Decision

The agent has **no update mechanism** in 0.1. Administrators install and upgrade agents. Auto-update ships only with all of:

1. A release manifest signed with an Ed25519 key held **outside** the flyw8t server (a release-signing key, as PortGlass's updater uses; `portglass-core::update` is the reference). A compromised flyw8t server must not be able to push a binary.
2. Authenticode-signed Windows binaries (Azure Artifact Signing, as netviz, PortGlass and tuldMi already do), checked by the agent before replacing itself.
3. Version monotonicity (no downgrade unless explicitly allowed by a signed manifest), staged rollout by organization, and automatic rollback if the new agent fails to reconnect within a bound.
4. The update is itself a job with a lifecycle and evidence: success means "the device reconnected and reported the new version", not "the download finished".

## Why

A remote-execution product's update channel is its most powerful attack path (threat T9). Shipping it unsigned "for now" would quietly make a server compromise into an arbitrary-code fleet compromise.
