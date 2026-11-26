# ADR-0008: No agent auto-update until updates are signed

**Status:** accepted · **Date:** 2026-10-29

**Default policy confirmed by the operator:** 2026-11-26.

## Decision

The agent has **no update mechanism** in 0.1. Administrators install and upgrade agents. Auto-update ships only with all of:

1. A release manifest signed with an Ed25519 key held **outside** the flyw8t server (a release-signing key, as PortGlass's updater uses; `portglass-core::update` is the reference). A compromised flyw8t server must not be able to push a binary.
2. Authenticode-signed Windows binaries (Azure Artifact Signing, as netviz, PortGlass and tuldMi already do), checked by the agent before replacing itself.
3. Version monotonicity (no downgrade unless explicitly allowed by a signed manifest), staged rollout by organization, and automatic rollback if the new agent fails to reconnect within a bound.
4. The update is itself a job with a lifecycle and evidence: success means "the device reconnected and reported the new version", not "the download finished".

## Fleet policy

When the signed updater ships, automatic updates are enabled by default for enrolled agents that support it. An eligible agent receives the approved release as its rollout cohort opens and the device checks in. Its enrollment and job journal carry forward. An update waits for active jobs and technician sessions to finish before restarting the agent.

Expose **Automatic agent updates** to administrators at the organization and device levels. A device can opt out or inherit the organization setting. Turning updates off for the organization pauses its whole fleet. An explicit opt-out persists across reconnects and upgrades, and policy changes appear in audit history. This also lets an administrator keep an Intune-managed fleet on its own update schedule.

Start with a small Windows canary after the 0.2.0 sprint. Verify a signed upgrade through reconnect on a real enrolled PC, then exercise a broken release and confirm rollback preserves the same enrollment. Include a device with updates turned off and an offline device that rejoins later. Show the installed version and update result in Device Activity. Older agents need a managed upgrade to a build that contains the updater before they become eligible.

## Why

A remote-execution product's update channel is its most powerful attack path (threat T9). Shipping it unsigned "for now" would quietly make a server compromise into an arbitrary-code fleet compromise.
