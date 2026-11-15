# A coherent operations product family

Operator direction, 2026-11-14: flyw8t is the main RMM/network operations console.
Consider AnchorDesk and Material Web when shaping the family experience.

## What was inspected

AnchorDesk's `web-client/src/theme.ts`, theme provider, app shell, package manifest,
device-provider documentation and NetViz inventory description. AnchorDesk currently
uses React with MUI, not Google's `@material/web` custom elements. flyw8t currently
uses server-rendered Leptos with native HTML forms. PortGlass uses its own local
controller UI. Common appearance does not imply a common component implementation.

## Shared design contract

- Semantic Material color roles, typography, spacing, outlined surfaces, shape and
  interaction states. Start with AnchorDesk's default light/dark palettes. This sprint
  maps flyw8t's stylesheet onto `--md-sys-color-*` roles and aligns shapes and typography.
- Customer → site → device context stays visible. Each product may keep its own domain
  vocabulary internally, with explicit external identity mappings at integration boundaries.
- Use the same device summary, filters, status chips, history presentation, action grouping,
  empty states and phone-width behavior. Status always includes text; color is supplementary.
- Distinguish reported, received, stale, live, requested, connected and verified. Product
  handoffs must preserve those distinctions rather than flattening them into green badges.
- Introduce capabilities where they complete work: discovery and PortGlass access on a
  network asset, endpoint diagnostics on an endpoint, ticket context through AnchorDesk.
  The network workspace already identifies its NetViz and PortGlass capabilities.
- Product identity remains visible inside a shared shell. The first step exists: `FLYW8T_FAMILY_LINKS` lists the
  operator's other products as plain links in the console's navigation (a **Products** group, each marked as
  leaving the console). It passes no context and shares no sign-in. A fuller configured app switcher
  should list deployed products the operator can actually open, preserve authorized context
  through supported links, and show unavailable capabilities honestly. Do not guess customer
  URLs, pretend to share sign-in, or add disconnected marketing cards to operational screens.

## Material Web implementation direction

Adopt a small family UI contract rather than requiring every product to import React.
Shared tokens and component behavior can have MUI and server-rendered adapters, with a
Material Web adapter for controls where custom elements improve the experience. Keep
forms usable while enhancement loads, self-host assets, preserve the console's CSP and
CSRF behavior, and test keyboard, touch, dark mode and reduced motion.

Before selecting `@material/web` as the literal family-wide dependency, account for its
upstream maintenance status: the official repository describes maintenance mode pending
new maintainers ([upstream README](https://github.com/material-components/material-web)).
Using Material's design language and introducing that specific package are separate
implementation decisions. This sprint implements the shared visual foundation; it does
not replace MUI in AnchorDesk or claim the console uses custom elements already.

## Product responsibilities

| Product | Owns | Integration boundary |
|---|---|---|
| flyw8t | RMM organizations/sites, network asset UUIDs, collectors, endpoint jobs, policies and operational audit | Public authenticated APIs and narrowly scoped collector ingest |
| NetViz | Discovery engine and observations; standalone scanner remains useful | Existing versioned probe contract |
| PortGlass | Pinned trust, destination policy enforcement, device sessions and browser lifetime | Untrusted prefill link; explicit local Connect |
| AnchorDesk | Tickets, customer/contact records, service workflow and ticket-side configuration records | Device-provider references and future ticket/context links; no shared database |

AnchorDesk already has a multi-provider inventory model and company-associated probes.
Keep its ticket-side records linked to flyw8t's stable identifiers instead of creating a
second authoritative network-monitoring engine there. A production sync adapter and
shared sign-in/context exchange remain separate work; they are not implemented here.
The first sprint's network inventory is available through the console. A scoped JSON
read API for network assets is a follow-up seam for that provider adapter; the existing
endpoint `/api/v1/devices` API is not presented as an agentless network inventory API.
