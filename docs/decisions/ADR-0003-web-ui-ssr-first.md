# ADR-0003: Web console is server-rendered first

**Status:** accepted · **Date:** 2026-10-29

## Context

The brief prefers Leptos (Rust/WASM) with server-side rendering where appropriate, and minimal JavaScript. The development machine has no `wasm32-unknown-unknown` target or `cargo-leptos`, and the vertical slice needed a working console, not a mockup.

## Decision

Render every page on the server with Leptos (`ssr` feature, `view!` → HTML), with **no hydration and no WASM bundle** for now:

- Forms POST and the server redirects (post/redirect/get), carrying the session's CSRF token.
- In-flight job pages refresh themselves with `<meta http-equiv="refresh">` until the job reaches a final state, and stop refreshing after that.
- CSP is `default-src 'none'` with stylesheet and images from self only: no script at all, inline or otherwise.

## Why this is not a compromise for a technician

Every page is a few kilobytes of HTML, loads on a phone over a poor connection, works with JavaScript disabled, and is keyboard-navigable by default (native forms and links). Server rendering also keeps authorization in one place: the page cannot show anything the server did not decide to render.

## When to add hydration

When a view needs live updates without a full reload (a job's output streaming, the device list updating connection badges in place), add Leptos hydration for that island, served as a same-origin WASM bundle, and extend the CSP with `script-src 'self' 'wasm-unsafe-eval'` for those pages only. The view code is already Leptos components, so this is additive.

The attended-support consent page ([ADR-0010](ADR-0010-attended-support.md)) is the known exception: WebRTC and screen capture are browser JavaScript APIs and cannot be server-rendered.
