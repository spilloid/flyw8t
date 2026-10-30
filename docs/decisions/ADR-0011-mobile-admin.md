# ADR-0011: Mobile administration

**Status:** proposed (goal accepted by the operator 2026-10-30, corporate-strategy D-0055; the approach below needs confirmation) · **Date:** 2026-10-30

## Context

The operator wants "a great mobile admin client". Technicians are paged away from their desks. From a phone they need to see what is wrong, act within their scope (run a diagnostic, cancel a job, start or end a support session), and trust what they see, with the same honesty as the desktop console. Live is labelled live, cached data shows its age, and an outcome that is unknown is shown as unknown.

Today:
- The console is server-rendered and already responsive. `ui_capture` checks every page at phone width for overflow and browser errors.
- The JSON API (`/api/v1`) uses bearer tokens.
- There is no push channel, and sign-in is password plus TOTP.

## Options

| | Installable mobile web app (PWA) over the existing console | Native client (Rust core + platform UI, or Tauri 2 mobile) over `/api/v1` |
|---|---|---|
| Install friction | None: "Add to Home Screen" from the console | App stores, or sideloading for self-hosters |
| Self-hosting fit | Exact: each deployment serves its own app | Hard: one store app has to be pointed at any server, and trust that server |
| Notifications | Web Push (iOS 16.4+ for installed web apps); needs VAPID keys only, no vendor account | APNs/FCM: needs Apple and Google developer accounts (**recurring cost**) and a relay for self-hosted servers |
| Sign-in | Same session, MFA and CSRF model as the console; passkeys (WebAuthn) when built | A new credential plane per device (device-bound tokens), plus biometrics |
| Offline | Shell plus last-seen data, clearly labelled stale | Same, with more control |
| Effort | Small: manifest, icons, service worker for the shell, Web Push, touch-first layouts | Large: a second UI, API coverage for every console action, release pipelines |
| Attended support from a phone | Viewing a shared screen works in mobile browsers | Same |

## Proposed decision

1. **First, the console becomes a first-class installable mobile web app.** It gets a web app manifest, touch-first layouts for the screens a technician needs on call (alerts, devices, run a diagnostic, jobs, support), and Web Push for findings and job outcomes. The service worker caches only the shell; data is never shown as current from a cache. No vendor accounts and nothing recurring.
2. **Second, a native client, once the API covers every console action.** It would be built on the same `/api/v1` with device-bound, revocable, scoped tokens (STD-004's token plane), and it reuses the `flyw8t-protocol` and `flyw8t-domain` crates so outcome labels cannot drift from the server's. Store distribution and APNs/FCM involve recurring developer-account costs, so **that step needs the operator's approval** before it starts.
3. Either way, every new console feature lands with a phone-width design, and `ui_capture` keeps failing on overflow at 390 px.

## Revisit when

- Web Push proves unreliable on iOS for installed web apps.
- Technicians need device features the web cannot give (for example a native share sheet into tickets, or widgets).
- AnchorDesk ships its own mobile client that flyw8t should plug into instead.
