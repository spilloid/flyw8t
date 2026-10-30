//! The flyw8t web console, rendered on the server with Leptos.
//!
//! Every page is complete HTML that works with JavaScript disabled: forms post, the server
//! redirects, and in-flight jobs refresh with a meta refresh until they reach a final state.
//! See `docs/decisions/ADR-0003-web-ui-ssr-first.md`.

pub mod fmt;
pub mod model;
mod pages;

pub use pages::*;

/// Stylesheet served at `/static/app.css`.
pub const STYLESHEET: &str = include_str!("app.css");

/// Script for the attended-support pages only (ADR-0010), served at `/static/support.js`.
pub const SUPPORT_JS: &str = include_str!("support.js");

/// Icon served at `/static/icon.svg` and `/favicon.ico`.
pub const ICON_SVG: &str = include_str!("icon.svg");

/// Web app manifest, served at `/manifest.webmanifest`: makes the console installable on a
/// phone's home screen (ADR-0011). It names only static assets; no data is cached.
pub const MANIFEST: &str = include_str!("manifest.webmanifest");

/// Home-screen icons, served at `/static/icons/<name>`.
pub const APP_ICONS: &[(&str, &str, &[u8])] = &[
    (
        "icon-192.png",
        "image/png",
        include_bytes!("icons/icon-192.png"),
    ),
    (
        "icon-512.png",
        "image/png",
        include_bytes!("icons/icon-512.png"),
    ),
    (
        "icon-maskable-512.png",
        "image/png",
        include_bytes!("icons/icon-maskable-512.png"),
    ),
    (
        "apple-touch-icon.png",
        "image/png",
        include_bytes!("icons/apple-touch-icon.png"),
    ),
    (
        "icon-maskable.svg",
        "image/svg+xml",
        include_bytes!("icons/icon-maskable.svg"),
    ),
];
