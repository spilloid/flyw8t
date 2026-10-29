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
