//! Multi-cookie session management for HTTP clients and web tooling.
//!
//! This crate intentionally focuses on reusable building blocks that any web
//! tooling can use:
//!
//! - Multi-cookie jar handling with domain- and path-scoped storage.
//! - Cookie parsing from Set-Cookie style header lines.
//! - Session persistence to JSON for sharing state across runs.
//! - CSRF token extraction and request-time injection helpers.
//!
//! # Usage
//!
//! ```rust
//! use authjar::{AuthSession, Cookie, CsrfSource, SessionSettings};
//!
//! // Create a session with cookies.
//! let mut session = AuthSession::new("admin");
//! session.add_cookie("PHPSESSID", "abc123", "example.com");
//! session.add_cookie("auth_token", "xyz789", "example.com");
//!
//! // Apply cookies to an outgoing request.
//! let cookies = session.cookie_header("example.com", &SessionSettings::default());
//! assert!(cookies.contains("PHPSESSID=abc123"));
//! ```


#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod csrf;
mod session;

pub use csrf::{CsrfSource, CsrfToken, extract_csrf_tokens, inject_csrf_token};
pub use session::{AuthJarError, AuthSession, Cookie, SessionSettings, SessionStore};
