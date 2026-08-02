//! A framework-neutral Rust foundation for Better Auth.
//!
//! This crate owns runtime state and security behavior while framework
//! adapters are expected to translate their request/response types into the
//! small http types used here.

pub mod context;
pub mod cookies;
pub mod password;
pub mod security;

pub use better_auth_core as core;
pub use context::{AuthContext, RequestContext, RequestMetadata};
pub use cookies::{AuthCookie, CookieSameSite, SecretKeySet};
pub use password::{hash_password, verify_password};
pub use security::{check_csrf, extract_client_ip};
