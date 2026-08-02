//! Framework-neutral client request construction and transport helpers.
//!
//! The request builder, retry policy, and HTTP transport live in separate
//! modules so browser bindings can reuse the small request contract without
//! pulling in server-side auth services.

mod request;
mod retry;
mod transport;

pub use request::AuthClient;
pub use retry::RetryPolicy;
