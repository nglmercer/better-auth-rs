use thiserror::Error;

/// Errors shared by the auth context, adapters, and plugins.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("rate limit exceeded; retry after {retry_after_seconds} seconds")]
    RateLimited { retry_after_seconds: u64 },

    #[error("not found")]
    NotFound,

    #[error("adapter error: {0}")]
    Adapter(String),

    #[error("plugin error: {0}")]
    Plugin(String),

    #[error("cryptographic error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, AuthError>;
