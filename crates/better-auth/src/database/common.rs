use better_auth_core::error::AuthError;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

pub(super) fn json_error(error: serde_json::Error) -> AuthError {
    AuthError::Adapter(format!("SQLite JSON error: {error}"))
}
