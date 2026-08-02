use better_auth_core::{
    error::AuthError,
    plugin::Endpoint,
    schema::{FieldSchema, FieldType},
};
use http::Method;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub(super) fn endpoint(method: Method, path: &str, description: &str) -> Endpoint {
    Endpoint::new(method, path, description)
}

pub(super) fn required(field_type: FieldType) -> FieldSchema {
    FieldSchema::required(field_type)
}

pub(super) fn optional(field_type: FieldType) -> FieldSchema {
    FieldSchema::optional(field_type)
}

pub(super) fn hash_secret(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex_encode(&digest)
}

pub(super) fn member_id(organization_id: &str, user_id: &str) -> String {
    format!("{organization_id}:{user_id}")
}

pub(super) fn slugify(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

pub(super) fn urlencoding(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

pub(super) fn random_challenge() -> String {
    Uuid::new_v4().simple().to_string()
}

pub(crate) fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

pub(super) fn serialize_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Adapter(error.to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
