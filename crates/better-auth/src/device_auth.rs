//! Device authorization grant (RFC 8628) for clients without a browser.
//!
//! The device shows a short user code and polls. The user approves the code in a
//! browser while signed in. Only then does polling return a session. The device
//! code is stored as a hash. Approval and redemption are each a single conditional
//! write, so a code cannot be redeemed twice even by concurrent pollers.

use crate::context::AuthContext;
use better_auth_core::{
    adapter::Query,
    error::{AuthError, Result},
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const TABLE: &str = "device_code";
pub const EXPIRES_IN_SECONDS: u64 = 600;
pub const POLL_INTERVAL_SECONDS: u64 = 5;
/// Uppercase letters without the look-alikes I, L, O and U, plus digits 2-9.
const USER_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTVWXYZ23456789";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeviceCodeGrant {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}

/// Outcome of one poll. Errors follow RFC 8628 section 3.5.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PollOutcome {
    Approved { user_id: String },
    Pending,
    SlowDown,
    AccessDenied,
    Expired,
}

#[derive(Clone)]
pub struct DeviceAuthService {
    context: AuthContext,
    verification_uri: String,
}

impl DeviceAuthService {
    pub fn new(context: AuthContext, verification_uri: impl Into<String>) -> Self {
        Self {
            context,
            verification_uri: verification_uri.into(),
        }
    }

    pub async fn start(&self, client_id: &str) -> Result<DeviceCodeGrant> {
        validate_client_id(client_id)?;
        let device_code = random_string(32);
        let user_code = random_user_code();
        let now = now_seconds();
        self.context
            .adapter
            .insert_record(
                TABLE,
                json!({
                    "id": uuid::Uuid::new_v4().to_string(),
                    "device_code_hash": hash(&device_code),
                    "user_code": user_code,
                    "client_id": client_id,
                    "user_id": "",
                    "status": "pending",
                    "expires_at": (now + EXPIRES_IN_SECONDS) as i64,
                    "last_poll_at": 0,
                    "created_at": now as i64,
                }),
            )
            .await?;
        Ok(DeviceCodeGrant {
            user_code: format_user_code(&user_code),
            device_code,
            verification_uri: self.verification_uri.clone(),
            expires_in: EXPIRES_IN_SECONDS,
            interval: POLL_INTERVAL_SECONDS,
        })
    }

    /// Approves a user code for the signed-in user. Returns `false` for unknown,
    /// expired or already decided codes.
    pub async fn approve(&self, user_id: &str, user_code: &str) -> Result<bool> {
        self.decide(user_code, Some(user_id)).await
    }

    pub async fn deny(&self, user_code: &str) -> Result<bool> {
        self.decide(user_code, None).await
    }

    async fn decide(&self, user_code: &str, user_id: Option<&str>) -> Result<bool> {
        let Some(row) = self.find_by_user_code(user_code).await? else {
            return Ok(false);
        };
        let now = now_seconds();
        if row.get("status").and_then(Value::as_str) != Some("pending")
            || row.get("expires_at").and_then(Value::as_u64).unwrap_or(0) <= now
        {
            return Ok(false);
        }
        let (status, user) = match user_id {
            Some(user) => ("approved", user.to_owned()),
            None => ("denied", String::new()),
        };
        // Conditional on `pending`, so two concurrent decisions cannot both win.
        let changed = self
            .context
            .adapter
            .update_where(
                TABLE,
                Query::new()
                    .eq("id", row["id"].as_str().unwrap_or_default().to_owned())
                    .eq("status", "pending".to_owned()),
                json!({"status": status, "user_id": user}),
            )
            .await?;
        Ok(changed > 0)
    }

    pub async fn poll(&self, device_code: &str, client_id: &str) -> Result<PollOutcome> {
        let row = self
            .context
            .adapter
            .find_one(
                TABLE,
                Query::new().eq("device_code_hash", hash(device_code)),
            )
            .await?
            .ok_or(AuthError::Unauthorized)?;
        if row.get("client_id").and_then(Value::as_str) != Some(client_id) {
            return Err(AuthError::Unauthorized);
        }
        let id = row["id"].as_str().unwrap_or_default().to_owned();
        let now = now_seconds();
        if row.get("expires_at").and_then(Value::as_u64).unwrap_or(0) <= now {
            self.discard(&id).await?;
            return Ok(PollOutcome::Expired);
        }
        let last = row.get("last_poll_at").and_then(Value::as_u64).unwrap_or(0);
        self.context
            .adapter
            .update_where(
                TABLE,
                Query::new().eq("id", id.clone()),
                json!({"last_poll_at": now as i64}),
            )
            .await?;
        match row.get("status").and_then(Value::as_str) {
            Some("denied") => {
                self.discard(&id).await?;
                Ok(PollOutcome::AccessDenied)
            }
            Some("approved") => {
                // Redeem exactly once. Only the poller whose delete removes the
                // row receives the user.
                if self.discard(&id).await? == 1 {
                    let user_id = row["user_id"].as_str().unwrap_or_default().to_owned();
                    Ok(PollOutcome::Approved { user_id })
                } else {
                    Err(AuthError::Unauthorized)
                }
            }
            _ => {
                if last != 0 && now.saturating_sub(last) < POLL_INTERVAL_SECONDS {
                    Ok(PollOutcome::SlowDown)
                } else {
                    Ok(PollOutcome::Pending)
                }
            }
        }
    }

    /// Reports whether a user code is still awaiting a decision.
    pub async fn is_pending(&self, user_code: &str) -> Result<bool> {
        let Some(row) = self.find_by_user_code(user_code).await? else {
            return Ok(false);
        };
        Ok(row.get("status").and_then(Value::as_str) == Some("pending")
            && row.get("expires_at").and_then(Value::as_u64).unwrap_or(0) > now_seconds())
    }

    async fn find_by_user_code(&self, user_code: &str) -> Result<Option<Value>> {
        let normalized = normalize_user_code(user_code);
        if normalized.len() != 8 {
            return Ok(None);
        }
        self.context
            .adapter
            .find_one(TABLE, Query::new().eq("user_code", normalized))
            .await
    }

    async fn discard(&self, id: &str) -> Result<u64> {
        self.context
            .adapter
            .delete_where(TABLE, Query::new().eq("id", id.to_owned()))
            .await
    }
}

fn validate_client_id(client_id: &str) -> Result<()> {
    if (1..=64).contains(&client_id.len())
        && client_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Ok(())
    } else {
        Err(AuthError::InvalidRequest("client_id is invalid".into()))
    }
}

/// Accepts the code with or without the dash and in any letter case.
pub fn normalize_user_code(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase()
}

fn format_user_code(code: &str) -> String {
    format!("{}-{}", &code[..4], &code[4..])
}

fn random_user_code() -> String {
    let mut code = String::with_capacity(8);
    while code.len() < 8 {
        let mut byte = [0u8; 1];
        getrandom::getrandom(&mut byte).expect("operating system random source is unavailable");
        // Rejection sampling keeps the 30-symbol alphabet uniform (256 = 8 * 30 + 16).
        if usize::from(byte[0]) < USER_CODE_ALPHABET.len() * 8 {
            code.push(char::from(
                USER_CODE_ALPHABET[usize::from(byte[0]) % USER_CODE_ALPHABET.len()],
            ));
        }
    }
    code
}

fn random_string(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    getrandom::getrandom(&mut buffer).expect("operating system random source is unavailable");
    data_encoding::BASE32_NOPAD
        .encode(&buffer)
        .to_ascii_lowercase()
}

fn hash(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_codes_use_the_unambiguous_alphabet_and_normalize() {
        for _ in 0..100 {
            let code = random_user_code();
            assert_eq!(code.len(), 8);
            assert!(code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)));
        }
        assert_eq!(normalize_user_code("bcdf-ghjk"), "BCDFGHJK");
        assert_eq!(format_user_code("BCDFGHJK"), "BCDF-GHJK");
    }
}
