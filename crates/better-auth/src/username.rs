//! Usernames: case-insensitive, unique, and usable for password sign-in.
//!
//! Usernames are stored in normalized (lowercase) form. The unique index on the
//! normalized value is the authority. The read check only gives a friendlier
//! error, and a lost race maps to the same "taken" answer.

use crate::{context::AuthContext, email_password::User};
use better_auth_core::{
    adapter::Query,
    error::{AuthError, Result},
};
use serde_json::json;

const USER_TABLE: &str = "user";
const MIN_LENGTH: usize = 3;
const MAX_LENGTH: usize = 30;

/// Lowercases and validates a username. Allowed: ASCII letters, digits, `_`
/// and `.`, starting with a letter or digit.
pub fn normalize_username(input: &str) -> Result<String> {
    let normalized = input.trim().to_ascii_lowercase();
    let length = normalized.len();
    let valid_chars = normalized
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.');
    let starts_well = normalized
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if (MIN_LENGTH..=MAX_LENGTH).contains(&length) && valid_chars && starts_well {
        Ok(normalized)
    } else {
        Err(AuthError::InvalidRequest(
            "username must be 3-30 characters: letters, digits, '_' or '.', starting with a letter or digit".into(),
        ))
    }
}

#[derive(Clone)]
pub struct UsernameService {
    context: AuthContext,
}

impl UsernameService {
    pub fn new(context: AuthContext) -> Self {
        Self { context }
    }

    /// Sets the username of `user_id` and returns the normalized value.
    pub async fn set(&self, user_id: &str, username: &str) -> Result<String> {
        let normalized = normalize_username(username)?;
        if self.taken_by_other(&normalized, user_id).await? {
            return Err(taken());
        }
        match self
            .context
            .adapter
            .update_where(
                USER_TABLE,
                Query::new().eq("id", user_id.to_owned()),
                json!({"username": normalized}),
            )
            .await
        {
            Ok(_) => Ok(normalized),
            Err(error) => {
                if self.taken_by_other(&normalized, user_id).await? {
                    Err(taken())
                } else {
                    Err(error)
                }
            }
        }
    }

    /// Finds the user with this username. Input is normalized first, so the
    /// lookup is case-insensitive.
    pub async fn find_user(&self, username: &str) -> Result<Option<User>> {
        let Ok(normalized) = normalize_username(username) else {
            return Ok(None);
        };
        self.context
            .adapter
            .find_one(USER_TABLE, Query::new().eq("username", normalized))
            .await?
            .map(|value| {
                serde_json::from_value(value).map_err(|error| AuthError::Adapter(error.to_string()))
            })
            .transpose()
    }

    async fn taken_by_other(&self, normalized: &str, user_id: &str) -> Result<bool> {
        Ok(self
            .context
            .adapter
            .find_one(
                USER_TABLE,
                Query::new().eq("username", normalized.to_owned()),
            )
            .await?
            .is_some_and(|value| {
                value.get("id").and_then(serde_json::Value::as_str) != Some(user_id)
            }))
    }
}

fn taken() -> AuthError {
    AuthError::InvalidRequest("username is already taken".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_are_normalized_and_validated() {
        assert_eq!(normalize_username("  Alice_01 ").unwrap(), "alice_01");
        assert!(normalize_username("ab").is_err());
        assert!(normalize_username("_leading").is_err());
        assert!(normalize_username("has space").is_err());
        assert!(normalize_username("unicode-é").is_err());
        assert!(normalize_username(&"a".repeat(31)).is_err());
    }
}
