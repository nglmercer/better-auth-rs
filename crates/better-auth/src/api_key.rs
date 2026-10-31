//! API keys for server-to-server access, owned by a user.
//!
//! A key looks like `ba_<prefix>_<secret>`. The prefix is stored in clear for
//! lookup. The secret is stored only as a keyed hash, so a database leak does
//! not reveal usable keys. The plaintext is returned once, at creation.
//!
//! Keys carry scopes, an optional expiry and a revocation flag. Every
//! authentication checks all three, in constant time for the secret.

use crate::{context::AuthContext, cookies::SecretKeySet};
use better_auth_core::{
    adapter::{Query, SecondaryStorage},
    error::{AuthError, Result},
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use subtle::ConstantTimeEq;

const TABLE: &str = "api_key";
const PREFIX_BYTES: usize = 9;
const SECRET_BYTES: usize = 24;
const MAX_SCOPES: usize = 20;
const MAX_NAME: usize = 100;

/// Public view of a key. It never contains the secret or its hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ApiKeyView {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<u64>,
    pub revoked: bool,
    pub created_at: u64,
}

/// Result of a successful authentication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedKey {
    pub user_id: String,
    pub key_id: String,
    pub scopes: Vec<String>,
}

/// A newly created key. `key` is shown once and cannot be recovered later.
#[derive(Clone, Debug)]
pub struct CreatedApiKey {
    pub key: String,
    pub view: ApiKeyView,
}

#[derive(Clone)]
pub struct ApiKeyService {
    context: AuthContext,
    storage: Option<Arc<dyn SecondaryStorage>>,
    material: Vec<u8>,
}

impl ApiKeyService {
    pub fn new(context: AuthContext) -> Result<Self> {
        let keys = SecretKeySet::from_options(&context.options)?;
        let material = keys
            .key_for_version(keys.current_version())
            .ok_or_else(|| AuthError::Crypto("current secret version is missing".into()))?
            .to_vec();
        Ok(Self {
            storage: context.secondary_storage.clone(),
            context,
            material,
        })
    }

    pub async fn create(
        &self,
        user_id: &str,
        name: &str,
        scopes: &[String],
        expires_in: Option<Duration>,
    ) -> Result<CreatedApiKey> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_NAME {
            return Err(AuthError::InvalidRequest(
                "name must be 1-100 characters".into(),
            ));
        }
        validate_scopes(scopes)?;
        let prefix = random_token(PREFIX_BYTES);
        let secret = random_token(SECRET_BYTES);
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_seconds();
        let expires_at = expires_in.map(|ttl| now + ttl.as_secs());
        let view = ApiKeyView {
            id: id.clone(),
            name: name.to_owned(),
            prefix: prefix.clone(),
            scopes: scopes.to_vec(),
            expires_at,
            revoked: false,
            created_at: now,
        };
        self.context
            .adapter
            .insert_record(
                TABLE,
                json!({
                    "id": id,
                    "user_id": user_id,
                    "name": view.name,
                    "prefix": prefix,
                    "key_hash": self.hash(&secret),
                    "scopes": scopes,
                    "expires_at": expires_at.map(|value| value as i64).unwrap_or(0),
                    "has_expiry": expires_at.is_some(),
                    "revoked": false,
                    "created_at": now,
                }),
            )
            .await?;
        Ok(CreatedApiKey {
            key: format!("ba_{prefix}_{secret}"),
            view,
        })
    }

    pub async fn list(&self, user_id: &str) -> Result<Vec<ApiKeyView>> {
        let rows = self
            .context
            .adapter
            .find_many(TABLE, Query::new().eq("user_id", user_id.to_owned()))
            .await?;
        Ok(rows.iter().filter_map(view_from_row).collect())
    }

    /// Revokes one of the user's keys. Other users' keys are reported as not found.
    pub async fn revoke(&self, user_id: &str, key_id: &str) -> Result<bool> {
        let changed = self
            .context
            .adapter
            .update_where(
                TABLE,
                Query::new()
                    .eq("id", key_id.to_owned())
                    .eq("user_id", user_id.to_owned()),
                json!({"revoked": true}),
            )
            .await?;
        Ok(changed > 0)
    }

    /// Checks a presented key and its scope. Usage is counted in secondary
    /// storage when it is configured.
    pub async fn authenticate(
        &self,
        presented: &str,
        required_scope: Option<&str>,
    ) -> Result<AuthenticatedKey> {
        let (prefix, secret) = parse_key(presented).ok_or(AuthError::Unauthorized)?;
        let row = self
            .context
            .adapter
            .find_one(TABLE, Query::new().eq("prefix", prefix.to_owned()))
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let stored = row
            .get("key_hash")
            .and_then(Value::as_str)
            .ok_or(AuthError::Unauthorized)?;
        let candidate = self.hash(secret);
        let matches = stored.len() == candidate.len()
            && bool::from(stored.as_bytes().ct_eq(candidate.as_bytes()));
        if !matches || row.get("revoked").and_then(Value::as_bool) != Some(false) {
            return Err(AuthError::Unauthorized);
        }
        let has_expiry = row
            .get("has_expiry")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if has_expiry {
            let expires_at = row.get("expires_at").and_then(Value::as_u64).unwrap_or(0);
            if expires_at <= now_seconds() {
                return Err(AuthError::Unauthorized);
            }
        }
        let key_id = row
            .get("id")
            .and_then(Value::as_str)
            .ok_or(AuthError::Unauthorized)?
            .to_owned();
        let scopes: Vec<String> = row
            .get("scopes")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(scope) = required_scope {
            if !scopes.iter().any(|granted| granted == scope) {
                return Err(AuthError::Forbidden(
                    "API key lacks the required scope".into(),
                ));
            }
        }
        if let Some(storage) = &self.storage {
            let _ = storage
                .increment(
                    &format!("api-key:uses:{key_id}"),
                    1,
                    Duration::from_secs(365 * 24 * 3600),
                )
                .await?;
        }
        let user_id = row
            .get("user_id")
            .and_then(Value::as_str)
            .ok_or(AuthError::Unauthorized)?
            .to_owned();
        Ok(AuthenticatedKey {
            user_id,
            key_id,
            scopes,
        })
    }

    fn hash(&self, secret: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"better-auth:api-key\0");
        hasher.update(&self.material);
        hasher.update(secret.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

fn view_from_row(row: &Value) -> Option<ApiKeyView> {
    let has_expiry = row
        .get("has_expiry")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Some(ApiKeyView {
        id: row.get("id")?.as_str()?.to_owned(),
        name: row.get("name")?.as_str()?.to_owned(),
        prefix: row.get("prefix")?.as_str()?.to_owned(),
        scopes: row
            .get("scopes")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        expires_at: has_expiry
            .then(|| row.get("expires_at").and_then(Value::as_u64))
            .flatten(),
        revoked: row.get("revoked").and_then(Value::as_bool).unwrap_or(false),
        created_at: row.get("created_at").and_then(Value::as_u64).unwrap_or(0),
    })
}

fn parse_key(presented: &str) -> Option<(&str, &str)> {
    let rest = presented.strip_prefix("ba_")?;
    let (prefix, secret) = rest.split_once('_')?;
    (!prefix.is_empty() && !secret.is_empty()).then_some((prefix, secret))
}

fn validate_scopes(scopes: &[String]) -> Result<()> {
    if scopes.len() > MAX_SCOPES {
        return Err(AuthError::InvalidRequest("too many scopes".into()));
    }
    for scope in scopes {
        let valid = (1..=64).contains(&scope.len())
            && scope.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b':' | b'_' | b'-')
            });
        if !valid {
            return Err(AuthError::InvalidRequest(format!(
                "invalid scope {scope:?}"
            )));
        }
    }
    Ok(())
}

fn random_token(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    getrandom::getrandom(&mut buffer).expect("operating system random source is unavailable");
    data_encoding::BASE32_NOPAD
        .encode(&buffer)
        .to_ascii_lowercase()
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
    fn key_format_round_trips_and_rejects_malformed_input() {
        assert_eq!(parse_key("ba_abc_def"), Some(("abc", "def")));
        assert_eq!(parse_key("xx_abc_def"), None);
        assert_eq!(parse_key("ba_abc"), None);
        assert_eq!(parse_key("ba__def"), None);
    }

    #[test]
    fn scopes_are_validated() {
        assert!(validate_scopes(&["orders:read".into(), "a_b-c".into()]).is_ok());
        assert!(validate_scopes(&["Orders:Read".into()]).is_err());
        assert!(validate_scopes(&["x".repeat(65)]).is_err());
    }
}
