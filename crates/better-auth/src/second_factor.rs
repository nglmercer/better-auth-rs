//! Second-factor enrollment, sign-in challenges and single-use codes.
//!
//! Secrets are encrypted at rest. Each TOTP time step and each backup code
//! can be accepted only once, which is enforced with an atomic counter in
//! secondary storage. Challenges are single use and allow a bounded number of
//! wrong codes. Without secondary storage, the service refuses to start, so
//! there is no path that skips these guarantees.

use crate::{
    context::AuthContext,
    cookies::SecretKeySet,
    email_password::User,
    plugins::{build_otpauth_url, generate_totp_secret, totp_code},
};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use better_auth_core::{
    adapter::{Query, SecondaryStorage, StorageValue},
    error::{AuthError, Result},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use uuid::Uuid;

const TWO_FACTOR_TABLE: &str = "two_factor";
const TOTP_STEP_SECONDS: u64 = 30;
const TOTP_DIGITS: u32 = 6;
/// Accepts one step before and after the current one for clock drift.
const TOTP_WINDOW_STEPS: i64 = 1;
const BACKUP_CODE_COUNT: usize = 10;
const CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_CHALLENGE_ATTEMPTS: u64 = 5;
/// Used-code markers must outlive every code they guard, so they are kept long.
const USED_MARKER_TTL: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);
const ISSUER: &str = "Better Auth";

/// Returned once at enrollment. The secret and backup codes are never shown
/// again, so the caller must show them to the user now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentStart {
    pub secret: String,
    pub totp_uri: String,
    pub backup_codes: Vec<String>,
}

#[derive(Clone)]
pub struct SecondFactorService {
    context: AuthContext,
    storage: Arc<dyn SecondaryStorage>,
    key: [u8; 32],
}

impl SecondFactorService {
    pub fn new(context: AuthContext) -> Result<Self> {
        let storage = context.secondary_storage.clone().ok_or_else(|| {
            AuthError::InvalidConfiguration("two-factor requires secondary storage".into())
        })?;
        let keys = SecretKeySet::from_options(&context.options)?;
        let material = keys
            .key_for_version(keys.current_version())
            .ok_or_else(|| AuthError::Crypto("current secret version is missing".into()))?;
        let mut hasher = Sha256::new();
        hasher.update(b"better-auth:two-factor-secret\0");
        hasher.update(material);
        let key: [u8; 32] = hasher.finalize().into();
        Ok(Self {
            context,
            storage,
            key,
        })
    }

    /// Starts enrollment. Any pending enrollment for the user is replaced, and
    /// an enabled second factor must be disabled first.
    pub async fn begin_enrollment(&self, user: &User) -> Result<EnrollmentStart> {
        if self.enabled_record(&user.id).await?.is_some() {
            return Err(AuthError::Forbidden(
                "two-factor authentication is already enabled".into(),
            ));
        }
        let totp = generate_totp_secret(&user.email, ISSUER);
        let backup_codes = new_backup_codes();
        let hashes: Vec<String> = backup_codes.iter().map(|code| hash_code(code)).collect();
        let adapter = &self.context.adapter;
        adapter
            .delete_where(
                TWO_FACTOR_TABLE,
                Query::new().eq("user_id", user.id.clone()),
            )
            .await?;
        adapter
            .insert_record(
                TWO_FACTOR_TABLE,
                json!({
                    "id": Uuid::new_v4().to_string(),
                    "user_id": user.id,
                    "secret": self.seal(&totp.secret)?,
                    "enabled": false,
                    "backup_codes": hashes,
                }),
            )
            .await?;
        Ok(EnrollmentStart {
            secret: totp.secret,
            totp_uri: totp.otpauth_url,
            backup_codes,
        })
    }

    /// Enables the second factor once the user proves that the authenticator
    /// produces valid codes.
    pub async fn confirm_enrollment(&self, user_id: &str, code: &str) -> Result<()> {
        let record = self
            .pending_record(user_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        let secret = self.open(&record)?;
        if !self.accept_totp(user_id, &secret, code).await? {
            return Err(AuthError::Unauthorized);
        }
        self.context
            .adapter
            .update_where(
                TWO_FACTOR_TABLE,
                Query::new().eq("user_id", user_id.to_owned()),
                json!({"enabled": true}),
            )
            .await?;
        Ok(())
    }

    /// The authenticator URI for an enabled second factor, rebuilt from the stored
    /// secret. Fails when no second factor is enabled.
    pub async fn totp_uri(&self, user: &User) -> Result<String> {
        let record = self
            .enabled_record(&user.id)
            .await?
            .ok_or(AuthError::NotFound)?;
        let secret = self.open(&record)?;
        Ok(build_otpauth_url(&user.email, ISSUER, &secret))
    }

    /// Replaces the backup codes of an enabled second factor. The old codes stop
    /// working as soon as this returns, because only the new hashes are stored.
    pub async fn regenerate_backup_codes(&self, user_id: &str) -> Result<Vec<String>> {
        self.enabled_record(user_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        let codes = new_backup_codes();
        let hashes: Vec<String> = codes.iter().map(|code| hash_code(code)).collect();
        self.context
            .adapter
            .update_where(
                TWO_FACTOR_TABLE,
                Query::new().eq("user_id", user_id.to_owned()),
                json!({"backup_codes": hashes}),
            )
            .await?;
        Ok(codes)
    }

    /// Removes the second factor. The caller must re-verify the password first.
    pub async fn disable(&self, user_id: &str) -> Result<()> {
        self.context
            .adapter
            .delete_where(
                TWO_FACTOR_TABLE,
                Query::new().eq("user_id", user_id.to_owned()),
            )
            .await?;
        Ok(())
    }

    /// Opens a sign-in challenge after the password was accepted. The token is
    /// random, and only its hash is stored.
    pub async fn create_challenge(&self, user_id: &str) -> Result<String> {
        let token = random_token();
        let expires_at = now_seconds() + CHALLENGE_TTL.as_secs();
        self.storage
            .set(
                &challenge_key(&token),
                StorageValue::with_ttl(
                    json!({"user_id": user_id, "attempts": 0, "expires_at": expires_at}),
                    CHALLENGE_TTL,
                ),
            )
            .await?;
        Ok(token)
    }

    /// Completes a challenge with a TOTP or backup code and returns the user
    /// id. The challenge is consumed atomically. A wrong code counts against
    /// it, and the fifth wrong code ends it.
    pub async fn complete_challenge(&self, token: &str, code: &str) -> Result<String> {
        let key = challenge_key(token);
        let record = self
            .storage
            .get_and_delete(&key)
            .await?
            .ok_or(AuthError::Unauthorized)?
            .value;
        let user_id = record
            .get("user_id")
            .and_then(Value::as_str)
            .ok_or(AuthError::Unauthorized)?
            .to_owned();
        let attempts = record.get("attempts").and_then(Value::as_u64).unwrap_or(0);
        let expires_at = record
            .get("expires_at")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if self.verify_second_factor(&user_id, code).await? {
            return Ok(user_id);
        }
        let attempts = attempts + 1;
        let now = now_seconds();
        if attempts < MAX_CHALLENGE_ATTEMPTS && expires_at > now {
            self.storage
                .set(
                    &key,
                    StorageValue::with_ttl(
                        json!({"user_id": user_id, "attempts": attempts, "expires_at": expires_at}),
                        Duration::from_secs(expires_at - now),
                    ),
                )
                .await?;
        }
        Err(AuthError::Unauthorized)
    }

    async fn verify_second_factor(&self, user_id: &str, code: &str) -> Result<bool> {
        let Some(record) = self.enabled_record(user_id).await? else {
            return Ok(false);
        };
        let secret = self.open(&record)?;
        if self.accept_totp(user_id, &secret, code).await? {
            return Ok(true);
        }
        self.accept_backup_code(user_id, &record, code).await
    }

    /// Accepts a TOTP code once per time step. The first use of a step claims
    /// it atomically, so a replayed code inside its window is refused.
    async fn accept_totp(&self, user_id: &str, secret: &str, code: &str) -> Result<bool> {
        let Some(step) = matching_step(secret, code.trim(), now_seconds())? else {
            return Ok(false);
        };
        let claimed = self
            .storage
            .increment(&format!("2fa:totp:{user_id}:{step}"), 1, USED_MARKER_TTL)
            .await?;
        Ok(claimed == 1)
    }

    async fn accept_backup_code(&self, user_id: &str, record: &Value, code: &str) -> Result<bool> {
        let normalized = normalize_backup_code(code);
        let hash = hash_code(&normalized);
        let listed = record
            .get("backup_codes")
            .and_then(Value::as_array)
            .is_some_and(|codes| codes.iter().any(|stored| stored.as_str() == Some(&hash)));
        if !listed {
            return Ok(false);
        }
        // A backup code is spent by its first atomic claim, not by a read.
        let claimed = self
            .storage
            .increment(&format!("2fa:backup:{user_id}:{hash}"), 1, USED_MARKER_TTL)
            .await?;
        Ok(claimed == 1)
    }

    async fn enabled_record(&self, user_id: &str) -> Result<Option<Value>> {
        Ok(self
            .context
            .adapter
            .find_one(
                TWO_FACTOR_TABLE,
                Query::new().eq("user_id", user_id.to_owned()),
            )
            .await?
            .filter(|record| record.get("enabled").and_then(Value::as_bool) == Some(true)))
    }

    async fn pending_record(&self, user_id: &str) -> Result<Option<Value>> {
        Ok(self
            .context
            .adapter
            .find_one(
                TWO_FACTOR_TABLE,
                Query::new().eq("user_id", user_id.to_owned()),
            )
            .await?
            .filter(|record| record.get("enabled").and_then(Value::as_bool) != Some(true)))
    }

    fn seal(&self, secret: &str) -> Result<String> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce)
            .map_err(|error| AuthError::Crypto(format!("random source failed: {error}")))?;
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| AuthError::Crypto("invalid encryption key".into()))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), secret.as_bytes())
            .map_err(|_| AuthError::Crypto("secret encryption failed".into()))?;
        let mut envelope = nonce.to_vec();
        envelope.extend_from_slice(&ciphertext);
        Ok(URL_SAFE_NO_PAD.encode(envelope))
    }

    fn open(&self, record: &Value) -> Result<String> {
        let envelope = record
            .get("secret")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::Crypto("two-factor record has no secret".into()))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(envelope)
            .map_err(|_| AuthError::Crypto("two-factor secret is malformed".into()))?;
        if bytes.len() < 12 {
            return Err(AuthError::Crypto("two-factor secret is malformed".into()));
        }
        let (nonce, ciphertext) = bytes.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| AuthError::Crypto("invalid encryption key".into()))?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| AuthError::Crypto("two-factor secret failed authentication".into()))?;
        String::from_utf8(plaintext)
            .map_err(|_| AuthError::Crypto("two-factor secret is not text".into()))
    }
}

/// Returns the TOTP time step that matches `code` within the drift window.
fn matching_step(secret: &str, code: &str, now: u64) -> Result<Option<u64>> {
    if code.len() != TOTP_DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(None);
    }
    let current = (now / TOTP_STEP_SECONDS) as i64;
    for delta in -TOTP_WINDOW_STEPS..=TOTP_WINDOW_STEPS {
        let step = current + delta;
        if step < 0 {
            continue;
        }
        let step = step as u64;
        let candidate = totp_code(
            secret,
            step * TOTP_STEP_SECONDS,
            TOTP_STEP_SECONDS,
            TOTP_DIGITS,
        )?;
        // Constant-time comparison: the code is a guessable secret for the window.
        if bool::from(candidate.as_bytes().ct_eq(code.as_bytes())) {
            return Ok(Some(step));
        }
    }
    Ok(None)
}

fn new_backup_codes() -> Vec<String> {
    (0..BACKUP_CODE_COUNT)
        .map(|_| {
            let bytes = random_bytes::<10>();
            // 10 random bytes give 80 bits, shown as 16 base32 characters.
            let encoded = data_encoding::BASE32_NOPAD.encode(&bytes);
            format!("{}-{}", &encoded[..8], &encoded[8..16])
        })
        .collect()
}

fn normalize_backup_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase()
}

fn hash_code(code: &str) -> String {
    let digest = Sha256::digest(normalize_backup_code(code).as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn challenge_key(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    format!(
        "2fa:challenge:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).expect("operating system random source is unavailable");
    bytes
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
    fn backup_codes_are_unique_and_wide() {
        let codes = new_backup_codes();
        assert_eq!(codes.len(), BACKUP_CODE_COUNT);
        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), BACKUP_CODE_COUNT);
        assert!(codes.iter().all(|code| code.len() == 17));
    }

    #[test]
    fn backup_code_matching_ignores_case_and_separators() {
        assert_eq!(hash_code("abcd-efgh"), hash_code("ABCDEFGH"));
        assert_ne!(hash_code("abcd-efgh"), hash_code("abcd-efgj"));
    }

    #[test]
    fn totp_matching_accepts_only_the_window_and_reports_the_step() {
        let secret = data_encoding::BASE32_NOPAD.encode(b"12345678901234567890");
        let now = 59;
        assert_eq!(matching_step(&secret, "287082", now).unwrap(), Some(1));
        assert_eq!(matching_step(&secret, "000000", now).unwrap(), None);
        assert_eq!(matching_step(&secret, "28708", now).unwrap(), None);
        assert_eq!(matching_step(&secret, "28708a", now).unwrap(), None);
    }
}
