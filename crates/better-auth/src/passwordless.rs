//! Passwordless sign-in: magic links and one-time email codes.
//!
//! Both flows prove control of a mailbox, so a successful sign-in marks the
//! address as verified. Tokens are random and single use. Codes are stored only
//! as keyed hashes, and each code allows a bounded number of wrong attempts.

use crate::{
    context::AuthContext, cookies::SecretKeySet, email_password::User,
    verification::VerificationService,
};
use better_auth_core::{
    adapter::{DbOperation, Query, SecondaryStorage, StorageValue},
    error::{AuthError, Result},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use uuid::Uuid;

const USER_TABLE: &str = "user";
const ACCOUNT_TABLE: &str = "account";
const MAGIC_LINK_PURPOSE: &str = "magic-link";
pub const MAGIC_LINK_TTL: Duration = Duration::from_secs(5 * 60);
pub const EMAIL_OTP_TTL: Duration = Duration::from_secs(5 * 60);

/// What an emailed code is for. Each purpose has its own namespace, so a code
/// issued for one purpose cannot complete another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmailOtpPurpose {
    SignIn,
    EmailVerification,
    PasswordReset,
    EmailChange,
}

impl EmailOtpPurpose {
    /// Parses the `type` field of `POST /email-otp/send-verification-otp`.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "sign-in" => Ok(Self::SignIn),
            "email-verification" => Ok(Self::EmailVerification),
            "forget-password" => Ok(Self::PasswordReset),
            "email-change" => Ok(Self::EmailChange),
            _ => Err(AuthError::InvalidRequest(
                "type must be sign-in, email-verification, forget-password or email-change".into(),
            )),
        }
    }

    fn namespace(self) -> &'static str {
        match self {
            // Sign-in keeps the namespace of the original email code, so codes
            // already in flight keep working across the upgrade.
            Self::SignIn => "email",
            Self::EmailVerification => "email-verification",
            Self::PasswordReset => "forget-password",
            Self::EmailChange => "email-change",
        }
    }
}
pub const MAX_EMAIL_OTP_ATTEMPTS: u64 = 5;

#[derive(Clone)]
pub struct PasswordlessService {
    context: AuthContext,
    storage: Arc<dyn SecondaryStorage>,
    verification: VerificationService,
    key: [u8; 32],
}

impl PasswordlessService {
    pub fn new(context: AuthContext) -> Result<Self> {
        let storage = context.secondary_storage.clone().ok_or_else(|| {
            AuthError::InvalidConfiguration(
                "passwordless sign-in requires secondary storage".into(),
            )
        })?;
        let keys = SecretKeySet::from_options(&context.options)?;
        let material = keys
            .key_for_version(keys.current_version())
            .ok_or_else(|| AuthError::Crypto("current secret version is missing".into()))?;
        let mut hasher = Sha256::new();
        hasher.update(b"better-auth:passwordless\0");
        hasher.update(material);
        let key = hasher.finalize().into();
        Ok(Self {
            verification: VerificationService::new(storage.clone()),
            context,
            storage,
            key,
        })
    }

    /// Issues a magic-link token for `email`. The token is returned whether or
    /// not an account exists, so the caller's response cannot reveal that.
    pub async fn issue_magic_link(&self, email: &str) -> Result<String> {
        let email = normalize_email(email)?;
        self.verification
            .issue(MAGIC_LINK_PURPOSE, &email, MAGIC_LINK_TTL)
            .await
    }

    /// Consumes a magic-link token and returns the signed-in user. The account
    /// is created on first use.
    pub async fn consume_magic_link(&self, token: &str) -> Result<User> {
        let email = self
            .verification
            .consume(MAGIC_LINK_PURPOSE, token)
            .await?
            .ok_or(AuthError::Unauthorized)?;
        self.find_or_create_verified_user(&email).await
    }

    /// Issues a six-digit code for `email` and returns it for delivery. The
    /// code is kept only as a keyed hash.
    pub async fn issue_email_otp(&self, email: &str) -> Result<String> {
        let email = normalize_email(email)?;
        self.issue_otp("email", &email).await
    }

    /// Checks an emailed code. A correct code is consumed. A wrong code counts
    /// against the attempt limit.
    pub async fn verify_email_otp(&self, email: &str, code: &str) -> Result<User> {
        let email = normalize_email(email)?;
        if self.take_otp("email", &email, code).await? {
            return self.find_or_create_verified_user(&email).await;
        }
        Err(AuthError::Unauthorized)
    }

    /// Checks an emailed code without spending it. A correct code stays valid until its
    /// expiry or until it is consumed, and a wrong one counts against the attempt limit.
    /// Use this only where a second step consumes the code, because two requests can
    /// both pass the check.
    pub async fn check_purpose_otp(
        &self,
        purpose: EmailOtpPurpose,
        email: &str,
        code: &str,
    ) -> Result<bool> {
        let identifier = normalize_email(email)?;
        let namespace = purpose.namespace();
        let key = otp_key(namespace, &identifier);
        let Some(stored) = self.storage.get(&key).await? else {
            return Ok(false);
        };
        let record = stored.value;
        let expires_at = record
            .get("expires_at")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let stored_hash = record
            .get("hash")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let candidate = self.code_hash(&format!("{namespace}:{identifier}"), code);
        let matches = stored_hash.len() == candidate.len()
            && bool::from(stored_hash.as_bytes().ct_eq(candidate.as_bytes()));
        if expires_at > now_seconds() && matches {
            return Ok(true);
        }
        // A wrong guess is recorded exactly as a failed consume would record it.
        self.take_otp(namespace, &identifier, code).await?;
        Ok(false)
    }

    /// Issues an emailed code for `purpose` and returns it for delivery.
    pub async fn issue_purpose_otp(&self, purpose: EmailOtpPurpose, email: &str) -> Result<String> {
        let email = normalize_email(email)?;
        self.issue_otp(purpose.namespace(), &email).await
    }

    /// Consumes an emailed code issued for `purpose`. A code issued for one purpose
    /// is never accepted for another.
    pub async fn take_purpose_otp(
        &self,
        purpose: EmailOtpPurpose,
        email: &str,
        code: &str,
    ) -> Result<bool> {
        let email = normalize_email(email)?;
        self.take_otp(purpose.namespace(), &email, code).await
    }

    /// Issues a one-time code for `identifier` in `namespace` and returns it for delivery.
    /// Only a keyed hash is stored, with the attempt count and expiry.
    pub(crate) async fn issue_otp(&self, namespace: &str, identifier: &str) -> Result<String> {
        let code = random_code();
        self.storage
            .set(
                &otp_key(namespace, identifier),
                StorageValue::with_ttl(
                    json!({
                        "hash": self.code_hash(&format!("{namespace}:{identifier}"), &code),
                        "attempts": 0,
                        "expires_at": now_seconds() + EMAIL_OTP_TTL.as_secs(),
                    }),
                    EMAIL_OTP_TTL,
                ),
            )
            .await?;
        Ok(code)
    }

    /// Returns `true` and consumes the code when it matches. A wrong code counts
    /// against the attempt limit, and the code is discarded when the limit is reached.
    pub(crate) async fn take_otp(
        &self,
        namespace: &str,
        identifier: &str,
        code: &str,
    ) -> Result<bool> {
        let key = otp_key(namespace, identifier);
        // Taking the record atomically means concurrent guesses cannot all
        // consume the same attempt.
        let Some(stored_value) = self.storage.get_and_delete(&key).await? else {
            return Ok(false);
        };
        let record = stored_value.value;
        let expires_at = record
            .get("expires_at")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let attempts = record.get("attempts").and_then(Value::as_u64).unwrap_or(0);
        let stored = record
            .get("hash")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let now = now_seconds();
        let candidate = self.code_hash(&format!("{namespace}:{identifier}"), code);
        let matches = stored.len() == candidate.len()
            && bool::from(stored.as_bytes().ct_eq(candidate.as_bytes()));
        if expires_at > now && matches {
            return Ok(true);
        }
        let attempts = attempts + 1;
        if attempts < MAX_EMAIL_OTP_ATTEMPTS && expires_at > now {
            self.storage
                .set(
                    &key,
                    StorageValue::with_ttl(
                        json!({"hash": stored, "attempts": attempts, "expires_at": expires_at}),
                        Duration::from_secs(expires_at - now),
                    ),
                )
                .await?;
        }
        Ok(false)
    }

    fn code_hash(&self, email: &str, code: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.key);
        hasher.update(email.as_bytes());
        hasher.update([0u8]);
        hasher.update(code.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Returns the account for `email`, creating it when absent. Passwordless
    /// proof of the mailbox marks the address as verified.
    /// Issues an SMS code for `phone` (normalized to E.164) and returns it for delivery.
    pub async fn issue_phone_otp(&self, phone: &str) -> Result<String> {
        let phone = crate::phone::normalize_phone(phone)?;
        self.issue_otp("phone", &phone).await
    }

    /// Checks an SMS code and returns the account for that number, creating it on first use.
    pub async fn verify_phone_otp(&self, phone: &str, code: &str) -> Result<User> {
        let phone = crate::phone::normalize_phone(phone)?;
        if !self.take_otp("phone", &phone, code).await? {
            return Err(AuthError::Unauthorized);
        }
        let adapter = &self.context.adapter;
        if let Some(value) = adapter
            .find_one(USER_TABLE, Query::new().eq("phone_number", phone.clone()))
            .await?
        {
            return serde_json::from_value(value).map_err(|e| AuthError::Adapter(e.to_string()));
        }
        // A number never matches an account by email. It belongs only to the
        // account that holds it, and the account's email is synthetic.
        let digits: String = phone.chars().filter(char::is_ascii_digit).collect();
        let user = User {
            id: Uuid::new_v4().to_string(),
            email: format!("phone-{digits}@phone.invalid"),
            name: phone.clone(),
            email_verified: false,
            image: None,
            additional_fields: serde_json::Map::new(),
        };
        let mut record =
            serde_json::to_value(&user).map_err(|e| AuthError::Adapter(e.to_string()))?;
        record["phone_number"] = json!(phone);
        record["phone_number_verified"] = json!(true);
        adapter
            .transaction(vec![DbOperation::InsertRecord {
                table: USER_TABLE.into(),
                record,
            }])
            .await?;
        Ok(user)
    }

    /// Returns the account for a mailbox that the caller has just proven.
    pub(crate) async fn sign_in_verified_email(&self, email: &str) -> Result<User> {
        self.find_or_create_verified_user(email).await
    }

    async fn find_or_create_verified_user(&self, email: &str) -> Result<User> {
        let adapter = &self.context.adapter;
        if let Some(value) = adapter
            .find_one(USER_TABLE, Query::new().eq("email", email.to_owned()))
            .await?
        {
            let mut user: User = serde_json::from_value(value)
                .map_err(|error| AuthError::Adapter(error.to_string()))?;
            if !user.email_verified {
                // The mailbox is now proven, but a password set before the proof
                // may belong to someone else. Remove it, and end any sessions it
                // created, before the account is marked verified.
                adapter
                    .transaction(vec![
                        DbOperation::DeleteWhere {
                            table: ACCOUNT_TABLE.into(),
                            query: Query::new().eq("id", format!("{}:credential", user.id)),
                        },
                        DbOperation::DeleteWhere {
                            table: "session".into(),
                            query: Query::new().eq("user_id", user.id.clone()),
                        },
                        DbOperation::UpdateWhere {
                            table: USER_TABLE.into(),
                            query: Query::new().eq("id", user.id.clone()),
                            changes: json!({"email_verified": true}),
                        },
                    ])
                    .await?;
                user.email_verified = true;
            }
            return Ok(user);
        }
        let name: String = email
            .split('@')
            .next()
            .unwrap_or("User")
            .chars()
            .take(200)
            .collect();
        let mut user = User {
            id: Uuid::new_v4().to_string(),
            email: email.to_owned(),
            name: if name.is_empty() { "User".into() } else { name },
            email_verified: true,
            image: None,
            additional_fields: serde_json::Map::new(),
        };
        self.context.before_user_create(&mut user).await?;
        let record =
            serde_json::to_value(&user).map_err(|error| AuthError::Adapter(error.to_string()))?;
        if let Err(error) = adapter
            .transaction(vec![DbOperation::InsertRecord {
                table: USER_TABLE.into(),
                record,
            }])
            .await
        {
            // A concurrent first sign-in may have created the account. Prefer
            // the stored account; otherwise report the original failure.
            if let Some(value) = adapter
                .find_one(USER_TABLE, Query::new().eq("email", email.to_owned()))
                .await?
            {
                return serde_json::from_value(value)
                    .map_err(|e| AuthError::Adapter(e.to_string()));
            }
            return Err(error);
        }
        if let Err(error) = self.context.after_user_create(&user).await {
            let _ = adapter
                .transaction(vec![DbOperation::DeleteWhere {
                    table: USER_TABLE.into(),
                    query: Query::new().eq("id", user.id.clone()),
                }])
                .await;
            return Err(error);
        }
        Ok(user)
    }
}

fn otp_key(namespace: &str, identifier: &str) -> String {
    let digest = Sha256::digest(format!("{namespace}:{identifier}").as_bytes());
    format!(
        "otp:{namespace}:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn normalize_email(email: &str) -> Result<String> {
    let normalized = email.trim().to_ascii_lowercase();
    let valid = normalized.len() >= 3
        && normalized.len() <= 320
        && normalized.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        });
    if valid {
        Ok(normalized)
    } else {
        Err(AuthError::InvalidRequest("email is invalid".into()))
    }
}

/// Six decimal digits from the OS RNG, using rejection sampling to avoid bias.
fn random_code() -> String {
    const LIMIT: u32 = u32::MAX - (u32::MAX % 1_000_000);
    loop {
        let mut bytes = [0u8; 4];
        getrandom::getrandom(&mut bytes).expect("operating system random source is unavailable");
        let value = u32::from_be_bytes(bytes);
        if value < LIMIT {
            return format!("{:06}", value % 1_000_000);
        }
    }
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
    fn codes_are_six_digits() {
        for _ in 0..200 {
            let code = random_code();
            assert_eq!(code.len(), 6);
            assert!(code.bytes().all(|b| b.is_ascii_digit()));
        }
    }
}
