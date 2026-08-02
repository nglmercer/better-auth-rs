use super::shared::{endpoint, hash_secret, required, urlencoding};
use better_auth_core::{
    error::{AuthError, Result},
    plugin::{Endpoint, Plugin},
    schema::{FieldType, SchemaExtension, TableSchema},
};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use http::Method;
use sha1::Sha1;
use std::collections::BTreeSet;
use uuid::Uuid;

type HmacSha1 = Hmac<Sha1>;

#[derive(Clone, Copy, Debug, Default)]
pub struct TwoFactorPlugin;

impl Plugin for TwoFactorPlugin {
    fn name(&self) -> &'static str {
        "two-factor"
    }
    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(
                Method::POST,
                "/two-factor/enable",
                "Enable TOTP two-factor authentication",
            ),
            endpoint(
                Method::POST,
                "/two-factor/verify",
                "Verify a TOTP or backup code",
            ),
            endpoint(
                Method::POST,
                "/two-factor/disable",
                "Disable two-factor authentication",
            ),
        ]
    }
    fn schema(&self) -> SchemaExtension {
        SchemaExtension::default().table(
            "two_factor",
            TableSchema::default()
                .field("id", required(FieldType::String).unique())
                .field("user_id", required(FieldType::String).unique())
                .field("secret", required(FieldType::String))
                .field("enabled", required(FieldType::Boolean))
                .field("backup_codes", required(FieldType::Json)),
        )
    }
    fn error_codes(&self) -> std::collections::BTreeMap<String, String> {
        [(
            "TWO_FACTOR_REQUIRED".into(),
            "two-factor verification required".into(),
        )]
        .into_iter()
        .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpSecret {
    pub secret: String,
    pub otpauth_url: String,
}

pub fn generate_totp_secret(account_name: &str, issuer: &str) -> TotpSecret {
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let mut bytes = Vec::with_capacity(20);
    bytes.extend_from_slice(first.as_bytes());
    bytes.extend_from_slice(&second.as_bytes()[..4]);
    let secret = BASE32_NOPAD.encode(&bytes);
    let otpauth_url = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}",
        urlencoding(account_name),
        urlencoding(issuer),
        secret,
        urlencoding(issuer)
    );
    TotpSecret {
        secret,
        otpauth_url,
    }
}

pub fn totp_code(
    secret: &str,
    unix_seconds: u64,
    step_seconds: u64,
    digits: u32,
) -> Result<String> {
    if !(4..=10).contains(&digits) || step_seconds == 0 {
        return Err(AuthError::InvalidConfiguration(
            "invalid TOTP parameters".into(),
        ));
    }
    let key = BASE32_NOPAD
        .decode(secret.as_bytes())
        .map_err(|_| AuthError::InvalidRequest("invalid TOTP secret".into()))?;
    let counter = unix_seconds / step_seconds;
    let mut mac = <HmacSha1 as Mac>::new_from_slice(&key)
        .map_err(|_| AuthError::Crypto("invalid TOTP key".into()))?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulo = 10_u32.pow(digits);
    Ok(format!(
        "{:0width$}",
        binary % modulo,
        width = digits as usize
    ))
}

pub fn verify_totp(
    secret: &str,
    code: &str,
    unix_seconds: u64,
    step_seconds: u64,
    window: i8,
) -> Result<bool> {
    if !(0..=5).contains(&window) {
        return Err(AuthError::InvalidConfiguration(
            "invalid TOTP window".into(),
        ));
    }
    let window = window as u64;
    for offset in 0..=(window * 2) {
        let delta = offset as i64 - window as i64;
        let timestamp = if delta.is_negative() {
            unix_seconds.saturating_sub(delta.unsigned_abs() * step_seconds)
        } else {
            unix_seconds.saturating_add(delta as u64 * step_seconds)
        };
        if totp_code(secret, timestamp, step_seconds, code.len() as u32)?.as_str() == code {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Clone, Debug)]
pub struct BackupCodeSet {
    hashes: BTreeSet<String>,
}

impl BackupCodeSet {
    pub fn generate(count: usize) -> (Self, Vec<String>) {
        let mut hashes = BTreeSet::new();
        let mut plain = Vec::with_capacity(count);
        for _ in 0..count {
            let code = Uuid::new_v4().simple().to_string()[..10].to_owned();
            hashes.insert(hash_secret(&code));
            plain.push(code);
        }
        (Self { hashes }, plain)
    }

    pub fn consume(&mut self, code: &str) -> bool {
        self.hashes.remove(&hash_secret(code))
    }
}
