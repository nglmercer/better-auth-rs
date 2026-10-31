//! Phone-number sign-in with SMS one-time codes.
//!
//! Numbers are normalized to E.164 form: a leading `+`, then 8 to 15 digits.
//! Delivery goes through [`PhoneSender`], so the application chooses the SMS
//! provider. The code is stored as a keyed hash, with the same attempt limit as
//! email codes.

use async_trait::async_trait;
use better_auth_core::error::{AuthError, Result};
use std::sync::Mutex;

/// Sends a one-time code by SMS. Implementations own retries and provider errors.
#[async_trait]
pub trait PhoneSender: Send + Sync {
    async fn send_code(&self, phone: &str, code: &str) -> Result<()>;
}

/// Normalizes a number to E.164. Spaces, dashes, dots and parentheses are removed.
pub fn normalize_phone(input: &str) -> Result<String> {
    let cleaned: String = input
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '.' | '(' | ')'))
        .collect();
    let digits = cleaned.strip_prefix('+').ok_or_else(|| {
        AuthError::InvalidRequest("phone number must start with '+' and a country code".into())
    })?;
    let valid = (8..=15).contains(&digits.len())
        && digits.bytes().all(|b| b.is_ascii_digit())
        && !digits.starts_with('0');
    if valid {
        Ok(format!("+{digits}"))
    } else {
        Err(AuthError::InvalidRequest("phone number is invalid".into()))
    }
}

/// Keeps sent messages in memory, for tests and local development.
#[derive(Default)]
pub struct CapturingPhoneSender {
    sent: Mutex<Vec<(String, String)>>,
}

impl CapturingPhoneSender {
    pub fn last_code(&self) -> Option<String> {
        self.sent
            .lock()
            .ok()
            .and_then(|sent| sent.last().map(|(_, code)| code.clone()))
    }
}

#[async_trait]
impl PhoneSender for CapturingPhoneSender {
    async fn send_code(&self, phone: &str, code: &str) -> Result<()> {
        if let Ok(mut sent) = self.sent.lock() {
            sent.push((phone.to_owned(), code.to_owned()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_normalize_to_e164() {
        assert_eq!(
            normalize_phone("+1 (555) 010-9999").unwrap(),
            "+15550109999"
        );
        assert!(
            normalize_phone("15550109999").is_err(),
            "country code is required"
        );
        assert!(normalize_phone("+0123456789").is_err());
        assert!(normalize_phone("+12").is_err());
        assert!(normalize_phone("+1555abc0999").is_err());
    }
}
