use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use better_auth_core::{
    error::{AuthError, Result},
    options::AuthOptions,
};
use hmac::{Hmac, Mac};
use http::HeaderMap;
use sha2::Sha256;
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CookieSameSite {
    Lax,
    Strict,
    None,
}

impl CookieSameSite {
    fn as_str(self) -> &'static str {
        match self {
            Self::Lax => "Lax",
            Self::Strict => "Strict",
            Self::None => "None",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthCookie {
    pub name: String,
    pub value: String,
    pub max_age_seconds: Option<u64>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: CookieSameSite,
    pub path: String,
}

impl AuthCookie {
    pub fn session(value: impl Into<String>, secure: bool, base_path: &str, max_age: u64) -> Self {
        let prefix = if secure { "__Secure-" } else { "" };
        Self {
            name: format!("{prefix}better-auth.session_token"),
            value: value.into(),
            max_age_seconds: Some(max_age),
            secure,
            http_only: true,
            same_site: CookieSameSite::Lax,
            path: base_path.to_owned(),
        }
    }

    pub fn removal(name: impl Into<String>, secure: bool, base_path: &str) -> Self {
        Self {
            name: name.into(),
            value: String::new(),
            max_age_seconds: Some(0),
            secure,
            http_only: true,
            same_site: CookieSameSite::Lax,
            path: base_path.to_owned(),
        }
    }

    pub fn to_set_cookie_header(&self) -> String {
        let mut header = format!(
            "{}={}; Path={}; SameSite={}",
            self.name,
            self.value,
            self.path,
            self.same_site.as_str()
        );
        if let Some(max_age) = self.max_age_seconds {
            header.push_str(&format!("; Max-Age={max_age}"));
        }
        if self.http_only {
            header.push_str("; HttpOnly");
        }
        if self.secure {
            header.push_str("; Secure");
        }
        header
    }
}

#[derive(Clone)]
pub struct SecretKeySet {
    current_version: String,
    keys: HashMap<String, Vec<u8>>,
}

impl SecretKeySet {
    pub fn from_options(options: &AuthOptions) -> Result<Self> {
        let keys = options
            .all_secrets()
            .map(|(version, secret)| (version.to_owned(), secret.as_bytes().to_vec()))
            .collect();
        Ok(Self {
            current_version: options.secret_version.clone(),
            keys,
        })
    }

    /// Signs with the active key and embeds its version in the envelope. A
    /// verifier can select a rotated key directly instead of trying every key.
    pub fn sign(&self, value: &str) -> Result<String> {
        let key = self
            .keys
            .get(&self.current_version)
            .ok_or_else(|| AuthError::Crypto("current secret version is missing".into()))?;
        let payload = URL_SAFE_NO_PAD.encode(value.as_bytes());
        let message = format!("{}.{}", self.current_version, payload);
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|_| AuthError::Crypto("invalid HMAC key".into()))?;
        mac.update(message.as_bytes());
        Ok(format!(
            "{message}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        ))
    }

    pub fn verify(&self, envelope: &str) -> Result<String> {
        let mut parts = envelope.split('.');
        let version = parts.next().ok_or(AuthError::Unauthorized)?;
        let payload = parts.next().ok_or(AuthError::Unauthorized)?;
        let signature = parts.next().ok_or(AuthError::Unauthorized)?;
        if parts.next().is_some() {
            return Err(AuthError::Unauthorized);
        }
        let key = self.keys.get(version).ok_or(AuthError::Unauthorized)?;
        let mut mac = HmacSha256::new_from_slice(key).map_err(|_| AuthError::Unauthorized)?;
        mac.update(format!("{version}.{payload}").as_bytes());
        let expected = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| AuthError::Unauthorized)?;
        mac.verify_slice(&expected)
            .map_err(|_| AuthError::Unauthorized)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| AuthError::Unauthorized)?;
        String::from_utf8(bytes).map_err(|_| AuthError::Unauthorized)
    }
}

pub fn request_cookies(headers: &HeaderMap) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    let Some(header) = headers.get("cookie").and_then(|value| value.to_str().ok()) else {
        return cookies;
    };
    for pair in header.split(';') {
        let Some((name, value)) = pair.trim().split_once('=') else {
            continue;
        };
        cookies.insert(name.trim().to_owned(), value.trim().to_owned());
    }
    cookies
}

pub fn session_cookie_from_options(
    options: &AuthOptions,
    value: impl Into<String>,
    secure: bool,
) -> AuthCookie {
    AuthCookie::session(
        value,
        secure,
        &options.base_path,
        options.session.expires_in_seconds,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyset() -> SecretKeySet {
        let options = AuthOptions {
            secret: "c".repeat(32),
            secret_rotation: vec![better_auth_core::options::SecretVersion {
                version: "old".into(),
                secret: "o".repeat(32),
            }],
            ..AuthOptions::default()
        };
        SecretKeySet::from_options(&options).unwrap()
    }

    #[test]
    fn versioned_signature_round_trips() {
        let keys = keyset();
        let signed = keys.sign("session-123").unwrap();
        assert_eq!(keys.verify(&signed).unwrap(), "session-123");
        assert!(keys.verify("old.invalid.signature").is_err());
    }
}
