use aes_gcm::{
    aead::{Aead, KeyInit as AesKeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use better_auth_core::{
    error::{AuthError, Result},
    options::{AuthOptions, CookieOptions},
};
use hmac::{Hmac, Mac};
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

pub use better_auth_core::options::CookieSameSite;

fn same_site_as_str(value: CookieSameSite) -> &'static str {
    match value {
        CookieSameSite::Lax => "Lax",
        CookieSameSite::Strict => "Strict",
        CookieSameSite::None => "None",
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
    pub domain: Option<String>,
}

impl AuthCookie {
    /// Compatibility constructor using explicit legacy cookie attributes.
    pub fn session(value: impl Into<String>, secure: bool, base_path: &str, max_age: u64) -> Self {
        let options = CookieOptions {
            path: base_path.to_owned(),
            ..CookieOptions::default()
        };
        Self::session_with_options(value, secure, &options, max_age)
    }

    /// Builds a session cookie from the application cookie policy. `secure` is
    /// the request transport hint and is overridden by an explicit policy.
    pub fn session_with_options(
        value: impl Into<String>,
        transport_secure: bool,
        options: &CookieOptions,
        max_age: u64,
    ) -> Self {
        let secure = options.secure.unwrap_or(transport_secure);
        Self {
            name: session_cookie_name(options, transport_secure),
            value: value.into(),
            max_age_seconds: Some(max_age),
            secure,
            http_only: options.http_only,
            same_site: options.same_site,
            path: options.path.clone(),
            domain: options.domain.clone(),
        }
    }

    /// Compatibility constructor using explicit legacy cookie attributes.
    pub fn removal(name: impl Into<String>, secure: bool, base_path: &str) -> Self {
        let options = CookieOptions {
            path: base_path.to_owned(),
            ..CookieOptions::default()
        };
        Self::removal_with_options(name, secure, &options)
    }

    pub fn removal_with_options(
        name: impl Into<String>,
        transport_secure: bool,
        options: &CookieOptions,
    ) -> Self {
        let secure = options.secure.unwrap_or(transport_secure);
        Self {
            name: name.into(),
            value: String::new(),
            max_age_seconds: Some(0),
            secure,
            http_only: options.http_only,
            same_site: options.same_site,
            path: options.path.clone(),
            domain: options.domain.clone(),
        }
    }

    pub fn to_set_cookie_header(&self) -> String {
        let mut header = format!(
            "{}={}; Path={}; SameSite={}",
            self.name,
            self.value,
            self.path,
            same_site_as_str(self.same_site)
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
        if let Some(domain) = &self.domain {
            header.push_str(&format!("; Domain={domain}"));
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

    pub fn current_version(&self) -> &str {
        &self.current_version
    }

    pub fn key_for_version(&self, version: &str) -> Option<&[u8]> {
        self.keys.get(version).map(Vec::as_slice)
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
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
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
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| AuthError::Unauthorized)?;
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct CookieCacheClaims {
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    #[serde(default)]
    pub data: Value,
}

/// Compact JWT and direct-encryption JWE codecs for cookie-cached sessions.
/// The JWE implementation uses the standard direct AES-256-GCM content
/// encryption shape (protected header, empty encrypted-key, IV, ciphertext,
/// tag) and embeds the key version as kid for rotation lookup.
#[derive(Clone)]
pub struct CookieCacheCodec {
    keys: SecretKeySet,
}

impl CookieCacheCodec {
    pub fn new(keys: SecretKeySet) -> Self {
        Self { keys }
    }

    pub fn encode(
        &self,
        strategy: better_auth_core::options::CookieCacheStrategy,
        subject: impl Into<String>,
        data: Value,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<String> {
        if expires_at <= issued_at {
            return Err(AuthError::InvalidRequest(
                "cookie-cache expiry must be after issuance".into(),
            ));
        }
        let claims = CookieCacheClaims {
            sub: subject.into(),
            iat: issued_at,
            exp: expires_at,
            data,
        };
        let payload = serde_json::to_vec(&claims).map_err(|error| {
            AuthError::Crypto(format!("cookie claims serialization failed: {error}"))
        })?;
        match strategy {
            better_auth_core::options::CookieCacheStrategy::Jwt => self.encode_jwt(&payload),
            better_auth_core::options::CookieCacheStrategy::Jwe => self.encode_jwe(&payload),
        }
    }

    pub fn decode(
        &self,
        strategy: better_auth_core::options::CookieCacheStrategy,
        token: &str,
        now: u64,
    ) -> Result<CookieCacheClaims> {
        let claims = match strategy {
            better_auth_core::options::CookieCacheStrategy::Jwt => self.decode_jwt(token)?,
            better_auth_core::options::CookieCacheStrategy::Jwe => self.decode_jwe(token)?,
        };
        if claims.exp <= now || claims.iat > now.saturating_add(60) {
            return Err(AuthError::Unauthorized);
        }
        Ok(claims)
    }

    fn encode_jwt(&self, payload: &[u8]) -> Result<String> {
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "alg": "HS256",
                "typ": "JWT",
                "kid": self.keys.current_version(),
            }))
            .map_err(|error| AuthError::Crypto(error.to_string()))?,
        );
        let payload = URL_SAFE_NO_PAD.encode(payload);
        let message = format!("{header}.{payload}");
        let key = self
            .keys
            .key_for_version(self.keys.current_version())
            .ok_or_else(|| AuthError::Crypto("current secret version is missing".into()))?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
            .map_err(|_| AuthError::Crypto("invalid HMAC key".into()))?;
        mac.update(message.as_bytes());
        Ok(format!(
            "{message}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        ))
    }

    fn decode_jwt(&self, token: &str) -> Result<CookieCacheClaims> {
        let mut parts = token.split('.');
        let header_segment = parts.next().ok_or(AuthError::Unauthorized)?;
        let payload = parts.next().ok_or(AuthError::Unauthorized)?;
        let signature = parts.next().ok_or(AuthError::Unauthorized)?;
        if parts.next().is_some() {
            return Err(AuthError::Unauthorized);
        }
        let header: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(header_segment)
                .map_err(|_| AuthError::Unauthorized)?,
        )
        .map_err(|_| AuthError::Unauthorized)?;
        if header.get("alg").and_then(Value::as_str) != Some("HS256") {
            return Err(AuthError::Unauthorized);
        }
        let version = header
            .get("kid")
            .and_then(Value::as_str)
            .ok_or(AuthError::Unauthorized)?;
        let key = self
            .keys
            .key_for_version(version)
            .ok_or(AuthError::Unauthorized)?;
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| AuthError::Unauthorized)?;
        mac.update(format!("{header_segment}.{payload}").as_bytes());
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| AuthError::Unauthorized)?;
        mac.verify_slice(&signature)
            .map_err(|_| AuthError::Unauthorized)?;
        serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(payload)
                .map_err(|_| AuthError::Unauthorized)?,
        )
        .map_err(|_| AuthError::Unauthorized)
    }

    fn encode_jwe(&self, payload: &[u8]) -> Result<String> {
        let protected = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "alg": "dir",
                "enc": "A256GCM",
                "kid": self.keys.current_version(),
            }))
            .map_err(|error| AuthError::Crypto(error.to_string()))?,
        );
        let uuid = uuid::Uuid::new_v4();
        let nonce_bytes = &uuid.as_bytes()[..12];
        let nonce = Nonce::from_slice(nonce_bytes);
        let key_material = self
            .keys
            .key_for_version(self.keys.current_version())
            .ok_or_else(|| AuthError::Crypto("current secret version is missing".into()))?;
        let key = sha2::Sha256::digest(key_material);
        let cipher = <Aes256Gcm as AesKeyInit>::new_from_slice(&key)
            .map_err(|_| AuthError::Crypto("invalid encryption key".into()))?;
        let encrypted = cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: payload,
                    aad: protected.as_bytes(),
                },
            )
            .map_err(|_| AuthError::Crypto("cookie encryption failed".into()))?;
        let split = encrypted.len().checked_sub(16).ok_or_else(|| {
            AuthError::Crypto("encrypted cookie is missing an authentication tag".into())
        })?;
        let (ciphertext, tag) = encrypted.split_at(split);
        Ok(format!(
            "{protected}..{}.{}.{}",
            URL_SAFE_NO_PAD.encode(nonce_bytes),
            URL_SAFE_NO_PAD.encode(ciphertext),
            URL_SAFE_NO_PAD.encode(tag)
        ))
    }

    fn decode_jwe(&self, token: &str) -> Result<CookieCacheClaims> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 5 || !parts[1].is_empty() || parts[4].is_empty() {
            return Err(AuthError::Unauthorized);
        }
        let protected = parts[0];
        let header: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(protected)
                .map_err(|_| AuthError::Unauthorized)?,
        )
        .map_err(|_| AuthError::Unauthorized)?;
        if header.get("alg").and_then(Value::as_str) != Some("dir")
            || header.get("enc").and_then(Value::as_str) != Some("A256GCM")
        {
            return Err(AuthError::Unauthorized);
        }
        let version = header
            .get("kid")
            .and_then(Value::as_str)
            .ok_or(AuthError::Unauthorized)?;
        let key_material = self
            .keys
            .key_for_version(version)
            .ok_or(AuthError::Unauthorized)?;
        let key = sha2::Sha256::digest(key_material);
        let cipher =
            <Aes256Gcm as AesKeyInit>::new_from_slice(&key).map_err(|_| AuthError::Unauthorized)?;
        let nonce = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|_| AuthError::Unauthorized)?;
        if nonce.len() != 12 {
            return Err(AuthError::Unauthorized);
        }
        let mut encrypted = URL_SAFE_NO_PAD
            .decode(parts[3])
            .map_err(|_| AuthError::Unauthorized)?;
        encrypted.extend_from_slice(
            &URL_SAFE_NO_PAD
                .decode(parts[4])
                .map_err(|_| AuthError::Unauthorized)?,
        );
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                aes_gcm::aead::Payload {
                    msg: &encrypted,
                    aad: protected.as_bytes(),
                },
            )
            .map_err(|_| AuthError::Unauthorized)?;
        serde_json::from_slice(&plaintext).map_err(|_| AuthError::Unauthorized)
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
    AuthCookie::session_with_options(
        value,
        secure,
        &options.cookie,
        options.session.expires_in_seconds,
    )
}

/// Resolves the session-cookie name consistently for reading, setting, and
/// removing the cookie.
pub fn session_cookie_name(options: &CookieOptions, transport_secure: bool) -> String {
    let secure = options.secure.unwrap_or(transport_secure);
    options.name.clone().unwrap_or_else(|| {
        let prefix = if secure { "__Secure-" } else { "" };
        format!("{prefix}better-auth.session_token")
    })
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

    #[test]
    fn jwt_and_jwe_cookie_cache_round_trip() {
        let keys = keyset();
        let codec = CookieCacheCodec::new(keys);
        for strategy in [
            better_auth_core::options::CookieCacheStrategy::Jwt,
            better_auth_core::options::CookieCacheStrategy::Jwe,
        ] {
            let token = codec
                .encode(strategy, "user-1", json!({"role": "user"}), 100, 200)
                .unwrap();
            let claims = codec.decode(strategy, &token, 150).unwrap();
            assert_eq!(claims.sub, "user-1");
            assert_eq!(claims.data["role"], "user");
            assert!(codec.decode(strategy, &token, 200).is_err());
        }
    }

    #[test]
    fn session_cookie_uses_independent_application_policy() {
        let options = AuthOptions {
            secret: "c".repeat(32),
            cookie: better_auth_core::options::CookieOptions {
                name: Some("app_session".into()),
                path: "/".into(),
                domain: Some("example.com".into()),
                secure: Some(true),
                http_only: false,
                same_site: CookieSameSite::Strict,
            },
            ..AuthOptions::default()
        };
        let cookie = session_cookie_from_options(&options, "token", false);
        assert_eq!(cookie.name, "app_session");
        assert!(cookie.secure);
        assert_eq!(cookie.path, "/");
        assert_eq!(cookie.domain.as_deref(), Some("example.com"));
        assert!(cookie.to_set_cookie_header().contains("Domain=example.com"));
        assert!(!cookie.to_set_cookie_header().contains("HttpOnly"));
    }
}
