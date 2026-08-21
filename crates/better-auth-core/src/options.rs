use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Static or request-resolved base URL configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum BaseUrl {
    Static(String),
    Dynamic { allowed_hosts: Vec<String> },
}

impl BaseUrl {
    pub fn dynamic(allowed_hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::Dynamic {
            allowed_hosts: allowed_hosts.into_iter().map(Into::into).collect(),
        }
    }

    pub fn allowed_hosts(&self) -> Option<&[String]> {
        match self {
            Self::Static(_) => None,
            Self::Dynamic { allowed_hosts } => Some(allowed_hosts),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CookieCacheStrategy {
    Jwe,
    Jwt,
}

/// The SameSite policy used when Better Auth emits a cookie.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CookieSameSite {
    Lax,
    Strict,
    None,
}

impl Default for CookieSameSite {
    fn default() -> Self {
        Self::Lax
    }
}

/// Cookie attributes are deliberately independent from `AuthOptions::base_path`.
/// An application may mount auth handlers below `/api/auth` while sharing the
/// session with its API and WebSocket routes at `/`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct CookieOptions {
    /// Custom session-cookie name. The standard Better Auth name is used when
    /// this is absent; secure transport still receives the `__Secure-` prefix.
    pub name: Option<String>,
    pub path: String,
    pub domain: Option<String>,
    /// `None` follows the request transport (`https` => secure).
    pub secure: Option<bool>,
    pub http_only: bool,
    pub same_site: CookieSameSite,
}

impl Default for CookieOptions {
    fn default() -> Self {
        Self {
            name: None,
            path: "/".to_owned(),
            domain: None,
            secure: None,
            http_only: true,
            same_site: CookieSameSite::Lax,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CookieCacheOptions {
    pub enabled: bool,
    pub strategy: CookieCacheStrategy,
    pub refresh_cache: bool,
    pub max_age_seconds: u64,
}

impl Default for CookieCacheOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            strategy: CookieCacheStrategy::Jwe,
            refresh_cache: true,
            // Zero means follow session.expires_in_seconds when the
            // cookie-cache default is applied.
            max_age_seconds: 0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SessionOptions {
    pub expires_in_seconds: u64,
    pub update_age_seconds: u64,
    pub cookie_cache: CookieCacheOptions,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            expires_in_seconds: 7 * 24 * 60 * 60,
            update_age_seconds: 24 * 60 * 60,
            cookie_cache: CookieCacheOptions::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdvancedOptions {
    /// Only honor forwarded host/proto headers when this is true. Deployments
    /// behind a proxy should set this explicitly after constraining the proxy.
    pub trusted_proxy_headers: bool,
    /// Header names trusted for client-IP extraction, in priority order.
    pub trusted_ip_headers: Vec<String>,
}

/// Password-hashing cost controls. New hashes use these values; verification
/// always reads the parameters stored in the existing PHC hash, so changing
/// the cost does not invalidate existing passwords.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct PasswordHashOptions {
    /// Scrypt's log2(N) work factor. The default uses 32 MiB per operation.
    pub scrypt_log_n: u8,
    pub scrypt_r: u32,
    pub scrypt_p: u32,
}

impl Default for PasswordHashOptions {
    fn default() -> Self {
        Self {
            // The scrypt crate's default is log_n=17 (128 MiB), which is too
            // slow for the default local server on modest development hosts.
            scrypt_log_n: 15,
            scrypt_r: 8,
            scrypt_p: 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuthOptions {
    pub base_url: Option<BaseUrl>,
    pub base_path: String,
    #[serde(default)]
    pub cookie: CookieOptions,
    pub secret: String,
    pub secret_version: String,
    pub secret_rotation: Vec<SecretVersion>,
    pub session: SessionOptions,
    pub trusted_origins: Vec<String>,
    pub trusted_providers: Vec<String>,
    pub advanced: AdvancedOptions,
    #[serde(default)]
    pub password_hash: PasswordHashOptions,
    /// Legacy serialized compatibility field. `AuthContext` derives this from
    /// whether a primary adapter is configured; applications should use
    /// `AuthContext::builder(...).database(...)` instead of maintaining it.
    pub has_database: bool,
    pub has_secondary_storage: bool,
    pub store_account_cookie: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SecretVersion {
    pub version: String,
    pub secret: String,
}

impl Default for AuthOptions {
    fn default() -> Self {
        Self {
            base_url: None,
            base_path: "/api/auth".to_owned(),
            cookie: CookieOptions::default(),
            secret: String::new(),
            secret_version: "current".to_owned(),
            secret_rotation: Vec::new(),
            session: SessionOptions::default(),
            trusted_origins: Vec::new(),
            trusted_providers: Vec::new(),
            advanced: AdvancedOptions::default(),
            password_hash: PasswordHashOptions::default(),
            has_database: false,
            has_secondary_storage: false,
            store_account_cookie: false,
        }
    }
}

impl AuthOptions {
    /// Applies the defaults described by the TypeScript implementation.
    pub fn apply_defaults(&mut self) {
        if !self.has_database && !self.has_secondary_storage {
            self.session.cookie_cache.enabled = true;
            self.session.cookie_cache.strategy = CookieCacheStrategy::Jwe;
            self.session.cookie_cache.refresh_cache = true;
            if self.session.cookie_cache.max_age_seconds == 0 {
                self.session.cookie_cache.max_age_seconds = self.session.expires_in_seconds;
            }
        }

        if !self.has_database {
            self.store_account_cookie = true;
        }

        if self.base_path.is_empty() {
            self.base_path = "/api/auth".to_owned();
        }
        if !self.base_path.starts_with('/') {
            self.base_path.insert(0, '/');
        }

        if self.cookie.path.is_empty() {
            self.cookie.path = "/".to_owned();
        } else if !self.cookie.path.starts_with('/') {
            self.cookie.path.insert(0, '/');
        }
    }

    pub fn all_secrets(&self) -> impl Iterator<Item = (&str, &str)> {
        std::iter::once((self.secret_version.as_str(), self.secret.as_str())).chain(
            self.secret_rotation
                .iter()
                .map(|entry| (entry.version.as_str(), entry.secret.as_str())),
        )
    }

    pub fn validate(&self) -> crate::Result<()> {
        if self.secret.len() < 32 {
            return Err(crate::AuthError::InvalidConfiguration(
                "secret must be at least 32 bytes".to_owned(),
            ));
        }
        if self.base_path == "/" || !self.base_path.starts_with('/') {
            return Err(crate::AuthError::InvalidConfiguration(
                "base_path must be an absolute non-root path".to_owned(),
            ));
        }
        if self.cookie.path.is_empty() || !self.cookie.path.starts_with('/') {
            return Err(crate::AuthError::InvalidConfiguration(
                "cookie.path must be an absolute path".to_owned(),
            ));
        }
        if self.cookie.same_site == CookieSameSite::None && self.cookie.secure == Some(false) {
            return Err(crate::AuthError::InvalidConfiguration(
                "SameSite=None cookies must be secure".to_owned(),
            ));
        }
        if self
            .cookie
            .name
            .as_deref()
            .is_some_and(|name| name.trim().is_empty())
        {
            return Err(crate::AuthError::InvalidConfiguration(
                "cookie.name cannot be empty".to_owned(),
            ));
        }

        let mut versions = BTreeSet::new();
        for (version, secret) in self.all_secrets() {
            if version.is_empty() || !versions.insert(version) {
                return Err(crate::AuthError::InvalidConfiguration(
                    "secret versions must be non-empty and unique".to_owned(),
                ));
            }
            if secret.len() < 32 {
                return Err(crate::AuthError::InvalidConfiguration(format!(
                    "secret for version '{version}' must be at least 32 bytes"
                )));
            }
        }

        if let Some(BaseUrl::Dynamic { allowed_hosts }) = &self.base_url {
            if allowed_hosts.is_empty() {
                return Err(crate::AuthError::InvalidConfiguration(
                    "base_url.allowed_hosts cannot be empty".to_owned(),
                ));
            }
            if allowed_hosts.iter().any(|host| host.trim().is_empty()) {
                return Err(crate::AuthError::InvalidConfiguration(
                    "base_url.allowed_hosts cannot contain empty patterns".to_owned(),
                ));
            }
        }
        Ok(())
    }
}
