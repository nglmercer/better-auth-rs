use async_trait::async_trait;
use better_auth_core::{
    error::{AuthError, Result},
    options::PasswordHashOptions,
};
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use scrypt::{Params, Scrypt};
use std::sync::Arc;

const SCRYPT_OUTPUT_LENGTH: usize = 32;

/// The result of a password check. A successful legacy check can request an
/// automatic write-back using the primary provider's format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordVerification {
    pub valid: bool,
    pub needs_rehash: bool,
}

#[async_trait]
pub trait PasswordProvider: Send + Sync {
    async fn hash(&self, password: &str) -> Result<String>;

    async fn verify(&self, password: &str, encoded: &str) -> Result<PasswordVerification>;
}

/// The default Better Auth password format: a PHC-encoded scrypt hash.
#[derive(Clone, Debug)]
pub struct ScryptPhcPasswordProvider {
    options: PasswordHashOptions,
}

impl ScryptPhcPasswordProvider {
    pub fn new(options: PasswordHashOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &PasswordHashOptions {
        &self.options
    }
}

#[async_trait]
impl PasswordProvider for ScryptPhcPasswordProvider {
    async fn hash(&self, password: &str) -> Result<String> {
        hash_password_async(password, &self.options).await
    }

    async fn verify(&self, password: &str, encoded: &str) -> Result<PasswordVerification> {
        let password = password.to_owned();
        let encoded = encoded.to_owned();
        let options = self.options.clone();
        tokio::task::spawn_blocking(move || {
            let parsed = PasswordHash::new(&encoded)
                .map_err(|error| AuthError::Crypto(format!("invalid password hash: {error}")))?;
            let valid = Scrypt.verify_password(password.as_bytes(), &parsed).is_ok();
            let needs_rehash = parsed.algorithm.as_str() != "scrypt"
                || parsed.params.get_decimal("ln") != Some(options.scrypt_log_n as u32)
                || parsed.params.get_decimal("r") != Some(options.scrypt_r)
                || parsed.params.get_decimal("p") != Some(options.scrypt_p);
            Ok(PasswordVerification {
                valid,
                needs_rehash: valid && needs_rehash,
            })
        })
        .await
        .map_err(|error| {
            AuthError::Crypto(format!("password verification worker failed: {error}"))
        })?
    }
}

/// Tries a primary provider and then one or more legacy providers. Any
/// successful legacy verification is marked for rehash by the primary
/// provider. Legacy implementations can live in an application crate without
/// making this library depend on an application's old password format.
pub struct CompositePasswordProvider {
    pub primary: Arc<dyn PasswordProvider>,
    pub legacy: Vec<Arc<dyn PasswordProvider>>,
}

impl CompositePasswordProvider {
    pub fn new(
        primary: Arc<dyn PasswordProvider>,
        legacy: impl IntoIterator<Item = Arc<dyn PasswordProvider>>,
    ) -> Self {
        Self {
            primary,
            legacy: legacy.into_iter().collect(),
        }
    }
}

#[async_trait]
impl PasswordProvider for CompositePasswordProvider {
    async fn hash(&self, password: &str) -> Result<String> {
        self.primary.hash(password).await
    }

    async fn verify(&self, password: &str, encoded: &str) -> Result<PasswordVerification> {
        let mut last_error = None;
        match self.primary.verify(password, encoded).await {
            Ok(result) if result.valid => return Ok(result),
            Ok(_) => {}
            Err(error) => last_error = Some(error),
        }

        for provider in &self.legacy {
            match provider.verify(password, encoded).await {
                Ok(result) if result.valid => {
                    return Ok(PasswordVerification {
                        valid: true,
                        needs_rehash: true,
                    });
                }
                Ok(_) => {}
                Err(error) => last_error = Some(error),
            }
        }

        if let Some(error) = last_error {
            // A malformed/unsupported hash is treated as an unsuccessful
            // login only after every configured provider had a chance to
            // recognize it. Preserve provider errors for diagnostics.
            if self.legacy.is_empty() {
                return Err(error);
            }
        }
        Ok(PasswordVerification {
            valid: false,
            needs_rehash: false,
        })
    }
}

/// Hashes passwords using the configured scrypt parameters.
pub fn hash_password(password: &str) -> Result<String> {
    hash_password_with_options(password, &PasswordHashOptions::default())
}

pub fn hash_password_with_options(password: &str, options: &PasswordHashOptions) -> Result<String> {
    if password.is_empty() {
        return Err(AuthError::InvalidRequest("password cannot be empty".into()));
    }
    let salt = SaltString::generate(&mut password_hash::rand_core::OsRng);
    Scrypt
        .hash_password_customized(
            password.as_bytes(),
            None,
            None,
            scrypt_params(options)?,
            &salt,
        )
        .map(|hash| hash.to_string())
        .map_err(|error| AuthError::Crypto(format!("password hashing failed: {error}")))
}

pub fn verify_password(password: &str, encoded_hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(encoded_hash)
        .map_err(|error| AuthError::Crypto(format!("invalid password hash: {error}")))?;
    Ok(Scrypt.verify_password(password.as_bytes(), &parsed).is_ok())
}

/// Run the CPU- and memory-heavy hash on Tokio's blocking thread pool instead
/// of occupying an async runtime worker while a request is being processed.
pub async fn hash_password_async(password: &str, options: &PasswordHashOptions) -> Result<String> {
    let password = password.to_owned();
    let options = options.clone();
    tokio::task::spawn_blocking(move || hash_password_with_options(&password, &options))
        .await
        .map_err(|error| AuthError::Crypto(format!("password hashing worker failed: {error}")))?
}

pub async fn verify_password_async(password: &str, encoded_hash: &str) -> Result<bool> {
    let password = password.to_owned();
    let encoded_hash = encoded_hash.to_owned();
    tokio::task::spawn_blocking(move || verify_password(&password, &encoded_hash))
        .await
        .map_err(|error| {
            AuthError::Crypto(format!("password verification worker failed: {error}"))
        })?
}

fn scrypt_params(options: &PasswordHashOptions) -> Result<Params> {
    Params::new(
        options.scrypt_log_n,
        options.scrypt_r,
        options.scrypt_p,
        SCRYPT_OUTPUT_LENGTH,
    )
    .map_err(|error| AuthError::InvalidConfiguration(format!("invalid scrypt parameters: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrypt_hash_verifies_and_rejects_wrong_password() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash).unwrap());
        assert!(!verify_password("wrong", &hash).unwrap());
    }

    #[test]
    fn configured_scrypt_cost_is_stored_in_the_hash() {
        let options = PasswordHashOptions {
            scrypt_log_n: 13,
            ..PasswordHashOptions::default()
        };
        let hash = hash_password_with_options("password", &options).unwrap();
        assert!(hash.contains("ln=13"));
        assert!(verify_password("password", &hash).unwrap());
    }

    #[tokio::test]
    async fn provider_marks_successful_hashes_for_rehash() {
        let old = ScryptPhcPasswordProvider::new(PasswordHashOptions {
            scrypt_log_n: 13,
            ..PasswordHashOptions::default()
        });
        let current = ScryptPhcPasswordProvider::new(PasswordHashOptions::default());
        let encoded = old.hash("password").await.unwrap();
        let result = current.verify("password", &encoded).await.unwrap();
        assert_eq!(
            result,
            PasswordVerification {
                valid: true,
                needs_rehash: true,
            }
        );
    }
}
