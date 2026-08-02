use better_auth_core::error::{AuthError, Result};
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use scrypt::Scrypt;

/// Hashes passwords using scrypt, matching Better Auth's secure default.
pub fn hash_password(password: &str) -> Result<String> {
    if password.is_empty() {
        return Err(AuthError::InvalidRequest("password cannot be empty".into()));
    }
    let salt = SaltString::generate(&mut password_hash::rand_core::OsRng);
    Scrypt
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| AuthError::Crypto(format!("password hashing failed: {error}")))
}

pub fn verify_password(password: &str, encoded_hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(encoded_hash)
        .map_err(|error| AuthError::Crypto(format!("invalid password hash: {error}")))?;
    Ok(Scrypt.verify_password(password.as_bytes(), &parsed).is_ok())
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
}
