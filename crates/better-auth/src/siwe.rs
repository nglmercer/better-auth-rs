//! Sign In With Ethereum (EIP-4361) with EIP-191 personal signatures.
//!
//! The server issues a nonce. The wallet signs a SIWE message that contains it.
//! The nonce is consumed on use, so a signed message cannot be replayed. The
//! signer's address is recovered from the signature and must match the address
//! in the message. Only the nonce's own five-minute lifetime bounds the message's
//! validity: an `Expiration Time` field is not enforced beyond that.

use crate::{context::AuthContext, email_password::User};
use better_auth_core::{
    adapter::{DbOperation, Query, SecondaryStorage, StorageValue},
    error::{AuthError, Result},
};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde_json::json;
use sha3::{Digest, Keccak256};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

const NONCE_TTL: Duration = Duration::from_secs(5 * 60);
const ACCOUNT_PROVIDER: &str = "siwe";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiweMessage {
    pub domain: String,
    pub address: String,
    pub uri: String,
    pub chain_id: String,
    pub nonce: String,
}

/// Parses the EIP-4361 text format. The fields this module relies on are
/// required, and the rest are ignored.
pub fn parse_message(text: &str) -> Result<SiweMessage> {
    let invalid = || AuthError::InvalidRequest("malformed SIWE message".into());
    let mut lines = text.lines();
    let first = lines.next().ok_or_else(invalid)?;
    let domain = first
        .strip_suffix(" wants you to sign in with your Ethereum account:")
        .ok_or_else(invalid)?
        .to_owned();
    let address = lines.next().ok_or_else(invalid)?.trim().to_owned();
    let field = |name: &str| -> Option<String> {
        text.lines()
            .find_map(|line| line.strip_prefix(name).map(|value| value.trim().to_owned()))
    };
    let message = SiweMessage {
        domain,
        address: address.clone(),
        uri: field("URI: ").ok_or_else(invalid)?,
        chain_id: field("Chain ID: ").ok_or_else(invalid)?,
        nonce: field("Nonce: ").ok_or_else(invalid)?,
    };
    if field("Version: ").as_deref() != Some("1") {
        return Err(AuthError::InvalidRequest("unsupported SIWE version".into()));
    }
    if !is_address(&address) {
        return Err(invalid());
    }
    Ok(message)
}

fn is_address(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// Recovers the lowercase `0x` address that produced an EIP-191 signature over `message`.
pub fn recover_address(message: &str, signature_hex: &str) -> Result<String> {
    let invalid = || AuthError::Unauthorized;
    let raw = hex_decode(signature_hex.trim_start_matches("0x")).ok_or_else(invalid)?;
    if raw.len() != 65 {
        return Err(invalid());
    }
    let recovery_byte = match raw[64] {
        v @ (0 | 1) => v,
        v @ (27 | 28) => v - 27,
        _ => return Err(invalid()),
    };
    let signature = Signature::from_slice(&raw[..64]).map_err(|_| invalid())?;
    let recovery = RecoveryId::from_byte(recovery_byte).ok_or_else(invalid)?;
    let prefixed = format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message);
    let digest = Keccak256::digest(prefixed.as_bytes());
    let key =
        VerifyingKey::recover_from_prehash(&digest, &signature, recovery).map_err(|_| invalid())?;
    let point = key.to_encoded_point(false);
    let address_digest = Keccak256::digest(&point.as_bytes()[1..]);
    Ok(format!("0x{}", hex_encode(&address_digest[12..])))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

#[derive(Clone)]
pub struct SiweService {
    context: AuthContext,
    storage: Arc<dyn SecondaryStorage>,
    domain: String,
}

impl SiweService {
    /// `domain` is the host the wallet must name in the message.
    pub fn new(context: AuthContext, domain: impl Into<String>) -> Result<Self> {
        let storage = context.secondary_storage.clone().ok_or_else(|| {
            AuthError::InvalidConfiguration("SIWE requires secondary storage".into())
        })?;
        Ok(Self {
            context,
            storage,
            domain: domain.into(),
        })
    }

    pub async fn issue_nonce(&self) -> Result<String> {
        let nonce = Uuid::new_v4().simple().to_string();
        self.storage
            .set(
                &format!("siwe:nonce:{nonce}"),
                StorageValue::with_ttl(json!({"issued": true}), NONCE_TTL),
            )
            .await?;
        Ok(nonce)
    }

    /// Verifies a signed message and returns the wallet's user, creating it on first use.
    pub async fn verify(&self, message_text: &str, signature: &str) -> Result<User> {
        let message = parse_message(message_text)?;
        if message.domain != self.domain {
            return Err(AuthError::Unauthorized);
        }
        if self
            .storage
            .get_and_delete(&format!("siwe:nonce:{}", message.nonce))
            .await?
            .is_none()
        {
            return Err(AuthError::Unauthorized);
        }
        let recovered = recover_address(message_text, signature)?;
        if recovered != message.address.to_ascii_lowercase() {
            return Err(AuthError::Unauthorized);
        }
        self.find_or_create_wallet_user(&recovered).await
    }

    async fn find_or_create_wallet_user(&self, address: &str) -> Result<User> {
        let adapter = &self.context.adapter;
        let account_id = format!("{ACCOUNT_PROVIDER}:{address}");
        if let Some(account) = adapter
            .find_one("account", Query::new().eq("id", account_id.clone()))
            .await?
        {
            let user_id = account
                .get("user_id")
                .and_then(serde_json::Value::as_str)
                .ok_or(AuthError::Unauthorized)?;
            let row = adapter
                .find_one("user", Query::new().eq("id", user_id.to_owned()))
                .await?
                .ok_or(AuthError::Unauthorized)?;
            return serde_json::from_value(row).map_err(|e| AuthError::Adapter(e.to_string()));
        }
        let user = User {
            id: Uuid::new_v4().to_string(),
            email: format!("{address}@wallet.invalid"),
            name: address.to_owned(),
            email_verified: false,
            image: None,
            additional_fields: serde_json::Map::new(),
        };
        adapter
            .transaction(vec![
                DbOperation::InsertRecord {
                    table: "user".into(),
                    record: serde_json::to_value(&user)
                        .map_err(|e| AuthError::Adapter(e.to_string()))?,
                },
                DbOperation::InsertRecord {
                    table: "account".into(),
                    record: json!({
                        "id": account_id,
                        "user_id": user.id,
                        "provider_id": ACCOUNT_PROVIDER,
                        "account_id": address,
                    }),
                },
            ])
            .await?;
        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    fn signing_key() -> SigningKey {
        SigningKey::from_slice(&[7u8; 32]).unwrap()
    }

    fn address_of(key: &SigningKey) -> String {
        let point = key.verifying_key().to_encoded_point(false);
        let digest = Keccak256::digest(&point.as_bytes()[1..]);
        format!("0x{}", hex_encode(&digest[12..]))
    }

    fn message(address: &str, nonce: &str) -> String {
        format!(
            "example.com wants you to sign in with your Ethereum account:\n{address}\n\n\
             Sign in to Example.\n\nURI: https://example.com\nVersion: 1\nChain ID: 1\n\
             Nonce: {nonce}\nIssued At: 2026-01-01T00:00:00Z"
        )
    }

    fn sign(key: &SigningKey, text: &str) -> String {
        let prefixed = format!("\x19Ethereum Signed Message:\n{}{}", text.len(), text);
        let digest = Keccak256::digest(prefixed.as_bytes());
        let (signature, recovery) = key.sign_prehash_recoverable(&digest).unwrap();
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(recovery.to_byte() + 27);
        format!("0x{}", hex_encode(&bytes))
    }

    #[test]
    fn recovers_the_signing_address() {
        let key = signing_key();
        let address = address_of(&key);
        let text = message(&address, "abc");
        assert_eq!(recover_address(&text, &sign(&key, &text)).unwrap(), address);
        assert!(recover_address(&message(&address, "abd"), &sign(&key, &text)).unwrap() != address);
    }

    #[test]
    fn parses_the_required_fields_and_rejects_others() {
        let key = signing_key();
        let address = address_of(&key);
        let parsed = parse_message(&message(&address, "n-1")).unwrap();
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.nonce, "n-1");
        assert!(parse_message("not a siwe message").is_err());
        assert!(parse_message(&message("0xnothex", "n")).is_err());
    }
}
