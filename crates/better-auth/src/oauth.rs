use crate::{
    context::AuthContext,
    cookies::{AuthCookie, CookieCacheCodec, SecretKeySet},
    email_password::{AuthResult, User},
    session::{AuthPrincipal, SessionService},
};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use better_auth_core::{
    adapter::{DbOperation, Query, SecondaryStorage, StorageValue},
    error::{AuthError, Result},
    options::CookieOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use url::Url;
use uuid::Uuid;

const ACCOUNT_TABLE: &str = "account";
const USER_TABLE: &str = "user";
const SESSION_TABLE: &str = "session";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OAuthStateStorage {
    Verification,
    SignedCookie,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthProviderConfig {
    pub id: String,
    pub authorization_endpoint: Url,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub state_ttl: Duration,
}

impl OAuthProviderConfig {
    pub fn new(
        id: impl Into<String>,
        authorization_endpoint: Url,
        client_id: impl Into<String>,
    ) -> Result<Self> {
        if authorization_endpoint.scheme() != "https" {
            return Err(AuthError::InvalidConfiguration(
                "OAuth authorization endpoints must use HTTPS".into(),
            ));
        }
        Ok(Self {
            id: id.into(),
            authorization_endpoint,
            client_id: client_id.into(),
            scopes: Vec::new(),
            state_ttl: Duration::from_secs(10 * 60),
        })
    }

    pub fn scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

impl PkcePair {
    pub fn generate() -> Self {
        let verifier = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Self {
            verifier,
            challenge,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct OAuthState {
    provider_id: String,
    state: String,
    redirect_uri: String,
    code_verifier: String,
    nonce: String,
    expires_at: u64,
}

#[derive(Clone, Debug)]
pub struct OAuthAuthorization {
    pub provider_id: String,
    pub state: String,
    pub code_verifier: String,
    pub nonce: String,
    pub authorization_url: Url,
    pub state_cookie: Option<AuthCookie>,
}

#[derive(Clone)]
pub struct OAuthStateManager {
    storage: Option<Arc<dyn SecondaryStorage>>,
    keys: SecretKeySet,
    mode: OAuthStateStorage,
    cookie: CookieOptions,
}

impl OAuthStateManager {
    pub fn new(
        storage: Option<Arc<dyn SecondaryStorage>>,
        keys: SecretKeySet,
        mode: OAuthStateStorage,
        base_path: impl Into<String>,
    ) -> Result<Self> {
        let base_path = base_path.into();
        let cookie = CookieOptions {
            path: base_path.clone(),
            ..CookieOptions::default()
        };
        Self::new_with_cookie_options(storage, keys, mode, base_path, cookie)
    }

    pub fn new_with_cookie_options(
        storage: Option<Arc<dyn SecondaryStorage>>,
        keys: SecretKeySet,
        mode: OAuthStateStorage,
        _base_path: impl Into<String>,
        cookie: CookieOptions,
    ) -> Result<Self> {
        if mode == OAuthStateStorage::Verification && storage.is_none() {
            return Err(AuthError::InvalidConfiguration(
                "verification OAuth state storage requires secondary storage".into(),
            ));
        }
        Ok(Self {
            storage,
            keys,
            mode,
            cookie,
        })
    }

    pub async fn begin(
        &self,
        provider: &OAuthProviderConfig,
        redirect_uri: &str,
        secure_cookie: bool,
    ) -> Result<OAuthAuthorization> {
        let pkce = PkcePair::generate();
        let state = Uuid::new_v4().simple().to_string();
        let nonce = Uuid::new_v4().simple().to_string();
        let expires_at = now_seconds() + provider.state_ttl.as_secs();
        let record = OAuthState {
            provider_id: provider.id.clone(),
            state: state.clone(),
            redirect_uri: redirect_uri.to_owned(),
            code_verifier: pkce.verifier.clone(),
            nonce: nonce.clone(),
            expires_at,
        };
        let mut authorization_url = provider.authorization_endpoint.clone();
        {
            let mut query = authorization_url.query_pairs_mut();
            query
                .append_pair("client_id", &provider.client_id)
                .append_pair("redirect_uri", redirect_uri)
                .append_pair("response_type", "code")
                .append_pair("state", &state)
                .append_pair("code_challenge", &pkce.challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("nonce", &nonce);
            if !provider.scopes.is_empty() {
                query.append_pair("scope", &provider.scopes.join(" "));
            }
        }

        let state_cookie = match self.mode {
            OAuthStateStorage::Verification => {
                let storage = self.storage.as_ref().ok_or_else(|| {
                    AuthError::InvalidConfiguration("OAuth state storage unavailable".into())
                })?;
                storage
                    .set(
                        &state_key(&state),
                        StorageValue::with_ttl(
                            serde_json::to_value(&record).map_err(serialize_error)?,
                            provider.state_ttl,
                        ),
                    )
                    .await?;
                None
            }
            OAuthStateStorage::SignedCookie => {
                let signed = self
                    .keys
                    .sign(&serde_json::to_string(&record).map_err(serialize_error)?)?;
                Some(AuthCookie {
                    name: "better-auth.oauth_state".into(),
                    value: signed,
                    max_age_seconds: Some(provider.state_ttl.as_secs()),
                    secure: self.cookie.secure.unwrap_or(secure_cookie),
                    http_only: self.cookie.http_only,
                    same_site: self.cookie.same_site,
                    path: self.cookie.path.clone(),
                    domain: self.cookie.domain.clone(),
                })
            }
        };
        Ok(OAuthAuthorization {
            provider_id: provider.id.clone(),
            state,
            code_verifier: pkce.verifier,
            nonce,
            authorization_url,
            state_cookie,
        })
    }

    pub async fn consume(
        &self,
        provider_id: &str,
        state: &str,
        signed_cookie: Option<&str>,
    ) -> Result<(String, String, String)> {
        let record: OAuthState = match self.mode {
            OAuthStateStorage::Verification => {
                let storage = self.storage.as_ref().ok_or_else(|| {
                    AuthError::InvalidConfiguration("OAuth state storage unavailable".into())
                })?;
                let value = storage
                    .get_and_delete(&state_key(state))
                    .await?
                    .ok_or(AuthError::Unauthorized)?;
                serde_json::from_value(value.value).map_err(serialize_error)?
            }
            OAuthStateStorage::SignedCookie => {
                let signed = signed_cookie.ok_or(AuthError::Unauthorized)?;
                let raw = self.keys.verify(signed)?;
                serde_json::from_str(&raw).map_err(serialize_error)?
            }
        };
        if record.provider_id != provider_id
            || record.state != state
            || record.expires_at <= now_seconds()
        {
            return Err(AuthError::Unauthorized);
        }
        Ok((record.redirect_uri, record.code_verifier, record.nonce))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<u64>,
    pub token_type: String,
    #[serde(default)]
    pub id_token: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthUserProfile {
    pub provider_account_id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
    pub email_verified: bool,
}

#[async_trait]
pub trait OAuthProvider: Send + Sync {
    fn id(&self) -> &str;
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<OAuthTokens>;
    async fn profile(&self, tokens: &OAuthTokens) -> Result<OAuthUserProfile>;

    fn validate_tokens(&self, _tokens: &OAuthTokens, _expected_nonce: &str) -> Result<()> {
        Ok(())
    }
}

/// Creates the application-owned identity before a new Better Auth OAuth user is
/// persisted. For legacy applications, insert the legacy user first and return a
/// `User` whose ID is the decimal representation of the legacy primary key.
///
/// Implementations must make `rollback_user` idempotent. If the Better Auth
/// transaction, lifecycle hooks, or session creation fails, this hook is called
/// to compensate for an already-created application identity.
#[async_trait]
pub trait OAuthUserProvisioner: Send + Sync {
    async fn create_user(&self, profile: &OAuthUserProfile) -> Result<User>;
    async fn rollback_user(&self, user: &User) -> Result<()>;
}

#[derive(Clone)]
pub struct OAuthService {
    context: AuthContext,
    state: OAuthStateManager,
    token_vault: ProviderTokenVault,
}

impl OAuthService {
    pub fn new(context: AuthContext, mode: OAuthStateStorage) -> Result<Self> {
        let keys = SecretKeySet::from_options(&context.options)?;
        let state = OAuthStateManager::new_with_cookie_options(
            context.secondary_storage.clone(),
            keys.clone(),
            mode,
            context.options.base_path.clone(),
            context.options.cookie.clone(),
        )?;
        Ok(Self {
            context,
            state,
            token_vault: ProviderTokenVault::new(keys),
        })
    }

    pub async fn begin(
        &self,
        provider: &OAuthProviderConfig,
        redirect_uri: &str,
        secure_cookie: bool,
    ) -> Result<OAuthAuthorization> {
        self.state
            .begin(provider, redirect_uri, secure_cookie)
            .await
    }

    /// Default OAuth completion retains UUID-based Better Auth user IDs.
    /// Applications with externally owned numeric IDs should call
    /// `complete_with_provisioner` instead.
    pub async fn complete<P: OAuthProvider>(
        &self,
        provider: &P,
        code: &str,
        state: &str,
        signed_state_cookie: Option<&str>,
        secure_cookie: bool,
    ) -> Result<AuthResult> {
        self.complete_inner(provider, code, state, signed_state_cookie, secure_cookie, None)
            .await
    }

    /// Completes OAuth with application-controlled creation of *new* users.
    /// Existing linked accounts or verified-email matches never call the
    /// provisioner. The provisioner may allocate a numeric legacy user ID.
    pub async fn complete_with_provisioner<P: OAuthProvider>(
        &self,
        provider: &P,
        code: &str,
        state: &str,
        signed_state_cookie: Option<&str>,
        secure_cookie: bool,
        provisioner: &dyn OAuthUserProvisioner,
    ) -> Result<AuthResult> {
        self.complete_inner(
            provider,
            code,
            state,
            signed_state_cookie,
            secure_cookie,
            Some(provisioner),
        )
        .await
    }

    async fn complete_inner<P: OAuthProvider>(
        &self,
        provider: &P,
        code: &str,
        state: &str,
        signed_state_cookie: Option<&str>,
        secure_cookie: bool,
        provisioner: Option<&dyn OAuthUserProvisioner>,
    ) -> Result<AuthResult> {
        if !self.context.options.has_database {
            return Err(AuthError::InvalidConfiguration(
                "OAuth authentication requires a primary database".into(),
            ));
        }
        let (redirect_uri, verifier, nonce) = self
            .state
            .consume(provider.id(), state, signed_state_cookie)
            .await?;
        let tokens = provider
            .exchange_code(code, &redirect_uri, &verifier)
            .await?;
        provider.validate_tokens(&tokens, &nonce)?;
        let profile = provider.profile(&tokens).await?;
        if profile.provider_account_id.trim().is_empty() {
            return Err(AuthError::InvalidRequest("OAuth provider returned an empty account ID".into()));
        }
        let (user, new_user, account_id) = self
            .find_or_create_user(provider.id(), &profile, &tokens, provisioner)
            .await?;
        let result = SessionService::new(self.context.clone())?
            .create(user.clone(), secure_cookie)
            .await;
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                if new_user {
                    return Err(self.compensate(error, &user, &account_id, provisioner, true).await);
                }
                return Err(error);
            }
        };
        if let Err(error) = self
            .context
            .after_sign_in(&AuthPrincipal {
                user: result.user.clone(),
                session: result.session.clone(),
            })
            .await
        {
            if new_user {
                return Err(self.compensate(error, &user, &account_id, provisioner, true).await);
            }
            return Err(error);
        }
        Ok(result)
    }

    async fn find_or_create_user(
        &self,
        provider_id: &str,
        profile: &OAuthUserProfile,
        tokens: &OAuthTokens,
        provisioner: Option<&dyn OAuthUserProvisioner>,
    ) -> Result<(User, bool, String)> {
        let account_id = format!("oauth:{provider_id}:{}", profile.provider_account_id);
        if let Some(account) = self
            .context
            .adapter
            .find_one(ACCOUNT_TABLE, Query::new().eq("id", account_id.clone()))
            .await?
        {
            let user_id = account
                .get("user_id")
                .and_then(Value::as_str)
                .ok_or_else(|| AuthError::Adapter("OAuth account has no user_id".into()))?;
            let value = self
                .context
                .adapter
                .find_one(USER_TABLE, Query::new().eq("id", user_id.to_owned()))
                .await?
                .ok_or(AuthError::Unauthorized)?;
            let user = serde_json::from_value(value).map_err(serialize_error)?;
            return Ok((user, false, account_id));
        }
        let email = profile
            .email
            .as_deref()
            .ok_or_else(|| AuthError::InvalidRequest("OAuth provider did not return an email".into()))?
            .trim()
            .to_ascii_lowercase();
        if email.is_empty() {
            return Err(AuthError::InvalidRequest("OAuth provider returned an empty email".into()));
        }
        // Encrypt tokens before allocating an external legacy row, so a
        // vault/serialization failure cannot leave that row orphaned.
        let token_envelope = self.token_vault.seal(provider_id, tokens)?;
        let existing = self
            .context
            .adapter
            .find_one(USER_TABLE, Query::new().eq("email", email.clone()))
            .await?;
        if existing.is_some() && !profile.email_verified {
            return Err(AuthError::Unauthorized);
        }

        let mut new_user = None;
        let user = if let Some(value) = existing {
            serde_json::from_value(value).map_err(serialize_error)?
        } else {
            let mut user = if let Some(provisioner) = provisioner {
                provisioner.create_user(profile).await?
            } else {
                User {
                    id: Uuid::new_v4().to_string(),
                    email: email.clone(),
                    name: profile.name.clone().unwrap_or_else(|| "User".into()),
                    email_verified: profile.email_verified,
                    image: profile.image.clone(),
                    additional_fields: serde_json::Map::new(),
                }
            };
            let original = user.clone();
            if user.id.trim().is_empty() || user.email != email {
                let error = AuthError::InvalidRequest(
                    "OAuth provisioner must return a non-empty ID and the normalized provider email".into(),
                );
                return Err(self.rollback_provisioner(error, &original, provisioner).await);
            }
            if let Err(error) = self.context.before_user_create(&mut user).await {
                return Err(self.rollback_provisioner(error, &original, provisioner).await);
            }
            if provisioner.is_some() && (user.id != original.id || user.email != original.email) {
                let error = AuthError::InvalidRequest(
                    "OAuth lifecycle hooks must not change provisioned identity".into(),
                );
                return Err(self.rollback_provisioner(error, &original, provisioner).await);
            }
            new_user = Some(user.clone());
            user
        };
        let is_new_user = new_user.is_some();
        let mut operations = Vec::with_capacity(2);
        if let Some(new_user) = new_user {
            operations.push(DbOperation::InsertRecord {
                table: USER_TABLE.into(),
                record: serde_json::to_value(new_user).map_err(serialize_error)?,
            });
        }
        operations.push(DbOperation::InsertRecord {
            table: ACCOUNT_TABLE.into(),
            record: json!({
                "id": account_id,
                "user_id": user.id,
                "provider_id": provider_id,
                "account_id": profile.provider_account_id,
                "token_envelope": token_envelope,
            }),
        });
        if let Err(error) = self.context.adapter.transaction(operations).await {
            if is_new_user {
                return Err(self.rollback_provisioner(error, &user, provisioner).await);
            }
            return Err(error);
        }
        if is_new_user {
            if let Err(error) = self.context.after_user_create(&user).await {
                return Err(self.compensate(error, &user, &account_id, provisioner, true).await);
            }
        }
        Ok((user, is_new_user, account_id))
    }

    async fn rollback_provisioner(
        &self,
        error: AuthError,
        user: &User,
        provisioner: Option<&dyn OAuthUserProvisioner>,
    ) -> AuthError {
        if let Some(provisioner) = provisioner {
            if let Err(cleanup) = provisioner.rollback_user(user).await {
                return AuthError::Adapter(format!("{error}; legacy rollback failed: {cleanup}"));
            }
        }
        error
    }

    async fn compensate(
        &self,
        error: AuthError,
        user: &User,
        account_id: &str,
        provisioner: Option<&dyn OAuthUserProvisioner>,
        persisted: bool,
    ) -> AuthError {
        if persisted {
            let cleanup = self.context.adapter.transaction(vec![
                DbOperation::DeleteWhere {
                    table: SESSION_TABLE.into(),
                    query: Query::new().eq("user_id", user.id.clone()),
                },
                DbOperation::DeleteWhere {
                    table: ACCOUNT_TABLE.into(),
                    query: Query::new().eq("id", account_id.to_owned()).eq("user_id", user.id.clone()),
                },
                DbOperation::DeleteWhere {
                    table: USER_TABLE.into(),
                    query: Query::new().eq("id", user.id.clone()),
                },
            ]).await;
            if let Err(cleanup) = cleanup {
                return AuthError::Adapter(format!("{error}; Better Auth rollback failed: {cleanup}"));
            }
        }
        self.rollback_provisioner(error, user, provisioner).await
    }
}

#[derive(Clone)]
pub struct ProviderTokenVault {
    codec: CookieCacheCodec,
}

impl ProviderTokenVault {
    pub fn new(keys: SecretKeySet) -> Self {
        Self {
            codec: CookieCacheCodec::new(keys),
        }
    }

    pub fn seal(&self, provider_id: &str, tokens: &OAuthTokens) -> Result<String> {
        let now = now_seconds();
        self.codec.encode(
            better_auth_core::options::CookieCacheStrategy::Jwe,
            provider_id,
            serde_json::to_value(tokens).map_err(serialize_error)?,
            now,
            tokens.expires_at.unwrap_or(now + 24 * 60 * 60).max(now + 1),
        )
    }

    pub fn open(&self, envelope: &str) -> Result<OAuthTokens> {
        let claims = self.codec.decode(
            better_auth_core::options::CookieCacheStrategy::Jwe,
            envelope,
            now_seconds(),
        )?;
        serde_json::from_value(claims.data).map_err(serialize_error)
    }
}

fn state_key(state: &str) -> String {
    format!("oauth:state:{state}")
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

fn serialize_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Adapter(format!("OAuth state serialization failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::{
        adapter::{memory::{MemoryDb, MemorySecondaryStorage}, DbAdapter},
        options::{AuthOptions, BaseUrl},
    };

    #[tokio::test]
    async fn pkce_and_verification_state_are_single_use() {
        let options = AuthOptions {
            secret: "o".repeat(32),
            ..AuthOptions::default()
        };
        let keys = SecretKeySet::from_options(&options).unwrap();
        let manager = OAuthStateManager::new(
            Some(Arc::new(MemorySecondaryStorage::default())),
            keys,
            OAuthStateStorage::Verification,
            "/api/auth",
        )
        .unwrap();
        let config = OAuthProviderConfig::new(
            "example",
            Url::parse("https://provider.example/authorize").unwrap(),
            "client",
        )
        .unwrap();
        let auth = manager
            .begin(&config, "https://app.example/callback", true)
            .await
            .unwrap();
        assert!(auth.authorization_url.as_str().contains("code_challenge="));
        let (_, verifier, nonce) = manager.consume("example", &auth.state, None).await.unwrap();
        assert_eq!(verifier, auth.code_verifier);
        assert_eq!(nonce, auth.nonce);
        assert!(manager.consume("example", &auth.state, None).await.is_err());
    }

    #[tokio::test]
    async fn signed_cookie_state_round_trips_without_storage() {
        let options = AuthOptions {
            secret: "o".repeat(32),
            ..AuthOptions::default()
        };
        let keys = SecretKeySet::from_options(&options).unwrap();
        let manager =
            OAuthStateManager::new(None, keys, OAuthStateStorage::SignedCookie, "/api/auth")
                .unwrap();
        let config = OAuthProviderConfig::new(
            "example",
            Url::parse("https://provider.example/authorize").unwrap(),
            "client",
        )
        .unwrap();
        let auth = manager
            .begin(&config, "https://app.example/callback", true)
            .await
            .unwrap();
        let cookie = auth.state_cookie.unwrap();
        let (_, verifier, nonce) = manager
            .consume("example", &auth.state, Some(&cookie.value))
            .await
            .unwrap();
        assert_eq!(verifier, auth.code_verifier);
        assert_eq!(nonce, auth.nonce);
    }

    struct MockProvider;

    #[async_trait]
    impl OAuthProvider for MockProvider {
        fn id(&self) -> &str {
            "mock"
        }

        async fn exchange_code(
            &self,
            _code: &str,
            _redirect_uri: &str,
            _code_verifier: &str,
        ) -> Result<OAuthTokens> {
            Ok(OAuthTokens {
                access_token: "access".into(),
                refresh_token: None,
                expires_at: None,
                token_type: "Bearer".into(),
                id_token: None,
            })
        }

        async fn profile(&self, _tokens: &OAuthTokens) -> Result<OAuthUserProfile> {
            Ok(OAuthUserProfile {
                provider_account_id: "account-1".into(),
                email: Some("oauth@example.com".into()),
                name: Some("OAuth User".into()),
                image: None,
                email_verified: true,
            })
        }
    }

    #[tokio::test]
    async fn oauth_completion_links_account_and_issues_a_session() {
        let context = AuthContext::new(
            AuthOptions {
                secret: "p".repeat(32),
                base_url: Some(BaseUrl::Static("https://example.com".into())),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(MemoryDb::default()),
            Some(Arc::new(MemorySecondaryStorage::default())),
            Vec::new(),
        )
        .unwrap();
        let service = OAuthService::new(context, OAuthStateStorage::Verification).unwrap();
        let provider = MockProvider;
        let config = OAuthProviderConfig::new(
            "mock",
            Url::parse("https://provider.example/authorize").unwrap(),
            "client",
        )
        .unwrap();
        let authorization = service
            .begin(&config, "https://example.com/callback", true)
            .await
            .unwrap();
        let result = service
            .complete(&provider, "code", &authorization.state, None, true)
            .await
            .unwrap();
        assert_eq!(result.user.email, "oauth@example.com");
        assert_eq!(result.session.user_id, result.user.id);
    }
    struct FixtureProvider {
        name: &'static str,
        account: &'static str,
        email: &'static str,
        verified: bool,
    }

    #[async_trait]
    impl OAuthProvider for FixtureProvider {
        fn id(&self) -> &str {
            self.name
        }

        async fn exchange_code(
            &self,
            _code: &str,
            _redirect_uri: &str,
            _code_verifier: &str,
        ) -> Result<OAuthTokens> {
            Ok(OAuthTokens {
                access_token: "fixture-access".into(),
                refresh_token: None,
                expires_at: None,
                token_type: "Bearer".into(),
                id_token: None,
            })
        }

        async fn profile(&self, _tokens: &OAuthTokens) -> Result<OAuthUserProfile> {
            Ok(OAuthUserProfile {
                provider_account_id: self.account.into(),
                email: Some(self.email.into()),
                name: Some("OAuth Fixture".into()),
                image: None,
                email_verified: self.verified,
            })
        }
    }

    struct LegacyProvisioner {
        db: Arc<MemoryDb>,
    }

    #[async_trait]
    impl OAuthUserProvisioner for LegacyProvisioner {
        async fn create_user(&self, profile: &OAuthUserProfile) -> Result<User> {
            self.db.insert_record(
                "legacy_users",
                json!({ "id": "42", "email": profile.email }),
            ).await?;
            Ok(User {
                id: "42".into(),
                email: profile.email.as_deref().unwrap().to_ascii_lowercase(),
                name: profile.name.clone().unwrap_or_else(|| "User".into()),
                email_verified: profile.email_verified,
                image: profile.image.clone(),
                additional_fields: serde_json::Map::new(),
            })
        }

        async fn rollback_user(&self, user: &User) -> Result<()> {
            self.db
                .delete_where("legacy_users", Query::new().eq("id", user.id.clone()))
                .await?;
            Ok(())
        }
    }

    fn fixture_context(db: Arc<MemoryDb>) -> AuthContext {
        AuthContext::new(
            AuthOptions {
                secret: "p".repeat(32),
                base_url: Some(BaseUrl::Static("https://example.com".into())),
                has_database: true,
                ..AuthOptions::default()
            },
            db,
            Some(Arc::new(MemorySecondaryStorage::default())),
            Vec::new(),
        ).unwrap()
    }

    fn fixture_config(id: &str) -> OAuthProviderConfig {
        OAuthProviderConfig::new(
            id,
            Url::parse("https://provider.example/authorize").unwrap(),
            "client",
        ).unwrap()
    }

    #[tokio::test]
    async fn google_oauth_provisions_numeric_user_and_resolves_session() {
        let db = Arc::new(MemoryDb::default());
        let context = fixture_context(db.clone());
        let service = OAuthService::new(context.clone(), OAuthStateStorage::Verification).unwrap();
        let provisioner = LegacyProvisioner { db: db.clone() };
        let provider = FixtureProvider {
            name: "google", account: "google-123", email: "legacy@example.com", verified: true,
        };
        let begin = service.begin(&fixture_config("google"), "https://example.com/callback", true)
            .await.unwrap();
        let result = service.complete_with_provisioner(
            &provider, "code", &begin.state, None, true, &provisioner
        ).await.unwrap();
        assert_eq!(result.user.id, "42");
        assert_eq!(result.session.user_id, "42");
        assert!(db.find_one("legacy_users", Query::new().eq("id", "42")).await.unwrap().is_some());
        assert!(db.find_one("user", Query::new().eq("id", "42")).await.unwrap().is_some());

        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {}", result.session_token).parse().unwrap(),
        );
        let resolved = SessionService::new(context)
            .unwrap()
            .resolve_with_transport(&headers, true, crate::session::SessionTransport::Bearer)
            .await.unwrap().unwrap();
        assert_eq!(resolved.user.id, "42");

        // The linked provider account must bypass the provisioner on later logins.
        let begin = service.begin(&fixture_config("google"), "https://example.com/callback", true)
            .await.unwrap();
        let again = service.complete(&provider, "code", &begin.state, None, true).await.unwrap();
        assert_eq!(again.user.id, "42");
        assert_eq!(db.find_many("legacy_users", Query::new()).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn github_verified_email_links_existing_user_without_new_legacy_row() {
        let db = Arc::new(MemoryDb::default());
        db.insert_record("user", json!({
            "id": "77", "email": "existing@example.com", "name": "Existing",
            "email_verified": true, "image": null
        })).await.unwrap();
        let context = fixture_context(db.clone());
        let service = OAuthService::new(context, OAuthStateStorage::Verification).unwrap();
        let provisioner = LegacyProvisioner { db: db.clone() };
        let provider = FixtureProvider {
            name: "github", account: "github-456", email: "existing@example.com", verified: true,
        };
        let begin = service.begin(&fixture_config("github"), "https://example.com/callback", true)
            .await.unwrap();
        let result = service.complete_with_provisioner(
            &provider, "code", &begin.state, None, true, &provisioner
        ).await.unwrap();
        assert_eq!(result.user.id, "77");
        assert!(db.find_many("legacy_users", Query::new()).await.unwrap().is_empty());
        let account = db.find_one("account", Query::new().eq("id", "oauth:github:github-456"))
            .await.unwrap().unwrap();
        assert_eq!(account["user_id"], "77");
    }

    #[tokio::test]
    async fn unverified_email_cannot_link_existing_user() {
        let db = Arc::new(MemoryDb::default());
        db.insert_record("user", json!({
            "id": "77", "email": "existing@example.com", "name": "Existing",
            "email_verified": true, "image": null
        })).await.unwrap();
        let service = OAuthService::new(fixture_context(db.clone()), OAuthStateStorage::Verification).unwrap();
        let provider = FixtureProvider {
            name: "github", account: "unverified-456",
            email: "existing@example.com", verified: false,
        };
        let begin = service.begin(&fixture_config("github"), "https://example.com/callback", true)
            .await.unwrap();
        assert!(matches!(
            service.complete(&provider, "code", &begin.state, None, true).await,
            Err(AuthError::Unauthorized)
        ));
        assert!(db.find_many("account", Query::new()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_better_auth_insert_rolls_back_legacy_user() {
        let db = Arc::new(MemoryDb::default());
        db.insert_record("user", json!({
            "id": "42", "email": "unrelated@example.com", "name": "Unrelated",
            "email_verified": true, "image": null
        })).await.unwrap();
        let service = OAuthService::new(fixture_context(db.clone()), OAuthStateStorage::Verification).unwrap();
        let provisioner = LegacyProvisioner { db: db.clone() };
        let provider = FixtureProvider {
            name: "google", account: "collision", email: "new@example.com", verified: true,
        };
        let begin = service.begin(&fixture_config("google"), "https://example.com/callback", true)
            .await.unwrap();
        assert!(service.complete_with_provisioner(
            &provider, "code", &begin.state, None, true, &provisioner
        ).await.is_err());
        assert!(db.find_many("legacy_users", Query::new()).await.unwrap().is_empty());
        assert!(db.find_many("account", Query::new()).await.unwrap().is_empty());
    }

    struct RejectSession;

    #[async_trait]
    impl crate::hooks::AuthHooks for RejectSession {
        async fn before_session_create(&self, _user: &User) -> Result<()> {
            Err(AuthError::Forbidden("test session rejection".into()))
        }
    }

    #[tokio::test]
    async fn failed_session_creation_compensates_both_stores() {
        let db = Arc::new(MemoryDb::default());
        let context = AuthContext::new_with_hooks(
            AuthOptions {
                secret: "p".repeat(32),
                base_url: Some(BaseUrl::Static("https://example.com".into())),
                has_database: true,
                ..AuthOptions::default()
            },
            db.clone(),
            Some(Arc::new(MemorySecondaryStorage::default())),
            Vec::new(),
            vec![Arc::new(RejectSession)],
        ).unwrap();
        let service = OAuthService::new(context, OAuthStateStorage::Verification).unwrap();
        let provisioner = LegacyProvisioner { db: db.clone() };
        let provider = FixtureProvider {
            name: "google", account: "session-reject", email: "new@example.com", verified: true,
        };
        let begin = service.begin(&fixture_config("google"), "https://example.com/callback", true)
            .await.unwrap();
        assert!(service.complete_with_provisioner(
            &provider, "code", &begin.state, None, true, &provisioner
        ).await.is_err());
        for table in ["legacy_users", "user", "account", "session"] {
            assert!(db.find_many(table, Query::new()).await.unwrap().is_empty(), "{table}");
        }
    }

}
