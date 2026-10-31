use crate::{
    context::AuthContext,
    cookies::AuthCookie,
    session::{AuthPrincipal, SessionService},
};
use better_auth_core::{
    adapter::{DbOperation, Query},
    error::{AuthError, Result},
};
use serde::{de::Deserializer, Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

const USER_TABLE: &str = "user";
const ACCOUNT_TABLE: &str = "account";
/// A real scrypt hash with the default parameters, used only to equalize timing.
/// It never matches a password a user could have, because it is a fixed value.
const DUMMY_PASSWORD_HASH: &str =
    "$scrypt$ln=15,r=8,p=1$psZvxW4xaeM76X2nvYV9Tw$pYBD6BLXG2Pn/CoYyM3g71r18m0bNhA7+lshZ6QvUxc";
pub(crate) const TWO_FACTOR_TABLE: &str = "two_factor";
pub(crate) const TWO_FACTOR_PLUGIN: &str = "two-factor";
const TWO_FACTOR_REQUIRED: &str = "TWO_FACTOR_REQUIRED";
const EMAIL_PROVIDER: &str = "credential";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub email_verified: bool,
    pub image: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_additional_fields",
        skip_serializing_if = "Map::is_empty"
    )]
    pub additional_fields: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SignUpInput {
    pub email: String,
    pub name: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SignInInput {
    pub email: String,
    pub password: String,
}

/// A pre-hashed credential imported from an existing application. The hash is
/// stored byte-for-byte and is only verified or upgraded after a successful
/// password login through the configured `PasswordProvider`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ImportCredential {
    pub id: Option<String>,
    pub email: String,
    pub name: String,
    pub email_verified: bool,
    pub password_hash: String,
    #[serde(default)]
    pub additional_fields: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug)]
pub struct AuthResult {
    pub user: User,
    pub session: Session,
    pub cookie: AuthCookie,
    /// The opaque token can be used with `Authorization: Bearer` when an
    /// application opts into bearer transport. Web responses need not expose
    /// it when cookies are the configured transport.
    pub session_token: String,
}

/// Imports existing users without requiring the plaintext password. Imported
/// hashes are intentionally not re-encoded; the normal sign-in flow can use a
/// composite provider to verify a legacy format and automatically rehash it.
#[derive(Clone)]
pub struct CredentialService {
    context: AuthContext,
}

impl CredentialService {
    pub fn new(context: AuthContext) -> Self {
        Self { context }
    }

    pub fn context(&self) -> &AuthContext {
        &self.context
    }

    pub async fn import(&self, credential: ImportCredential) -> Result<User> {
        require_database(&self.context)?;
        let email = normalize_email(&credential.email)?;
        validate_name(&credential.name)?;
        if credential.password_hash.is_empty() {
            return Err(AuthError::InvalidRequest(
                "password_hash cannot be empty".into(),
            ));
        }
        let id = credential.id.unwrap_or_else(|| Uuid::new_v4().to_string());
        if id.trim().is_empty() {
            return Err(AuthError::InvalidRequest("user id cannot be empty".into()));
        }
        if self
            .context
            .adapter
            .find_one(USER_TABLE, Query::new().eq("email", email.clone()))
            .await?
            .is_some()
        {
            return Err(AuthError::InvalidRequest(
                "email is already registered".into(),
            ));
        }

        let mut user = User {
            id,
            email,
            name: credential.name,
            email_verified: credential.email_verified,
            image: None,
            additional_fields: credential.additional_fields,
        };
        self.context.before_user_create(&mut user).await?;
        let account = json!({
            "id": format!("{}:{EMAIL_PROVIDER}", user.id),
            "user_id": user.id,
            "provider_id": EMAIL_PROVIDER,
            "account_id": user.email,
            "password_hash": credential.password_hash,
        });
        self.context
            .adapter
            .transaction(vec![
                DbOperation::InsertRecord {
                    table: USER_TABLE.into(),
                    record: serde_json::to_value(&user).map_err(serialize_error)?,
                },
                DbOperation::InsertRecord {
                    table: ACCOUNT_TABLE.into(),
                    record: account,
                },
            ])
            .await?;
        self.context.after_user_create(&user).await?;
        Ok(user)
    }
}

/// Core email/password operations. Request handlers should call these methods
/// only after applying request-level CSRF and rate-limit policy.
#[derive(Clone)]
pub struct EmailPasswordService {
    context: AuthContext,
    sessions: SessionService,
}

impl EmailPasswordService {
    pub fn new(context: AuthContext) -> Result<Self> {
        Ok(Self {
            sessions: SessionService::new(context.clone())?,
            context,
        })
    }

    pub fn context(&self) -> &AuthContext {
        &self.context
    }

    pub fn sessions(&self) -> &SessionService {
        &self.sessions
    }

    pub async fn sign_up(&self, input: SignUpInput, secure_cookie: bool) -> Result<AuthResult> {
        self.require_database()?;
        let email = normalize_email(&input.email)?;
        validate_name(&input.name)?;
        validate_password(&input.password)?;
        if self
            .context
            .adapter
            .find_one(USER_TABLE, Query::new().eq("email", email.clone()))
            .await?
            .is_some()
        {
            return Err(AuthError::InvalidRequest(
                "email is already registered".into(),
            ));
        }

        let mut user = User {
            id: Uuid::new_v4().to_string(),
            email,
            name: input.name,
            email_verified: false,
            image: None,
            additional_fields: Map::new(),
        };
        self.context.before_user_create(&mut user).await?;
        let password_hash = self.context.password_provider.hash(&input.password).await?;
        let account_id = format!("{}:{EMAIL_PROVIDER}", user.id);
        let account = json!({
            "id": account_id,
            "user_id": user.id,
            "provider_id": EMAIL_PROVIDER,
            "account_id": user.email,
            "password_hash": password_hash,
        });
        let inserted = self
            .context
            .adapter
            .transaction(vec![
                DbOperation::InsertRecord {
                    table: USER_TABLE.into(),
                    record: serde_json::to_value(&user).map_err(serialize_error)?,
                },
                DbOperation::InsertRecord {
                    table: ACCOUNT_TABLE.into(),
                    record: account,
                },
            ])
            .await;
        if let Err(error) = inserted {
            // A concurrent sign-up for the same address can pass the read check
            // above. The unique index rejects the loser, which then gets the same
            // answer as a sequential duplicate instead of an internal error.
            let taken = self
                .context
                .adapter
                .find_one(USER_TABLE, Query::new().eq("email", user.email.clone()))
                .await?
                .is_some();
            return Err(if taken {
                AuthError::InvalidRequest("email is already registered".into())
            } else {
                error
            });
        }
        if let Err(error) = self.context.after_user_create(&user).await {
            // A failed lifecycle hook must not leave a usable account behind.
            // Cleanup is best effort: the hook error is what the caller needs.
            let _ = self
                .context
                .adapter
                .transaction(vec![
                    DbOperation::DeleteWhere {
                        table: ACCOUNT_TABLE.into(),
                        query: Query::new().eq("user_id", user.id.clone()),
                    },
                    DbOperation::DeleteWhere {
                        table: USER_TABLE.into(),
                        query: Query::new().eq("id", user.id.clone()),
                    },
                ])
                .await;
            return Err(error);
        }

        self.finish_sign_in(user, secure_cookie).await
    }

    /// Checks the email and password and returns the user without creating a
    /// session. Callers that handle a second factor branch on the result.
    pub async fn verify_credentials(&self, input: SignInInput) -> Result<User> {
        self.require_database()?;
        let email = normalize_email(&input.email)?;
        let Some(user_value) = self
            .context
            .adapter
            .find_one(USER_TABLE, Query::new().eq("email", email))
            .await?
        else {
            return self.reject_after_dummy_verify(&input.password).await;
        };
        let user: User = serde_json::from_value(user_value).map_err(serialize_error)?;
        let account_id = format!("{}:{EMAIL_PROVIDER}", user.id);
        let Some(account) = self
            .context
            .adapter
            .find_one(ACCOUNT_TABLE, Query::new().eq("id", account_id.clone()))
            .await?
        else {
            return self.reject_after_dummy_verify(&input.password).await;
        };
        let Some(password_hash) = account.get("password_hash").and_then(Value::as_str) else {
            return self.reject_after_dummy_verify(&input.password).await;
        };
        let verification = self
            .context
            .password_provider
            .verify(&input.password, password_hash)
            .await?;
        if !verification.valid {
            return Err(AuthError::Unauthorized);
        }
        if verification.needs_rehash {
            let replacement = self.context.password_provider.hash(&input.password).await?;
            self.context
                .adapter
                .update_where(
                    ACCOUNT_TABLE,
                    Query::new().eq("id", account_id),
                    json!({"password_hash": replacement}),
                )
                .await?;
        }

        Ok(user)
    }

    pub async fn sign_in(&self, input: SignInInput, secure_cookie: bool) -> Result<AuthResult> {
        let user = self.verify_credentials(input).await?;
        // No session may exist until the second factor is verified. Callers
        // that can complete a challenge use `verify_credentials` instead.
        if two_factor_required(&self.context, &user.id).await? {
            return Err(AuthError::Forbidden(TWO_FACTOR_REQUIRED.into()));
        }
        self.finish_sign_in(user, secure_cookie).await
    }

    /// Spends the same password-hashing time as a real check before refusing.
    /// Without this, an unknown address answers faster than a known one, and
    /// response timing reveals which accounts exist.
    async fn reject_after_dummy_verify(&self, password: &str) -> Result<User> {
        let _ = self
            .context
            .password_provider
            .verify(password, DUMMY_PASSWORD_HASH)
            .await;
        Err(AuthError::Unauthorized)
    }

    /// Creates the session for a user whose credentials, and any second factor,
    /// have already been verified.
    pub async fn complete_sign_in(&self, user: User, secure_cookie: bool) -> Result<AuthResult> {
        self.finish_sign_in(user, secure_cookie).await
    }

    pub async fn session_from_cookie(
        &self,
        headers: &http::HeaderMap,
        secure_cookie: bool,
    ) -> Result<Option<(User, Session)>> {
        let Some(principal) = self.sessions.resolve(headers, secure_cookie).await? else {
            return Ok(None);
        };
        // A ban takes effect on the next request, even for a session that was
        // created before it, in case the sessions were not deleted in time.
        if crate::plugins::account_is_banned(&self.context, &principal.user.id).await? {
            return Ok(None);
        }
        Ok(Some((principal.user, principal.session)))
    }

    pub async fn refresh_session_cookie(
        &self,
        headers: &http::HeaderMap,
        secure_cookie: bool,
    ) -> Result<Option<AuthCookie>> {
        self.sessions.refresh(headers, secure_cookie).await
    }

    pub async fn sign_out(
        &self,
        headers: &http::HeaderMap,
        secure_cookie: bool,
    ) -> Result<AuthCookie> {
        self.sessions.revoke(headers, secure_cookie).await
    }

    async fn create_authenticated_session(
        &self,
        user: User,
        secure_cookie: bool,
    ) -> Result<AuthResult> {
        if crate::plugins::account_is_banned(&self.context, &user.id).await? {
            return Err(AuthError::Forbidden("account is banned".into()));
        }
        self.sessions.create(user, secure_cookie).await
    }

    async fn finish_sign_in(&self, user: User, secure_cookie: bool) -> Result<AuthResult> {
        let result = self
            .create_authenticated_session(user, secure_cookie)
            .await?;
        if let Err(error) = self
            .context
            .after_sign_in(&AuthPrincipal {
                user: result.user.clone(),
                session: result.session.clone(),
            })
            .await
        {
            // The client never receives this session, so it must not stay valid.
            let _ = self.sessions.discard(&result.session.id).await;
            return Err(error);
        }
        Ok(result)
    }

    fn require_database(&self) -> Result<()> {
        require_database(&self.context)
    }
}

/// Returns `true` when the user has a two-factor record that is not explicitly
/// disabled. The check only runs when the two-factor plugin is registered,
/// because its table is absent otherwise. A malformed `enabled` value is
/// treated as enabled.
/// Reports whether a plugin with this name is registered. Plugin-owned tables
/// exist only when their plugin is registered, so queries must check first.
pub(crate) fn has_plugin(context: &AuthContext, name: &str) -> bool {
    context
        .plugins
        .plugins()
        .iter()
        .any(|plugin| plugin.name() == name)
}

pub(crate) async fn two_factor_required(context: &AuthContext, user_id: &str) -> Result<bool> {
    if !has_plugin(context, TWO_FACTOR_PLUGIN) {
        return Ok(false);
    }
    let record = context
        .adapter
        .find_one(
            TWO_FACTOR_TABLE,
            Query::new().eq("user_id", user_id.to_owned()),
        )
        .await?;
    Ok(record.is_some_and(|record| record.get("enabled").and_then(Value::as_bool) != Some(false)))
}

fn require_database(context: &AuthContext) -> Result<()> {
    if context.options.has_database {
        Ok(())
    } else {
        Err(AuthError::InvalidConfiguration(
            "email/password authentication requires a primary database".into(),
        ))
    }
}

pub(crate) fn normalize_email(email: &str) -> Result<String> {
    let normalized = email.trim().to_ascii_lowercase();
    let valid = normalized.len() >= 3
        && normalized.len() <= 320
        && normalized.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        });
    if !valid {
        return Err(AuthError::InvalidRequest("invalid email address".into()));
    }
    Ok(normalized)
}

/// Password policy shared by sign-up, password change and password reset.
/// The minimum follows the NIST SP 800-63B recommendation of 8 characters.
pub(crate) fn validate_password(password: &str) -> Result<()> {
    let length = password.chars().count();
    if !(8..=128).contains(&length) {
        return Err(AuthError::InvalidRequest(
            "password must be between 8 and 128 characters".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_name(name: &str) -> Result<()> {
    let length = name.chars().count();
    if !(1..=200).contains(&length) {
        return Err(AuthError::InvalidRequest(
            "name must be between 1 and 200 characters".into(),
        ));
    }
    Ok(())
}

fn serialize_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Adapter(format!("record serialization failed: {error}"))
}

fn deserialize_additional_fields<'de, D>(
    deserializer: D,
) -> std::result::Result<Map<String, Value>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Map<String, Value>>::deserialize(deserializer).map(|value| value.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::{
        adapter::{memory::MemoryDb, DbAdapter, Query},
        options::{AuthOptions, BaseUrl},
    };
    use http::HeaderMap;
    use std::sync::Arc;

    #[tokio::test]
    async fn email_password_flow_persists_and_reads_a_session() {
        let context = AuthContext::new(
            AuthOptions {
                secret: "e".repeat(32),
                base_url: Some(BaseUrl::Static("https://example.com".into())),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(MemoryDb::default()),
            None,
            Vec::new(),
        )
        .unwrap();
        let service = EmailPasswordService::new(context).unwrap();
        let result = service
            .sign_up(
                SignUpInput {
                    email: "User@Example.com".into(),
                    name: "User".into(),
                    password: "correct horse battery staple".into(),
                },
                true,
            )
            .await
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            result
                .cookie
                .to_set_cookie_header()
                .split(';')
                .next()
                .unwrap()
                .parse()
                .unwrap(),
        );
        let (user, session) = service
            .session_from_cookie(&headers, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user.email, "user@example.com");
        assert_eq!(session.user_id, result.user.id);
        let mut bearer_headers = HeaderMap::new();
        bearer_headers.insert(
            "authorization",
            format!("Bearer {}", result.session_token).parse().unwrap(),
        );
        let principal = service
            .sessions()
            .resolve_with_transport(
                &bearer_headers,
                true,
                crate::session::SessionTransport::Bearer,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(principal.user.id, result.user.id);
        let removal = service.sign_out(&headers, true).await.unwrap();
        assert_eq!(removal.max_age_seconds, Some(0));
        assert!(service
            .session_from_cookie(&headers, true)
            .await
            .unwrap()
            .is_none());
    }

    struct FailingSessionHook;

    #[async_trait::async_trait]
    impl crate::hooks::AuthHooks for FailingSessionHook {
        async fn after_session_create(&self, _user: &User, _session: &Session) -> Result<()> {
            Err(AuthError::Plugin("downstream sync failed".into()))
        }
    }

    #[tokio::test]
    async fn failed_session_hook_leaves_no_orphan_session() {
        let context = AuthContext::new_with_hooks(
            AuthOptions {
                secret: "h".repeat(32),
                base_url: Some(BaseUrl::Static("https://example.com".into())),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(MemoryDb::default()),
            None,
            Vec::new(),
            vec![Arc::new(FailingSessionHook)],
        )
        .unwrap();
        let service = EmailPasswordService::new(context.clone()).unwrap();
        let error = service
            .sign_up(
                SignUpInput {
                    email: "orphan@example.com".into(),
                    name: "Orphan".into(),
                    password: "correct horse battery staple".into(),
                },
                true,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, AuthError::Plugin(_)));
        let sessions = context
            .adapter
            .find_many("session", Query::new())
            .await
            .unwrap();
        assert!(sessions.is_empty(), "orphan sessions: {sessions:?}");
    }

    struct CountingPasswords {
        inner: crate::password::ScryptPhcPasswordProvider,
        verifications: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl crate::password::PasswordProvider for CountingPasswords {
        async fn hash(&self, password: &str) -> Result<String> {
            self.inner.hash(password).await
        }

        async fn verify(
            &self,
            password: &str,
            encoded: &str,
        ) -> Result<crate::password::PasswordVerification> {
            self.verifications
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.verify(password, encoded).await
        }
    }

    #[tokio::test]
    async fn unknown_address_pays_the_same_hashing_cost_as_a_known_one() {
        use std::sync::atomic::Ordering::SeqCst;
        let passwords = Arc::new(CountingPasswords {
            inner: crate::password::ScryptPhcPasswordProvider::new(
                AuthOptions::default().password_hash,
            ),
            verifications: std::sync::atomic::AtomicUsize::new(0),
        });
        let context = AuthContext::new_with_password_provider(
            AuthOptions {
                secret: "u".repeat(32),
                base_url: Some(BaseUrl::Static("https://example.com".into())),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(MemoryDb::default()),
            None,
            Vec::new(),
            passwords.clone(),
        )
        .unwrap();
        let service = EmailPasswordService::new(context).unwrap();
        let attempt = |email: &str| SignInInput {
            email: email.into(),
            password: "some password here".into(),
        };
        let unknown = service.sign_in(attempt("nobody@example.com"), true).await;
        assert!(matches!(unknown, Err(AuthError::Unauthorized)));
        assert_eq!(
            passwords.verifications.load(SeqCst),
            1,
            "unknown address is hashed too"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn concurrent_sign_up_with_one_email_creates_exactly_one_account() {
        use crate::database::SqliteDbAdapter;
        use better_auth_core::{migration::MigrationPlan, schema::core_schema};

        let adapter = Arc::new(SqliteDbAdapter::in_memory().unwrap());
        adapter
            .apply_migrations(&MigrationPlan::from_schema(&core_schema()))
            .await
            .unwrap();
        // The delay runs after the read check, so both sign-ups see no user and
        // then race to insert. That is the window the unique index must close.
        struct WidenRaceWindow;

        #[async_trait::async_trait]
        impl crate::hooks::AuthHooks for WidenRaceWindow {
            async fn before_user_create(&self, _user: &mut User) -> Result<()> {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                Ok(())
            }
        }

        let context = AuthContext::new_with_hooks(
            AuthOptions {
                secret: "c".repeat(32),
                base_url: Some(BaseUrl::Static("https://example.com".into())),
                has_database: true,
                ..AuthOptions::default()
            },
            adapter.clone(),
            None,
            Vec::new(),
            vec![Arc::new(WidenRaceWindow)],
        )
        .unwrap();
        let service = EmailPasswordService::new(context).unwrap();
        let input = || SignUpInput {
            email: "race@example.com".into(),
            name: "Race".into(),
            password: "correct horse battery staple".into(),
        };
        let (first, second) = tokio::join!(
            service.sign_up(input(), true),
            service.sign_up(input(), true)
        );
        let outcomes = [first, second];
        assert_eq!(outcomes.iter().filter(|o| o.is_ok()).count(), 1);
        let loser = outcomes
            .into_iter()
            .find(|o| o.is_err())
            .unwrap()
            .unwrap_err();
        assert!(matches!(loser, AuthError::InvalidRequest(_)), "{loser:?}");
        let users = adapter.find_many(USER_TABLE, Query::new()).await.unwrap();
        assert_eq!(users.len(), 1);
    }

    #[tokio::test]
    async fn two_factor_enabled_user_gets_no_session_on_password_sign_in() {
        let context = AuthContext::new(
            AuthOptions {
                secret: "t".repeat(32),
                base_url: Some(BaseUrl::Static("https://example.com".into())),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(MemoryDb::default()),
            None,
            vec![Arc::new(crate::plugins::TwoFactorPlugin)],
        )
        .unwrap();
        let service = EmailPasswordService::new(context.clone()).unwrap();
        let signed_up = service
            .sign_up(
                SignUpInput {
                    email: "mfa@example.com".into(),
                    name: "MFA".into(),
                    password: "correct horse battery staple".into(),
                },
                true,
            )
            .await
            .unwrap();
        let user_id = signed_up.user.id.clone();
        context
            .adapter
            .transaction(vec![DbOperation::InsertRecord {
                table: "two_factor".into(),
                record: json!({
                    "id": "tf-1",
                    "user_id": user_id,
                    "secret": "JBSWY3DPEHPK3PXP",
                    "enabled": true,
                    "backup_codes": [],
                }),
            }])
            .await
            .unwrap();
        let input = || SignInInput {
            email: "mfa@example.com".into(),
            password: "correct horse battery staple".into(),
        };
        let refused = service.sign_in(input(), true).await.unwrap_err();
        assert!(matches!(refused, AuthError::Forbidden(ref code) if code == "TWO_FACTOR_REQUIRED"));

        context
            .adapter
            .update_where(
                "two_factor",
                Query::new().eq("user_id", user_id.clone()),
                json!({"enabled": false}),
            )
            .await
            .unwrap();
        assert!(service.sign_in(input(), true).await.is_ok());
    }

    #[tokio::test]
    async fn credential_import_preserves_the_supplied_hash() {
        let adapter = Arc::new(MemoryDb::default());
        let context = AuthContext::new(
            AuthOptions {
                secret: "i".repeat(32),
                ..AuthOptions::default()
            },
            adapter.clone(),
            None,
            Vec::new(),
        )
        .unwrap();
        let service = CredentialService::new(context);
        let user = service
            .import(ImportCredential {
                id: Some("legacy-user".into()),
                email: "Legacy@Example.com".into(),
                name: "Legacy User".into(),
                email_verified: true,
                password_hash: "legacy-salt:legacy-key".into(),
                additional_fields: Map::from_iter([("country".into(), Value::String("PE".into()))]),
            })
            .await
            .unwrap();

        assert_eq!(user.id, "legacy-user");
        let account = adapter
            .find_one(
                ACCOUNT_TABLE,
                Query::new().eq("id", "legacy-user:credential"),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(account["password_hash"], "legacy-salt:legacy-key");
    }
}
