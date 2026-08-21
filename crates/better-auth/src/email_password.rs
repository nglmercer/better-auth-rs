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
        if input.password.is_empty() {
            return Err(AuthError::InvalidRequest("password cannot be empty".into()));
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

        self.finish_sign_in(user, secure_cookie).await
    }

    pub async fn sign_in(&self, input: SignInInput, secure_cookie: bool) -> Result<AuthResult> {
        self.require_database()?;
        let email = normalize_email(&input.email)?;
        let user_value = self
            .context
            .adapter
            .find_one(USER_TABLE, Query::new().eq("email", email))
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let user: User = serde_json::from_value(user_value).map_err(serialize_error)?;
        let account_id = format!("{}:{EMAIL_PROVIDER}", user.id);
        let account = self
            .context
            .adapter
            .find_one(ACCOUNT_TABLE, Query::new().eq("id", account_id.clone()))
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let password_hash = account
            .get("password_hash")
            .and_then(Value::as_str)
            .ok_or(AuthError::Unauthorized)?;
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

        self.finish_sign_in(user, secure_cookie).await
    }

    pub async fn session_from_cookie(
        &self,
        headers: &http::HeaderMap,
        secure_cookie: bool,
    ) -> Result<Option<(User, Session)>> {
        Ok(self
            .sessions
            .resolve(headers, secure_cookie)
            .await?
            .map(|principal| (principal.user, principal.session)))
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
        self.sessions.create(user, secure_cookie).await
    }

    async fn finish_sign_in(&self, user: User, secure_cookie: bool) -> Result<AuthResult> {
        let result = self
            .create_authenticated_session(user, secure_cookie)
            .await?;
        self.context
            .after_sign_in(&AuthPrincipal {
                user: result.user.clone(),
                session: result.session.clone(),
            })
            .await?;
        Ok(result)
    }

    fn require_database(&self) -> Result<()> {
        if self.context.options.has_database {
            Ok(())
        } else {
            Err(AuthError::InvalidConfiguration(
                "email/password authentication requires a primary database".into(),
            ))
        }
    }
}

fn normalize_email(email: &str) -> Result<String> {
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

fn validate_name(name: &str) -> Result<()> {
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
        adapter::memory::MemoryDb,
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
}
