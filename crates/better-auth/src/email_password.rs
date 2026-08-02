use crate::{
    context::AuthContext,
    cookies::{request_cookies, AuthCookie, CookieCacheClaims, CookieCacheCodec, SecretKeySet},
    hash_password, verify_password,
};
use better_auth_core::{
    adapter::DbOperation,
    error::{AuthError, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const USER_TABLE: &str = "user";
const ACCOUNT_TABLE: &str = "account";
const SESSION_TABLE: &str = "session";
const EMAIL_PROVIDER: &str = "credential";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub email_verified: bool,
    pub image: Option<String>,
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
}

/// Core email/password operations. Request handlers should call these methods
/// only after applying request-level CSRF and rate-limit policy.
#[derive(Clone)]
pub struct EmailPasswordService {
    context: AuthContext,
    keys: SecretKeySet,
    cache: CookieCacheCodec,
}

impl EmailPasswordService {
    pub fn new(context: AuthContext) -> Result<Self> {
        let keys = SecretKeySet::from_options(&context.options)?;
        let cache = CookieCacheCodec::new(keys.clone());
        Ok(Self {
            context,
            keys,
            cache,
        })
    }

    pub fn context(&self) -> &AuthContext {
        &self.context
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
            .get_by_field(USER_TABLE, "email", &Value::String(email.clone()))
            .await?
            .is_some()
        {
            return Err(AuthError::InvalidRequest(
                "email is already registered".into(),
            ));
        }

        let user = User {
            id: Uuid::new_v4().to_string(),
            email,
            name: input.name,
            email_verified: false,
            image: None,
        };
        let password_hash = hash_password(&input.password)?;
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
                DbOperation::Insert {
                    table: USER_TABLE.into(),
                    id: user.id.clone(),
                    record: serde_json::to_value(&user).map_err(serialize_error)?,
                },
                DbOperation::Insert {
                    table: ACCOUNT_TABLE.into(),
                    id: account_id,
                    record: account,
                },
            ])
            .await?;

        self.create_authenticated_session(user, secure_cookie).await
    }

    pub async fn sign_in(&self, input: SignInInput, secure_cookie: bool) -> Result<AuthResult> {
        self.require_database()?;
        let email = normalize_email(&input.email)?;
        let (_, user_value) = self
            .context
            .adapter
            .get_by_field(USER_TABLE, "email", &Value::String(email))
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let user: User = serde_json::from_value(user_value).map_err(serialize_error)?;
        let account_id = format!("{}:{EMAIL_PROVIDER}", user.id);
        let account = self
            .context
            .adapter
            .get(ACCOUNT_TABLE, &account_id)
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let password_hash = account
            .get("password_hash")
            .and_then(Value::as_str)
            .ok_or(AuthError::Unauthorized)?;
        if !verify_password(&input.password, password_hash)? {
            return Err(AuthError::Unauthorized);
        }

        self.create_authenticated_session(user, secure_cookie).await
    }

    pub async fn session_from_cookie(
        &self,
        headers: &http::HeaderMap,
        secure_cookie: bool,
    ) -> Result<Option<(User, Session)>> {
        let cookies = request_cookies(headers);
        let name = if secure_cookie {
            "__Secure-better-auth.session_token"
        } else {
            "better-auth.session_token"
        };
        let Some(value) = cookies.get(name) else {
            return Ok(None);
        };
        let Ok(verified) = self.read_cookie(value) else {
            return Ok(None);
        };
        match verified {
            VerifiedCookie::Opaque(token) => self.session_from_database(&token).await,
            VerifiedCookie::Cache(claims) => {
                if self.context.options.has_database {
                    let Some(token) = claims.data.get("token").and_then(Value::as_str) else {
                        return Ok(None);
                    };
                    self.session_from_database(token).await
                } else {
                    let user: User = serde_json::from_value(
                        claims
                            .data
                            .get("user")
                            .cloned()
                            .ok_or(AuthError::Unauthorized)?,
                    )
                    .map_err(serialize_error)?;
                    let session: Session = serde_json::from_value(
                        claims
                            .data
                            .get("session")
                            .cloned()
                            .ok_or(AuthError::Unauthorized)?,
                    )
                    .map_err(serialize_error)?;
                    if session.user_id != user.id || session.expires_at <= now_seconds() {
                        return Ok(None);
                    }
                    Ok(Some((user, session)))
                }
            }
        }
    }

    pub async fn refresh_session_cookie(
        &self,
        headers: &http::HeaderMap,
        secure_cookie: bool,
    ) -> Result<Option<AuthCookie>> {
        let Some((user, mut session)) = self.session_from_cookie(headers, secure_cookie).await?
        else {
            return Ok(None);
        };
        let now = now_seconds();
        if session.expires_at.saturating_sub(now) > self.context.options.session.update_age_seconds
        {
            return Ok(None);
        }
        let cookies = request_cookies(headers);
        let name = session_cookie_name(secure_cookie);
        let Some(value) = cookies.get(name) else {
            return Ok(None);
        };
        let verified = self
            .read_cookie(value)
            .map_err(|_| AuthError::Unauthorized)?;
        let token = match verified {
            VerifiedCookie::Opaque(token) => token,
            VerifiedCookie::Cache(claims) => claims
                .data
                .get("token")
                .and_then(Value::as_str)
                .ok_or(AuthError::Unauthorized)?
                .to_owned(),
        };
        session.expires_at = now + self.context.options.session.expires_in_seconds;
        if self.context.options.has_database {
            self.context
                .adapter
                .update(
                    SESSION_TABLE,
                    &session.id,
                    json!({
                        "id": session.id,
                        "user_id": session.user_id,
                        "expires_at": session.expires_at,
                        "token_hash": hash_session_token(&token),
                    }),
                )
                .await?;
        }
        Ok(Some(self.build_cookie(
            &user,
            &session,
            &token,
            secure_cookie,
        )?))
    }

    pub async fn sign_out(
        &self,
        headers: &http::HeaderMap,
        secure_cookie: bool,
    ) -> Result<AuthCookie> {
        let cookies = request_cookies(headers);
        let name = if secure_cookie {
            "__Secure-better-auth.session_token"
        } else {
            "better-auth.session_token"
        };
        if let Some(value) = cookies.get(name) {
            if let Ok(verified) = self.read_cookie(value) {
                let token = match verified {
                    VerifiedCookie::Opaque(token) => Some(token),
                    VerifiedCookie::Cache(claims) => claims
                        .data
                        .get("token")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                };
                if let Some(token) = token {
                    let token_hash = hash_session_token(&token);
                    if let Some((session_id, _)) = self
                        .context
                        .adapter
                        .get_by_field(SESSION_TABLE, "token_hash", &Value::String(token_hash))
                        .await?
                    {
                        self.context
                            .adapter
                            .delete(SESSION_TABLE, &session_id)
                            .await?;
                    }
                }
            }
        }
        Ok(AuthCookie::removal(
            name,
            secure_cookie,
            &self.context.options.base_path,
        ))
    }

    async fn create_authenticated_session(
        &self,
        user: User,
        secure_cookie: bool,
    ) -> Result<AuthResult> {
        let token = Uuid::new_v4().to_string();
        let session = Session {
            id: Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            expires_at: now_seconds() + self.context.options.session.expires_in_seconds,
        };
        let record = json!({
            "id": session.id,
            "user_id": session.user_id,
            "expires_at": session.expires_at,
            "token_hash": hash_session_token(&token),
        });
        if self.context.options.has_database {
            self.context
                .adapter
                .insert(SESSION_TABLE, &session.id, record)
                .await?;
        }
        let cookie = self.build_cookie(&user, &session, &token, secure_cookie)?;
        Ok(AuthResult {
            user,
            session,
            cookie,
        })
    }

    pub(crate) async fn create_session_for_user(
        &self,
        user: User,
        secure_cookie: bool,
    ) -> Result<AuthResult> {
        self.create_authenticated_session(user, secure_cookie).await
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

    async fn session_from_database(&self, token: &str) -> Result<Option<(User, Session)>> {
        let token_hash = hash_session_token(token);
        let Some((_, session_value)) = self
            .context
            .adapter
            .get_by_field(SESSION_TABLE, "token_hash", &Value::String(token_hash))
            .await?
        else {
            return Ok(None);
        };
        let session: Session = serde_json::from_value(session_value).map_err(serialize_error)?;
        if session.expires_at <= now_seconds() {
            let _ = self
                .context
                .adapter
                .delete(SESSION_TABLE, &session.id)
                .await;
            return Ok(None);
        }
        let user_value = self
            .context
            .adapter
            .get(USER_TABLE, &session.user_id)
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let user = serde_json::from_value(user_value).map_err(serialize_error)?;
        Ok(Some((user, session)))
    }

    fn read_cookie(&self, value: &str) -> Result<VerifiedCookie> {
        if self.context.options.session.cookie_cache.enabled {
            Ok(VerifiedCookie::Cache(self.cache.decode(
                self.context.options.session.cookie_cache.strategy,
                value,
                now_seconds(),
            )?))
        } else {
            Ok(VerifiedCookie::Opaque(self.keys.verify(value)?))
        }
    }

    fn build_cookie(
        &self,
        user: &User,
        session: &Session,
        token: &str,
        secure_cookie: bool,
    ) -> Result<AuthCookie> {
        let value = if self.context.options.session.cookie_cache.enabled {
            let now = now_seconds();
            let cache_age = self.context.options.session.cookie_cache.max_age_seconds;
            self.cache.encode(
                self.context.options.session.cookie_cache.strategy,
                user.id.clone(),
                json!({"user": user, "session": session, "token": token}),
                now,
                now + if cache_age == 0 {
                    self.context.options.session.expires_in_seconds
                } else {
                    cache_age
                },
            )?
        } else {
            self.keys.sign(token)?
        };
        let max_age = if self.context.options.session.cookie_cache.enabled
            && self.context.options.session.cookie_cache.max_age_seconds > 0
        {
            self.context.options.session.cookie_cache.max_age_seconds
        } else {
            self.context.options.session.expires_in_seconds
        };
        Ok(AuthCookie::session(
            value,
            secure_cookie,
            &self.context.options.base_path,
            max_age,
        ))
    }
}

enum VerifiedCookie {
    Opaque(String),
    Cache(CookieCacheClaims),
}

fn session_cookie_name(secure_cookie: bool) -> &'static str {
    if secure_cookie {
        "__Secure-better-auth.session_token"
    } else {
        "better-auth.session_token"
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

fn hash_session_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

fn serialize_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Adapter(format!("record serialization failed: {error}"))
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
        let removal = service.sign_out(&headers, true).await.unwrap();
        assert_eq!(removal.max_age_seconds, Some(0));
        assert!(service
            .session_from_cookie(&headers, true)
            .await
            .unwrap()
            .is_none());
    }
}
