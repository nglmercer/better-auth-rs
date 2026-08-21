use crate::{
    context::{AuthContext, RequestMetadata},
    cookies::{
        request_cookies, session_cookie_name, AuthCookie, CookieCacheClaims, CookieCacheCodec,
        SecretKeySet,
    },
    email_password::{AuthResult, Session, User},
};
use better_auth_core::{
    adapter::Query,
    error::{AuthError, Result},
};
use http::HeaderMap;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const USER_TABLE: &str = "user";
const SESSION_TABLE: &str = "session";

/// The framework-neutral authenticated identity returned by session
/// resolution. Framework integrations can wrap this in their own extractor.
#[derive(Clone, Debug)]
pub struct AuthPrincipal {
    pub user: User,
    pub session: Session,
}

/// Transport used to carry a Better Auth session token. Cookies remain the
/// browser default; bearer support is opt-in for native clients and WebSocket
/// handshakes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionTransport {
    Cookie,
    Bearer,
    CookieOrBearer,
}

/// Session lifecycle and request authentication, independent of the login
/// mechanism that created the session.
#[derive(Clone)]
pub struct SessionService {
    context: AuthContext,
    keys: SecretKeySet,
    cache: CookieCacheCodec,
}

impl SessionService {
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

    /// Creates a session for any authenticated user, regardless of whether
    /// the user arrived through password, OAuth, SSO, or a passkey.
    pub async fn create(&self, user: User, secure_cookie: bool) -> Result<AuthResult> {
        self.context.before_session_create(&user).await?;
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
                .insert_record(SESSION_TABLE, record)
                .await?;
        }
        let cookie = self.build_cookie(&user, &session, &token, secure_cookie)?;
        let result = AuthResult {
            user,
            session,
            cookie,
            session_token: token,
        };
        self.context
            .after_session_create(&result.user, &result.session)
            .await?;
        Ok(result)
    }

    /// Resolves the current session from request metadata. This is suitable
    /// for HTTP middleware and WebSocket upgrade paths alike.
    pub async fn resolve_request(
        &self,
        request: &RequestMetadata,
    ) -> Result<Option<AuthPrincipal>> {
        self.resolve_request_with_transport(request, SessionTransport::Cookie)
            .await
    }

    pub async fn resolve_request_with_transport(
        &self,
        request: &RequestMetadata,
        transport: SessionTransport,
    ) -> Result<Option<AuthPrincipal>> {
        let request_context = self.context.resolve_request(request)?;
        let secure_cookie = request_context
            .base_url
            .as_ref()
            .is_some_and(|url| url.scheme() == "https");
        self.resolve_with_transport(&request.headers, secure_cookie, transport)
            .await
    }

    pub async fn resolve(
        &self,
        headers: &HeaderMap,
        secure_cookie: bool,
    ) -> Result<Option<AuthPrincipal>> {
        self.resolve_with_transport(headers, secure_cookie, SessionTransport::Cookie)
            .await
    }

    pub async fn resolve_with_transport(
        &self,
        headers: &HeaderMap,
        secure_cookie: bool,
        transport: SessionTransport,
    ) -> Result<Option<AuthPrincipal>> {
        if matches!(
            transport,
            SessionTransport::Bearer | SessionTransport::CookieOrBearer
        ) {
            if let Some(token) = bearer_token(headers) {
                let principal = self.resolve_database(&token).await?;
                if principal.is_some() || transport == SessionTransport::Bearer {
                    return Ok(principal);
                }
            }
            if transport == SessionTransport::Bearer {
                return Ok(None);
            }
        }
        self.resolve_cookie(headers, secure_cookie).await
    }

    async fn resolve_cookie(
        &self,
        headers: &HeaderMap,
        secure_cookie: bool,
    ) -> Result<Option<AuthPrincipal>> {
        let cookies = request_cookies(headers);
        let name = session_cookie_name(&self.context.options.cookie, secure_cookie);
        let Some(value) = cookies.get(&name) else {
            return Ok(None);
        };
        let Ok(verified) = self.read_cookie(value) else {
            return Ok(None);
        };
        match verified {
            VerifiedCookie::Opaque(token) => self.resolve_database(&token).await,
            VerifiedCookie::Cache(claims) => {
                if self.context.options.has_database {
                    let Some(token) = claims.data.get("token").and_then(Value::as_str) else {
                        return Ok(None);
                    };
                    self.resolve_database(token).await
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
                    Ok(Some(AuthPrincipal { user, session }))
                }
            }
        }
    }

    pub async fn refresh(
        &self,
        headers: &HeaderMap,
        secure_cookie: bool,
    ) -> Result<Option<AuthCookie>> {
        let Some(principal) = self.resolve(headers, secure_cookie).await? else {
            return Ok(None);
        };
        let now = now_seconds();
        if principal.session.expires_at.saturating_sub(now)
            > self.context.options.session.update_age_seconds
        {
            return Ok(None);
        }
        let cookies = request_cookies(headers);
        let name = session_cookie_name(&self.context.options.cookie, secure_cookie);
        let Some(value) = cookies.get(&name) else {
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
        let session = Session {
            expires_at: now + self.context.options.session.expires_in_seconds,
            ..principal.session
        };
        if self.context.options.has_database {
            self.context
                .adapter
                .update_where(
                    SESSION_TABLE,
                    Query::new().eq("id", session.id.clone()),
                    json!({
                        "user_id": session.user_id,
                        "expires_at": session.expires_at,
                        "token_hash": hash_session_token(&token),
                    }),
                )
                .await?;
        }
        Ok(Some(self.build_cookie(
            &principal.user,
            &session,
            &token,
            secure_cookie,
        )?))
    }

    pub async fn revoke(&self, headers: &HeaderMap, secure_cookie: bool) -> Result<AuthCookie> {
        let name = session_cookie_name(&self.context.options.cookie, secure_cookie);
        let cookies = request_cookies(headers);
        if let Some(value) = cookies.get(&name) {
            if let Ok(verified) = self.read_cookie(value) {
                let token = match verified {
                    VerifiedCookie::Opaque(token) => Some(token),
                    VerifiedCookie::Cache(claims) => claims
                        .data
                        .get("token")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                };
                if self.context.options.has_database {
                    if let Some(token) = token {
                        self.context
                            .adapter
                            .delete_where(
                                SESSION_TABLE,
                                Query::new().eq("token_hash", hash_session_token(&token)),
                            )
                            .await?;
                    }
                }
            }
        }
        Ok(AuthCookie::removal_with_options(
            name,
            secure_cookie,
            &self.context.options.cookie,
        ))
    }

    pub async fn revoke_all_for_user(&self, user_id: &str) -> Result<u64> {
        if !self.context.options.has_database {
            return Ok(0);
        }
        self.context
            .adapter
            .delete_where(
                SESSION_TABLE,
                Query::new().eq("user_id", user_id.to_owned()),
            )
            .await
    }

    pub async fn revoke_token(&self, token: &str) -> Result<u64> {
        if !self.context.options.has_database {
            return Ok(0);
        }
        self.context
            .adapter
            .delete_where(
                SESSION_TABLE,
                Query::new().eq("token_hash", hash_session_token(token)),
            )
            .await
    }

    async fn resolve_database(&self, token: &str) -> Result<Option<AuthPrincipal>> {
        let Some(session_value) = self
            .context
            .adapter
            .find_one(
                SESSION_TABLE,
                Query::new().eq("token_hash", hash_session_token(token)),
            )
            .await?
        else {
            return Ok(None);
        };
        let session: Session = serde_json::from_value(session_value).map_err(serialize_error)?;
        if session.expires_at <= now_seconds() {
            let _ = self
                .context
                .adapter
                .delete_where(SESSION_TABLE, Query::new().eq("id", session.id.clone()))
                .await;
            return Ok(None);
        }
        let user_value = self
            .context
            .adapter
            .find_one(USER_TABLE, Query::new().eq("id", session.user_id.clone()))
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let user = serde_json::from_value(user_value).map_err(serialize_error)?;
        Ok(Some(AuthPrincipal { user, session }))
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
        Ok(AuthCookie::session_with_options(
            value,
            secure_cookie,
            &self.context.options.cookie,
            max_age,
        ))
    }
}

enum VerifiedCookie {
    Opaque(String),
    Cache(CookieCacheClaims),
}

fn hash_session_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.trim().is_empty() {
        return None;
    }
    Some(token.trim().to_owned())
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
