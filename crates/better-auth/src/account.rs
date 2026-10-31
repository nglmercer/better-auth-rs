//! Account and session management for the signed-in user.
//!
//! Every operation resolves the caller's session first and then scopes its
//! queries to that user. Session identifiers supplied by the client are never
//! trusted on their own, so one user cannot list or revoke another user's
//! sessions.

use crate::{
    context::AuthContext,
    cookies::AuthCookie,
    email_password::{
        has_plugin, validate_name, validate_password, EmailPasswordService, Session, User,
        TWO_FACTOR_PLUGIN, TWO_FACTOR_TABLE,
    },
};
use better_auth_core::{
    adapter::{DbOperation, Query},
    error::{AuthError, Result},
};
use http::HeaderMap;
use serde::Serialize;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

const USER_TABLE: &str = "user";
const ACCOUNT_TABLE: &str = "account";
const SESSION_TABLE: &str = "session";
const EMAIL_PROVIDER: &str = "credential";

/// Public view of a session. The token hash and any secret material are
/// deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionSummary {
    pub id: String,
    pub expires_at: u64,
    pub current: bool,
}

/// Public view of a linked provider account. Tokens are never included.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LinkedAccount {
    pub provider_id: String,
    pub account_id: String,
}

/// Outcome of revoking a session. `current_session_ended` tells the caller
/// that the request's own cookie must be cleared.
#[derive(Clone, Debug)]
pub struct RevokeOutcome {
    pub revoked: u64,
    pub cookie: Option<AuthCookie>,
}

#[derive(Clone)]
pub struct AccountService {
    email_password: EmailPasswordService,
}

impl AccountService {
    pub fn new(context: AuthContext) -> Result<Self> {
        Ok(Self {
            email_password: EmailPasswordService::new(context)?,
        })
    }

    fn context(&self) -> &AuthContext {
        self.email_password.context()
    }

    async fn current(&self, headers: &HeaderMap, secure_cookie: bool) -> Result<(User, Session)> {
        self.email_password
            .session_from_cookie(headers, secure_cookie)
            .await?
            .ok_or(AuthError::Unauthorized)
    }

    /// Lists the caller's unexpired sessions, marking the current one.
    pub async fn list_sessions(
        &self,
        headers: &HeaderMap,
        secure_cookie: bool,
    ) -> Result<Vec<SessionSummary>> {
        let (user, current) = self.current(headers, secure_cookie).await?;
        let now = now_seconds();
        let rows = self
            .context()
            .adapter
            .find_many(SESSION_TABLE, Query::new().eq("user_id", user.id.clone()))
            .await?;
        let mut sessions: Vec<SessionSummary> = rows
            .iter()
            .filter_map(|row| {
                let id = row.get("id")?.as_str()?.to_owned();
                let expires_at = row.get("expires_at")?.as_u64()?;
                (expires_at > now).then(|| SessionSummary {
                    current: id == current.id,
                    id,
                    expires_at,
                })
            })
            .collect();
        sessions.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(sessions)
    }

    /// Revokes one of the caller's sessions. A session that belongs to someone
    /// else is reported as not found, which does not reveal that it exists.
    pub async fn revoke_session(
        &self,
        headers: &HeaderMap,
        secure_cookie: bool,
        session_id: &str,
    ) -> Result<RevokeOutcome> {
        let (user, current) = self.current(headers, secure_cookie).await?;
        if session_id == current.id {
            let cookie = self.email_password.sign_out(headers, secure_cookie).await?;
            return Ok(RevokeOutcome {
                revoked: 1,
                cookie: Some(cookie),
            });
        }
        let revoked = self
            .context()
            .adapter
            .delete_where(
                SESSION_TABLE,
                Query::new()
                    .eq("id", session_id.to_owned())
                    .eq("user_id", user.id),
            )
            .await?;
        if revoked == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(RevokeOutcome {
            revoked,
            cookie: None,
        })
    }

    /// Revokes every session of the caller except the current one.
    pub async fn revoke_other_sessions(
        &self,
        headers: &HeaderMap,
        secure_cookie: bool,
    ) -> Result<u64> {
        let (user, current) = self.current(headers, secure_cookie).await?;
        self.context()
            .adapter
            .delete_where(
                SESSION_TABLE,
                Query::new().eq("user_id", user.id).ne("id", current.id),
            )
            .await
    }

    /// Revokes every session of the caller, including the current one, and
    /// returns the cookie that clears this browser's session.
    pub async fn revoke_all_sessions(
        &self,
        headers: &HeaderMap,
        secure_cookie: bool,
    ) -> Result<AuthCookie> {
        let (user, _) = self.current(headers, secure_cookie).await?;
        self.context()
            .adapter
            .delete_where(SESSION_TABLE, Query::new().eq("user_id", user.id))
            .await?;
        self.email_password.sign_out(headers, secure_cookie).await
    }

    /// Changes the caller's password after re-checking the current one. Every
    /// other session is revoked so a stolen session cannot survive the change.
    pub async fn change_password(
        &self,
        headers: &HeaderMap,
        secure_cookie: bool,
        current_password: &str,
        new_password: &str,
    ) -> Result<u64> {
        let (user, current) = self.current(headers, secure_cookie).await?;
        validate_password(new_password)?;
        let account_id = format!("{}:{EMAIL_PROVIDER}", user.id);
        self.require_password(&account_id, current_password).await?;
        let replacement = self.context().password_provider.hash(new_password).await?;
        self.context()
            .adapter
            .update_where(
                ACCOUNT_TABLE,
                Query::new().eq("id", account_id),
                json!({"password_hash": replacement}),
            )
            .await?;
        let revoked = self
            .context()
            .adapter
            .delete_where(
                SESSION_TABLE,
                Query::new()
                    .eq("user_id", user.id.clone())
                    .ne("id", current.id),
            )
            .await?;
        self.context().after_password_change(&user.id).await?;
        Ok(revoked)
    }

    /// Updates the caller's display name.
    pub async fn update_user(
        &self,
        headers: &HeaderMap,
        secure_cookie: bool,
        name: &str,
    ) -> Result<User> {
        let (user, _) = self.current(headers, secure_cookie).await?;
        validate_name(name)?;
        self.context()
            .adapter
            .update_where(
                USER_TABLE,
                Query::new().eq("id", user.id.clone()),
                json!({"name": name}),
            )
            .await?;
        Ok(User {
            name: name.to_owned(),
            ..user
        })
    }

    /// Lists provider accounts linked to the caller.
    pub async fn list_accounts(
        &self,
        headers: &HeaderMap,
        secure_cookie: bool,
    ) -> Result<Vec<LinkedAccount>> {
        let (user, _) = self.current(headers, secure_cookie).await?;
        let rows = self
            .context()
            .adapter
            .find_many(ACCOUNT_TABLE, Query::new().eq("user_id", user.id))
            .await?;
        Ok(rows
            .iter()
            .filter_map(|row| {
                Some(LinkedAccount {
                    provider_id: row.get("provider_id")?.as_str()?.to_owned(),
                    account_id: row.get("account_id")?.as_str()?.to_owned(),
                })
            })
            .collect())
    }

    /// Removes one provider link from the caller. The last remaining sign-in method
    /// cannot be removed, so the account stays reachable. The check and the delete
    /// are not one transaction, so two concurrent unlinks could still remove both.
    pub async fn unlink_account(
        &self,
        headers: &HeaderMap,
        secure_cookie: bool,
        provider_id: &str,
    ) -> Result<()> {
        let (user, _) = self.current(headers, secure_cookie).await?;
        let linked = self.list_accounts(headers, secure_cookie).await?;
        if !linked
            .iter()
            .any(|account| account.provider_id == provider_id)
        {
            return Err(AuthError::NotFound);
        }
        if linked.len() <= 1 {
            return Err(AuthError::InvalidRequest(
                "cannot unlink the only sign-in method".into(),
            ));
        }
        self.context()
            .adapter
            .delete_where(
                ACCOUNT_TABLE,
                Query::new()
                    .eq("user_id", user.id)
                    .eq("provider_id", provider_id.to_owned()),
            )
            .await?;
        Ok(())
    }

    /// Deletes the caller's account after a password re-check. Sessions,
    /// credentials, two-factor records and the user row are removed in one
    /// transaction. Only then is the cookie cleared.
    pub async fn delete_user(
        &self,
        headers: &HeaderMap,
        secure_cookie: bool,
        password: &str,
    ) -> Result<AuthCookie> {
        let (user, _) = self.current(headers, secure_cookie).await?;
        let account_id = format!("{}:{EMAIL_PROVIDER}", user.id);
        self.require_password(&account_id, password).await?;
        self.context().before_user_delete(&user.id).await?;
        let mut operations = vec![DbOperation::DeleteWhere {
            table: SESSION_TABLE.into(),
            query: Query::new().eq("user_id", user.id.clone()),
        }];
        if has_plugin(self.context(), TWO_FACTOR_PLUGIN) {
            operations.push(DbOperation::DeleteWhere {
                table: TWO_FACTOR_TABLE.into(),
                query: Query::new().eq("user_id", user.id.clone()),
            });
        }
        operations.push(DbOperation::DeleteWhere {
            table: ACCOUNT_TABLE.into(),
            query: Query::new().eq("user_id", user.id.clone()),
        });
        operations.push(DbOperation::DeleteWhere {
            table: USER_TABLE.into(),
            query: Query::new().eq("id", user.id.clone()),
        });
        self.context().adapter.transaction(operations).await?;
        self.email_password.sign_out(headers, secure_cookie).await
    }

    /// Re-verifies the password of an already authenticated user before a
    /// sensitive change such as enabling a second factor.
    pub(crate) async fn verify_current_password(&self, user: &User, password: &str) -> Result<()> {
        let account_id = format!("{}:{EMAIL_PROVIDER}", user.id);
        self.require_password(&account_id, password).await
    }

    /// Verifies a password against the credential account and returns
    /// `Forbidden` when it does not match. Re-authentication failures are not
    /// reported as unauthenticated, so the caller can tell them apart.
    async fn require_password(&self, account_id: &str, password: &str) -> Result<()> {
        let account = self
            .context()
            .adapter
            .find_one(ACCOUNT_TABLE, Query::new().eq("id", account_id.to_owned()))
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let hash = account
            .get("password_hash")
            .and_then(Value::as_str)
            .ok_or(AuthError::Unauthorized)?;
        let verification = self
            .context()
            .password_provider
            .verify(password, hash)
            .await?;
        if verification.valid {
            Ok(())
        } else {
            Err(AuthError::Forbidden("password is incorrect".into()))
        }
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}
