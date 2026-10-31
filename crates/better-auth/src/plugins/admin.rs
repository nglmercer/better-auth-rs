use super::shared::{endpoint, now_seconds};
use crate::context::AuthContext;
use better_auth_core::{
    adapter::{DbAdapter, Query},
    error::{AuthError, Result},
    plugin::{Endpoint, Plugin},
    schema::{FieldSchema, FieldType, SchemaExtension, TableSchema},
};
use http::Method;
use serde_json::{json, Value};
use std::{collections::BTreeSet, sync::Arc};

pub(crate) const ADMIN_PLUGIN_NAME: &str = "admin";

/// Longest ban reason stored. Longer reasons are refused rather than truncated,
/// so the reason an administrator entered is the reason that is recorded.
const BAN_REASON_MAX_CHARS: usize = 500;

#[derive(Clone, Copy, Debug, Default)]
pub struct AdminPlugin;

impl Plugin for AdminPlugin {
    fn name(&self) -> &'static str {
        ADMIN_PLUGIN_NAME
    }
    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(
                Method::GET,
                "/admin/list-users",
                "List users for administrators",
            ),
            endpoint(Method::POST, "/admin/set-role", "Set a user role"),
            endpoint(
                Method::POST,
                "/admin/ban-user",
                "Ban a user and end their sessions",
            ),
            endpoint(Method::POST, "/admin/unban-user", "Lift a user's ban"),
            endpoint(
                Method::POST,
                "/admin/list-user-sessions",
                "List a user's sessions",
            ),
            endpoint(
                Method::POST,
                "/admin/revoke-user-session",
                "Revoke one session by id",
            ),
            endpoint(
                Method::POST,
                "/admin/revoke-user-sessions",
                "Revoke every session of a user",
            ),
            endpoint(
                Method::POST,
                "/admin/remove-user",
                "Delete a user with their sessions and linked accounts",
            ),
        ]
    }
    fn schema(&self) -> SchemaExtension {
        // Stored as seconds since the Unix epoch, so every SQL dialect and the
        // in-memory adapter agree on the type. A null expiry means no expiry.
        SchemaExtension::default().table(
            "user",
            TableSchema::default()
                .field("banned", FieldSchema::optional(FieldType::Boolean))
                .field("ban_reason", FieldSchema::optional(FieldType::String))
                .field("ban_expires", FieldSchema::optional(FieldType::Integer)),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminGuard {
    roles: BTreeSet<String>,
}

impl AdminGuard {
    pub fn new(roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            roles: roles.into_iter().map(Into::into).collect(),
        }
    }

    pub fn allows(&self, role: &str) -> bool {
        self.roles.contains(role)
    }
}

/// What the administrator role may do, as `(resource, action)` pairs. Only actions the
/// server implements are listed, so `has-permission` never promises more than the
/// routes deliver.
const ADMIN_GRANTS: &[(&str, &str)] = &[
    ("user", "create"),
    ("user", "list"),
    ("user", "update"),
    ("user", "set-role"),
    ("user", "set-password"),
    ("user", "ban"),
    ("user", "delete"),
    ("session", "list"),
    ("session", "revoke"),
    ("session", "delete"),
];

/// Whether the administrator role grants every pair in `permission`.
pub fn admin_grants(permission: &std::collections::BTreeMap<String, Vec<String>>) -> bool {
    !permission.is_empty()
        && permission.iter().all(|(resource, actions)| {
            !actions.is_empty()
                && actions.iter().all(|action| {
                    ADMIN_GRANTS
                        .iter()
                        .any(|(granted_resource, granted_action)| {
                            resource == granted_resource && action == granted_action
                        })
                })
        })
}

/// Whether a user record is under an active ban at `now`. A ban whose expiry has
/// passed no longer applies, even though the record still says `banned`.
fn ban_is_active(user: &Value, now: u64) -> bool {
    let banned = match user.get("banned") {
        Some(Value::Bool(flag)) => *flag,
        // Some SQL dialects return booleans as integers.
        Some(Value::Number(number)) => number.as_i64() == Some(1),
        _ => false,
    };
    banned
        && user
            .get("ban_expires")
            .and_then(Value::as_u64)
            .is_none_or(|expires| expires > now)
}

/// Whether `user_id` may not sign in or use a session right now. Without the
/// admin plugin no bans exist, so this costs no query.
pub(crate) async fn account_is_banned(context: &AuthContext, user_id: &str) -> Result<bool> {
    if !crate::email_password::has_plugin(context, ADMIN_PLUGIN_NAME) {
        return Ok(false);
    }
    let user = context
        .adapter
        .find_one("user", Query::new().eq("id", user_id.to_owned()))
        .await?;
    Ok(user.is_some_and(|user| ban_is_active(&user, now_seconds())))
}

#[derive(Clone)]
pub struct AdminService {
    adapter: Arc<dyn DbAdapter>,
    guard: AdminGuard,
}

impl AdminService {
    pub fn new(adapter: Arc<dyn DbAdapter>, guard: AdminGuard) -> Self {
        Self { adapter, guard }
    }

    /// Fails unless `actor_id` holds an administrator role. Every admin method
    /// calls this first, so direct service callers get the same check as HTTP.
    async fn require_admin(&self, actor_id: &str) -> Result<()> {
        let actor = self
            .adapter
            .find_one("user", Query::new().eq("id", actor_id.to_owned()))
            .await?
            .ok_or(AuthError::Unauthorized)?;
        if !self.guard.allows(
            actor
                .get("role")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
        ) {
            return Err(AuthError::Forbidden("administrator role required".into()));
        }
        Ok(())
    }

    /// Lists users with the fields an administrator needs. Password hashes and
    /// other credentials are never read by this query.
    pub async fn list_users(
        &self,
        actor_id: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<serde_json::Value>> {
        self.require_admin(actor_id).await?;
        let rows = self
            .adapter
            .find_many(
                "user",
                Query::new()
                    .order_by(better_auth_core::adapter::OrderBy {
                        field: "id".into(),
                        direction: better_auth_core::adapter::OrderDirection::Asc,
                    })
                    .limit(limit.min(100))
                    .offset(offset),
            )
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                serde_json::json!({
                    "id": row.get("id").cloned().unwrap_or_default(),
                    "email": row.get("email").cloned().unwrap_or_default(),
                    "name": row.get("name").cloned().unwrap_or_default(),
                    "role": row.get("role").cloned().unwrap_or_default(),
                    "email_verified": row.get("email_verified").cloned().unwrap_or_default(),
                })
            })
            .collect())
    }

    /// Fails unless `actor_id` is an administrator.
    pub async fn ensure_admin(&self, actor_id: &str) -> Result<()> {
        self.require_admin(actor_id).await
    }

    /// The user as an administrator sees it.
    pub async fn get_user(&self, actor_id: &str, user_id: &str) -> Result<Value> {
        self.require_admin(actor_id).await?;
        self.ensure_user(user_id).await?;
        self.user_view(user_id).await
    }

    /// Changes a user's name or role. Administrators cannot change their own role,
    /// so an administrator cannot demote themselves out of the role.
    pub async fn update_user(
        &self,
        actor_id: &str,
        user_id: &str,
        name: Option<&str>,
        role: Option<&str>,
    ) -> Result<Value> {
        self.require_admin(actor_id).await?;
        self.ensure_user(user_id).await?;
        let mut changes = serde_json::Map::new();
        if let Some(name) = name {
            crate::email_password::validate_name(name)?;
            changes.insert("name".into(), json!(name));
        }
        if let Some(role) = role {
            if actor_id == user_id {
                return Err(AuthError::InvalidRequest(
                    "administrators cannot change their own role".into(),
                ));
            }
            if role.trim().is_empty() || role.len() > 64 {
                return Err(AuthError::InvalidRequest("role is invalid".into()));
            }
            changes.insert("role".into(), json!(role));
        }
        if !changes.is_empty() {
            self.adapter
                .update_where(
                    "user",
                    Query::new().eq("id", user_id.to_owned()),
                    Value::Object(changes),
                )
                .await?;
        }
        self.user_view(user_id).await
    }

    /// Revokes every session of `user_id`. Used when an account must be locked
    /// out immediately.
    pub async fn revoke_user_sessions(&self, actor_id: &str, user_id: &str) -> Result<u64> {
        self.require_admin(actor_id).await?;
        self.adapter
            .delete_where("session", Query::new().eq("user_id", user_id.to_owned()))
            .await
    }

    /// Bans `user_id` and ends their sessions. `expires_in` is in seconds; without
    /// it the ban lasts until lifted. Administrators cannot ban themselves, so an
    /// administrator cannot lock every administrator out.
    pub async fn ban_user(
        &self,
        actor_id: &str,
        user_id: &str,
        reason: Option<&str>,
        expires_in: Option<u64>,
    ) -> Result<Value> {
        self.require_admin(actor_id).await?;
        if actor_id == user_id {
            return Err(AuthError::InvalidRequest(
                "administrators cannot ban themselves".into(),
            ));
        }
        if reason.is_some_and(|reason| reason.chars().count() > BAN_REASON_MAX_CHARS) {
            return Err(AuthError::InvalidRequest(format!(
                "ban reason must be at most {BAN_REASON_MAX_CHARS} characters"
            )));
        }
        self.ensure_user(user_id).await?;
        let expires = expires_in.map(|seconds| now_seconds().saturating_add(seconds));
        self.adapter
            .update_where(
                "user",
                Query::new().eq("id", user_id.to_owned()),
                json!({
                    "banned": true,
                    "ban_reason": reason.unwrap_or("No reason"),
                    "ban_expires": expires,
                }),
            )
            .await?;
        self.adapter
            .delete_where("session", Query::new().eq("user_id", user_id.to_owned()))
            .await?;
        self.user_view(user_id).await
    }

    pub async fn unban_user(&self, actor_id: &str, user_id: &str) -> Result<Value> {
        self.require_admin(actor_id).await?;
        self.ensure_user(user_id).await?;
        self.adapter
            .update_where(
                "user",
                Query::new().eq("id", user_id.to_owned()),
                json!({"banned": false, "ban_reason": null, "ban_expires": null}),
            )
            .await?;
        self.user_view(user_id).await
    }

    /// Lists sessions by id and expiry only. Session tokens are never returned,
    /// so a listing cannot be replayed as a credential.
    pub async fn list_user_sessions(&self, actor_id: &str, user_id: &str) -> Result<Vec<Value>> {
        self.require_admin(actor_id).await?;
        let rows = self
            .adapter
            .find_many("session", Query::new().eq("user_id", user_id.to_owned()))
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                json!({
                    "id": row.get("id").cloned().unwrap_or_default(),
                    "expires_at": row.get("expires_at").cloned().unwrap_or_default(),
                })
            })
            .collect())
    }

    pub async fn revoke_user_session(&self, actor_id: &str, session_id: &str) -> Result<u64> {
        self.require_admin(actor_id).await?;
        self.adapter
            .delete_where("session", Query::new().eq("id", session_id.to_owned()))
            .await
    }

    /// Deletes a user with their sessions and linked accounts. Other records that
    /// refer to the user, such as organization memberships, are not removed here.
    pub async fn remove_user(&self, actor_id: &str, user_id: &str) -> Result<()> {
        self.require_admin(actor_id).await?;
        if actor_id == user_id {
            return Err(AuthError::InvalidRequest(
                "administrators cannot remove themselves".into(),
            ));
        }
        self.ensure_user(user_id).await?;
        for table in ["session", "account"] {
            self.adapter
                .delete_where(table, Query::new().eq("user_id", user_id.to_owned()))
                .await?;
        }
        self.adapter
            .delete_where("user", Query::new().eq("id", user_id.to_owned()))
            .await?;
        Ok(())
    }

    pub async fn set_role(&self, actor_id: &str, user_id: &str, role: &str) -> Result<()> {
        self.require_admin(actor_id).await?;
        let mut user = self
            .adapter
            .find_one("user", Query::new().eq("id", user_id.to_owned()))
            .await?
            .ok_or(AuthError::NotFound)?;
        user["role"] = role.into();
        self.adapter
            .update_where("user", Query::new().eq("id", user_id.to_owned()), user)
            .await?;
        Ok(())
    }

    async fn ensure_user(&self, user_id: &str) -> Result<()> {
        self.adapter
            .find_one("user", Query::new().eq("id", user_id.to_owned()))
            .await?
            .map(|_| ())
            .ok_or(AuthError::NotFound)
    }

    /// The user as an administrator sees it, including the ban state. Credentials
    /// are not included.
    async fn user_view(&self, user_id: &str) -> Result<Value> {
        let user = self
            .adapter
            .find_one("user", Query::new().eq("id", user_id.to_owned()))
            .await?
            .ok_or(AuthError::NotFound)?;
        Ok(json!({
            "id": user.get("id").cloned().unwrap_or_default(),
            "email": user.get("email").cloned().unwrap_or_default(),
            "name": user.get("name").cloned().unwrap_or_default(),
            "email_verified": user.get("email_verified").cloned().unwrap_or_default(),
            "role": user.get("role").cloned().unwrap_or_default(),
            "banned": ban_is_active(&user, now_seconds()),
            "ban_reason": user.get("ban_reason").cloned().unwrap_or_default(),
            "ban_expires": user.get("ban_expires").cloned().unwrap_or_default(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ban_applies_until_it_expires_or_is_lifted() {
        let now = 1_000;
        assert!(!ban_is_active(&json!({"banned": false}), now));
        assert!(!ban_is_active(&json!({}), now));
        assert!(ban_is_active(&json!({"banned": true}), now));
        assert!(ban_is_active(
            &json!({"banned": true, "ban_expires": 2_000}),
            now
        ));
        assert!(!ban_is_active(
            &json!({"banned": true, "ban_expires": 999}),
            now
        ));
        assert!(ban_is_active(
            &json!({"banned": 1, "ban_expires": null}),
            now
        ));
        assert!(!ban_is_active(&json!({"banned": 0}), now));
    }
}
