use super::shared::endpoint;
use better_auth_core::{
    adapter::{DbAdapter, Query},
    error::{AuthError, Result},
    plugin::{Endpoint, Plugin},
};
use http::Method;
use std::{collections::BTreeSet, sync::Arc};

#[derive(Clone, Copy, Debug, Default)]
pub struct AdminPlugin;

impl Plugin for AdminPlugin {
    fn name(&self) -> &'static str {
        "admin"
    }
    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(
                Method::GET,
                "/admin/list-users",
                "List users for administrators",
            ),
            endpoint(Method::POST, "/admin/set-role", "Set a user role"),
        ]
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

#[derive(Clone)]
pub struct AdminService {
    adapter: Arc<dyn DbAdapter>,
    guard: AdminGuard,
}

impl AdminService {
    pub fn new(adapter: Arc<dyn DbAdapter>, guard: AdminGuard) -> Self {
        Self { adapter, guard }
    }

    pub async fn set_role(&self, actor_id: &str, user_id: &str, role: &str) -> Result<()> {
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
}
