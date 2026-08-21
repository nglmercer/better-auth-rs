use crate::{
    email_password::{Session, User},
    session::AuthPrincipal,
};
use async_trait::async_trait;
use better_auth_core::Result;

/// Application lifecycle callbacks. These callbacks intentionally do not
/// describe application-specific profile fields; an application can use the
/// Better Auth user id to synchronize its own tables or services.
#[async_trait]
pub trait AuthHooks: Send + Sync {
    async fn before_user_create(&self, _user: &mut User) -> Result<()> {
        Ok(())
    }

    async fn after_user_create(&self, _user: &User) -> Result<()> {
        Ok(())
    }

    async fn before_session_create(&self, _user: &User) -> Result<()> {
        Ok(())
    }

    async fn after_sign_in(&self, _principal: &AuthPrincipal) -> Result<()> {
        Ok(())
    }

    async fn after_password_change(&self, _user_id: &str) -> Result<()> {
        Ok(())
    }

    async fn before_user_delete(&self, _user_id: &str) -> Result<()> {
        Ok(())
    }

    async fn after_session_create(&self, _user: &User, _session: &Session) -> Result<()> {
        Ok(())
    }
}
