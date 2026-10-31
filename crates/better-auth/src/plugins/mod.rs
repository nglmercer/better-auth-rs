mod admin;
mod api_key;
mod jwt;
mod organization;
mod passkey;
mod passwordless;
mod scim;
mod shared;
mod sso;
mod two_factor;
mod username;

pub(crate) use admin::account_is_banned;
pub(crate) use admin::admin_grants;
pub use admin::{AdminGuard, AdminPlugin, AdminService};
pub use api_key::{ApiKeyPlugin, API_KEY_PLUGIN};
pub use jwt::JwtPlugin;
pub use organization::{Organization, OrganizationMember, OrganizationPlugin, OrganizationService};
pub use passkey::{PasskeyChallenge, PasskeyPlugin, PasskeyService};
pub use passwordless::{
    AnonymousPlugin, DeviceAuthorizationPlugin, EmailOtpPlugin, LastLoginMethodPlugin,
    MagicLinkPlugin, MultiSessionPlugin, OneTapPlugin, OneTimeTokenPlugin, PhoneNumberPlugin,
    SiwePlugin,
};
pub use scim::{
    generate_scim_token, verify_scim_token, ScimBulkOperation, ScimBulkResponse, ScimGroup,
    ScimGroupMember, ScimPatchOperation, ScimPlugin, ScimService, ScimTokenRecord,
};
pub use sso::{SsoConnectionConfig, SsoConnectionService, SsoPlugin};
pub(crate) use two_factor::build_otpauth_url;
pub use two_factor::{
    generate_totp_secret, totp_code, verify_totp, BackupCodeSet, TotpSecret, TwoFactorPlugin,
};
pub use username::{UsernamePlugin, USERNAME_PLUGIN};

#[cfg(test)]
mod tests {
    use super::shared::now_seconds;
    use super::*;
    use better_auth_core::adapter::{
        memory::{MemoryDb, MemorySecondaryStorage},
        DbAdapter,
    };
    use data_encoding::BASE32_NOPAD;
    use serde_json::json;
    use std::{sync::Arc, time::Duration};

    #[test]
    fn totp_matches_rfc_vector() {
        let secret = BASE32_NOPAD.encode(b"12345678901234567890");
        assert_eq!(totp_code(&secret, 59, 30, 8).unwrap(), "94287082");
        assert!(verify_totp(&secret, "94287082", 59, 30, 1).unwrap());
    }

    #[test]
    fn backup_codes_are_one_time() {
        let (mut set, codes) = BackupCodeSet::generate(2);
        assert!(set.consume(&codes[0]));
        assert!(!set.consume(&codes[0]));
    }

    #[tokio::test]
    async fn organization_service_creates_owner_membership() {
        let service = OrganizationService::new(Arc::new(MemoryDb::default()));
        let organization = service.create("Acme, Inc.", "user-1").await.unwrap();
        let member = service
            .member(&organization.id, "user-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(member.role, "owner");
    }

    #[tokio::test]
    async fn passkey_challenges_are_single_use() {
        let service = PasskeyService::new(Arc::new(MemorySecondaryStorage::default()));
        let challenge = service
            .begin("key", None, "example.com", Duration::from_secs(60))
            .await
            .unwrap();
        assert!(service.consume("key", &challenge.challenge).await.is_ok());
        assert!(service.consume("key", &challenge.challenge).await.is_err());
    }

    #[test]
    fn scim_tokens_are_hashed() {
        let (token, hash) = generate_scim_token();
        assert!(verify_scim_token(&token, &hash));
        assert!(!verify_scim_token("wrong", &hash));
    }

    #[tokio::test]
    async fn admin_and_scim_services_enforce_and_persist_roles() {
        let adapter = Arc::new(MemoryDb::default());
        adapter
            .insert_record(
                "user",
                json!({"id":"admin","email":"admin@example.com","name":"Admin","email_verified":true,"role":"admin","additional_fields":{}}),
            )
            .await
            .unwrap();
        adapter
            .insert_record(
                "user",
                json!({"id":"user","email":"user@example.com","name":"User","email_verified":true,"role":"user","additional_fields":{}}),
            )
            .await
            .unwrap();
        let admin = AdminService::new(adapter.clone(), AdminGuard::new(["admin"]));
        admin.set_role("admin", "user", "manager").await.unwrap();
        let scim = ScimService::new(adapter.clone());
        // Only "user" belongs to org-1. "admin" is an account outside it.
        adapter
            .insert_record(
                "organization_member",
                json!({"id":"org-1:user","organization_id":"org-1","user_id":"user","role":"member"}),
            )
            .await
            .unwrap();
        let updated = scim
            .update_user("org-1", "user", json!({"name":"Updated"}))
            .await
            .unwrap();
        assert_eq!(updated["name"], "Updated");
        // Listing shows members only, and a user outside the organization is not found.
        let page = scim.list_users("org-1", 1, 1).await.unwrap();
        assert_eq!(page["totalResults"], 1);
        assert_eq!(page["itemsPerPage"], 1);
        assert!(matches!(
            scim.get_user("org-1", "admin").await,
            Err(better_auth_core::error::AuthError::NotFound)
        ));
        let filtered = scim
            .list_users_filtered(
                "org-1",
                1,
                10,
                Some(r#"(userName eq "user@example.com") and active eq true"#),
            )
            .await
            .unwrap();
        assert_eq!(filtered["totalResults"], 1);
        let value_path = scim
            .list_users_filtered(
                "org-1",
                1,
                10,
                Some(r#"emails[type eq "work"].value eq "user@example.com""#),
            )
            .await
            .unwrap();
        assert_eq!(value_path["totalResults"], 1);
        // Bulk requests are refused until they are scoped to an organization.
        let operations = vec![ScimBulkOperation {
            method: "PATCH".into(),
            path: "/Users/user".into(),
            data: Some(json!({"displayName":"Bulk Updated"})),
        }];
        assert!(scim.apply_bulk("org-1", &operations, 1).await.is_err());
        scim.update_user(
            "org-1",
            "user",
            json!([{"op":"replace","path":"displayName","value":"Patched Again"}]),
        )
        .await
        .unwrap();
        assert_eq!(
            scim.get_user("org-1", "user").await.unwrap()["displayName"],
            "Patched Again"
        );
        // A SCIM request cannot set a role, whatever its shape.
        assert!(scim
            .update_user("org-1", "user", json!({"role":"admin"}))
            .await
            .is_err());
        assert!(scim
            .update_user(
                "org-1",
                "user",
                json!([{"op":"replace","path":"role","value":"admin"}])
            )
            .await
            .is_err());
        let token = scim
            .issue_token("org-1", Some(now_seconds() + 60))
            .await
            .unwrap();
        assert!(scim
            .authorize_token(&token, Some("org-1"), now_seconds())
            .await
            .is_ok());
        assert!(scim
            .authorize_token(&token, Some("org-2"), now_seconds())
            .await
            .is_err());
        let group = scim.create_group("org-1", "Operators").await.unwrap();
        let group_id = group["id"].as_str().unwrap();
        scim.add_group_member("org-1", group_id, "user")
            .await
            .unwrap();
        assert_eq!(
            scim.get_group("org-1", group_id).await.unwrap()["members"][0]["value"],
            "user"
        );
        let groups = scim.list_groups("org-1", 1, 10).await.unwrap();
        assert_eq!(groups["totalResults"], 1);
        // A group of another organization is invisible here, and cannot take members from here.
        let other = scim.create_group("org-2", "Elsewhere").await.unwrap();
        let other_id = other["id"].as_str().unwrap();
        assert!(scim.get_group("org-1", other_id).await.is_err());
        assert!(scim
            .add_group_member("org-1", other_id, "user")
            .await
            .is_err());
        assert!(scim.delete_group("org-1", other_id).await.is_err());
        // Only organization members can join a group.
        assert!(scim
            .add_group_member("org-1", group_id, "admin")
            .await
            .is_err());
        scim.remove_group_member("org-1", group_id, "user")
            .await
            .unwrap();
        scim.delete_group("org-1", group_id).await.unwrap();
        assert!(scim.get_group("org-1", group_id).await.is_err());
    }
}
