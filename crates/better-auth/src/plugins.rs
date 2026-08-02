use crate::sso::SsoProtocol;
use better_auth_core::{
    adapter::{DbAdapter, DbOperation, SecondaryStorage, StorageValue},
    error::{AuthError, Result},
    plugin::{Endpoint, Plugin},
    schema::{FieldSchema, FieldType, SchemaExtension, TableSchema},
};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use http::Method;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use uuid::Uuid;

type HmacSha1 = Hmac<Sha1>;

fn endpoint(method: Method, path: &str, description: &str) -> Endpoint {
    Endpoint::new(method, path, description)
}

fn required(field_type: FieldType) -> FieldSchema {
    FieldSchema::required(field_type)
}

fn optional(field_type: FieldType) -> FieldSchema {
    FieldSchema::optional(field_type)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TwoFactorPlugin;

impl Plugin for TwoFactorPlugin {
    fn name(&self) -> &'static str {
        "two-factor"
    }
    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(
                Method::POST,
                "/two-factor/enable",
                "Enable TOTP two-factor authentication",
            ),
            endpoint(
                Method::POST,
                "/two-factor/verify",
                "Verify a TOTP or backup code",
            ),
            endpoint(
                Method::POST,
                "/two-factor/disable",
                "Disable two-factor authentication",
            ),
        ]
    }
    fn schema(&self) -> SchemaExtension {
        SchemaExtension::default().table(
            "two_factor",
            TableSchema::default()
                .field("id", required(FieldType::String).unique())
                .field("user_id", required(FieldType::String).unique())
                .field("secret", required(FieldType::String))
                .field("enabled", required(FieldType::Boolean))
                .field("backup_codes", required(FieldType::Json)),
        )
    }
    fn error_codes(&self) -> std::collections::BTreeMap<String, String> {
        [(
            "TWO_FACTOR_REQUIRED".into(),
            "two-factor verification required".into(),
        )]
        .into_iter()
        .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpSecret {
    pub secret: String,
    pub otpauth_url: String,
}

pub fn generate_totp_secret(account_name: &str, issuer: &str) -> TotpSecret {
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let mut bytes = Vec::with_capacity(20);
    bytes.extend_from_slice(first.as_bytes());
    bytes.extend_from_slice(&second.as_bytes()[..4]);
    let secret = BASE32_NOPAD.encode(&bytes);
    let otpauth_url = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}",
        urlencoding(account_name),
        urlencoding(issuer),
        secret,
        urlencoding(issuer)
    );
    TotpSecret {
        secret,
        otpauth_url,
    }
}

pub fn totp_code(
    secret: &str,
    unix_seconds: u64,
    step_seconds: u64,
    digits: u32,
) -> Result<String> {
    if !(4..=10).contains(&digits) || step_seconds == 0 {
        return Err(AuthError::InvalidConfiguration(
            "invalid TOTP parameters".into(),
        ));
    }
    let key = BASE32_NOPAD
        .decode(secret.as_bytes())
        .map_err(|_| AuthError::InvalidRequest("invalid TOTP secret".into()))?;
    let counter = unix_seconds / step_seconds;
    let mut mac = <HmacSha1 as Mac>::new_from_slice(&key)
        .map_err(|_| AuthError::Crypto("invalid TOTP key".into()))?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulo = 10_u32.pow(digits);
    Ok(format!(
        "{:0width$}",
        binary % modulo,
        width = digits as usize
    ))
}

pub fn verify_totp(
    secret: &str,
    code: &str,
    unix_seconds: u64,
    step_seconds: u64,
    window: i8,
) -> Result<bool> {
    if window < 0 || window > 5 {
        return Err(AuthError::InvalidConfiguration(
            "invalid TOTP window".into(),
        ));
    }
    let window = window as u64;
    for offset in 0..=(window * 2) {
        let delta = offset as i64 - window as i64;
        let timestamp = if delta.is_negative() {
            unix_seconds.saturating_sub(delta.unsigned_abs() * step_seconds)
        } else {
            unix_seconds.saturating_add(delta as u64 * step_seconds)
        };
        if totp_code(secret, timestamp, step_seconds, code.len() as u32)?.as_str() == code {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Clone, Debug)]
pub struct BackupCodeSet {
    hashes: BTreeSet<String>,
}

impl BackupCodeSet {
    pub fn generate(count: usize) -> (Self, Vec<String>) {
        let mut hashes = BTreeSet::new();
        let mut plain = Vec::with_capacity(count);
        for _ in 0..count {
            let code = Uuid::new_v4().simple().to_string()[..10].to_owned();
            hashes.insert(hash_secret(&code));
            plain.push(code);
        }
        (Self { hashes }, plain)
    }

    pub fn consume(&mut self, code: &str) -> bool {
        self.hashes.remove(&hash_secret(code))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub created_by: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrganizationMember {
    pub organization_id: String,
    pub user_id: String,
    pub role: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OrganizationPlugin;

impl Plugin for OrganizationPlugin {
    fn name(&self) -> &'static str {
        "organization"
    }
    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(
                Method::POST,
                "/organization/create",
                "Create an organization",
            ),
            endpoint(
                Method::POST,
                "/organization/add-member",
                "Add an organization member",
            ),
            endpoint(
                Method::GET,
                "/organization/list",
                "List organizations for the user",
            ),
        ]
    }
    fn schema(&self) -> SchemaExtension {
        SchemaExtension::default()
            .table(
                "organization",
                TableSchema::default()
                    .field("id", required(FieldType::String).unique())
                    .field("name", required(FieldType::String))
                    .field("slug", required(FieldType::String).unique())
                    .field("created_by", required(FieldType::String)),
            )
            .table(
                "organization_member",
                TableSchema::default()
                    .field("id", required(FieldType::String).unique())
                    .field("organization_id", required(FieldType::String))
                    .field("user_id", required(FieldType::String))
                    .field("role", required(FieldType::String)),
            )
    }
}

#[derive(Clone)]
pub struct OrganizationService {
    adapter: Arc<dyn DbAdapter>,
}

impl OrganizationService {
    pub fn new(adapter: Arc<dyn DbAdapter>) -> Self {
        Self { adapter }
    }

    pub async fn create(&self, name: &str, created_by: &str) -> Result<Organization> {
        let name = name.trim();
        if name.is_empty() || name.len() > 120 {
            return Err(AuthError::InvalidRequest(
                "organization name is invalid".into(),
            ));
        }
        let organization = Organization {
            id: Uuid::new_v4().to_string(),
            name: name.to_owned(),
            slug: slugify(name),
            created_by: created_by.to_owned(),
        };
        let member = OrganizationMember {
            organization_id: organization.id.clone(),
            user_id: created_by.to_owned(),
            role: "owner".into(),
        };
        let member_id = member_id(&member.organization_id, &member.user_id);
        self.adapter
            .transaction(vec![
                DbOperation::Insert {
                    table: "organization".into(),
                    id: organization.id.clone(),
                    record: serde_json::to_value(&organization).map_err(serialize_error)?,
                },
                DbOperation::Insert {
                    table: "organization_member".into(),
                    id: member_id,
                    record: serde_json::to_value(&member).map_err(serialize_error)?,
                },
            ])
            .await?;
        Ok(organization)
    }

    pub async fn add_member(
        &self,
        organization_id: &str,
        user_id: &str,
        role: &str,
    ) -> Result<OrganizationMember> {
        if self
            .adapter
            .get("organization", organization_id)
            .await?
            .is_none()
        {
            return Err(AuthError::NotFound);
        }
        let member = OrganizationMember {
            organization_id: organization_id.to_owned(),
            user_id: user_id.to_owned(),
            role: role.to_owned(),
        };
        self.adapter
            .insert(
                "organization_member",
                &member_id(organization_id, user_id),
                serde_json::to_value(&member).map_err(serialize_error)?,
            )
            .await?;
        Ok(member)
    }

    pub async fn member(
        &self,
        organization_id: &str,
        user_id: &str,
    ) -> Result<Option<OrganizationMember>> {
        let Some(value) = self
            .adapter
            .get("organization_member", &member_id(organization_id, user_id))
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(
            serde_json::from_value(value).map_err(serialize_error)?,
        ))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PasskeyPlugin;

impl Plugin for PasskeyPlugin {
    fn name(&self) -> &'static str {
        "passkey"
    }
    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(
                Method::POST,
                "/passkey/generate-challenge",
                "Generate a WebAuthn challenge",
            ),
            endpoint(
                Method::POST,
                "/passkey/register",
                "Register a passkey credential",
            ),
            endpoint(
                Method::POST,
                "/passkey/authenticate",
                "Authenticate with a passkey",
            ),
        ]
    }
    fn schema(&self) -> SchemaExtension {
        SchemaExtension::default().table(
            "passkey",
            TableSchema::default()
                .field("id", required(FieldType::String).unique())
                .field("user_id", required(FieldType::String))
                .field("credential_id", required(FieldType::String).unique())
                .field("public_key", required(FieldType::Bytes))
                .field("counter", required(FieldType::Integer))
                .field("credential", required(FieldType::Json))
                .field("transports", optional(FieldType::Json)),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasskeyChallenge {
    pub challenge: String,
    pub user_id: Option<String>,
    pub rp_id: String,
    pub expires_at: u64,
}

#[derive(Clone)]
pub struct PasskeyService {
    storage: Arc<dyn SecondaryStorage>,
}

impl PasskeyService {
    pub fn new(storage: Arc<dyn SecondaryStorage>) -> Self {
        Self { storage }
    }

    pub async fn begin(
        &self,
        key: &str,
        user_id: Option<String>,
        rp_id: &str,
        ttl: Duration,
    ) -> Result<PasskeyChallenge> {
        let challenge = random_challenge();
        let state = PasskeyChallenge {
            challenge: challenge.clone(),
            user_id,
            rp_id: rp_id.to_owned(),
            expires_at: now_seconds() + ttl.as_secs(),
        };
        self.storage
            .set(
                &format!("passkey:challenge:{key}"),
                StorageValue::with_ttl(serde_json::to_value(&state).map_err(serialize_error)?, ttl),
            )
            .await?;
        Ok(state)
    }

    pub async fn consume(&self, key: &str, expected_challenge: &str) -> Result<PasskeyChallenge> {
        let value = self
            .storage
            .get_and_delete(&format!("passkey:challenge:{key}"))
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let state: PasskeyChallenge =
            serde_json::from_value(value.value).map_err(serialize_error)?;
        if state.challenge != expected_challenge || state.expires_at <= now_seconds() {
            return Err(AuthError::Unauthorized);
        }
        Ok(state)
    }
}

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
            .get("user", actor_id)
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
            .get("user", user_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        user["role"] = role.into();
        self.adapter.update("user", user_id, user).await
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SsoConnectionConfig {
    pub id: String,
    #[serde(default)]
    pub protocol: SsoProtocol,
    pub issuer: String,
    pub client_id: String,
    pub discovery_url: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SsoPlugin;

impl Plugin for SsoPlugin {
    fn name(&self) -> &'static str {
        "sso"
    }
    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(
                Method::GET,
                "/sso/authorize",
                "Start an enterprise SSO flow",
            ),
            endpoint(Method::POST, "/sso/connections", "Create an SSO connection"),
            endpoint(
                Method::GET,
                "/sso/saml/authorize",
                "Start a SAML enterprise SSO flow",
            ),
            endpoint(
                Method::POST,
                "/sso/saml/callback",
                "Validate a SAML enterprise SSO response",
            ),
        ]
    }
    fn schema(&self) -> SchemaExtension {
        SchemaExtension::default().table(
            "sso_connection",
            TableSchema::default()
                .field("id", required(FieldType::String).unique())
                .field("protocol", required(FieldType::String))
                .field("issuer", required(FieldType::String))
                .field("client_id", required(FieldType::String))
                .field("discovery_url", required(FieldType::String)),
        )
    }
}

impl SsoConnectionConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.issuer.starts_with("https://") || !self.discovery_url.starts_with("https://") {
            return Err(AuthError::InvalidConfiguration(
                "SSO endpoints must use HTTPS".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct SsoConnectionService {
    adapter: Arc<dyn DbAdapter>,
}

impl SsoConnectionService {
    pub fn new(adapter: Arc<dyn DbAdapter>) -> Self {
        Self { adapter }
    }

    pub async fn create(&self, connection: SsoConnectionConfig) -> Result<()> {
        connection.validate()?;
        self.adapter
            .insert(
                "sso_connection",
                &connection.id,
                serde_json::to_value(&connection).map_err(serialize_error)?,
            )
            .await
    }

    pub async fn get(&self, id: &str) -> Result<Option<SsoConnectionConfig>> {
        let Some(value) = self.adapter.get("sso_connection", id).await? else {
            return Ok(None);
        };
        Ok(Some(
            serde_json::from_value(value).map_err(serialize_error)?,
        ))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ScimPlugin;

impl Plugin for ScimPlugin {
    fn name(&self) -> &'static str {
        "scim"
    }
    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(Method::GET, "/scim/v2/Users", "List SCIM users"),
            endpoint(Method::POST, "/scim/v2/Users", "Create a SCIM user"),
            endpoint(Method::GET, "/scim/v2/Users/:id", "Get a SCIM user"),
            endpoint(Method::PATCH, "/scim/v2/Users/:id", "Update a SCIM user"),
            endpoint(Method::DELETE, "/scim/v2/Users/:id", "Delete a SCIM user"),
            endpoint(Method::GET, "/scim/v2/Groups", "List SCIM groups"),
            endpoint(Method::POST, "/scim/v2/Groups", "Create a SCIM group"),
            endpoint(Method::GET, "/scim/v2/Groups/:id", "Get a SCIM group"),
            endpoint(Method::PATCH, "/scim/v2/Groups/:id", "Update a SCIM group"),
            endpoint(Method::DELETE, "/scim/v2/Groups/:id", "Delete a SCIM group"),
            endpoint(Method::POST, "/scim/v2/Bulk", "Apply SCIM bulk operations"),
        ]
    }
    fn schema(&self) -> SchemaExtension {
        SchemaExtension::default()
            .table(
                "scim_token",
                TableSchema::default()
                    .field("id", required(FieldType::String).unique())
                    .field("organization_id", required(FieldType::String))
                    .field("token_hash", required(FieldType::String).unique())
                    .field("expires_at", optional(FieldType::DateTime)),
            )
            .table(
                "scim_group",
                TableSchema::default()
                    .field("id", required(FieldType::String).unique())
                    .field("display_name", required(FieldType::String))
                    .field("organization_id", required(FieldType::String)),
            )
            .table(
                "scim_group_member",
                TableSchema::default()
                    .field("id", required(FieldType::String).unique())
                    .field("group_id", required(FieldType::String))
                    .field("user_id", required(FieldType::String)),
            )
    }
}

pub fn generate_scim_token() -> (String, String) {
    let token = format!("scim_{}", Uuid::new_v4().simple());
    (token.clone(), hash_secret(&token))
}

pub fn verify_scim_token(token: &str, expected_hash: &str) -> bool {
    hash_secret(token) == expected_hash
}

#[derive(Clone)]
pub struct ScimService {
    adapter: Arc<dyn DbAdapter>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScimBulkOperation {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScimBulkResponse {
    pub method: String,
    pub path: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScimPatchOperation {
    pub op: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub value: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScimGroup {
    pub id: String,
    pub display_name: String,
    pub organization_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScimGroupMember {
    pub group_id: String,
    pub user_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScimTokenRecord {
    pub id: String,
    pub organization_id: String,
    pub token_hash: String,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

impl ScimService {
    pub fn new(adapter: Arc<dyn DbAdapter>) -> Self {
        Self { adapter }
    }

    pub async fn issue_token(
        &self,
        organization_id: &str,
        expires_at: Option<u64>,
    ) -> Result<String> {
        if organization_id.trim().is_empty() {
            return Err(AuthError::InvalidRequest(
                "SCIM organization_id cannot be empty".into(),
            ));
        }
        let (token, token_hash) = generate_scim_token();
        let record = ScimTokenRecord {
            id: Uuid::new_v4().to_string(),
            organization_id: organization_id.into(),
            token_hash,
            expires_at,
        };
        self.adapter
            .insert(
                "scim_token",
                &record.id,
                serde_json::to_value(&record).map_err(serialize_error)?,
            )
            .await?;
        Ok(token)
    }

    pub async fn authorize_token(
        &self,
        token: &str,
        organization_id: Option<&str>,
        now_seconds: u64,
    ) -> Result<ScimTokenRecord> {
        let hash = hash_secret(token);
        let Some((_, value)) = self
            .adapter
            .get_by_field("scim_token", "token_hash", &serde_json::Value::String(hash))
            .await?
        else {
            return Err(AuthError::Unauthorized);
        };
        let record: ScimTokenRecord = serde_json::from_value(value).map_err(serialize_error)?;
        if organization_id.is_some_and(|id| id != record.organization_id)
            || record
                .expires_at
                .is_some_and(|expires| expires <= now_seconds)
        {
            return Err(AuthError::Unauthorized);
        }
        Ok(record)
    }

    pub async fn create_user(&self, email: &str, name: &str) -> Result<serde_json::Value> {
        let user = json!({
            "id": Uuid::new_v4().to_string(),
            "email": email.trim().to_ascii_lowercase(),
            "name": name.trim(),
            "email_verified": true,
            "role": "user",
        });
        let id = user["id"]
            .as_str()
            .ok_or_else(|| AuthError::Adapter("SCIM user has no id".into()))?;
        self.adapter.insert("user", id, user.clone()).await?;
        Ok(user)
    }

    pub async fn update_user(
        &self,
        user_id: &str,
        patch: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let mut user = self
            .adapter
            .get("user", user_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        user = apply_scim_user_patch(user, &patch)?;
        self.adapter.update("user", user_id, user.clone()).await?;
        Ok(user)
    }

    pub async fn list_users(&self, start_index: usize, count: usize) -> Result<serde_json::Value> {
        self.list_users_filtered(start_index, count, None).await
    }

    pub async fn get_user(&self, user_id: &str) -> Result<serde_json::Value> {
        let user = self
            .adapter
            .get("user", user_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        Ok(scim_user_resource(user_id, &user))
    }

    pub async fn delete_user(&self, user_id: &str) -> Result<()> {
        if self.adapter.get("user", user_id).await?.is_none() {
            return Err(AuthError::NotFound);
        }
        self.adapter.delete("user", user_id).await
    }

    pub async fn create_group(
        &self,
        organization_id: &str,
        display_name: &str,
    ) -> Result<serde_json::Value> {
        let display_name = display_name.trim();
        if organization_id.trim().is_empty() || display_name.is_empty() {
            return Err(AuthError::InvalidRequest(
                "SCIM group organization and displayName are required".into(),
            ));
        }
        let group = ScimGroup {
            id: Uuid::new_v4().to_string(),
            display_name: display_name.into(),
            organization_id: organization_id.into(),
        };
        self.adapter
            .insert(
                "scim_group",
                &group.id,
                serde_json::to_value(&group).map_err(serialize_error)?,
            )
            .await?;
        self.group_resource(&group).await
    }

    pub async fn get_group(&self, group_id: &str) -> Result<serde_json::Value> {
        let group = self.load_group(group_id).await?;
        self.group_resource(&group).await
    }

    pub async fn list_groups(
        &self,
        organization_id: &str,
        start_index: usize,
        count: usize,
    ) -> Result<serde_json::Value> {
        if start_index == 0 {
            return Err(AuthError::InvalidRequest(
                "SCIM startIndex is one-based".into(),
            ));
        }
        let groups = self
            .adapter
            .list("scim_group")
            .await?
            .into_iter()
            .filter_map(|(_, value)| serde_json::from_value::<ScimGroup>(value).ok())
            .filter(|group| group.organization_id == organization_id)
            .collect::<Vec<_>>();
        let total = groups.len();
        let start = start_index.saturating_sub(1).min(total);
        let end = start.saturating_add(count).min(total);
        let mut resources = Vec::new();
        for group in &groups[start..end] {
            resources.push(self.group_resource(group).await?);
        }
        Ok(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": total,
            "startIndex": start + 1,
            "itemsPerPage": resources.len(),
            "Resources": resources,
        }))
    }

    pub async fn update_group(
        &self,
        group_id: &str,
        patch: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let mut group = self.load_group(group_id).await?;
        let Some(object) = patch.as_object() else {
            return Err(AuthError::InvalidRequest(
                "SCIM group patch must be an object".into(),
            ));
        };
        if let Some(value) = object
            .get("displayName")
            .or_else(|| object.get("display_name"))
            .and_then(serde_json::Value::as_str)
        {
            if value.trim().is_empty() {
                return Err(AuthError::InvalidRequest(
                    "SCIM group displayName cannot be empty".into(),
                ));
            }
            group.display_name = value.trim().into();
        }
        self.adapter
            .update(
                "scim_group",
                group_id,
                serde_json::to_value(&group).map_err(serialize_error)?,
            )
            .await?;
        if let Some(members) = object.get("members") {
            self.replace_group_members(group_id, members).await?;
        }
        self.group_resource(&group).await
    }

    pub async fn delete_group(&self, group_id: &str) -> Result<()> {
        self.load_group(group_id).await?;
        let operations = self
            .adapter
            .list("scim_group_member")
            .await?
            .into_iter()
            .filter(|(_, value)| {
                value.get("group_id").and_then(serde_json::Value::as_str) == Some(group_id)
            })
            .map(|(id, _)| DbOperation::Delete {
                table: "scim_group_member".into(),
                id,
            })
            .chain(std::iter::once(DbOperation::Delete {
                table: "scim_group".into(),
                id: group_id.into(),
            }))
            .collect();
        self.adapter.transaction(operations).await
    }

    pub async fn add_group_member(&self, group_id: &str, user_id: &str) -> Result<()> {
        self.load_group(group_id).await?;
        if self.adapter.get("user", user_id).await?.is_none() {
            return Err(AuthError::NotFound);
        }
        let member = ScimGroupMember {
            group_id: group_id.into(),
            user_id: user_id.into(),
        };
        self.adapter
            .insert(
                "scim_group_member",
                &scim_group_member_id(group_id, user_id),
                serde_json::to_value(member).map_err(serialize_error)?,
            )
            .await
    }

    pub async fn remove_group_member(&self, group_id: &str, user_id: &str) -> Result<()> {
        self.load_group(group_id).await?;
        self.adapter
            .delete(
                "scim_group_member",
                &scim_group_member_id(group_id, user_id),
            )
            .await
    }

    pub async fn list_users_filtered(
        &self,
        start_index: usize,
        count: usize,
        filter: Option<&str>,
    ) -> Result<serde_json::Value> {
        if start_index == 0 {
            return Err(AuthError::InvalidRequest(
                "SCIM startIndex is one-based".into(),
            ));
        }
        let predicate = ScimFilter::parse(filter)?;
        let records = self
            .adapter
            .list("user")
            .await?
            .into_iter()
            .filter(|(_, user)| predicate.matches(user))
            .collect::<Vec<_>>();
        let total = records.len();
        let start = start_index.saturating_sub(1).min(total);
        let end = start.saturating_add(count).min(total);
        let resources = records[start..end]
            .iter()
            .map(|(id, user)| scim_user_resource(id, user))
            .collect::<Vec<_>>();
        Ok(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": total,
            "startIndex": start + 1,
            "itemsPerPage": resources.len(),
            "Resources": resources,
        }))
    }

    pub async fn apply_bulk(
        &self,
        operations: &[ScimBulkOperation],
        fail_on_errors: usize,
    ) -> Result<Vec<ScimBulkResponse>> {
        if operations.len() > 1_000 {
            return Err(AuthError::InvalidRequest(
                "SCIM bulk request exceeds the 1000 operation limit".into(),
            ));
        }
        let mut planned = Vec::new();
        let mut responses = Vec::with_capacity(operations.len());
        let mut errors = 0;
        for operation in operations {
            let method = operation.method.to_ascii_uppercase();
            let path = normalize_scim_path(&operation.path)?;
            let id = path.strip_prefix("/Users/").unwrap_or_default();
            let result = match (method.as_str(), id.is_empty()) {
                ("POST", true) => {
                    let data = operation.data.clone().ok_or_else(|| {
                        AuthError::InvalidRequest("SCIM POST operation requires data".into())
                    })?;
                    let user = scim_user_from_resource(&data)?;
                    let id = Uuid::new_v4().to_string();
                    let mut user = user;
                    user["id"] = id.clone().into();
                    planned.push(DbOperation::Insert {
                        table: "user".into(),
                        id: id.clone(),
                        record: user.clone(),
                    });
                    Ok((201, Some(scim_user_resource(&id, &user))))
                }
                ("PUT", false) | ("PATCH", false) => {
                    let existing = self
                        .adapter
                        .get("user", id)
                        .await?
                        .ok_or(AuthError::NotFound)?;
                    let data = operation.data.clone().ok_or_else(|| {
                        AuthError::InvalidRequest("SCIM update operation requires data".into())
                    })?;
                    let updated = if method == "PUT" {
                        scim_user_from_resource(&data)?
                    } else {
                        merge_scim_patch(existing, &data)?
                    };
                    let mut updated = updated;
                    updated["id"] = id.into();
                    planned.push(DbOperation::Update {
                        table: "user".into(),
                        id: id.into(),
                        record: updated.clone(),
                    });
                    Ok((200, Some(scim_user_resource(id, &updated))))
                }
                ("DELETE", false) => {
                    if self.adapter.get("user", id).await?.is_none() {
                        Err(AuthError::NotFound)
                    } else {
                        planned.push(DbOperation::Delete {
                            table: "user".into(),
                            id: id.into(),
                        });
                        Ok((204, None))
                    }
                }
                ("POST", false) | ("PUT", true) | ("PATCH", true) | ("DELETE", true) => {
                    Err(AuthError::InvalidRequest("invalid SCIM bulk path".into()))
                }
                _ => Err(AuthError::InvalidRequest(format!(
                    "unsupported SCIM bulk method: {}",
                    operation.method
                ))),
            };
            match result {
                Ok((status, response)) => responses.push(ScimBulkResponse {
                    method,
                    path: operation.path.clone(),
                    status,
                    response,
                }),
                Err(error) => {
                    errors += 1;
                    responses.push(ScimBulkResponse {
                        method,
                        path: operation.path.clone(),
                        status: error.status_code(),
                        response: Some(json!({"detail": error.to_string()})),
                    });
                    if fail_on_errors != 0 && errors >= fail_on_errors {
                        break;
                    }
                }
            }
        }
        if fail_on_errors != 0 && errors >= fail_on_errors {
            return Err(AuthError::InvalidRequest(
                "SCIM bulk request exceeded failOnErrors".into(),
            ));
        } else {
            if !planned.is_empty() {
                self.adapter.transaction(planned).await?;
            }
        }
        Ok(responses)
    }

    async fn load_group(&self, group_id: &str) -> Result<ScimGroup> {
        let value = self
            .adapter
            .get("scim_group", group_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        serde_json::from_value(value).map_err(serialize_error)
    }

    async fn group_resource(&self, group: &ScimGroup) -> Result<serde_json::Value> {
        let members = self
            .adapter
            .list("scim_group_member")
            .await?
            .into_iter()
            .filter_map(|(_, value)| serde_json::from_value::<ScimGroupMember>(value).ok())
            .filter(|member| member.group_id == group.id)
            .map(|member| json!({"value": member.user_id}))
            .collect::<Vec<_>>();
        Ok(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": group.id,
            "displayName": group.display_name,
            "members": members,
            "meta": {"resourceType": "Group"},
        }))
    }

    async fn replace_group_members(
        &self,
        group_id: &str,
        members: &serde_json::Value,
    ) -> Result<()> {
        let Some(members) = members.as_array() else {
            return Err(AuthError::InvalidRequest(
                "SCIM group members must be an array".into(),
            ));
        };
        let mut operations = self
            .adapter
            .list("scim_group_member")
            .await?
            .into_iter()
            .filter(|(_, value)| {
                value.get("group_id").and_then(serde_json::Value::as_str) == Some(group_id)
            })
            .map(|(id, _)| DbOperation::Delete {
                table: "scim_group_member".into(),
                id,
            })
            .collect::<Vec<_>>();
        for member in members {
            let user_id = member
                .get("value")
                .or_else(|| member.get("user_id"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    AuthError::InvalidRequest("SCIM group member requires value".into())
                })?;
            if self.adapter.get("user", user_id).await?.is_none() {
                return Err(AuthError::NotFound);
            }
            let member = ScimGroupMember {
                group_id: group_id.into(),
                user_id: user_id.into(),
            };
            operations.push(DbOperation::Insert {
                table: "scim_group_member".into(),
                id: scim_group_member_id(group_id, user_id),
                record: serde_json::to_value(member).map_err(serialize_error)?,
            });
        }
        self.adapter.transaction(operations).await
    }
}

#[derive(Clone, Debug)]
enum ScimFilter {
    All,
    Present(String),
    Compare {
        attribute: String,
        operator: ScimCompare,
        expected: String,
    },
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
}

#[derive(Clone, Copy, Debug)]
enum ScimCompare {
    Eq,
    Ne,
    Contains,
    StartsWith,
    EndsWith,
    GreaterThan,
    GreaterOrEqual,
    LessThan,
    LessOrEqual,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ScimFilterToken {
    Word(String),
    Value(String),
    Open,
    Close,
}

impl ScimFilter {
    fn parse(filter: Option<&str>) -> Result<Self> {
        let Some(filter) = filter.map(str::trim).filter(|filter| !filter.is_empty()) else {
            return Ok(Self::All);
        };
        let mut parser = ScimFilterParser {
            tokens: tokenize_scim_filter(filter)?,
            position: 0,
        };
        let result = parser.parse_or()?;
        if parser.position != parser.tokens.len() {
            return Err(AuthError::InvalidRequest(
                "unexpected tokens at end of SCIM filter".into(),
            ));
        }
        Ok(result)
    }

    fn matches(&self, user: &serde_json::Value) -> bool {
        match self {
            Self::All => true,
            Self::Present(attribute) => scim_attribute(user, attribute).is_some(),
            Self::Compare {
                attribute,
                operator,
                expected,
            } => {
                let Some(actual) = scim_attribute(user, attribute) else {
                    return false;
                };
                match operator {
                    ScimCompare::Eq => actual.eq_ignore_ascii_case(expected),
                    ScimCompare::Ne => !actual.eq_ignore_ascii_case(expected),
                    ScimCompare::Contains => actual
                        .to_ascii_lowercase()
                        .contains(&expected.to_ascii_lowercase()),
                    ScimCompare::StartsWith => actual
                        .to_ascii_lowercase()
                        .starts_with(&expected.to_ascii_lowercase()),
                    ScimCompare::EndsWith => actual
                        .to_ascii_lowercase()
                        .ends_with(&expected.to_ascii_lowercase()),
                    ScimCompare::GreaterThan => compare_scim_values(&actual, expected).is_gt(),
                    ScimCompare::GreaterOrEqual => compare_scim_values(&actual, expected).is_ge(),
                    ScimCompare::LessThan => compare_scim_values(&actual, expected).is_lt(),
                    ScimCompare::LessOrEqual => compare_scim_values(&actual, expected).is_le(),
                }
            }
            Self::And(left, right) => left.matches(user) && right.matches(user),
            Self::Or(left, right) => left.matches(user) || right.matches(user),
        }
    }
}

struct ScimFilterParser {
    tokens: Vec<ScimFilterToken>,
    position: usize,
}

impl ScimFilterParser {
    fn parse_or(&mut self) -> Result<ScimFilter> {
        let mut result = self.parse_and()?;
        while self.take_word("or") {
            result = ScimFilter::Or(Box::new(result), Box::new(self.parse_and()?));
        }
        Ok(result)
    }

    fn parse_and(&mut self) -> Result<ScimFilter> {
        let mut result = self.parse_factor()?;
        while self.take_word("and") {
            result = ScimFilter::And(Box::new(result), Box::new(self.parse_factor()?));
        }
        Ok(result)
    }

    fn parse_factor(&mut self) -> Result<ScimFilter> {
        if self.take_token(ScimFilterToken::Open) {
            let result = self.parse_or()?;
            if !self.take_token(ScimFilterToken::Close) {
                return Err(AuthError::InvalidRequest(
                    "unclosed parenthesis in SCIM filter".into(),
                ));
            }
            return Ok(result);
        }
        let attribute = match self.next() {
            Some(ScimFilterToken::Word(attribute)) => normalize_scim_attribute(&attribute)?,
            _ => {
                return Err(AuthError::InvalidRequest(
                    "SCIM filter must start with an attribute".into(),
                ))
            }
        };
        let operator = match self.next() {
            Some(ScimFilterToken::Word(operator)) => operator.to_ascii_lowercase(),
            _ => {
                return Err(AuthError::InvalidRequest(
                    "SCIM filter is missing an operator".into(),
                ))
            }
        };
        if operator == "pr" {
            return Ok(ScimFilter::Present(attribute));
        }
        let operator = match operator.as_str() {
            "eq" => ScimCompare::Eq,
            "ne" => ScimCompare::Ne,
            "co" => ScimCompare::Contains,
            "sw" => ScimCompare::StartsWith,
            "ew" => ScimCompare::EndsWith,
            "gt" => ScimCompare::GreaterThan,
            "ge" => ScimCompare::GreaterOrEqual,
            "lt" => ScimCompare::LessThan,
            "le" => ScimCompare::LessOrEqual,
            _ => {
                return Err(AuthError::InvalidRequest(
                    "unsupported SCIM filter operator".into(),
                ))
            }
        };
        let expected = match self.next() {
            Some(ScimFilterToken::Word(value) | ScimFilterToken::Value(value)) => value,
            _ => {
                return Err(AuthError::InvalidRequest(
                    "SCIM comparison is missing a value".into(),
                ))
            }
        };
        Ok(ScimFilter::Compare {
            attribute,
            operator,
            expected,
        })
    }

    fn next(&mut self) -> Option<ScimFilterToken> {
        let token = self.tokens.get(self.position).cloned();
        if token.is_some() {
            self.position += 1;
        }
        token
    }

    fn take_token(&mut self, expected: ScimFilterToken) -> bool {
        if self.tokens.get(self.position) == Some(&expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn take_word(&mut self, expected: &str) -> bool {
        if matches!(
            self.tokens.get(self.position),
            Some(ScimFilterToken::Word(word)) if word.eq_ignore_ascii_case(expected)
        ) {
            self.position += 1;
            true
        } else {
            false
        }
    }
}

fn tokenize_scim_filter(filter: &str) -> Result<Vec<ScimFilterToken>> {
    let characters = filter.chars().collect::<Vec<_>>();
    let mut tokens = Vec::new();
    let mut position = 0;
    while position < characters.len() {
        if characters[position].is_whitespace() {
            position += 1;
        } else if characters[position] == '(' {
            tokens.push(ScimFilterToken::Open);
            position += 1;
        } else if characters[position] == ')' {
            tokens.push(ScimFilterToken::Close);
            position += 1;
        } else if matches!(characters[position], '"' | '\'') {
            let quote = characters[position];
            position += 1;
            let mut value = String::new();
            let mut closed = false;
            while position < characters.len() {
                let character = characters[position];
                position += 1;
                if character == quote {
                    closed = true;
                    break;
                }
                if character == '\\' && position < characters.len() {
                    value.push(characters[position]);
                    position += 1;
                } else {
                    value.push(character);
                }
            }
            if !closed {
                return Err(AuthError::InvalidRequest(
                    "unterminated quoted value in SCIM filter".into(),
                ));
            }
            tokens.push(ScimFilterToken::Value(value));
        } else {
            let start = position;
            while position < characters.len()
                && !characters[position].is_whitespace()
                && !matches!(characters[position], '(' | ')')
            {
                position += 1;
            }
            tokens.push(ScimFilterToken::Word(
                characters[start..position].iter().collect(),
            ));
        }
    }
    Ok(tokens)
}

fn compare_scim_values(actual: &str, expected: &str) -> std::cmp::Ordering {
    match (actual.parse::<f64>(), expected.parse::<f64>()) {
        (Ok(actual), Ok(expected)) => actual
            .partial_cmp(&expected)
            .unwrap_or(std::cmp::Ordering::Equal),
        _ => actual
            .to_ascii_lowercase()
            .cmp(&expected.to_ascii_lowercase()),
    }
}

fn normalize_scim_attribute(attribute: &str) -> Result<String> {
    match attribute.to_ascii_lowercase().as_str() {
        "id" => Ok("id".into()),
        "username" | "emails.value" | "email" => Ok("email".into()),
        "displayname" | "name" => Ok("name".into()),
        "active" => Ok("active".into()),
        _ => Err(AuthError::InvalidRequest(format!(
            "unsupported SCIM attribute: {attribute}"
        ))),
    }
}

fn scim_attribute(user: &serde_json::Value, attribute: &str) -> Option<String> {
    if attribute == "active" {
        return Some(
            user.get("active")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true)
                .to_string(),
        );
    }
    user.get(attribute)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

fn scim_user_resource(id: &str, user: &serde_json::Value) -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": id,
        "userName": user.get("email"),
        "displayName": user.get("name"),
        "active": user.get("active").and_then(serde_json::Value::as_bool).unwrap_or(true),
        "meta": {"resourceType": "User"},
    })
}

fn scim_user_from_resource(resource: &serde_json::Value) -> Result<serde_json::Value> {
    let email = resource
        .get("userName")
        .or_else(|| resource.get("email"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|email| email.contains('@'))
        .ok_or_else(|| AuthError::InvalidRequest("SCIM userName must be an email".into()))?;
    let name = resource
        .get("displayName")
        .or_else(|| resource.get("name"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or(email);
    Ok(json!({
        "email": email.to_ascii_lowercase(),
        "name": name.trim(),
        "email_verified": true,
        "role": "user",
        "active": resource.get("active").and_then(serde_json::Value::as_bool).unwrap_or(true),
    }))
}

fn apply_scim_user_patch(
    mut user: serde_json::Value,
    patch: &serde_json::Value,
) -> Result<serde_json::Value> {
    if patch.is_array() {
        let operations = serde_json::from_value::<Vec<ScimPatchOperation>>(patch.clone())
            .map_err(serialize_error)?;
        for operation in operations {
            apply_scim_patch_operation(&mut user, &operation)?;
        }
        return Ok(user);
    }
    let Some(patch) = patch.as_object() else {
        return Err(AuthError::InvalidRequest(
            "SCIM patch must be an object or operation array".into(),
        ));
    };
    for (key, value) in patch {
        if matches!(key.as_str(), "id" | "schemas" | "meta") {
            continue;
        }
        apply_scim_patch_operation(
            &mut user,
            &ScimPatchOperation {
                op: "replace".into(),
                path: Some(key.clone()),
                value: Some(value.clone()),
            },
        )?;
    }
    Ok(user)
}

fn apply_scim_patch_operation(
    user: &mut serde_json::Value,
    operation: &ScimPatchOperation,
) -> Result<()> {
    let op = operation.op.to_ascii_lowercase();
    if !matches!(op.as_str(), "add" | "replace" | "remove") {
        return Err(AuthError::InvalidRequest(format!(
            "unsupported SCIM PATCH operation: {}",
            operation.op
        )));
    }
    let Some(path) = operation.path.as_deref() else {
        if op == "remove" {
            return Err(AuthError::InvalidRequest(
                "SCIM remove requires a path".into(),
            ));
        }
        let Some(value) = operation.value.as_ref() else {
            return Err(AuthError::InvalidRequest(
                "SCIM add/replace requires a value".into(),
            ));
        };
        let Some(object) = value.as_object() else {
            return Err(AuthError::InvalidRequest(
                "SCIM add/replace without path requires an object".into(),
            ));
        };
        for (key, value) in object {
            apply_scim_patch_operation(
                user,
                &ScimPatchOperation {
                    op: op.clone(),
                    path: Some(key.clone()),
                    value: Some(value.clone()),
                },
            )?;
        }
        return Ok(());
    };
    let attribute = normalize_scim_patch_attribute(path)?;
    if op == "remove" {
        if let Some(object) = user.as_object_mut() {
            object.remove(&attribute);
        }
        return Ok(());
    }
    let value = operation
        .value
        .clone()
        .ok_or_else(|| AuthError::InvalidRequest("SCIM add/replace requires a value".into()))?;
    if attribute == "email" {
        let email = value
            .as_str()
            .map(str::trim)
            .filter(|value| value.contains('@'))
            .ok_or_else(|| AuthError::InvalidRequest("SCIM userName must be an email".into()))?;
        user["email"] = email.to_ascii_lowercase().into();
    } else if attribute == "name" {
        user["name"] = value;
    } else if attribute == "active" {
        if !value.is_boolean() {
            return Err(AuthError::InvalidRequest(
                "SCIM active must be boolean".into(),
            ));
        }
        user["active"] = value;
    } else if attribute == "role" {
        user["role"] = value;
    }
    Ok(())
}

fn normalize_scim_patch_attribute(path: &str) -> Result<String> {
    let path = path.trim();
    let normalized = match path.to_ascii_lowercase().as_str() {
        "username" | "email" | "emails.value" => "email",
        "displayname" | "name" => "name",
        "active" => "active",
        "role" => "role",
        _ => {
            if path.to_ascii_lowercase().starts_with("emails[")
                && path.to_ascii_lowercase().ends_with("].value")
            {
                "email"
            } else {
                return Err(AuthError::InvalidRequest(format!(
                    "unsupported SCIM PATCH path: {path}"
                )));
            }
        }
    };
    Ok(normalized.into())
}

fn merge_scim_patch(
    user: serde_json::Value,
    patch: &serde_json::Value,
) -> Result<serde_json::Value> {
    apply_scim_user_patch(user, patch)
}

fn normalize_scim_path(path: &str) -> Result<String> {
    let path = if let Some(path) = path.strip_prefix("/scim/v2") {
        format!("/{}", path.trim_start_matches('/'))
    } else if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    let path = path.trim_end_matches('/');
    if path == "/Users" || path.starts_with("/Users/") {
        Ok(path.into())
    } else {
        Err(AuthError::InvalidRequest("invalid SCIM bulk path".into()))
    }
}

fn scim_group_member_id(group_id: &str, user_id: &str) -> String {
    format!("{group_id}:{user_id}")
}

trait ScimErrorStatus {
    fn status_code(&self) -> u16;
}

impl ScimErrorStatus for AuthError {
    fn status_code(&self) -> u16 {
        match self {
            AuthError::InvalidRequest(_) => 400,
            AuthError::Unauthorized => 401,
            AuthError::Forbidden(_) => 403,
            AuthError::NotFound => 404,
            AuthError::RateLimited { .. } => 429,
            AuthError::InvalidConfiguration(_)
            | AuthError::Adapter(_)
            | AuthError::Plugin(_)
            | AuthError::Crypto(_) => 500,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct JwtPlugin;

impl Plugin for JwtPlugin {
    fn name(&self) -> &'static str {
        "jwt"
    }
    fn endpoints(&self) -> Vec<Endpoint> {
        vec![endpoint(
            Method::GET,
            "/token",
            "Issue a JWT for the current session",
        )]
    }
    fn error_codes(&self) -> std::collections::BTreeMap<String, String> {
        [("JWT_INVALID".into(), "JWT is invalid or expired".into())]
            .into_iter()
            .collect()
    }
}

fn hash_secret(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn member_id(organization_id: &str, user_id: &str) -> String {
    format!("{organization_id}:{user_id}")
}

fn slugify(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn urlencoding(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

fn random_challenge() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

fn serialize_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Adapter(format!("plugin serialization failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::adapter::memory::{MemoryDb, MemorySecondaryStorage};

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
            .insert(
                "user",
                "admin",
                json!({"id":"admin","email":"admin@example.com","name":"Admin","email_verified":true,"role":"admin"}),
            )
            .await
            .unwrap();
        adapter
            .insert(
                "user",
                "user",
                json!({"id":"user","email":"user@example.com","name":"User","email_verified":true,"role":"user"}),
            )
            .await
            .unwrap();
        let admin = AdminService::new(adapter.clone(), AdminGuard::new(["admin"]));
        admin.set_role("admin", "user", "manager").await.unwrap();
        let scim = ScimService::new(adapter);
        let updated = scim
            .update_user("user", json!({"name":"Updated"}))
            .await
            .unwrap();
        assert_eq!(updated["name"], "Updated");
        let page = scim.list_users(1, 1).await.unwrap();
        assert_eq!(page["totalResults"], 2);
        assert_eq!(page["itemsPerPage"], 1);
        let filtered = scim
            .list_users_filtered(
                1,
                10,
                Some(r#"(userName eq "user@example.com") and active eq true"#),
            )
            .await
            .unwrap();
        assert_eq!(filtered["totalResults"], 1);
        let operations = vec![ScimBulkOperation {
            method: "PATCH".into(),
            path: "/Users/user".into(),
            data: Some(json!({"displayName":"Bulk Updated"})),
        }];
        let result = scim.apply_bulk(&operations, 1).await.unwrap();
        assert_eq!(result[0].status, 200);
        assert_eq!(
            scim.get_user("user").await.unwrap()["displayName"],
            "Bulk Updated"
        );
        scim.update_user(
            "user",
            json!([{"op":"replace","path":"displayName","value":"Patched Again"}]),
        )
        .await
        .unwrap();
        assert_eq!(
            scim.get_user("user").await.unwrap()["displayName"],
            "Patched Again"
        );
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
        scim.add_group_member(group_id, "user").await.unwrap();
        assert_eq!(
            scim.get_group(group_id).await.unwrap()["members"][0]["value"],
            "user"
        );
        let groups = scim.list_groups("org-1", 1, 10).await.unwrap();
        assert_eq!(groups["totalResults"], 1);
        scim.remove_group_member(group_id, "user").await.unwrap();
        scim.delete_group(group_id).await.unwrap();
        assert!(scim.get_group(group_id).await.is_err());
    }
}
