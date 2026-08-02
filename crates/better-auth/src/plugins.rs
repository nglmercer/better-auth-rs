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
        ]
    }
    fn schema(&self) -> SchemaExtension {
        SchemaExtension::default().table(
            "sso_connection",
            TableSchema::default()
                .field("id", required(FieldType::String).unique())
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
            endpoint(Method::POST, "/scim/v2/Bulk", "Apply SCIM bulk operations"),
        ]
    }
    fn schema(&self) -> SchemaExtension {
        SchemaExtension::default().table(
            "scim_token",
            TableSchema::default()
                .field("id", required(FieldType::String).unique())
                .field("organization_id", required(FieldType::String))
                .field("token_hash", required(FieldType::String).unique())
                .field("expires_at", optional(FieldType::DateTime)),
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

impl ScimService {
    pub fn new(adapter: Arc<dyn DbAdapter>) -> Self {
        Self { adapter }
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
        user = merge_scim_patch(user, &patch)?;
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
}

#[derive(Clone, Debug)]
enum ScimFilter {
    All,
    Eq(String, String),
    Contains(String, String),
    StartsWith(String, String),
    Present(String),
}

impl ScimFilter {
    fn parse(filter: Option<&str>) -> Result<Self> {
        let Some(filter) = filter.map(str::trim).filter(|filter| !filter.is_empty()) else {
            return Ok(Self::All);
        };
        let tokens = filter.split_whitespace().collect::<Vec<_>>();
        if tokens.len() == 2 && tokens[1].eq_ignore_ascii_case("pr") {
            return Ok(Self::Present(normalize_scim_attribute(tokens[0])?));
        }
        if tokens.len() < 3 {
            return Err(AuthError::InvalidRequest("invalid SCIM filter".into()));
        }
        let attribute = normalize_scim_attribute(tokens[0])?;
        let operator = tokens[1].to_ascii_lowercase();
        let raw = tokens[2..].join(" ");
        let value = raw
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .or_else(|| {
                raw.strip_prefix('\'')
                    .and_then(|value| value.strip_suffix('\''))
            })
            .unwrap_or(&raw)
            .to_owned();
        match operator.as_str() {
            "eq" => Ok(Self::Eq(attribute, value)),
            "co" => Ok(Self::Contains(attribute, value)),
            "sw" => Ok(Self::StartsWith(attribute, value)),
            "pr" if tokens.len() == 2 => Ok(Self::Present(attribute)),
            _ => Err(AuthError::InvalidRequest(
                "SCIM supports eq, co, sw, and pr filters".into(),
            )),
        }
    }

    fn matches(&self, user: &serde_json::Value) -> bool {
        if matches!(self, Self::All) {
            return true;
        }
        let Some(value) = scim_attribute(user, self.attribute()) else {
            return false;
        };
        match self {
            Self::All => true,
            Self::Eq(_, expected) => value.eq_ignore_ascii_case(expected),
            Self::Contains(_, expected) => value
                .to_ascii_lowercase()
                .contains(&expected.to_ascii_lowercase()),
            Self::StartsWith(_, expected) => value
                .to_ascii_lowercase()
                .starts_with(&expected.to_ascii_lowercase()),
            Self::Present(_) => true,
        }
    }

    fn attribute(&self) -> &str {
        match self {
            Self::All => "",
            Self::Eq(attribute, _)
            | Self::Contains(attribute, _)
            | Self::StartsWith(attribute, _)
            | Self::Present(attribute) => attribute,
        }
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

fn merge_scim_patch(
    mut user: serde_json::Value,
    patch: &serde_json::Value,
) -> Result<serde_json::Value> {
    let Some(patch) = patch.as_object() else {
        return Err(AuthError::InvalidRequest(
            "SCIM patch must be an object".into(),
        ));
    };
    for (key, value) in patch {
        match key.as_str() {
            "userName" | "email" => user["email"] = value.clone(),
            "displayName" | "name" => user["name"] = value.clone(),
            "active" => user["active"] = value.clone(),
            "role" => user["role"] = value.clone(),
            "id" | "schemas" | "meta" => {}
            _ => {
                return Err(AuthError::InvalidRequest(format!(
                    "unsupported SCIM patch attribute: {key}"
                )))
            }
        }
    }
    Ok(user)
}

fn normalize_scim_path(path: &str) -> Result<String> {
    let path = path
        .strip_prefix("/scim/v2")
        .or_else(|| path.strip_prefix("/"))
        .unwrap_or(path)
        .trim_end_matches('/');
    if path == "/Users" || path.starts_with("/Users/") {
        Ok(path.into())
    } else {
        Err(AuthError::InvalidRequest("invalid SCIM bulk path".into()))
    }
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
            .list_users_filtered(1, 10, Some(r#"userName eq "user@example.com""#))
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
    }
}
