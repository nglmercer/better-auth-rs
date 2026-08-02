use super::shared::{
    endpoint, hash_secret, now_seconds, optional, required, serialize_error,
};
use better_auth_core::{
    adapter::{DbAdapter, DbOperation},
    error::{AuthError, Result},
    plugin::{Endpoint, Plugin},
    schema::{FieldType, SchemaExtension, TableSchema},
};
use http::Method;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

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
    hash_secret(token)
        .as_bytes()
        .ct_eq(expected_hash.as_bytes())
        .into()
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
        self.list_users_query(start_index, count, filter, None, None)
            .await
    }

    pub async fn list_users_query(
        &self,
        start_index: usize,
        count: usize,
        filter: Option<&str>,
        sort_by: Option<&str>,
        sort_order: Option<&str>,
    ) -> Result<serde_json::Value> {
        if start_index == 0 {
            return Err(AuthError::InvalidRequest(
                "SCIM startIndex is one-based".into(),
            ));
        }
        let predicate = ScimFilter::parse(filter)?;
        let mut records = self
            .adapter
            .list("user")
            .await?
            .into_iter()
            .filter(|(_, user)| predicate.matches(user))
            .collect::<Vec<_>>();
        if let Some(sort_by) = sort_by {
            let sort_by = normalize_scim_attribute(sort_by)?;
            records.sort_by(|left, right| {
                scim_sort_value(&left.0, &left.1, &sort_by)
                    .cmp(&scim_sort_value(&right.0, &right.1, &sort_by))
            });
            if sort_order.is_some_and(|order| order.eq_ignore_ascii_case("descending")) {
                records.reverse();
            } else if sort_order.is_some_and(|order| !order.eq_ignore_ascii_case("ascending")) {
                return Err(AuthError::InvalidRequest(
                    "SCIM sortOrder must be ascending or descending".into(),
                ));
            }
        }
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
    ValuePath {
        base: String,
        subfilter: Box<Self>,
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
    OpenBracket,
    CloseBracket,
    Dot,
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
            } => scim_compare_matches(user, attribute, *operator, expected),
            Self::ValuePath {
                base,
                subfilter,
                attribute,
                operator,
                expected,
            } => {
                if base != "emails" || attribute != "email" {
                    return false;
                }
                let Some(email) = user.get("email").and_then(serde_json::Value::as_str) else {
                    return false;
                };
                let synthetic = serde_json::json!({
                    "type": "work",
                    "email": email,
                });
                subfilter.matches(&synthetic) && scim_compare_value(email, *operator, expected)
            }
            Self::And(left, right) => left.matches(user) && right.matches(user),
            Self::Or(left, right) => left.matches(user) || right.matches(user),
        }
    }
}

fn scim_compare_matches(
    user: &serde_json::Value,
    attribute: &str,
    operator: ScimCompare,
    expected: &str,
) -> bool {
    let Some(actual) = scim_attribute(user, attribute) else {
        return false;
    };
    scim_compare_value(&actual, operator, expected)
}

fn scim_compare_value(actual: &str, operator: ScimCompare, expected: &str) -> bool {
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
        ScimCompare::GreaterThan => compare_scim_values(actual, expected).is_gt(),
        ScimCompare::GreaterOrEqual => compare_scim_values(actual, expected).is_ge(),
        ScimCompare::LessThan => compare_scim_values(actual, expected).is_lt(),
        ScimCompare::LessOrEqual => compare_scim_values(actual, expected).is_le(),
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
        let raw_attribute = match self.next() {
            Some(ScimFilterToken::Word(attribute)) => attribute,
            _ => {
                return Err(AuthError::InvalidRequest(
                    "SCIM filter must start with an attribute".into(),
                ))
            }
        };
        let attribute = normalize_scim_attribute(&raw_attribute)?;
        if self.take_token(ScimFilterToken::OpenBracket) {
            let subfilter = self.parse_or()?;
            if !self.take_token(ScimFilterToken::CloseBracket)
                || !self.take_token(ScimFilterToken::Dot)
            {
                return Err(AuthError::InvalidRequest(
                    "invalid SCIM valuePath filter".into(),
                ));
            }
            let value_attribute = match self.next() {
                Some(ScimFilterToken::Word(value)) => normalize_scim_attribute(&value)?,
                _ => {
                    return Err(AuthError::InvalidRequest(
                        "SCIM valuePath is missing an attribute".into(),
                    ))
                }
            };
            let operator = match self.next() {
                Some(ScimFilterToken::Word(operator)) => scim_compare_operator(&operator)?,
                _ => {
                    return Err(AuthError::InvalidRequest(
                        "SCIM valuePath is missing an operator".into(),
                    ))
                }
            };
            let expected = match self.next() {
                Some(ScimFilterToken::Word(value) | ScimFilterToken::Value(value)) => value,
                _ => {
                    return Err(AuthError::InvalidRequest(
                        "SCIM valuePath is missing a value".into(),
                    ))
                }
            };
            return Ok(ScimFilter::ValuePath {
                base: attribute,
                subfilter: Box::new(subfilter),
                attribute: value_attribute,
                operator,
                expected,
            });
        }
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
        let operator = scim_compare_operator(&operator)?;
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

fn scim_compare_operator(operator: &str) -> Result<ScimCompare> {
    match operator.to_ascii_lowercase().as_str() {
        "eq" => Ok(ScimCompare::Eq),
        "ne" => Ok(ScimCompare::Ne),
        "co" => Ok(ScimCompare::Contains),
        "sw" => Ok(ScimCompare::StartsWith),
        "ew" => Ok(ScimCompare::EndsWith),
        "gt" => Ok(ScimCompare::GreaterThan),
        "ge" => Ok(ScimCompare::GreaterOrEqual),
        "lt" => Ok(ScimCompare::LessThan),
        "le" => Ok(ScimCompare::LessOrEqual),
        _ => Err(AuthError::InvalidRequest(
            "unsupported SCIM filter operator".into(),
        )),
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
        } else if characters[position] == '[' {
            tokens.push(ScimFilterToken::OpenBracket);
            position += 1;
        } else if characters[position] == ']' {
            tokens.push(ScimFilterToken::CloseBracket);
            position += 1;
        } else if characters[position] == '.' {
            tokens.push(ScimFilterToken::Dot);
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
                && !matches!(characters[position], '(' | ')' | '[' | ']' | '.')
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
        "emails" => Ok("emails".into()),
        "value" => Ok("email".into()),
        "type" => Ok("type".into()),
        "displayname" | "name" => Ok("name".into()),
        "active" => Ok("active".into()),
        _ => Err(AuthError::InvalidRequest(format!(
            "unsupported SCIM attribute: {attribute}"
        ))),
    }
}

fn scim_attribute(user: &serde_json::Value, attribute: &str) -> Option<String> {
    if attribute == "emails" {
        return user
            .get("email")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);
    }
    if attribute == "type" {
        return user
            .get("type")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);
    }
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

fn scim_sort_value(id: &str, user: &serde_json::Value, attribute: &str) -> String {
    if attribute == "id" {
        return id.to_ascii_lowercase();
    }
    scim_attribute(user, attribute)
        .unwrap_or_default()
        .to_ascii_lowercase()
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


