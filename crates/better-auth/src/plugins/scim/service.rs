use super::super::shared::{hash_secret, serialize_error};
use super::generate_scim_token;
use super::{
    filter::ScimFilter,
    helpers::{normalize_scim_path, scim_group_member_id, ScimErrorStatus},
    patch::{apply_scim_user_patch, merge_scim_patch},
    resources::{
        normalize_scim_attribute, scim_sort_value, scim_user_from_resource, scim_user_resource,
    },
    ScimBulkOperation, ScimBulkResponse, ScimGroup, ScimGroupMember, ScimTokenRecord,
};
use better_auth_core::{
    adapter::{record_id, DbAdapter, DbOperation, Query},
    error::{AuthError, Result},
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct ScimService {
    adapter: Arc<dyn DbAdapter>,
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
            .insert_record(
                "scim_token",
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
        let Some(value) = self
            .adapter
            .find_one("scim_token", Query::new().eq("token_hash", hash))
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
        self.adapter.insert_record("user", user.clone()).await?;
        Ok(user)
    }

    pub async fn update_user(
        &self,
        user_id: &str,
        patch: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let mut user = self
            .adapter
            .find_one("user", Query::new().eq("id", user_id.to_owned()))
            .await?
            .ok_or(AuthError::NotFound)?;
        user = apply_scim_user_patch(user, &patch)?;
        self.adapter
            .update_where(
                "user",
                Query::new().eq("id", user_id.to_owned()),
                user.clone(),
            )
            .await?;
        Ok(user)
    }

    pub async fn list_users(&self, start_index: usize, count: usize) -> Result<serde_json::Value> {
        self.list_users_filtered(start_index, count, None).await
    }

    pub async fn get_user(&self, user_id: &str) -> Result<serde_json::Value> {
        let user = self
            .adapter
            .find_one("user", Query::new().eq("id", user_id.to_owned()))
            .await?
            .ok_or(AuthError::NotFound)?;
        Ok(scim_user_resource(user_id, &user))
    }

    pub async fn delete_user(&self, user_id: &str) -> Result<()> {
        if self
            .adapter
            .find_one("user", Query::new().eq("id", user_id.to_owned()))
            .await?
            .is_none()
        {
            return Err(AuthError::NotFound);
        }
        self.adapter
            .delete_where("user", Query::new().eq("id", user_id.to_owned()))
            .await?;
        Ok(())
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
            .insert_record(
                "scim_group",
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
            .find_many("scim_group", Query::new())
            .await?
            .into_iter()
            .filter_map(|value| serde_json::from_value::<ScimGroup>(value).ok())
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
            .update_where(
                "scim_group",
                Query::new().eq("id", group_id.to_owned()),
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
        let operations = vec![
            DbOperation::DeleteWhere {
                table: "scim_group_member".into(),
                query: Query::new().eq("group_id", group_id.to_owned()),
            },
            DbOperation::DeleteWhere {
                table: "scim_group".into(),
                query: Query::new().eq("id", group_id.to_owned()),
            },
        ];
        self.adapter.transaction(operations).await
    }

    pub async fn add_group_member(&self, group_id: &str, user_id: &str) -> Result<()> {
        self.load_group(group_id).await?;
        if self
            .adapter
            .find_one("user", Query::new().eq("id", user_id.to_owned()))
            .await?
            .is_none()
        {
            return Err(AuthError::NotFound);
        }
        let member = ScimGroupMember {
            group_id: group_id.into(),
            user_id: user_id.into(),
        };
        self.adapter
            .insert_record(
                "scim_group_member",
                with_id(
                    serde_json::to_value(member).map_err(serialize_error)?,
                    scim_group_member_id(group_id, user_id),
                )?,
            )
            .await?;
        Ok(())
    }

    pub async fn remove_group_member(&self, group_id: &str, user_id: &str) -> Result<()> {
        self.load_group(group_id).await?;
        self.adapter
            .delete_where(
                "scim_group_member",
                Query::new().eq("id", scim_group_member_id(group_id, user_id)),
            )
            .await?;
        Ok(())
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
            .find_many("user", Query::new())
            .await?
            .into_iter()
            .filter(|user| predicate.matches(user))
            .map(|user| Ok((record_id(&user)?, user)))
            .collect::<Result<Vec<_>>>()?;
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
                    planned.push(DbOperation::InsertRecord {
                        table: "user".into(),
                        record: user.clone(),
                    });
                    Ok((201, Some(scim_user_resource(&id, &user))))
                }
                ("PUT", false) | ("PATCH", false) => {
                    let existing = self
                        .adapter
                        .find_one("user", Query::new().eq("id", id.to_owned()))
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
                    planned.push(DbOperation::UpdateWhere {
                        table: "user".into(),
                        query: Query::new().eq("id", id.to_owned()),
                        changes: updated.clone(),
                    });
                    Ok((200, Some(scim_user_resource(id, &updated))))
                }
                ("DELETE", false) => {
                    if self
                        .adapter
                        .find_one("user", Query::new().eq("id", id.to_owned()))
                        .await?
                        .is_none()
                    {
                        Err(AuthError::NotFound)
                    } else {
                        planned.push(DbOperation::DeleteWhere {
                            table: "user".into(),
                            query: Query::new().eq("id", id.to_owned()),
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
            .find_one("scim_group", Query::new().eq("id", group_id.to_owned()))
            .await?
            .ok_or(AuthError::NotFound)?;
        serde_json::from_value(value).map_err(serialize_error)
    }

    async fn group_resource(&self, group: &ScimGroup) -> Result<serde_json::Value> {
        let members = self
            .adapter
            .find_many(
                "scim_group_member",
                Query::new().eq("group_id", group.id.clone()),
            )
            .await?
            .into_iter()
            .filter_map(|value| serde_json::from_value::<ScimGroupMember>(value).ok())
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
        let mut operations = vec![DbOperation::DeleteWhere {
            table: "scim_group_member".into(),
            query: Query::new().eq("group_id", group_id.to_owned()),
        }];
        for member in members {
            let user_id = member
                .get("value")
                .or_else(|| member.get("user_id"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    AuthError::InvalidRequest("SCIM group member requires value".into())
                })?;
            if self
                .adapter
                .find_one("user", Query::new().eq("id", user_id.to_owned()))
                .await?
                .is_none()
            {
                return Err(AuthError::NotFound);
            }
            let member = ScimGroupMember {
                group_id: group_id.into(),
                user_id: user_id.into(),
            };
            operations.push(DbOperation::InsertRecord {
                table: "scim_group_member".into(),
                record: with_id(
                    serde_json::to_value(member).map_err(serialize_error)?,
                    scim_group_member_id(group_id, user_id),
                )?,
            });
        }
        self.adapter.transaction(operations).await
    }
}

fn with_id(mut record: serde_json::Value, id: String) -> Result<serde_json::Value> {
    record
        .as_object_mut()
        .ok_or_else(|| AuthError::Adapter("SCIM record is not an object".into()))?
        .insert("id".into(), id.into());
    Ok(record)
}
