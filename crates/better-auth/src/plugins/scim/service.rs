use super::super::shared::{hash_secret, serialize_error};
use super::generate_scim_token;
use super::{
    filter::ScimFilter,
    helpers::scim_group_member_id,
    patch::apply_scim_user_patch,
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
use std::{collections::HashSet, sync::Arc};
use uuid::Uuid;

#[derive(Clone)]
pub struct ScimService {
    adapter: Arc<dyn DbAdapter>,
}
impl ScimService {
    pub fn new(adapter: Arc<dyn DbAdapter>) -> Self {
        Self { adapter }
    }

    /// Fails with `NotFound` unless `user_id` belongs to `organization_id`. A user outside
    /// the organization gets the same answer as a user who does not exist.
    async fn require_member(&self, organization_id: &str, user_id: &str) -> Result<()> {
        if self
            .adapter
            .find_one(
                "organization_member",
                Query::new().eq("id", membership_id(organization_id, user_id)),
            )
            .await?
            .is_some()
        {
            Ok(())
        } else {
            Err(AuthError::NotFound)
        }
    }

    async fn user_row(&self, user_id: &str) -> Result<serde_json::Value> {
        self.adapter
            .find_one("user", Query::new().eq("id", user_id.to_owned()))
            .await?
            .ok_or(AuthError::NotFound)
    }

    /// The IDs of the users who belong to `organization_id`.
    async fn member_ids(&self, organization_id: &str) -> Result<HashSet<String>> {
        Ok(self
            .adapter
            .find_many(
                "organization_member",
                Query::new().eq("organization_id", organization_id.to_owned()),
            )
            .await?
            .iter()
            .filter_map(|row| {
                row.get("user_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .collect())
    }

    /// Whether the user belongs to an organization other than `organization_id`.
    async fn in_other_organization(&self, organization_id: &str, user_id: &str) -> Result<bool> {
        Ok(self
            .adapter
            .find_many(
                "organization_member",
                Query::new().eq("user_id", user_id.to_owned()),
            )
            .await?
            .iter()
            .any(|row| {
                row.get("organization_id")
                    .and_then(serde_json::Value::as_str)
                    != Some(organization_id)
            }))
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

    /// Creates a user who is a member of `organization_id`. An email that already has an
    /// account is refused rather than linked, so a SCIM token cannot take over an existing
    /// account.
    pub async fn create_user(
        &self,
        organization_id: &str,
        email: &str,
        name: &str,
    ) -> Result<serde_json::Value> {
        let email = email.trim().to_ascii_lowercase();
        if self
            .adapter
            .find_one("user", Query::new().eq("email", email.clone()))
            .await?
            .is_some()
        {
            return Err(AuthError::InvalidRequest(
                "a user with this email already exists".into(),
            ));
        }
        let id = Uuid::new_v4().to_string();
        let user = json!({
            "id": id,
            "email": email,
            "name": name.trim(),
            "email_verified": true,
            "role": "user",
        });
        self.adapter
            .transaction(vec![
                DbOperation::InsertRecord {
                    table: "user".into(),
                    record: user.clone(),
                },
                DbOperation::InsertRecord {
                    table: "organization_member".into(),
                    record: membership_record(organization_id, &id),
                },
            ])
            .await?;
        Ok(user)
    }

    /// Creates a user from a SCIM resource body, as a member of `organization_id`.
    pub async fn create_from_resource(
        &self,
        organization_id: &str,
        resource: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let parsed = scim_user_from_resource(resource)?;
        let email = parsed["email"].as_str().unwrap_or_default();
        let name = parsed["name"].as_str().unwrap_or_default();
        let user = self.create_user(organization_id, email, name).await?;
        Ok(scim_user_resource(
            user["id"].as_str().unwrap_or_default(),
            &user,
        ))
    }

    /// Changes a member of `organization_id`. Role changes are refused by the PATCH
    /// parser, and a profile shared with another organization cannot be changed here.
    pub async fn update_user(
        &self,
        organization_id: &str,
        user_id: &str,
        patch: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.require_member(organization_id, user_id).await?;
        let existing = self.user_row(user_id).await?;
        let updated = apply_scim_user_patch(existing.clone(), &patch)?;
        let changed = ["email", "name", "active"]
            .iter()
            .any(|key| existing.get(*key) != updated.get(*key));
        if changed && self.in_other_organization(organization_id, user_id).await? {
            return Err(AuthError::Forbidden(
                "this user also belongs to another organization and cannot be changed here".into(),
            ));
        }
        self.adapter
            .update_where(
                "user",
                Query::new().eq("id", user_id.to_owned()),
                updated.clone(),
            )
            .await?;
        Ok(updated)
    }

    pub async fn list_users(
        &self,
        organization_id: &str,
        start_index: usize,
        count: usize,
    ) -> Result<serde_json::Value> {
        self.list_users_filtered(organization_id, start_index, count, None)
            .await
    }

    pub async fn get_user(
        &self,
        organization_id: &str,
        user_id: &str,
    ) -> Result<serde_json::Value> {
        self.require_member(organization_id, user_id).await?;
        let user = self.user_row(user_id).await?;
        Ok(scim_user_resource(user_id, &user))
    }

    /// Removes the user from `organization_id` only. The account stays, because other
    /// organizations, or the user's own sign-in, may still need it.
    pub async fn delete_user(&self, organization_id: &str, user_id: &str) -> Result<()> {
        self.require_member(organization_id, user_id).await?;
        // The user leaves this organization's groups with the membership. Groups of other
        // organizations are not touched.
        let groups = self
            .adapter
            .find_many(
                "scim_group",
                Query::new().eq("organization_id", organization_id.to_owned()),
            )
            .await?;
        for group in groups {
            if let Some(group_id) = group.get("id").and_then(serde_json::Value::as_str) {
                self.adapter
                    .delete_where(
                        "scim_group_member",
                        Query::new().eq("id", scim_group_member_id(group_id, user_id)),
                    )
                    .await?;
            }
        }
        self.adapter
            .delete_where(
                "organization_member",
                Query::new().eq("id", membership_id(organization_id, user_id)),
            )
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
        self.group_resource(organization_id, &group).await
    }

    pub async fn get_group(
        &self,
        organization_id: &str,
        group_id: &str,
    ) -> Result<serde_json::Value> {
        let group = self.load_group(organization_id, group_id).await?;
        self.group_resource(organization_id, &group).await
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
            resources.push(self.group_resource(organization_id, group).await?);
        }
        Ok(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": total,
            "startIndex": start + 1,
            "itemsPerPage": resources.len(),
            "Resources": resources,
        }))
    }

    /// Changes a group's name or members. Members must belong to `organization_id`.
    pub async fn update_group(
        &self,
        organization_id: &str,
        group_id: &str,
        patch: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let mut group = self.load_group(organization_id, group_id).await?;
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
            self.replace_group_members(organization_id, group_id, members)
                .await?;
        }
        self.group_resource(organization_id, &group).await
    }

    pub async fn delete_group(&self, organization_id: &str, group_id: &str) -> Result<()> {
        self.load_group(organization_id, group_id).await?;
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

    /// Adds a member of `organization_id` to one of its groups.
    pub async fn add_group_member(
        &self,
        organization_id: &str,
        group_id: &str,
        user_id: &str,
    ) -> Result<()> {
        self.load_group(organization_id, group_id).await?;
        self.require_member(organization_id, user_id).await?;
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

    pub async fn remove_group_member(
        &self,
        organization_id: &str,
        group_id: &str,
        user_id: &str,
    ) -> Result<()> {
        self.load_group(organization_id, group_id).await?;
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
        organization_id: &str,
        start_index: usize,
        count: usize,
        filter: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.list_users_query(organization_id, start_index, count, filter, None, None)
            .await
    }

    pub async fn list_users_query(
        &self,
        organization_id: &str,
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
        let members = self.member_ids(organization_id).await?;
        let mut records = self
            .adapter
            .find_many("user", Query::new())
            .await?
            .into_iter()
            .filter(|user| predicate.matches(user))
            .map(|user| Ok((record_id(&user)?, user)))
            .collect::<Result<Vec<_>>>()?;
        records.retain(|(id, _)| members.contains(id));
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

    /// SCIM bulk requests are not available yet. They act on users without the
    /// organization scope the other user operations enforce, so they are refused
    /// rather than run unscoped.
    pub async fn apply_bulk(
        &self,
        _organization_id: &str,
        _operations: &[ScimBulkOperation],
        _fail_on_errors: usize,
    ) -> Result<Vec<ScimBulkResponse>> {
        Err(AuthError::Forbidden(
            "SCIM bulk requests are not available until they are organization-scoped".into(),
        ))
    }

    /// The group, if it belongs to `organization_id`. Any other group is `NotFound`, so a
    /// token cannot learn that another organization's group exists.
    async fn load_group(&self, organization_id: &str, group_id: &str) -> Result<ScimGroup> {
        let value = self
            .adapter
            .find_one("scim_group", Query::new().eq("id", group_id.to_owned()))
            .await?
            .ok_or(AuthError::NotFound)?;
        let group: ScimGroup = serde_json::from_value(value).map_err(serialize_error)?;
        if group.organization_id != organization_id {
            return Err(AuthError::NotFound);
        }
        Ok(group)
    }

    /// The group as SCIM shows it. Only current members of `organization_id` are listed, so a
    /// membership left over from a removed user never appears.
    async fn group_resource(
        &self,
        organization_id: &str,
        group: &ScimGroup,
    ) -> Result<serde_json::Value> {
        let current = self.member_ids(organization_id).await?;
        let members = self
            .adapter
            .find_many(
                "scim_group_member",
                Query::new().eq("group_id", group.id.clone()),
            )
            .await?
            .into_iter()
            .filter_map(|value| serde_json::from_value::<ScimGroupMember>(value).ok())
            .filter(|member| current.contains(&member.user_id))
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

    /// Replaces a group's members. Each one must belong to `organization_id`, and the request
    /// is refused as a whole if any does not.
    async fn replace_group_members(
        &self,
        organization_id: &str,
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
            self.require_member(organization_id, user_id).await?;
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

/// The organization-membership record ID. It matches the organization plugin's member IDs.
fn membership_id(organization_id: &str, user_id: &str) -> String {
    format!("{organization_id}:{user_id}")
}

fn membership_record(organization_id: &str, user_id: &str) -> serde_json::Value {
    json!({
        "id": membership_id(organization_id, user_id),
        "organization_id": organization_id,
        "user_id": user_id,
        "role": "member",
    })
}
