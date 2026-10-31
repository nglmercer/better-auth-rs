use super::shared::{endpoint, member_id, required, serialize_error, slugify};
use better_auth_core::{
    adapter::{DbAdapter, DbOperation, Query},
    error::{AuthError, Result},
    plugin::{Endpoint, Plugin},
    schema::{FieldType, SchemaExtension, TableSchema},
};
use http::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

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
            .table(
                "organization_invitation",
                TableSchema::default()
                    .field("id", required(FieldType::String).unique())
                    .field("organization_id", required(FieldType::String))
                    .field("email", required(FieldType::String))
                    .field("role", required(FieldType::String))
                    .field("token_hash", required(FieldType::String).unique())
                    .field("expires_at", required(FieldType::DateTime))
                    .field("accepted", required(FieldType::Boolean)),
            )
            .table(
                "organization_team",
                TableSchema::default()
                    .field("id", required(FieldType::String).unique())
                    .field("organization_id", required(FieldType::String))
                    .field("name", required(FieldType::String)),
            )
            .table(
                "organization_team_member",
                TableSchema::default()
                    .field("id", required(FieldType::String).unique())
                    .field("team_id", required(FieldType::String))
                    .field("user_id", required(FieldType::String)),
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
        let name = validated_name(name)?;
        let organization = Organization {
            id: Uuid::new_v4().to_string(),
            slug: slugify(&name),
            name,
            created_by: created_by.to_owned(),
        };
        let member = OrganizationMember {
            organization_id: organization.id.clone(),
            user_id: created_by.to_owned(),
            role: "owner".into(),
        };
        let member_id = member_id(&member.organization_id, &member.user_id);
        let member_record = with_id(
            serde_json::to_value(&member).map_err(serialize_error)?,
            member_id,
        )?;
        self.adapter
            .transaction(vec![
                DbOperation::InsertRecord {
                    table: "organization".into(),
                    record: serde_json::to_value(&organization).map_err(serialize_error)?,
                },
                DbOperation::InsertRecord {
                    table: "organization_member".into(),
                    record: member_record,
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
            .find_one(
                "organization",
                Query::new().eq("id", organization_id.to_owned()),
            )
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
            .insert_record(
                "organization_member",
                with_id(
                    serde_json::to_value(&member).map_err(serialize_error)?,
                    member_id(organization_id, user_id),
                )?,
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
            .find_one(
                "organization_member",
                Query::new().eq("id", member_id(organization_id, user_id)),
            )
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(
            serde_json::from_value(value).map_err(serialize_error)?,
        ))
    }
}

fn with_id(mut record: Value, id: String) -> Result<Value> {
    record
        .as_object_mut()
        .ok_or_else(|| AuthError::Adapter("organization record is not an object".into()))?
        .insert("id".into(), Value::String(id));
    Ok(record)
}

/// Roles, from most to least privileged. `owner` manages everything. `admin`
/// manages members. `member` has no management rights.
pub const ROLES: [&str; 3] = ["owner", "admin", "member"];
const INVITATION_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Result of inviting someone. The plaintext token is returned once, for delivery.
#[derive(Clone, Debug)]
pub struct Invitation {
    pub token: String,
    pub email: String,
    pub role: String,
}

impl OrganizationService {
    async fn role_of(&self, organization_id: &str, user_id: &str) -> Result<Option<String>> {
        Ok(self
            .member(organization_id, user_id)
            .await?
            .map(|member| member.role))
    }

    /// Requires the actor to be a member. Non-members get `NotFound`, so the
    /// existence of an organization is not revealed to outsiders.
    async fn require_member(&self, organization_id: &str, actor: &str) -> Result<String> {
        self.role_of(organization_id, actor)
            .await?
            .ok_or(AuthError::NotFound)
    }

    async fn require_manager(&self, organization_id: &str, actor: &str) -> Result<String> {
        let role = self.require_member(organization_id, actor).await?;
        if role == "owner" || role == "admin" {
            Ok(role)
        } else {
            Err(AuthError::Forbidden(
                "organization admin role required".into(),
            ))
        }
    }

    async fn owner_count(&self, organization_id: &str) -> Result<usize> {
        Ok(self
            .adapter
            .find_many(
                "organization_member",
                Query::new()
                    .eq("organization_id", organization_id.to_owned())
                    .eq("role", "owner".to_owned()),
            )
            .await?
            .len())
    }

    /// Organizations the user belongs to.
    pub async fn list_for_user(&self, user_id: &str) -> Result<Vec<Organization>> {
        let memberships = self
            .adapter
            .find_many(
                "organization_member",
                Query::new().eq("user_id", user_id.to_owned()),
            )
            .await?;
        let mut organizations = Vec::new();
        for row in memberships {
            let Some(organization_id) = row.get("organization_id").and_then(Value::as_str) else {
                continue;
            };
            if let Some(value) = self
                .adapter
                .find_one(
                    "organization",
                    Query::new().eq("id", organization_id.to_owned()),
                )
                .await?
            {
                organizations.push(serde_json::from_value(value).map_err(serialize_error)?);
            }
        }
        Ok(organizations)
    }

    /// Members of an organization. Only members may read the list.
    pub async fn members(
        &self,
        organization_id: &str,
        actor: &str,
    ) -> Result<Vec<OrganizationMember>> {
        self.require_member(organization_id, actor).await?;
        let rows = self
            .adapter
            .find_many(
                "organization_member",
                Query::new().eq("organization_id", organization_id.to_owned()),
            )
            .await?;
        rows.into_iter()
            .map(|row| serde_json::from_value(row).map_err(serialize_error))
            .collect()
    }

    /// Creates a single-use invitation. The token is stored only as a hash.
    pub async fn invite(
        &self,
        organization_id: &str,
        actor: &str,
        email: &str,
        role: &str,
        token: &str,
    ) -> Result<Invitation> {
        self.require_manager(organization_id, actor).await?;
        if !ROLES.contains(&role) || role == "owner" {
            return Err(AuthError::InvalidRequest(
                "invitations grant admin or member, not owner".into(),
            ));
        }
        let email = email.trim().to_ascii_lowercase();
        self.adapter
            .insert_record(
                "organization_invitation",
                json!({
                    "id": Uuid::new_v4().to_string(),
                    "organization_id": organization_id,
                    "email": email,
                    "role": role,
                    "token_hash": hash_token(token),
                    "expires_at": now_seconds() + INVITATION_TTL_SECONDS,
                    "accepted": false,
                }),
            )
            .await?;
        Ok(Invitation {
            token: token.to_owned(),
            email,
            role: role.to_owned(),
        })
    }

    /// Accepts an invitation. The signed-in user's email must match the invitation.
    pub async fn accept(
        &self,
        user_id: &str,
        user_email: &str,
        token: &str,
    ) -> Result<OrganizationMember> {
        let row = self
            .adapter
            .find_one(
                "organization_invitation",
                Query::new().eq("token_hash", hash_token(token)),
            )
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let organization_id = row["organization_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let invited_email = row["email"].as_str().unwrap_or_default().to_owned();
        let role = row["role"].as_str().unwrap_or("member").to_owned();
        let expires_at = row["expires_at"].as_u64().unwrap_or(0);
        if row["accepted"].as_bool() != Some(false) || expires_at <= now_seconds() {
            return Err(AuthError::Unauthorized);
        }
        if invited_email != user_email.trim().to_ascii_lowercase() {
            return Err(AuthError::Forbidden(
                "this invitation was sent to another address".into(),
            ));
        }
        // Accepting is a conditional write, so a token works exactly once.
        let claimed = self
            .adapter
            .update_where(
                "organization_invitation",
                Query::new()
                    .eq("token_hash", hash_token(token))
                    .eq("accepted", false),
                json!({"accepted": true}),
            )
            .await?;
        if claimed == 0 {
            return Err(AuthError::Unauthorized);
        }
        if let Some(existing) = self.member(&organization_id, user_id).await? {
            return Ok(existing);
        }
        self.add_member(&organization_id, user_id, &role).await
    }

    /// Removes a member. Admins may remove members, only owners may remove owners,
    /// and the last owner cannot be removed.
    pub async fn remove_member(
        &self,
        organization_id: &str,
        actor: &str,
        target: &str,
    ) -> Result<()> {
        let actor_role = self.require_manager(organization_id, actor).await?;
        let target_role = self
            .role_of(organization_id, target)
            .await?
            .ok_or(AuthError::NotFound)?;
        if target_role == "owner" {
            if actor_role != "owner" {
                return Err(AuthError::Forbidden(
                    "only an owner can remove an owner".into(),
                ));
            }
            if self.owner_count(organization_id).await? <= 1 {
                return Err(AuthError::Forbidden(
                    "an organization keeps at least one owner".into(),
                ));
            }
        }
        self.remove_team_memberships(organization_id, target)
            .await?;
        self.adapter
            .delete_where(
                "organization_member",
                Query::new().eq("id", member_id(organization_id, target)),
            )
            .await?;
        Ok(())
    }

    /// Changes a member's role. Only owners change roles, and the last owner cannot be demoted.
    pub async fn set_role(
        &self,
        organization_id: &str,
        actor: &str,
        target: &str,
        role: &str,
    ) -> Result<()> {
        let actor_role = self.require_member(organization_id, actor).await?;
        if actor_role != "owner" {
            return Err(AuthError::Forbidden(
                "organization owner role required".into(),
            ));
        }
        if !ROLES.contains(&role) {
            return Err(AuthError::InvalidRequest(
                "unknown organization role".into(),
            ));
        }
        let current = self
            .role_of(organization_id, target)
            .await?
            .ok_or(AuthError::NotFound)?;
        if current == "owner" && role != "owner" && self.owner_count(organization_id).await? <= 1 {
            return Err(AuthError::Forbidden(
                "an organization keeps at least one owner".into(),
            ));
        }
        self.adapter
            .update_where(
                "organization_member",
                Query::new().eq("id", member_id(organization_id, target)),
                json!({"role": role}),
            )
            .await?;
        Ok(())
    }
}

/// Organization name rules, shared by create and update.
fn validated_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() || name.len() > 120 {
        return Err(AuthError::InvalidRequest(
            "organization name is invalid".into(),
        ));
    }
    Ok(name.to_owned())
}

/// Slugs are lowercase letters, digits and single dashes, 1 to 64 characters, and
/// neither start nor end with a dash.
fn validated_slug(slug: &str) -> Result<String> {
    let valid = !slug.is_empty()
        && slug.len() <= 64
        && !slug.starts_with('-')
        && !slug.ends_with('-')
        && !slug.contains("--")
        && slug
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if valid {
        Ok(slug.to_owned())
    } else {
        Err(AuthError::InvalidRequest(
            "organization slug may contain only lowercase letters, digits and single dashes".into(),
        ))
    }
}

/// An invitation as the people who may see it see it. The token hash is never included.
fn invitation_view(row: &Value) -> Value {
    json!({
        "id": row.get("id").cloned().unwrap_or_default(),
        "organization_id": row.get("organization_id").cloned().unwrap_or_default(),
        "email": row.get("email").cloned().unwrap_or_default(),
        "role": row.get("role").cloned().unwrap_or_default(),
        "expires_at": row.get("expires_at").cloned().unwrap_or_default(),
    })
}

/// A team inside an organization. Its members must also be members of the organization.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Team {
    pub id: String,
    pub organization_id: String,
    pub name: String,
}

/// What each built-in role may do, as `(resource, action)` pairs. The service checks
/// its own rules directly, and this table describes the same rules so an
/// application can ask about them. A test keeps the two in agreement.
pub fn role_grants(role: &str, resource: &str, action: &str) -> bool {
    let grants: &[(&str, &str)] = match role {
        "owner" => &[
            ("organization", "update"),
            ("organization", "delete"),
            ("member", "update"),
            ("member", "delete"),
            ("invitation", "create"),
            ("invitation", "cancel"),
            ("team", "create"),
            ("team", "update"),
            ("team", "delete"),
        ],
        "admin" => &[
            ("organization", "update"),
            ("member", "delete"),
            ("invitation", "create"),
            ("invitation", "cancel"),
            ("team", "create"),
            ("team", "update"),
            ("team", "delete"),
        ],
        _ => &[],
    };
    grants.contains(&(resource, action))
}

fn team_member_id(team_id: &str, user_id: &str) -> String {
    format!("{team_id}:{user_id}")
}

impl OrganizationService {
    async fn organization(&self, organization_id: &str) -> Result<Organization> {
        let value = self
            .adapter
            .find_one(
                "organization",
                Query::new().eq("id", organization_id.to_owned()),
            )
            .await?
            .ok_or(AuthError::NotFound)?;
        serde_json::from_value(value).map_err(serialize_error)
    }

    async fn slug_taken(&self, slug: &str) -> Result<bool> {
        Ok(self
            .adapter
            .find_one("organization", Query::new().eq("slug", slug.to_owned()))
            .await?
            .is_some())
    }

    /// The organization, for any member.
    pub async fn get(&self, organization_id: &str, actor: &str) -> Result<Organization> {
        self.require_member(organization_id, actor).await?;
        self.organization(organization_id).await
    }

    /// Changes the name or the slug. Owners and admins may do this. A slug that
    /// another organization already uses is refused.
    pub async fn update(
        &self,
        organization_id: &str,
        actor: &str,
        name: Option<&str>,
        slug: Option<&str>,
    ) -> Result<Organization> {
        self.require_manager(organization_id, actor).await?;
        let mut organization = self.organization(organization_id).await?;
        let mut changes = serde_json::Map::new();
        if let Some(name) = name {
            organization.name = validated_name(name)?;
            changes.insert("name".into(), json!(organization.name));
        }
        if let Some(slug) = slug {
            let slug = validated_slug(slug)?;
            if slug != organization.slug && self.slug_taken(&slug).await? {
                return Err(AuthError::InvalidRequest(
                    "that slug is already in use".into(),
                ));
            }
            organization.slug = slug;
            changes.insert("slug".into(), json!(organization.slug));
        }
        if !changes.is_empty() {
            self.adapter
                .update_where(
                    "organization",
                    Query::new().eq("id", organization_id.to_owned()),
                    Value::Object(changes),
                )
                .await?;
        }
        Ok(organization)
    }

    /// Deletes the organization with its teams, memberships and invitations, in one
    /// transaction. Only an owner may do this.
    pub async fn delete(&self, organization_id: &str, actor: &str) -> Result<()> {
        let role = self.require_member(organization_id, actor).await?;
        if role != "owner" {
            return Err(AuthError::Forbidden(
                "organization owner role required".into(),
            ));
        }
        self.organization(organization_id).await?;
        let by_organization = || Query::new().eq("organization_id", organization_id.to_owned());
        let mut operations = Vec::new();
        for team in self.teams(organization_id).await? {
            operations.push(DbOperation::DeleteWhere {
                table: "organization_team_member".into(),
                query: Query::new().eq("team_id", team.id),
            });
        }
        operations.push(DbOperation::DeleteWhere {
            table: "organization_team".into(),
            query: by_organization(),
        });
        operations.push(DbOperation::DeleteWhere {
            table: "organization_member".into(),
            query: by_organization(),
        });
        operations.push(DbOperation::DeleteWhere {
            table: "organization_invitation".into(),
            query: by_organization(),
        });
        operations.push(DbOperation::DeleteWhere {
            table: "organization".into(),
            query: Query::new().eq("id", organization_id.to_owned()),
        });
        self.adapter.transaction(operations).await
    }

    /// Removes the caller's own membership. The last owner cannot leave, so the
    /// organization is never left without one.
    pub async fn leave(&self, organization_id: &str, actor: &str) -> Result<()> {
        let role = self.require_member(organization_id, actor).await?;
        if role == "owner" && self.owner_count(organization_id).await? <= 1 {
            return Err(AuthError::Forbidden(
                "the last owner cannot leave; transfer ownership or delete the organization".into(),
            ));
        }
        self.remove_team_memberships(organization_id, actor).await?;
        self.adapter
            .delete_where(
                "organization_member",
                Query::new().eq("id", member_id(organization_id, actor)),
            )
            .await?;
        Ok(())
    }

    /// Pending invitations of an organization. Owners and admins may read them.
    pub async fn list_invitations(&self, organization_id: &str, actor: &str) -> Result<Vec<Value>> {
        self.require_manager(organization_id, actor).await?;
        let rows = self
            .adapter
            .find_many(
                "organization_invitation",
                Query::new()
                    .eq("organization_id", organization_id.to_owned())
                    .eq("accepted", false),
            )
            .await?;
        Ok(rows.iter().map(invitation_view).collect())
    }

    /// Withdraws a pending invitation. Returns false when no such invitation exists
    /// in this organization.
    pub async fn cancel_invitation(
        &self,
        organization_id: &str,
        actor: &str,
        invitation_id: &str,
    ) -> Result<bool> {
        self.require_manager(organization_id, actor).await?;
        let removed = self
            .adapter
            .delete_where(
                "organization_invitation",
                Query::new()
                    .eq("id", invitation_id.to_owned())
                    .eq("organization_id", organization_id.to_owned())
                    .eq("accepted", false),
            )
            .await?;
        Ok(removed > 0)
    }

    /// Declines an invitation sent to `user_email`. The invitation is deleted, so
    /// the token stops working. Returns false when the invitation is not theirs.
    pub async fn reject_invitation(&self, user_email: &str, invitation_id: &str) -> Result<bool> {
        let removed = self
            .adapter
            .delete_where(
                "organization_invitation",
                Query::new()
                    .eq("id", invitation_id.to_owned())
                    .eq("email", user_email.trim().to_ascii_lowercase())
                    .eq("accepted", false),
            )
            .await?;
        Ok(removed > 0)
    }

    /// Pending, unexpired invitations addressed to `user_email`.
    pub async fn list_user_invitations(&self, user_email: &str) -> Result<Vec<Value>> {
        let rows = self
            .adapter
            .find_many(
                "organization_invitation",
                Query::new()
                    .eq("email", user_email.trim().to_ascii_lowercase())
                    .eq("accepted", false),
            )
            .await?;
        let now = now_seconds();
        Ok(rows
            .iter()
            .filter(|row| row["expires_at"].as_u64().unwrap_or(0) > now)
            .map(invitation_view)
            .collect())
    }

    /// Whether the caller's role grants every `(resource, action)` pair requested.
    /// Non-members get `NotFound`, as everywhere else in this service.
    pub async fn has_permission(
        &self,
        organization_id: &str,
        actor: &str,
        permission: &std::collections::BTreeMap<String, Vec<String>>,
    ) -> Result<bool> {
        let role = self.require_member(organization_id, actor).await?;
        if permission.is_empty() {
            return Err(AuthError::InvalidRequest(
                "permission must name at least one resource and action".into(),
            ));
        }
        Ok(permission.iter().all(|(resource, actions)| {
            !actions.is_empty()
                && actions
                    .iter()
                    .all(|action| role_grants(&role, resource, action))
        }))
    }

    /// The organization with its members and teams. Owners and admins also get the
    /// pending invitations. Members without that role get an empty list.
    pub async fn get_full(&self, organization_id: &str, actor: &str) -> Result<Value> {
        let role = self.require_member(organization_id, actor).await?;
        let organization = self.organization(organization_id).await?;
        let members = self.members(organization_id, actor).await?;
        let teams = self.teams(organization_id).await?;
        let invitations = if role == "owner" || role == "admin" {
            self.list_invitations(organization_id, actor).await?
        } else {
            Vec::new()
        };
        Ok(json!({
            "organization": organization,
            "members": members,
            "teams": teams,
            "invitations": invitations,
        }))
    }

    /// One pending invitation of an organization. Owners and admins may read it.
    pub async fn get_invitation(
        &self,
        organization_id: &str,
        actor: &str,
        invitation_id: &str,
    ) -> Result<Value> {
        self.require_manager(organization_id, actor).await?;
        let row = self
            .adapter
            .find_one(
                "organization_invitation",
                Query::new()
                    .eq("id", invitation_id.to_owned())
                    .eq("organization_id", organization_id.to_owned())
                    .eq("accepted", false),
            )
            .await?
            .ok_or(AuthError::NotFound)?;
        Ok(invitation_view(&row))
    }

    /// Whether a slug is well formed and unused.
    pub async fn slug_available(&self, slug: &str) -> Result<bool> {
        let slug = validated_slug(slug)?;
        Ok(!self.slug_taken(&slug).await?)
    }

    async fn team(&self, organization_id: &str, team_id: &str) -> Result<Team> {
        let value = self
            .adapter
            .find_one(
                "organization_team",
                Query::new()
                    .eq("id", team_id.to_owned())
                    .eq("organization_id", organization_id.to_owned()),
            )
            .await?
            .ok_or(AuthError::NotFound)?;
        serde_json::from_value(value).map_err(serialize_error)
    }

    async fn teams(&self, organization_id: &str) -> Result<Vec<Team>> {
        self.adapter
            .find_many(
                "organization_team",
                Query::new().eq("organization_id", organization_id.to_owned()),
            )
            .await?
            .into_iter()
            .map(|row| serde_json::from_value(row).map_err(serialize_error))
            .collect()
    }

    /// Removes `user_id` from every team of the organization.
    async fn remove_team_memberships(&self, organization_id: &str, user_id: &str) -> Result<()> {
        for team in self.teams(organization_id).await? {
            self.adapter
                .delete_where(
                    "organization_team_member",
                    Query::new().eq("id", team_member_id(&team.id, user_id)),
                )
                .await?;
        }
        Ok(())
    }

    /// Teams of an organization, for any member.
    pub async fn list_teams(&self, organization_id: &str, actor: &str) -> Result<Vec<Team>> {
        self.require_member(organization_id, actor).await?;
        self.teams(organization_id).await
    }

    /// Creates a team. Owners and admins may do this.
    pub async fn create_team(
        &self,
        organization_id: &str,
        actor: &str,
        name: &str,
    ) -> Result<Team> {
        self.require_manager(organization_id, actor).await?;
        let team = Team {
            id: Uuid::new_v4().to_string(),
            organization_id: organization_id.to_owned(),
            name: validated_name(name)?,
        };
        self.adapter
            .insert_record(
                "organization_team",
                serde_json::to_value(&team).map_err(serialize_error)?,
            )
            .await?;
        Ok(team)
    }

    /// Renames a team. Owners and admins may do this.
    pub async fn update_team(
        &self,
        organization_id: &str,
        actor: &str,
        team_id: &str,
        name: &str,
    ) -> Result<Team> {
        self.require_manager(organization_id, actor).await?;
        let mut team = self.team(organization_id, team_id).await?;
        team.name = validated_name(name)?;
        self.adapter
            .update_where(
                "organization_team",
                Query::new().eq("id", team_id.to_owned()),
                json!({"name": team.name}),
            )
            .await?;
        Ok(team)
    }

    /// Deletes a team and its memberships in one transaction. Owners and admins may do this.
    pub async fn remove_team(
        &self,
        organization_id: &str,
        actor: &str,
        team_id: &str,
    ) -> Result<()> {
        self.require_manager(organization_id, actor).await?;
        self.team(organization_id, team_id).await?;
        self.adapter
            .transaction(vec![
                DbOperation::DeleteWhere {
                    table: "organization_team_member".into(),
                    query: Query::new().eq("team_id", team_id.to_owned()),
                },
                DbOperation::DeleteWhere {
                    table: "organization_team".into(),
                    query: Query::new().eq("id", team_id.to_owned()),
                },
            ])
            .await
    }

    /// Adds an organization member to a team. Only people who already belong to the
    /// organization can join one of its teams.
    pub async fn add_team_member(
        &self,
        organization_id: &str,
        actor: &str,
        team_id: &str,
        user_id: &str,
    ) -> Result<()> {
        self.require_manager(organization_id, actor).await?;
        self.team(organization_id, team_id).await?;
        if self.role_of(organization_id, user_id).await?.is_none() {
            return Err(AuthError::InvalidRequest(
                "the user is not a member of this organization".into(),
            ));
        }
        self.adapter
            .insert_record(
                "organization_team_member",
                json!({
                    "id": team_member_id(team_id, user_id),
                    "team_id": team_id,
                    "user_id": user_id,
                }),
            )
            .await?;
        Ok(())
    }

    /// Removes a person from a team. Returns false when they were not on it.
    pub async fn remove_team_member(
        &self,
        organization_id: &str,
        actor: &str,
        team_id: &str,
        user_id: &str,
    ) -> Result<bool> {
        self.require_manager(organization_id, actor).await?;
        self.team(organization_id, team_id).await?;
        let removed = self
            .adapter
            .delete_where(
                "organization_team_member",
                Query::new().eq("id", team_member_id(team_id, user_id)),
            )
            .await?;
        Ok(removed > 0)
    }

    /// The user IDs on a team, for any member of the organization.
    pub async fn list_team_members(
        &self,
        organization_id: &str,
        actor: &str,
        team_id: &str,
    ) -> Result<Vec<String>> {
        self.require_member(organization_id, actor).await?;
        self.team(organization_id, team_id).await?;
        let rows = self
            .adapter
            .find_many(
                "organization_team_member",
                Query::new().eq("team_id", team_id.to_owned()),
            )
            .await?;
        Ok(rows
            .iter()
            .filter_map(|row| {
                row.get("user_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect())
    }

    /// Teams the caller is on, across every organization they belong to.
    pub async fn list_user_teams(&self, actor: &str) -> Result<Vec<Team>> {
        let memberships = self
            .adapter
            .find_many(
                "organization_team_member",
                Query::new().eq("user_id", actor.to_owned()),
            )
            .await?;
        let mut teams = Vec::new();
        for row in memberships {
            let Some(team_id) = row.get("team_id").and_then(Value::as_str) else {
                continue;
            };
            if let Some(value) = self
                .adapter
                .find_one(
                    "organization_team",
                    Query::new().eq("id", team_id.to_owned()),
                )
                .await?
            {
                teams.push(serde_json::from_value(value).map_err(serialize_error)?);
            }
        }
        Ok(teams)
    }
}

fn hash_token(token: &str) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}
