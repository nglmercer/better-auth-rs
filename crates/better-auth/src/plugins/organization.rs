use super::shared::{endpoint, member_id, required, serialize_error, slugify};
use better_auth_core::{
    adapter::{DbAdapter, DbOperation, Query},
    error::{AuthError, Result},
    plugin::{Endpoint, Plugin},
    schema::{FieldType, SchemaExtension, TableSchema},
};
use http::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
