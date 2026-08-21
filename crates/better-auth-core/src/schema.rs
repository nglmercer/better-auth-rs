use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    String,
    Integer,
    Boolean,
    DateTime,
    Json,
    Bytes,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FieldSchema {
    pub field_type: FieldType,
    pub required: bool,
    pub unique: bool,
    pub nullable: bool,
}

impl FieldSchema {
    pub fn required(field_type: FieldType) -> Self {
        Self {
            field_type,
            required: true,
            unique: false,
            nullable: false,
        }
    }

    pub fn optional(field_type: FieldType) -> Self {
        Self {
            field_type,
            required: false,
            unique: false,
            nullable: true,
        }
    }

    pub fn unique(mut self) -> Self {
        self.unique = true;
        self
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TableSchema {
    pub fields: BTreeMap<String, FieldSchema>,
    #[serde(default)]
    pub primary_key: Option<String>,
}

impl TableSchema {
    pub fn field(mut self, name: impl Into<String>, field: FieldSchema) -> Self {
        self.fields.insert(name.into(), field);
        self
    }

    pub fn primary_key(mut self, field: impl Into<String>) -> Self {
        self.primary_key = Some(field.into());
        self
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SchemaExtension {
    pub tables: BTreeMap<String, TableSchema>,
}

impl SchemaExtension {
    pub fn table(mut self, name: impl Into<String>, schema: TableSchema) -> Self {
        self.tables.insert(name.into(), schema);
        self
    }

    pub fn merge(&mut self, extension: &SchemaExtension) -> crate::Result<()> {
        for (table_name, incoming) in &extension.tables {
            if let Some(existing) = self.tables.get_mut(table_name) {
                if let Some(incoming_primary_key) = &incoming.primary_key {
                    if let Some(existing_primary_key) = &existing.primary_key {
                        if existing_primary_key != incoming_primary_key {
                            return Err(crate::AuthError::InvalidConfiguration(format!(
                                "schema conflict for {table_name} primary key"
                            )));
                        }
                    } else {
                        existing.primary_key = Some(incoming_primary_key.clone());
                    }
                }
                for (field_name, incoming_field) in &incoming.fields {
                    if let Some(existing_field) = existing.fields.get(field_name) {
                        if existing_field != incoming_field {
                            return Err(crate::AuthError::InvalidConfiguration(format!(
                                "schema conflict for {table_name}.{field_name}"
                            )));
                        }
                    } else {
                        existing
                            .fields
                            .insert(field_name.clone(), incoming_field.clone());
                    }
                }
            } else {
                self.tables.insert(table_name.clone(), incoming.clone());
            }
        }
        Ok(())
    }
}

pub fn core_schema() -> SchemaExtension {
    use FieldType::*;
    SchemaExtension::default()
        .table(
            "user",
            TableSchema::default()
                .primary_key("id")
                .field("id", FieldSchema::required(String).unique())
                .field("email", FieldSchema::required(String).unique())
                .field("name", FieldSchema::required(String))
                .field("email_verified", FieldSchema::required(Boolean))
                .field("role", FieldSchema::optional(String))
                .field("image", FieldSchema::optional(String))
                .field("additional_fields", FieldSchema::optional(Json)),
        )
        .table(
            "session",
            TableSchema::default()
                .primary_key("id")
                .field("id", FieldSchema::required(String).unique())
                .field("user_id", FieldSchema::required(String))
                .field("expires_at", FieldSchema::required(DateTime))
                .field("token_hash", FieldSchema::required(String).unique()),
        )
        .table(
            "account",
            TableSchema::default()
                .primary_key("id")
                .field("id", FieldSchema::required(String).unique())
                .field("user_id", FieldSchema::required(String))
                .field("provider_id", FieldSchema::required(String))
                .field("account_id", FieldSchema::required(String))
                .field("password_hash", FieldSchema::optional(String)),
        )
        .table(
            "verification",
            TableSchema::default()
                .primary_key("id")
                .field("id", FieldSchema::required(String).unique())
                .field("identifier", FieldSchema::required(String))
                .field("value", FieldSchema::required(String))
                .field("expires_at", FieldSchema::required(DateTime)),
        )
}
