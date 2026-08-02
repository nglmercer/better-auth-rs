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
}

impl TableSchema {
    pub fn field(mut self, name: impl Into<String>, field: FieldSchema) -> Self {
        self.fields.insert(name.into(), field);
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
                for (field_name, incoming_field) in &incoming.fields {
                    if let Some(existing_field) = existing.fields.get(field_name) {
                        if existing_field != incoming_field {
                            return Err(crate::AuthError::InvalidConfiguration(format!(
                                "schema conflict for {table_name}.{field_name}"
                            )));
                        }
                    } else {
                        existing.fields.insert(field_name.clone(), incoming_field.clone());
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
                .field("id", FieldSchema::required(String).unique())
                .field("email", FieldSchema::required(String).unique())
                .field("name", FieldSchema::required(String))
                .field("email_verified", FieldSchema::required(Boolean))
                .field("image", FieldSchema::optional(String)),
        )
        .table(
            "session",
            TableSchema::default()
                .field("id", FieldSchema::required(String).unique())
                .field("user_id", FieldSchema::required(String))
                .field("expires_at", FieldSchema::required(DateTime))
                .field("token_hash", FieldSchema::required(String).unique()),
        )
        .table(
            "account",
            TableSchema::default()
                .field("id", FieldSchema::required(String).unique())
                .field("user_id", FieldSchema::required(String))
                .field("provider_id", FieldSchema::required(String))
                .field("account_id", FieldSchema::required(String)),
        )
        .table(
            "verification",
            TableSchema::default()
                .field("id", FieldSchema::required(String).unique())
                .field("identifier", FieldSchema::required(String))
                .field("value", FieldSchema::required(String))
                .field("expires_at", FieldSchema::required(DateTime)),
        )
}

