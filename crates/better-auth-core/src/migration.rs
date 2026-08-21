use crate::schema::{FieldSchema, SchemaExtension, TableSchema};
use crate::{AuthError, Result};
use async_trait::async_trait;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationStep {
    CreateTable {
        name: String,
        schema: TableSchema,
    },
    AddField {
        table: String,
        name: String,
        schema: FieldSchema,
    },
    CreateUniqueIndex {
        table: String,
        field: String,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MigrationPlan {
    pub steps: Vec<MigrationStep>,
}

impl MigrationPlan {
    pub fn from_schema(schema: &SchemaExtension) -> Self {
        let mut steps = Vec::new();
        for (table_name, table_schema) in &schema.tables {
            steps.push(MigrationStep::CreateTable {
                name: table_name.clone(),
                schema: table_schema.clone(),
            });
            for (field_name, field_schema) in &table_schema.fields {
                if field_schema.unique {
                    steps.push(MigrationStep::CreateUniqueIndex {
                        table: table_name.clone(),
                        field: field_name.clone(),
                    });
                }
            }
        }
        Self { steps }
    }

    /// Builds an upgrade plan from a previously recorded schema snapshot.
    /// New tables use the normal idempotent create statements; fields that are
    /// present only in `desired` become explicit `AddField` steps. Keeping the
    /// previous snapshot in the application makes schema evolution reviewable
    /// instead of silently treating metadata as the database itself.
    pub fn diff(previous: &SchemaExtension, desired: &SchemaExtension) -> Result<Self> {
        let mut steps = Vec::new();
        for (table_name, desired_table) in &desired.tables {
            let Some(previous_table) = previous.tables.get(table_name) else {
                steps.push(MigrationStep::CreateTable {
                    name: table_name.clone(),
                    schema: desired_table.clone(),
                });
                for (field_name, field_schema) in &desired_table.fields {
                    if field_schema.unique {
                        steps.push(MigrationStep::CreateUniqueIndex {
                            table: table_name.clone(),
                            field: field_name.clone(),
                        });
                    }
                }
                continue;
            };

            if previous_table.primary_key != desired_table.primary_key
                && previous_table.primary_key.is_some()
            {
                return Err(AuthError::InvalidConfiguration(format!(
                    "changing the primary key for {table_name} requires a manual migration"
                )));
            }
            for (field_name, field_schema) in &desired_table.fields {
                if let Some(previous_field) = previous_table.fields.get(field_name) {
                    if previous_field != field_schema {
                        return Err(AuthError::InvalidConfiguration(format!(
                            "changing the definition of {table_name}.{field_name} requires a manual migration"
                        )));
                    }
                } else {
                    steps.push(MigrationStep::AddField {
                        table: table_name.clone(),
                        name: field_name.clone(),
                        schema: field_schema.clone(),
                    });
                }
                if field_schema.unique {
                    steps.push(MigrationStep::CreateUniqueIndex {
                        table: table_name.clone(),
                        field: field_name.clone(),
                    });
                }
            }
        }
        Ok(Self { steps })
    }

    pub fn sql(&self, dialect: SqlDialect) -> Vec<String> {
        self.steps
            .iter()
            .map(|step| match step {
                MigrationStep::CreateTable { name, schema } => {
                    let fields = schema
                        .fields
                        .iter()
                        .map(|(field, definition)| {
                            let nullability = if definition.required || !definition.nullable {
                                " NOT NULL"
                            } else {
                                ""
                            };
                            let primary_key = (schema.primary_key.as_deref() == Some(field))
                                .then_some(" PRIMARY KEY")
                                .unwrap_or_default();
                            format!(
                                "{} {}{}{}",
                                quote(field, dialect),
                                sql_type(&definition.field_type, dialect),
                                nullability,
                                primary_key
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!(
                        "CREATE TABLE IF NOT EXISTS {} ({fields});",
                        quote(name, dialect)
                    )
                }
                MigrationStep::AddField {
                    table,
                    name,
                    schema,
                } => format!(
                    "ALTER TABLE {} ADD COLUMN {} {}{};",
                    quote(table, dialect),
                    quote(name, dialect),
                    sql_type(&schema.field_type, dialect),
                    if schema.required || !schema.nullable {
                        " NOT NULL"
                    } else {
                        ""
                    }
                ),
                MigrationStep::CreateUniqueIndex { table, field } => format!(
                    "CREATE UNIQUE INDEX IF NOT EXISTS {} ON {} ({});",
                    quote(&format!("{table}_{field}_unique"), dialect),
                    quote(table, dialect),
                    quote(field, dialect)
                ),
            })
            .collect()
    }

    pub async fn apply<E: MigrationExecutor>(
        &self,
        executor: &E,
        dialect: SqlDialect,
    ) -> Result<()> {
        for (step, statement) in self.steps.iter().zip(self.sql(dialect)) {
            if let MigrationStep::AddField { table, name, .. } = step {
                if executor
                    .column_exists(table, name)
                    .await?
                    .is_some_and(|value| value)
                {
                    continue;
                }
            }
            executor.execute(&statement).await?;
        }
        Ok(())
    }
}

#[async_trait]
pub trait MigrationExecutor: Send + Sync {
    async fn execute(&self, statement: &str) -> Result<()>;

    /// Returns `Some(true/false)` when the executor can inspect the schema.
    /// `None` preserves compatibility for simple executors and causes the
    /// migration statement to be executed.
    async fn column_exists(&self, _table: &str, _column: &str) -> Result<Option<bool>> {
        Ok(None)
    }
}

pub fn migration_error(message: impl Into<String>) -> AuthError {
    AuthError::Adapter(message.into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqlDialect {
    Postgres,
    Sqlite,
    MySql,
}

fn quote(value: &str, dialect: SqlDialect) -> String {
    match dialect {
        SqlDialect::MySql => format!("`{}`", value.replace('`', "``")),
        SqlDialect::Postgres | SqlDialect::Sqlite => {
            format!("\"{}\"", value.replace('"', "\"\""))
        }
    }
}

fn sql_type(field_type: &crate::schema::FieldType, dialect: SqlDialect) -> &'static str {
    match field_type {
        crate::schema::FieldType::String => "TEXT",
        crate::schema::FieldType::Integer => "BIGINT",
        crate::schema::FieldType::Boolean => match dialect {
            SqlDialect::MySql => "TINYINT(1)",
            SqlDialect::Postgres | SqlDialect::Sqlite => "BOOLEAN",
        },
        // Better Auth currently serializes timestamps as Unix seconds. A
        // numeric column keeps that contract portable across SQLite, libSQL,
        // Postgres, and MySQL while still allowing database-side comparisons.
        crate::schema::FieldType::DateTime => "BIGINT",
        crate::schema::FieldType::Json => "TEXT",
        crate::schema::FieldType::Bytes => match dialect {
            SqlDialect::Postgres => "BYTEA",
            SqlDialect::Sqlite | SqlDialect::MySql => "BLOB",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::core_schema;

    #[test]
    fn migration_plan_contains_core_tables_and_unique_indexes() {
        let plan = MigrationPlan::from_schema(&core_schema());
        assert!(plan
            .steps
            .iter()
            .any(|step| matches!(step, MigrationStep::CreateTable { name, .. } if name == "user")));
        assert!(plan
            .sql(SqlDialect::Postgres)
            .iter()
            .any(|sql| sql.contains("CREATE UNIQUE INDEX")));
    }

    #[test]
    fn schema_diff_contains_new_fields_without_recreating_tables() {
        let previous = core_schema();
        let mut desired = previous.clone();
        desired.tables.get_mut("user").unwrap().fields.insert(
            "country".into(),
            FieldSchema::optional(crate::schema::FieldType::String),
        );
        let plan = MigrationPlan::diff(&previous, &desired).unwrap();
        assert!(plan.steps.iter().any(|step| matches!(
            step,
            MigrationStep::AddField { table, name, .. }
                if table == "user" && name == "country"
        )));
        assert!(!plan.steps.iter().any(|step| matches!(
            step,
            MigrationStep::CreateTable { name, .. } if name == "user"
        )));
    }
}
