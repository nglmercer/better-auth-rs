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

    pub fn sql(&self, dialect: SqlDialect) -> Vec<String> {
        self.steps
            .iter()
            .map(|step| match step {
                MigrationStep::CreateTable { name, schema } => {
                    let fields = schema
                        .fields
                        .iter()
                        .map(|(field, definition)| {
                            format!(
                                "{} {}",
                                quote(field, dialect),
                                sql_type(&definition.field_type, dialect)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("CREATE TABLE {} ({fields});", quote(name, dialect))
                }
                MigrationStep::AddField {
                    table,
                    name,
                    schema,
                } => format!(
                    "ALTER TABLE {} ADD COLUMN {} {};",
                    quote(table, dialect),
                    quote(name, dialect),
                    sql_type(&schema.field_type, dialect)
                ),
                MigrationStep::CreateUniqueIndex { table, field } => format!(
                    "CREATE UNIQUE INDEX {} ON {} ({});",
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
        for statement in self.sql(dialect) {
            executor.execute(&statement).await?;
        }
        Ok(())
    }
}

#[async_trait]
pub trait MigrationExecutor: Send + Sync {
    async fn execute(&self, statement: &str) -> Result<()>;
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
        crate::schema::FieldType::String => "VARCHAR(255)",
        crate::schema::FieldType::Integer => "BIGINT",
        crate::schema::FieldType::Boolean => match dialect {
            SqlDialect::MySql => "TINYINT(1)",
            SqlDialect::Postgres | SqlDialect::Sqlite => "BOOLEAN",
        },
        crate::schema::FieldType::DateTime => match dialect {
            SqlDialect::Sqlite => "TEXT",
            SqlDialect::Postgres => "TIMESTAMPTZ",
            SqlDialect::MySql => "DATETIME(6)",
        },
        crate::schema::FieldType::Json => match dialect {
            SqlDialect::Sqlite => "TEXT",
            SqlDialect::Postgres | SqlDialect::MySql => "JSON",
        },
        crate::schema::FieldType::Bytes => "BLOB",
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
}
