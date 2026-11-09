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
    /// A plain index for a field marked `indexed`.
    CreateIndex {
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
                steps.extend(index_step(table_name, field_name, field_schema));
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
                    steps.extend(index_step(table_name, field_name, field_schema));
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
                    // An index can be added to an existing column in place;
                    // any other change to the definition cannot.
                    let mut comparable = previous_field.clone();
                    comparable.indexed = field_schema.indexed;
                    if &comparable != field_schema {
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
                steps.extend(index_step(table_name, field_name, field_schema));
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
                            let primary_key = if schema.primary_key.as_deref() == Some(field) {
                                " PRIMARY KEY"
                            } else {
                                ""
                            };
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
                MigrationStep::CreateUniqueIndex { table, field } => match dialect {
                    // MySQL has no `CREATE INDEX IF NOT EXISTS`; `apply` checks
                    // for the index first instead.
                    SqlDialect::MySql => format!(
                        "CREATE UNIQUE INDEX {} ON {} ({});",
                        quote(&unique_index_name(table, field), dialect),
                        quote(table, dialect),
                        quote(field, dialect)
                    ),
                    SqlDialect::Postgres | SqlDialect::Sqlite => format!(
                        "CREATE UNIQUE INDEX IF NOT EXISTS {} ON {} ({});",
                        quote(&unique_index_name(table, field), dialect),
                        quote(table, dialect),
                        quote(field, dialect)
                    ),
                },
                MigrationStep::CreateIndex { table, field } => format!(
                    "CREATE INDEX {}{} ON {} ({});",
                    match dialect {
                        SqlDialect::MySql => "",
                        SqlDialect::Postgres | SqlDialect::Sqlite => "IF NOT EXISTS ",
                    },
                    quote(&index_name(table, field), dialect),
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
            let index = match step {
                MigrationStep::CreateUniqueIndex { table, field } => {
                    Some((table, unique_index_name(table, field)))
                }
                MigrationStep::CreateIndex { table, field } => {
                    Some((table, index_name(table, field)))
                }
                _ => None,
            };
            if let Some((table, name)) = index {
                if dialect == SqlDialect::MySql
                    && executor
                        .index_exists(table, &name)
                        .await?
                        .is_some_and(|exists| exists)
                {
                    continue;
                }
            }
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

    /// Returns `Some(true/false)` when the executor can inspect indexes. Used
    /// only where the dialect cannot create an index conditionally.
    async fn index_exists(&self, _table: &str, _index: &str) -> Result<Option<bool>> {
        Ok(None)
    }
}

fn unique_index_name(table: &str, field: &str) -> String {
    format!("{table}_{field}_unique")
}

fn index_name(table: &str, field: &str) -> String {
    format!("{table}_{field}_idx")
}

/// The index a field asks for, if any. A unique index already serves lookups,
/// so `indexed` adds nothing on a unique field.
fn index_step(table: &str, field: &str, schema: &FieldSchema) -> Option<MigrationStep> {
    let (table, field) = (table.to_owned(), field.to_owned());
    if schema.unique {
        Some(MigrationStep::CreateUniqueIndex { table, field })
    } else if schema.indexed {
        Some(MigrationStep::CreateIndex { table, field })
    } else {
        None
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
        // MySQL cannot index TEXT without a prefix length. A bounded VARCHAR
        // keeps primary and unique string keys valid; 512 covers the longest
        // indexed value, an email address of up to 320 characters.
        crate::schema::FieldType::String => match dialect {
            SqlDialect::MySql => "VARCHAR(512)",
            SqlDialect::Postgres | SqlDialect::Sqlite => "TEXT",
        },
        crate::schema::FieldType::Integer => "BIGINT",
        // MySQL booleans are stored as BIGINT: the sqlx `Any` driver cannot
        // decode TINYINT(1), and the adapter maps 0/1 back to booleans.
        crate::schema::FieldType::Boolean => match dialect {
            SqlDialect::MySql => "BIGINT",
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
    fn indexed_fields_get_a_plain_index_in_every_dialect() {
        let plan = MigrationPlan::from_schema(&core_schema());
        assert!(plan.sql(SqlDialect::Sqlite).contains(
            &r#"CREATE INDEX IF NOT EXISTS "session_user_id_idx" ON "session" ("user_id");"#
                .to_owned()
        ));
        assert!(plan
            .sql(SqlDialect::MySql)
            .contains(&"CREATE INDEX `session_user_id_idx` ON `session` (`user_id`);".to_owned()));
        // A unique field is not indexed twice.
        assert!(!plan.steps.iter().any(|step| matches!(
            step,
            MigrationStep::CreateIndex { field, .. } if field == "token_hash"
        )));
    }

    #[test]
    fn schema_diff_adds_an_index_to_an_existing_column() {
        let mut previous = core_schema();
        previous
            .tables
            .get_mut("session")
            .unwrap()
            .fields
            .get_mut("user_id")
            .unwrap()
            .indexed = false;
        let plan = MigrationPlan::diff(&previous, &core_schema()).unwrap();
        assert!(plan.steps.contains(&MigrationStep::CreateIndex {
            table: "session".into(),
            field: "user_id".into(),
        }));
        assert!(!plan
            .steps
            .iter()
            .any(|step| matches!(step, MigrationStep::AddField { .. })));
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
