use super::common::{json_error, now_seconds};
use better_auth_core::{
    adapter::{
        record_id, DbAdapter, DbOperation, FilterOp, OrderDirection, Query, SecondaryStorage,
        StorageValue,
    },
    error::{AuthError, Result},
    migration::{MigrationExecutor, MigrationPlan, SqlDialect},
    schema::{core_schema, FieldType, SchemaExtension},
};
use libsql::{params_from_iter, Builder, TransactionBehavior};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Map, Number, Value};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Debug)]
pub enum LibSqlConfig {
    Local {
        path: PathBuf,
    },
    Remote {
        url: String,
        auth_token: SecretString,
    },
    RemoteReplica(RemoteReplica),
}

#[derive(Clone, Debug)]
pub struct RemoteReplica {
    pub path: PathBuf,
    pub url: String,
    pub auth_token: SecretString,
    pub sync_interval: Option<Duration>,
}

const SECONDARY_STORAGE_DDL: &str =
    "CREATE TABLE IF NOT EXISTS _better_auth_kv (storage_key TEXT PRIMARY KEY, value_json TEXT NOT NULL, expires_at INTEGER)";

async fn build_database(config: LibSqlConfig) -> Result<libsql::Database> {
    match config {
        LibSqlConfig::Local { path } => {
            Builder::new_local(path).build().await.map_err(libsql_error)
        }
        LibSqlConfig::Remote { url, auth_token } => {
            Builder::new_remote(url, auth_token.expose_secret().to_owned())
                .build()
                .await
                .map_err(libsql_error)
        }
        LibSqlConfig::RemoteReplica(replica) => {
            let builder = Builder::new_remote_replica(
                replica.path,
                replica.url,
                replica.auth_token.expose_secret().to_owned(),
            );
            if let Some(interval) = replica.sync_interval {
                builder
                    .sync_interval(interval)
                    .build()
                    .await
                    .map_err(libsql_error)
            } else {
                builder.build().await.map_err(libsql_error)
            }
        }
    }
}

pub struct LibSqlDbAdapter {
    // Keep the owning Database alive. libSQL's embedded-replica background
    // synchronizer is tied to this value's lifetime, not the cloned
    // Connection handle.
    database: Arc<libsql::Database>,
    connection: libsql::Connection,
    schema: Mutex<SchemaExtension>,
}

impl LibSqlDbAdapter {
    pub async fn connect(config: LibSqlConfig) -> Result<Self> {
        let database = Arc::new(build_database(config).await?);
        let connection = database.connect().map_err(libsql_error)?;
        Ok(Self {
            database,
            connection,
            schema: Mutex::new(core_schema()),
        })
    }

    pub async fn local(path: impl Into<PathBuf>) -> Result<Self> {
        Self::connect(LibSqlConfig::Local { path: path.into() }).await
    }

    pub async fn remote(
        url: impl Into<String>,
        auth_token: impl Into<SecretString>,
    ) -> Result<Self> {
        Self::connect(LibSqlConfig::Remote {
            url: url.into(),
            auth_token: auth_token.into(),
        })
        .await
    }

    pub async fn remote_replica(config: RemoteReplica) -> Result<Self> {
        Self::connect(LibSqlConfig::RemoteReplica(config)).await
    }

    pub fn secondary_storage(&self) -> LibSqlSecondaryStorage {
        LibSqlSecondaryStorage {
            _database: Arc::clone(&self.database),
            connection: self.connection.clone(),
        }
    }

    pub fn register_schema(&self, schema: &SchemaExtension) -> Result<()> {
        self.schema
            .lock()
            .map_err(|_| schema_lock_error())?
            .merge(schema)
    }

    pub async fn apply_migrations(&self, plan: &MigrationPlan) -> Result<()> {
        plan.apply(self, SqlDialect::Sqlite).await
    }

    fn connection(&self) -> libsql::Connection {
        self.connection.clone()
    }
}

#[async_trait::async_trait]
impl MigrationExecutor for LibSqlDbAdapter {
    async fn execute(&self, statement: &str) -> Result<()> {
        self.connection()
            .execute(statement, ())
            .await
            .map_err(libsql_error)?;
        Ok(())
    }

    async fn column_exists(&self, table: &str, column: &str) -> Result<Option<bool>> {
        let mut rows = self
            .connection()
            .query(
                &format!("PRAGMA table_info({})", quote_identifier(table)?),
                (),
            )
            .await
            .map_err(libsql_error)?;
        while let Some(row) = rows.next().await.map_err(libsql_error)? {
            if row.get_value(1).map_err(libsql_error)? == libsql::Value::Text(column.into()) {
                return Ok(Some(true));
            }
        }
        Ok(Some(false))
    }
}

#[async_trait::async_trait]
impl DbAdapter for LibSqlDbAdapter {
    fn register_schema(&self, schema: &SchemaExtension) -> Result<()> {
        Self::register_schema(self, schema)
    }

    async fn find_one(&self, table: &str, mut query: Query) -> Result<Option<Value>> {
        query.limit = Some(query.limit.unwrap_or(1).min(1));
        Ok(self.find_many(table, query).await?.into_iter().next())
    }

    async fn find_many(&self, table: &str, query: Query) -> Result<Vec<Value>> {
        let (where_sql, mut values) = where_clause(&query)?;
        let mut sql = format!("SELECT * FROM {}", quote_identifier(table)?);
        sql.push_str(&where_sql);
        sql.push_str(&order_clause(&query)?);
        append_pagination(&mut sql, &query, &mut values);
        let schema = self.schema.lock().map_err(|_| schema_lock_error())?.clone();
        let connection = self.connection();
        let mut rows = connection
            .query(&sql, params_from_iter(values))
            .await
            .map_err(libsql_error)?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().await.map_err(libsql_error)? {
            result.push(row_to_json(&row, table, &schema)?);
        }
        Ok(result)
    }

    async fn insert_record(&self, table: &str, record: Value) -> Result<Value> {
        let object = record_object(&record)?;
        let schema = self.schema.lock().map_err(|_| schema_lock_error())?.clone();
        let (sql, values) = insert_statement(table, object, &schema)?;
        self.connection()
            .execute(&sql, params_from_iter(values))
            .await
            .map_err(libsql_error)?;
        Ok(record)
    }

    async fn update_where(&self, table: &str, query: Query, changes: Value) -> Result<u64> {
        let object = record_object(&changes)?;
        if object.is_empty() {
            return Ok(0);
        }
        let schema = self.schema.lock().map_err(|_| schema_lock_error())?.clone();
        let (sql, values) = update_statement(table, query, object, &schema)?;
        self.connection()
            .execute(&sql, params_from_iter(values))
            .await
            .map_err(libsql_error)
    }

    async fn delete_where(&self, table: &str, query: Query) -> Result<u64> {
        let (where_sql, values) = where_clause(&query)?;
        self.connection()
            .execute(
                &format!("DELETE FROM {}{where_sql}", quote_identifier(table)?),
                params_from_iter(values),
            )
            .await
            .map_err(libsql_error)
    }

    async fn list(&self, table: &str) -> Result<Vec<(String, Value)>> {
        self.find_many(table, Query::new())
            .await?
            .into_iter()
            .map(|record| Ok((record_id(&record)?, record)))
            .collect()
    }

    async fn transaction(&self, operations: Vec<DbOperation>) -> Result<()> {
        let schema = self.schema.lock().map_err(|_| schema_lock_error())?.clone();
        let connection = self.connection();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await
            .map_err(libsql_error)?;
        for operation in operations {
            apply_transaction_operation(&transaction, operation, &schema).await?;
        }
        transaction.commit().await.map_err(libsql_error)
    }
}

#[derive(Clone)]
pub struct LibSqlSecondaryStorage {
    // Retained solely to keep replica synchronization alive.
    _database: Arc<libsql::Database>,
    connection: libsql::Connection,
}

impl LibSqlSecondaryStorage {
    pub async fn connect(config: LibSqlConfig) -> Result<Self> {
        let database = Arc::new(build_database(config).await?);
        let connection = database.connect().map_err(libsql_error)?;
        Ok(Self {
            _database: database,
            connection,
        })
    }

    /// Creates the secondary-storage table. This is intentionally explicit so
    /// connecting to a production database never changes its schema.
    pub async fn migrate(&self) -> Result<()> {
        self.connection
            .execute(SECONDARY_STORAGE_DDL, ())
            .await
            .map_err(libsql_error)?;
        Ok(())
    }

    fn connection(&self) -> libsql::Connection {
        self.connection.clone()
    }
}

#[async_trait::async_trait]
impl SecondaryStorage for LibSqlSecondaryStorage {
    async fn get(&self, key: &str) -> Result<Option<StorageValue>> {
        let connection = self.connection();
        read_kv(&connection, key).await
    }

    async fn set(&self, key: &str, value: StorageValue) -> Result<()> {
        let expires_at = value
            .expires_in
            .map(|ttl| now_seconds() as i64 + ttl.as_secs() as i64);
        self.connection()
            .execute(
                "INSERT INTO _better_auth_kv(storage_key, value_json, expires_at) VALUES (?1, ?2, ?3) ON CONFLICT(storage_key) DO UPDATE SET value_json = excluded.value_json, expires_at = excluded.expires_at",
                params_from_iter(vec![
                    libsql::Value::Text(key.to_owned()),
                    libsql::Value::Text(value.value.to_string()),
                    expires_at.map(libsql::Value::Integer).unwrap_or(libsql::Value::Null),
                ]),
            )
            .await
            .map_err(libsql_error)?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.connection()
            .execute(
                "DELETE FROM _better_auth_kv WHERE storage_key = ?1",
                params_from_iter(vec![libsql::Value::Text(key.to_owned())]),
            )
            .await
            .map_err(libsql_error)?;
        Ok(())
    }

    async fn increment(&self, key: &str, amount: i64, expires_in: Duration) -> Result<i64> {
        let connection = self.connection();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await
            .map_err(libsql_error)?;
        let existing = read_kv(&transaction, key).await?;
        let current = existing
            .as_ref()
            .and_then(|value| value.value.as_i64())
            .unwrap_or(0);
        let next = current
            .checked_add(amount)
            .ok_or_else(|| AuthError::Adapter("counter overflow".into()))?;
        let expires_at = existing
            .and_then(|value| value.expires_in)
            .map(|ttl| now_seconds() as i64 + ttl.as_secs() as i64)
            .unwrap_or(now_seconds() as i64 + expires_in.as_secs() as i64);
        transaction
            .execute(
                "INSERT INTO _better_auth_kv(storage_key, value_json, expires_at) VALUES (?1, ?2, ?3) ON CONFLICT(storage_key) DO UPDATE SET value_json = excluded.value_json, expires_at = excluded.expires_at",
                params_from_iter(vec![
                    libsql::Value::Text(key.to_owned()),
                    libsql::Value::Text(Value::from(next).to_string()),
                    libsql::Value::Integer(expires_at),
                ]),
            )
            .await
            .map_err(libsql_error)?;
        transaction.commit().await.map_err(libsql_error)?;
        Ok(next)
    }

    async fn get_and_delete(&self, key: &str) -> Result<Option<StorageValue>> {
        let connection = self.connection();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await
            .map_err(libsql_error)?;
        let result = read_kv(&transaction, key).await?;
        transaction
            .execute(
                "DELETE FROM _better_auth_kv WHERE storage_key = ?1",
                params_from_iter(vec![libsql::Value::Text(key.to_owned())]),
            )
            .await
            .map_err(libsql_error)?;
        transaction.commit().await.map_err(libsql_error)?;
        Ok(result)
    }
}

fn record_object(record: &Value) -> Result<&Map<String, Value>> {
    record
        .as_object()
        .ok_or_else(|| AuthError::Adapter("database records must be JSON objects".into()))
}

fn quote_identifier(identifier: &str) -> Result<String> {
    if identifier.is_empty()
        || !identifier
            .chars()
            .all(|character| character == '_' || character.is_ascii_alphanumeric())
    {
        return Err(AuthError::Adapter(format!(
            "invalid SQL identifier: {identifier}"
        )));
    }
    Ok(format!("\"{identifier}\""))
}

fn where_clause(query: &Query) -> Result<(String, Vec<libsql::Value>)> {
    let mut values = Vec::new();
    let mut predicates = Vec::new();
    for filter in &query.filters {
        let field = quote_identifier(&filter.field)?;
        match filter.op {
            FilterOp::Eq
            | FilterOp::Ne
            | FilterOp::Lt
            | FilterOp::Lte
            | FilterOp::Gt
            | FilterOp::Gte => {
                let operator = match filter.op {
                    FilterOp::Eq => "=",
                    FilterOp::Ne => "<>",
                    FilterOp::Lt => "<",
                    FilterOp::Lte => "<=",
                    FilterOp::Gt => ">",
                    FilterOp::Gte => ">=",
                    FilterOp::In => unreachable!(),
                };
                values.push(json_to_libsql(&filter.value, None)?);
                predicates.push(format!("{field} {operator} ?{}", values.len()));
            }
            FilterOp::In => {
                let Some(items) = filter.value.as_array() else {
                    return Err(AuthError::Adapter(format!(
                        "IN filter for {} must contain an array",
                        filter.field
                    )));
                };
                if items.is_empty() {
                    predicates.push("1 = 0".into());
                } else {
                    let placeholders = items
                        .iter()
                        .map(|item| {
                            values.push(json_to_libsql(item, None)?);
                            Ok(format!("?{}", values.len()))
                        })
                        .collect::<Result<Vec<_>>>()?
                        .join(", ");
                    predicates.push(format!("{field} IN ({placeholders})"));
                }
            }
        }
    }
    if predicates.is_empty() {
        Ok((String::new(), values))
    } else {
        Ok((format!(" WHERE {}", predicates.join(" AND ")), values))
    }
}

fn order_clause(query: &Query) -> Result<String> {
    if query.order_by.is_empty() {
        return Ok(" ORDER BY \"id\" ASC".into());
    }
    let orders = query
        .order_by
        .iter()
        .map(|order| {
            let direction = match order.direction {
                OrderDirection::Asc => "ASC",
                OrderDirection::Desc => "DESC",
            };
            Ok(format!("{} {direction}", quote_identifier(&order.field)?))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(format!(" ORDER BY {}", orders.join(", ")))
}

fn append_pagination(sql: &mut String, query: &Query, values: &mut Vec<libsql::Value>) {
    if let Some(limit) = query.limit {
        values.push(libsql::Value::Integer(limit as i64));
        sql.push_str(&format!(" LIMIT ?{}", values.len()));
    } else if query.offset.is_some() {
        sql.push_str(" LIMIT -1");
    }
    if let Some(offset) = query.offset {
        values.push(libsql::Value::Integer(offset as i64));
        sql.push_str(&format!(" OFFSET ?{}", values.len()));
    }
}

fn renumber_placeholders(sql: &str, offset: usize) -> String {
    let mut output = String::with_capacity(sql.len());
    let characters = sql.chars().collect::<Vec<_>>();
    let mut position = 0;
    while position < characters.len() {
        if characters[position] == '?' {
            position += 1;
            let start = position;
            while position < characters.len() && characters[position].is_ascii_digit() {
                position += 1;
            }
            let index = characters[start..position]
                .iter()
                .collect::<String>()
                .parse::<usize>()
                .unwrap_or(1);
            output.push_str(&format!("?{}", index + offset));
        } else {
            output.push(characters[position]);
            position += 1;
        }
    }
    output
}

fn json_to_libsql(value: &Value, field_type: Option<&FieldType>) -> Result<libsql::Value> {
    if value.is_null() {
        return Ok(libsql::Value::Null);
    }
    match field_type {
        Some(FieldType::Boolean) => Ok(libsql::Value::Integer(
            value
                .as_bool()
                .ok_or_else(|| AuthError::Adapter("expected a boolean value".into()))?
                as i64,
        )),
        Some(FieldType::Bytes) => Ok(libsql::Value::Blob(
            value
                .as_array()
                .ok_or_else(|| AuthError::Adapter("expected an array of bytes".into()))?
                .iter()
                .map(|item| {
                    item.as_u64()
                        .and_then(|byte| u8::try_from(byte).ok())
                        .ok_or_else(|| AuthError::Adapter("invalid byte value".into()))
                })
                .collect::<Result<Vec<_>>>()?,
        )),
        Some(FieldType::Json) | None if value.is_array() || value.is_object() => Ok(
            libsql::Value::Text(serde_json::to_string(value).map_err(json_error)?),
        ),
        _ => match value {
            Value::String(value) => Ok(libsql::Value::Text(value.clone())),
            Value::Bool(value) => Ok(libsql::Value::Integer(*value as i64)),
            Value::Number(value) => value
                .as_i64()
                .map(libsql::Value::Integer)
                .or_else(|| value.as_f64().map(libsql::Value::Real))
                .ok_or_else(|| AuthError::Adapter("unsupported JSON number".into())),
            Value::Array(_) | Value::Object(_) => Ok(libsql::Value::Text(
                serde_json::to_string(value).map_err(json_error)?,
            )),
            Value::Null => Ok(libsql::Value::Null),
        },
    }
}

fn row_to_json(row: &libsql::Row, table: &str, schema: &SchemaExtension) -> Result<Value> {
    let mut object = Map::new();
    for index in 0..row.column_count() {
        let name = row
            .column_name(index)
            .ok_or_else(|| AuthError::Adapter("libSQL row is missing a column name".into()))?;
        let field_type = schema
            .tables
            .get(table)
            .and_then(|table| table.fields.get(name))
            .map(|field| &field.field_type);
        object.insert(
            name.to_owned(),
            sql_to_json(row.get_value(index).map_err(libsql_error)?, field_type)?,
        );
    }
    Ok(Value::Object(object))
}

fn sql_to_json(value: libsql::Value, field_type: Option<&FieldType>) -> Result<Value> {
    match value {
        libsql::Value::Null => Ok(Value::Null),
        libsql::Value::Integer(value) if matches!(field_type, Some(FieldType::Boolean)) => {
            Ok(Value::Bool(value != 0))
        }
        libsql::Value::Integer(value) => Ok(Value::Number(value.into())),
        libsql::Value::Real(value) => Ok(Number::from_f64(value)
            .map(Value::Number)
            .unwrap_or(Value::Null)),
        libsql::Value::Text(value) => {
            if matches!(field_type, Some(FieldType::Json)) {
                serde_json::from_str(&value).map_err(json_error)
            } else {
                Ok(Value::String(value))
            }
        }
        libsql::Value::Blob(value) => {
            Ok(Value::Array(value.into_iter().map(Value::from).collect()))
        }
    }
}

fn insert_statement(
    table: &str,
    object: &Map<String, Value>,
    schema: &SchemaExtension,
) -> Result<(String, Vec<libsql::Value>)> {
    let mut fields = object.keys().cloned().collect::<Vec<_>>();
    fields.sort();
    let quoted_fields = fields
        .iter()
        .map(|field| quote_identifier(field))
        .collect::<Result<Vec<_>>>()?
        .join(", ");
    let placeholders = (1..=fields.len())
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let values = fields
        .iter()
        .map(|field| {
            json_to_libsql(
                object
                    .get(field)
                    .ok_or_else(|| AuthError::Adapter("record field disappeared".into()))?,
                schema
                    .tables
                    .get(table)
                    .and_then(|table| table.fields.get(field))
                    .map(|field| &field.field_type),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((
        format!(
            "INSERT INTO {} ({quoted_fields}) VALUES ({placeholders})",
            quote_identifier(table)?
        ),
        values,
    ))
}

fn update_statement(
    table: &str,
    query: Query,
    changes: &Map<String, Value>,
    schema: &SchemaExtension,
) -> Result<(String, Vec<libsql::Value>)> {
    let mut fields = changes.keys().cloned().collect::<Vec<_>>();
    fields.sort();
    let (where_sql, where_values) = where_clause(&query)?;
    let assignments = fields
        .iter()
        .enumerate()
        .map(|(index, field)| Ok(format!("{} = ?{}", quote_identifier(field)?, index + 1)))
        .collect::<Result<Vec<_>>>()?
        .join(", ");
    let mut values = fields
        .iter()
        .map(|field| {
            json_to_libsql(
                changes
                    .get(field)
                    .ok_or_else(|| AuthError::Adapter("change field disappeared".into()))?,
                schema
                    .tables
                    .get(table)
                    .and_then(|table| table.fields.get(field))
                    .map(|field| &field.field_type),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    values.extend(where_values);
    Ok((
        format!(
            "UPDATE {} SET {}",
            quote_identifier(table)?,
            format!(
                "{assignments}{}",
                renumber_placeholders(&where_sql, fields.len())
            )
        ),
        values,
    ))
}

async fn apply_transaction_operation(
    connection: &libsql::Connection,
    operation: DbOperation,
    schema: &SchemaExtension,
) -> Result<()> {
    match operation {
        DbOperation::Insert { table, id, record } => {
            let record = record_with_id(record, &id)?;
            let (sql, values) = insert_statement(&table, record_object(&record)?, schema)?;
            connection
                .execute(&sql, params_from_iter(values))
                .await
                .map_err(libsql_error)?;
        }
        DbOperation::InsertRecord { table, record } => {
            let (sql, values) = insert_statement(&table, record_object(&record)?, schema)?;
            connection
                .execute(&sql, params_from_iter(values))
                .await
                .map_err(libsql_error)?;
        }
        DbOperation::Update { table, id, record } => {
            let (sql, values) = update_statement(
                &table,
                Query::new().eq("id", id),
                record_object(&record)?,
                schema,
            )?;
            if connection
                .execute(&sql, params_from_iter(values))
                .await
                .map_err(libsql_error)?
                == 0
            {
                return Err(AuthError::NotFound);
            }
        }
        DbOperation::UpdateWhere {
            table,
            query,
            changes,
        } => {
            let (sql, values) = update_statement(&table, query, record_object(&changes)?, schema)?;
            connection
                .execute(&sql, params_from_iter(values))
                .await
                .map_err(libsql_error)?;
        }
        DbOperation::Delete { table, id } => {
            let (where_sql, values) = where_clause(&Query::new().eq("id", id))?;
            connection
                .execute(
                    &format!("DELETE FROM {}{where_sql}", quote_identifier(&table)?),
                    params_from_iter(values),
                )
                .await
                .map_err(libsql_error)?;
        }
        DbOperation::DeleteWhere { table, query } => {
            let (where_sql, values) = where_clause(&query)?;
            connection
                .execute(
                    &format!("DELETE FROM {}{where_sql}", quote_identifier(&table)?),
                    params_from_iter(values),
                )
                .await
                .map_err(libsql_error)?;
        }
    }
    Ok(())
}

fn record_with_id(record: Value, id: &str) -> Result<Value> {
    let Value::Object(mut object) = record else {
        return Err(AuthError::Adapter(
            "database records must be JSON objects".into(),
        ));
    };
    object.insert("id".into(), Value::String(id.to_owned()));
    Ok(Value::Object(object))
}

async fn read_kv(connection: &libsql::Connection, key: &str) -> Result<Option<StorageValue>> {
    let mut rows = connection
        .query(
            "SELECT value_json, expires_at FROM _better_auth_kv WHERE storage_key = ?1",
            params_from_iter(vec![libsql::Value::Text(key.to_owned())]),
        )
        .await
        .map_err(libsql_error)?;
    let Some(row) = rows.next().await.map_err(libsql_error)? else {
        return Ok(None);
    };
    let raw: String = row.get(0).map_err(libsql_error)?;
    let expires_at: Option<i64> = row.get(1).map_err(libsql_error)?;
    let now = now_seconds() as i64;
    if expires_at.is_some_and(|expires_at| expires_at <= now) {
        connection
            .execute(
                "DELETE FROM _better_auth_kv WHERE storage_key = ?1",
                params_from_iter(vec![libsql::Value::Text(key.to_owned())]),
            )
            .await
            .map_err(libsql_error)?;
        return Ok(None);
    }
    Ok(Some(StorageValue {
        value: serde_json::from_str(&raw).map_err(json_error)?,
        expires_in: expires_at.map(|expires_at| Duration::from_secs((expires_at - now) as u64)),
    }))
}

fn libsql_error(error: libsql::Error) -> AuthError {
    AuthError::Adapter(format!("libSQL adapter error: {error}"))
}

fn schema_lock_error() -> AuthError {
    AuthError::Adapter("libSQL adapter schema lock poisoned".into())
}
