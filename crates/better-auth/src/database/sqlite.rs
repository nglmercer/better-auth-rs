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
use rusqlite::{
    params, params_from_iter,
    types::{Value as SqlValue, ValueRef},
    Connection, OptionalExtension, TransactionBehavior,
};
use serde_json::{Map, Number, Value};
use std::{path::Path, sync::Mutex, time::Duration};

fn sqlite_error(error: rusqlite::Error) -> AuthError {
    AuthError::Adapter(format!("SQLite adapter error: {error}"))
}

fn lock_error() -> AuthError {
    AuthError::Adapter("SQLite adapter lock poisoned".into())
}

pub struct SqliteDbAdapter {
    connection: Mutex<Connection>,
    schema: Mutex<SchemaExtension>,
}

impl SqliteDbAdapter {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        initialize_libsql_runtime()?;
        let connection = Connection::open(path).map_err(sqlite_error)?;
        Self::from_connection(connection)
    }

    pub fn in_memory() -> Result<Self> {
        initialize_libsql_runtime()?;
        Self::from_connection(Connection::open_in_memory().map_err(sqlite_error)?)
    }

    fn from_connection(connection: Connection) -> Result<Self> {
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(sqlite_error)?;
        Ok(Self {
            connection: Mutex::new(connection),
            schema: Mutex::new(core_schema()),
        })
    }

    pub async fn apply_migrations(&self, plan: &MigrationPlan) -> Result<()> {
        plan.apply(self, SqlDialect::Sqlite).await
    }

    /// Registers application/plugin schema metadata so JSON and boolean
    /// values can be converted back from SQLite without guessing their type.
    pub fn register_schema(&self, schema: &SchemaExtension) -> Result<()> {
        self.schema.lock().map_err(|_| lock_error())?.merge(schema)
    }

    fn field_type(&self, table: &str, field: &str) -> Option<FieldType> {
        let schema = self.schema.lock().ok()?;
        schema
            .tables
            .get(table)
            .and_then(|table| table.fields.get(field))
            .map(|field| field.field_type.clone())
    }
}

#[async_trait::async_trait]
impl MigrationExecutor for SqliteDbAdapter {
    async fn execute(&self, statement: &str) -> Result<()> {
        self.connection
            .lock()
            .map_err(|_| lock_error())?
            .execute_batch(statement)
            .map_err(sqlite_error)
    }

    async fn column_exists(&self, table: &str, column: &str) -> Result<Option<bool>> {
        let connection = self.connection.lock().map_err(|_| lock_error())?;
        let exists = connection
            .query_row(
                "SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2 LIMIT 1",
                params![table, column],
                |_| Ok(()),
            )
            .optional()
            .map_err(sqlite_error)?
            .is_some();
        Ok(Some(exists))
    }
}

#[async_trait::async_trait]
impl DbAdapter for SqliteDbAdapter {
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

        let connection = self.connection.lock().map_err(|_| lock_error())?;
        let mut statement = connection.prepare(&sql).map_err(sqlite_error)?;
        let mut rows = statement
            .query(params_from_iter(values))
            .map_err(sqlite_error)?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let schema = self.schema.lock().map_err(|_| lock_error())?;
            result.push(row_to_json(row, table, &schema)?);
        }
        Ok(result)
    }

    async fn insert_record(&self, table: &str, record: Value) -> Result<Value> {
        let object = record_object(&record)?;
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
        let mut values = Vec::with_capacity(fields.len());
        for field in &fields {
            values.push(json_to_sql(
                object
                    .get(field)
                    .ok_or_else(|| AuthError::Adapter("record field disappeared".into()))?,
                self.field_type(table, field).as_ref(),
            )?);
        }
        let sql = format!(
            "INSERT INTO {} ({quoted_fields}) VALUES ({placeholders})",
            quote_identifier(table)?
        );
        self.connection
            .lock()
            .map_err(|_| lock_error())?
            .execute(&sql, params_from_iter(values))
            .map_err(sqlite_error)?;
        Ok(record)
    }

    async fn update_where(&self, table: &str, query: Query, changes: Value) -> Result<u64> {
        let object = record_object(&changes)?;
        if object.is_empty() {
            return Ok(0);
        }
        let mut fields = object.keys().cloned().collect::<Vec<_>>();
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
                json_to_sql(
                    object
                        .get(field)
                        .ok_or_else(|| AuthError::Adapter("change field disappeared".into()))?,
                    self.field_type(table, field).as_ref(),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        values.extend(where_values);
        let where_sql = renumber_placeholders(&where_sql, fields.len());
        let sql = format!(
            "UPDATE {} SET {assignments}{where_sql}",
            quote_identifier(table)?
        );
        let changed = self
            .connection
            .lock()
            .map_err(|_| lock_error())?
            .execute(&sql, params_from_iter(values))
            .map_err(sqlite_error)?;
        Ok(changed as u64)
    }

    async fn delete_where(&self, table: &str, query: Query) -> Result<u64> {
        let (where_sql, values) = where_clause(&query)?;
        let sql = format!("DELETE FROM {}{where_sql}", quote_identifier(table)?);
        let changed = self
            .connection
            .lock()
            .map_err(|_| lock_error())?
            .execute(&sql, params_from_iter(values))
            .map_err(sqlite_error)?;
        Ok(changed as u64)
    }

    async fn list(&self, table: &str) -> Result<Vec<(String, Value)>> {
        let records = self.find_many(table, Query::new()).await?;
        records
            .into_iter()
            .map(|record| Ok((record_id(&record)?, record)))
            .collect()
    }

    async fn transaction(&self, operations: Vec<DbOperation>) -> Result<()> {
        let mut connection = self.connection.lock().map_err(|_| lock_error())?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let schema = self.schema.lock().map_err(|_| lock_error())?;
        for operation in operations {
            apply_transaction_operation(&transaction, operation, &schema)?;
        }
        transaction.commit().map_err(sqlite_error)
    }
}

pub struct SqliteSecondaryStorage {
    connection: Mutex<Connection>,
}

impl SqliteSecondaryStorage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        initialize_libsql_runtime()?;
        Self::from_connection(Connection::open(path).map_err(sqlite_error)?)
    }

    pub fn in_memory() -> Result<Self> {
        initialize_libsql_runtime()?;
        Self::from_connection(Connection::open_in_memory().map_err(sqlite_error)?)
    }

    /// Creates the secondary-storage table. This is intentionally explicit so
    /// connecting to a production database never changes its schema.
    pub fn migrate(&self) -> Result<()> {
        self.connection
            .lock()
            .map_err(|_| lock_error())?
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS _better_auth_kv (\
                    storage_key TEXT PRIMARY KEY,\
                    value_json TEXT NOT NULL,\
                    expires_at INTEGER\
                );",
            )
            .map_err(sqlite_error)
    }

    fn from_connection(connection: Connection) -> Result<Self> {
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }
}

#[cfg(feature = "libsql")]
#[allow(deprecated)]
fn initialize_libsql_runtime() -> Result<()> {
    // libSQL's local engine requires SQLite's serialized threading mode to be
    // selected before any other SQLite engine is initialized in the process.
    // Initializing it here keeps this crate's SQLite and libSQL features
    // linkable together. Applications that initialize a different SQLite C
    // engine before constructing either adapter should choose one engine.
    libsql::Database::open_in_memory()
        .map(|_| ())
        .map_err(|error| AuthError::Adapter(format!("libSQL initialization error: {error}")))
}

#[cfg(not(feature = "libsql"))]
fn initialize_libsql_runtime() -> Result<()> {
    Ok(())
}

#[async_trait::async_trait]
impl SecondaryStorage for SqliteSecondaryStorage {
    async fn get(&self, key: &str) -> Result<Option<StorageValue>> {
        let connection = self.connection.lock().map_err(|_| lock_error())?;
        read_kv(&connection, key)
    }

    async fn set(&self, key: &str, value: StorageValue) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| lock_error())?;
        let expires_at = value
            .expires_in
            .map(|ttl| now_seconds() as i64 + ttl.as_secs() as i64);
        connection
            .execute(
                "INSERT INTO _better_auth_kv(storage_key, value_json, expires_at) VALUES (?1, ?2, ?3) ON CONFLICT(storage_key) DO UPDATE SET value_json = excluded.value_json, expires_at = excluded.expires_at",
                params![key, value.value.to_string(), expires_at],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| lock_error())?;
        connection
            .execute(
                "DELETE FROM _better_auth_kv WHERE storage_key = ?1",
                params![key],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    async fn increment(&self, key: &str, amount: i64, expires_in: Duration) -> Result<i64> {
        let mut connection = self.connection.lock().map_err(|_| lock_error())?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let existing = read_kv(&transaction, key)?;
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
                params![key, Value::from(next).to_string(), expires_at],
            )
            .map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(next)
    }

    async fn get_and_delete(&self, key: &str) -> Result<Option<StorageValue>> {
        let mut connection = self.connection.lock().map_err(|_| lock_error())?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let result = read_kv(&transaction, key)?;
        transaction
            .execute(
                "DELETE FROM _better_auth_kv WHERE storage_key = ?1",
                params![key],
            )
            .map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
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

fn where_clause(query: &Query) -> Result<(String, Vec<SqlValue>)> {
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
                values.push(json_to_sql(&filter.value, None)?);
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
                            values.push(json_to_sql(item, None)?);
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
    let mut orders = Vec::new();
    for order in &query.order_by {
        let direction = match order.direction {
            OrderDirection::Asc => "ASC",
            OrderDirection::Desc => "DESC",
        };
        orders.push(format!("{} {direction}", quote_identifier(&order.field)?));
    }
    Ok(format!(" ORDER BY {}", orders.join(", ")))
}

fn append_pagination(sql: &mut String, query: &Query, values: &mut Vec<SqlValue>) {
    if let Some(limit) = query.limit {
        values.push(SqlValue::Integer(limit as i64));
        sql.push_str(&format!(" LIMIT ?{}", values.len()));
    } else if query.offset.is_some() {
        sql.push_str(" LIMIT -1");
    }
    if let Some(offset) = query.offset {
        values.push(SqlValue::Integer(offset as i64));
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

fn json_to_sql(value: &Value, field_type: Option<&FieldType>) -> Result<SqlValue> {
    if value.is_null() {
        return Ok(SqlValue::Null);
    }
    match field_type {
        Some(FieldType::Boolean) => Ok(SqlValue::Integer(
            value
                .as_bool()
                .ok_or_else(|| AuthError::Adapter("expected a boolean value".into()))?
                as i64,
        )),
        Some(FieldType::Bytes) => Ok(SqlValue::Blob(
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
            SqlValue::Text(serde_json::to_string(value).map_err(json_error)?),
        ),
        _ => match value {
            Value::String(value) => Ok(SqlValue::Text(value.clone())),
            Value::Bool(value) => Ok(SqlValue::Integer(*value as i64)),
            Value::Number(value) => value
                .as_i64()
                .map(SqlValue::Integer)
                .or_else(|| value.as_f64().map(SqlValue::Real))
                .ok_or_else(|| AuthError::Adapter("unsupported JSON number".into())),
            Value::Array(_) | Value::Object(_) => Ok(SqlValue::Text(
                serde_json::to_string(value).map_err(json_error)?,
            )),
            Value::Null => Ok(SqlValue::Null),
        },
    }
}

fn row_to_json(row: &rusqlite::Row<'_>, table: &str, schema: &SchemaExtension) -> Result<Value> {
    let mut object = Map::new();
    let statement = row.as_ref();
    for index in 0..statement.column_count() {
        let name = statement
            .column_name(index)
            .map_err(|error| AuthError::Adapter(format!("SQLite column error: {error}")))?;
        let field_type = schema
            .tables
            .get(table)
            .and_then(|table| table.fields.get(name))
            .map(|field| &field.field_type);
        object.insert(
            name.to_owned(),
            sql_to_json(row.get_ref(index).map_err(sqlite_error)?, field_type)?,
        );
    }
    Ok(Value::Object(object))
}

fn sql_to_json(value: ValueRef<'_>, field_type: Option<&FieldType>) -> Result<Value> {
    match value {
        ValueRef::Null => Ok(Value::Null),
        ValueRef::Integer(value) if matches!(field_type, Some(FieldType::Boolean)) => {
            Ok(Value::Bool(value != 0))
        }
        ValueRef::Integer(value) => Ok(Value::Number(value.into())),
        ValueRef::Real(value) => Ok(Number::from_f64(value)
            .map(Value::Number)
            .unwrap_or(Value::Null)),
        ValueRef::Text(value) => {
            let text = std::str::from_utf8(value)
                .map_err(|error| AuthError::Adapter(format!("SQLite text error: {error}")))?;
            if matches!(field_type, Some(FieldType::Json)) {
                serde_json::from_str(text).map_err(json_error)
            } else {
                Ok(Value::String(text.to_owned()))
            }
        }
        ValueRef::Blob(value) => Ok(Value::Array(
            value.iter().copied().map(Value::from).collect(),
        )),
    }
}

fn apply_transaction_operation(
    connection: &Connection,
    operation: DbOperation,
    schema: &SchemaExtension,
) -> Result<()> {
    match operation {
        DbOperation::Insert { table, id, record } => {
            let record = record_with_id(record, &id)?;
            insert_sync(connection, &table, &record, schema)
        }
        DbOperation::Update { table, id, record } => {
            let changed = update_sync(
                connection,
                &table,
                Query::new().eq("id", id),
                &record,
                schema,
            )?;
            if changed == 0 {
                return Err(AuthError::NotFound);
            }
            Ok(())
        }
        DbOperation::Delete { table, id } => {
            delete_sync(connection, &table, Query::new().eq("id", id))?;
            Ok(())
        }
        DbOperation::InsertRecord { table, record } => {
            insert_sync(connection, &table, &record, schema)
        }
        DbOperation::UpdateWhere {
            table,
            query,
            changes,
        } => {
            update_sync(connection, &table, query, &changes, schema)?;
            Ok(())
        }
        DbOperation::DeleteWhere { table, query } => {
            delete_sync(connection, &table, query)?;
            Ok(())
        }
    }
}

fn insert_sync(
    connection: &Connection,
    table: &str,
    record: &Value,
    schema: &SchemaExtension,
) -> Result<()> {
    let object = record_object(record)?;
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
            json_to_sql(
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
    connection
        .execute(
            &format!(
                "INSERT INTO {} ({quoted_fields}) VALUES ({placeholders})",
                quote_identifier(table)?
            ),
            params_from_iter(values),
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn update_sync(
    connection: &Connection,
    table: &str,
    query: Query,
    changes: &Value,
    schema: &SchemaExtension,
) -> Result<u64> {
    let object = record_object(changes)?;
    if object.is_empty() {
        return Ok(0);
    }
    let mut fields = object.keys().cloned().collect::<Vec<_>>();
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
            json_to_sql(
                object
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
    let where_sql = renumber_placeholders(&where_sql, fields.len());
    let sql = format!(
        "UPDATE {} SET {assignments}{where_sql}",
        quote_identifier(table)?
    );
    Ok(connection
        .execute(&sql, params_from_iter(values))
        .map_err(sqlite_error)? as u64)
}

fn delete_sync(connection: &Connection, table: &str, query: Query) -> Result<u64> {
    let (where_sql, values) = where_clause(&query)?;
    Ok(connection
        .execute(
            &format!("DELETE FROM {}{where_sql}", quote_identifier(table)?),
            params_from_iter(values),
        )
        .map_err(sqlite_error)? as u64)
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

fn read_kv(connection: &Connection, key: &str) -> Result<Option<StorageValue>> {
    let row: Option<(String, Option<i64>)> = connection
        .query_row(
            "SELECT value_json, expires_at FROM _better_auth_kv WHERE storage_key = ?1",
            params![key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((raw, expires_at)) = row else {
        return Ok(None);
    };
    let now = now_seconds() as i64;
    if expires_at.is_some_and(|expires_at| expires_at <= now) {
        connection
            .execute(
                "DELETE FROM _better_auth_kv WHERE storage_key = ?1",
                params![key],
            )
            .map_err(sqlite_error)?;
        return Ok(None);
    }
    Ok(Some(StorageValue {
        value: serde_json::from_str(&raw).map_err(json_error)?,
        expires_in: expires_at.map(|expires_at| Duration::from_secs((expires_at - now) as u64)),
    }))
}
