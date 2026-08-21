use super::common::{json_error, now_seconds};
use better_auth_core::{
    adapter::{
        record_id, DbAdapter, DbOperation, FilterOp, OrderDirection, Query as CoreQuery,
        SecondaryStorage, StorageValue,
    },
    error::{AuthError, Result},
    migration::{MigrationExecutor, MigrationPlan, SqlDialect},
    schema::{core_schema, FieldType, SchemaExtension},
};
use serde_json::{Map, Number, Value};
use sqlx::{any::AnyArguments, Executor, Row, ValueRef};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

#[cfg(feature = "sqlx")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqlxBackend {
    Postgres,
    MySql,
}

#[cfg(feature = "sqlx")]
#[derive(Clone)]
pub struct SqlxDbAdapter {
    pool: sqlx::AnyPool,
    backend: SqlxBackend,
    schema: Arc<Mutex<SchemaExtension>>,
}

#[cfg(feature = "sqlx")]
impl SqlxDbAdapter {
    pub async fn connect(url: &str, backend: SqlxBackend) -> Result<Self> {
        validate_sqlx_url(url, backend)?;
        sqlx::any::install_default_drivers();
        let pool = sqlx::AnyPool::connect(url).await.map_err(sqlx_error)?;
        Ok(Self {
            pool,
            backend,
            schema: Arc::new(Mutex::new(core_schema())),
        })
    }

    pub async fn postgres(url: &str) -> Result<Self> {
        Self::connect(url, SqlxBackend::Postgres).await
    }

    pub async fn mysql(url: &str) -> Result<Self> {
        Self::connect(url, SqlxBackend::MySql).await
    }

    pub async fn apply_migrations(&self, plan: &MigrationPlan, dialect: SqlDialect) -> Result<()> {
        plan.apply(self, dialect).await
    }

    pub fn register_schema(&self, schema: &SchemaExtension) -> Result<()> {
        self.schema
            .lock()
            .map_err(|_| sqlx_lock_error())?
            .merge(schema)
    }
}

#[cfg(feature = "sqlx")]
pub type PostgresDbAdapter = SqlxDbAdapter;

#[cfg(feature = "sqlx")]
pub type MySqlDbAdapter = SqlxDbAdapter;

#[cfg(feature = "sqlx")]
#[async_trait::async_trait]
impl MigrationExecutor for SqlxDbAdapter {
    async fn execute(&self, statement: &str) -> Result<()> {
        self.pool.execute(statement).await.map_err(sqlx_error)?;
        Ok(())
    }

    async fn column_exists(&self, table: &str, column: &str) -> Result<Option<bool>> {
        let statement = match self.backend {
            SqlxBackend::Postgres => {
                "SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? AND column_name = ? LIMIT 1"
            }
            SqlxBackend::MySql => {
                "SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? LIMIT 1"
            }
        };
        let statement = sqlx_bind_sql(self.backend, statement);
        let row = sqlx::query(&statement)
            .bind(table)
            .bind(column)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_error)?;
        Ok(Some(row.is_some()))
    }
}

#[cfg(feature = "sqlx")]
#[async_trait::async_trait]
impl DbAdapter for SqlxDbAdapter {
    fn register_schema(&self, schema: &SchemaExtension) -> Result<()> {
        Self::register_schema(self, schema)
    }

    async fn find_one(&self, table: &str, mut query: CoreQuery) -> Result<Option<Value>> {
        query.limit = Some(query.limit.unwrap_or(1).min(1));
        Ok(self.find_many(table, query).await?.into_iter().next())
    }

    async fn find_many(&self, table: &str, query: CoreQuery) -> Result<Vec<Value>> {
        let (where_sql, mut values) = where_clause(&query, self.backend)?;
        let mut sql = format!("SELECT * FROM {}", quote_identifier(table, self.backend)?);
        sql.push_str(&where_sql);
        sql.push_str(&order_clause(&query, self.backend)?);
        append_pagination(&mut sql, &query, &mut values);
        let sql = sqlx_bind_sql(self.backend, &sql);
        let rows = bind_values(sqlx::query(&sql), values)
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_error)?;
        let schema = self.schema.lock().map_err(|_| sqlx_lock_error())?;
        rows.iter()
            .map(|row| row_to_json(row, table, &schema))
            .collect()
    }

    async fn insert_record(&self, table: &str, record: Value) -> Result<Value> {
        let object = record_object(&record)?;
        let (sql, values) = insert_statement(table, object, self.backend)?;
        bind_values(sqlx::query(&sqlx_bind_sql(self.backend, &sql)), values)
            .execute(&self.pool)
            .await
            .map_err(sqlx_error)?;
        Ok(record)
    }

    async fn update_where(&self, table: &str, query: CoreQuery, changes: Value) -> Result<u64> {
        let object = record_object(&changes)?;
        if object.is_empty() {
            return Ok(0);
        }
        let (where_sql, mut values) = where_clause(&query, self.backend)?;
        let mut fields = object.keys().cloned().collect::<Vec<_>>();
        fields.sort();
        let assignments = fields
            .iter()
            .map(|field| {
                format!(
                    "{} = ?",
                    quote_identifier(field, self.backend).expect("validated identifier")
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let mut change_values = fields
            .iter()
            .map(|field| {
                object
                    .get(field)
                    .ok_or_else(|| AuthError::Adapter("change field disappeared".into()))
                    .and_then(json_value_for_sqlx)
            })
            .collect::<Result<Vec<_>>>()?;
        change_values.append(&mut values);
        let sql = format!(
            "UPDATE {} SET {assignments}{where_sql}",
            quote_identifier(table, self.backend)?
        );
        let result = bind_values(
            sqlx::query(&sqlx_bind_sql(self.backend, &sql)),
            change_values,
        )
        .execute(&self.pool)
        .await
        .map_err(sqlx_error)?;
        Ok(result.rows_affected())
    }

    async fn delete_where(&self, table: &str, query: CoreQuery) -> Result<u64> {
        let (where_sql, values) = where_clause(&query, self.backend)?;
        let sql = format!(
            "DELETE FROM {}{where_sql}",
            quote_identifier(table, self.backend)?
        );
        let result = bind_values(sqlx::query(&sqlx_bind_sql(self.backend, &sql)), values)
            .execute(&self.pool)
            .await
            .map_err(sqlx_error)?;
        Ok(result.rows_affected())
    }

    async fn list(&self, table: &str) -> Result<Vec<(String, Value)>> {
        let records = self.find_many(table, CoreQuery::new()).await?;
        records
            .into_iter()
            .map(|record| Ok((record_id(&record)?, record)))
            .collect()
    }

    async fn transaction(&self, operations: Vec<DbOperation>) -> Result<()> {
        let mut transaction = self.pool.begin().await.map_err(sqlx_error)?;
        for operation in operations {
            let (sql, values, require_change) = operation_statement(operation, self.backend)?;
            let result = bind_values(sqlx::query(&sqlx_bind_sql(self.backend, &sql)), values)
                .execute(&mut *transaction)
                .await
                .map_err(sqlx_error)?;
            if require_change && result.rows_affected() == 0 {
                return Err(AuthError::NotFound);
            }
        }
        transaction.commit().await.map_err(sqlx_error)
    }
}

#[cfg(feature = "sqlx")]
#[derive(Clone)]
pub struct SqlxSecondaryStorage {
    pool: sqlx::AnyPool,
    backend: SqlxBackend,
}

#[cfg(feature = "sqlx")]
impl SqlxSecondaryStorage {
    pub async fn connect(url: &str, backend: SqlxBackend) -> Result<Self> {
        validate_sqlx_url(url, backend)?;
        sqlx::any::install_default_drivers();
        let pool = sqlx::AnyPool::connect(url).await.map_err(sqlx_error)?;
        Ok(Self { pool, backend })
    }

    pub async fn postgres(url: &str) -> Result<Self> {
        Self::connect(url, SqlxBackend::Postgres).await
    }

    pub async fn mysql(url: &str) -> Result<Self> {
        Self::connect(url, SqlxBackend::MySql).await
    }

    /// Creates the secondary-storage table. This is intentionally explicit so
    /// connecting to a production database never changes its schema.
    pub async fn migrate(&self) -> Result<()> {
        self.pool
            .execute(sqlx_kv_ddl(self.backend))
            .await
            .map_err(sqlx_error)?;
        Ok(())
    }
}

#[cfg(feature = "sqlx")]
pub type PostgresSecondaryStorage = SqlxSecondaryStorage;

#[cfg(feature = "sqlx")]
pub type MySqlSecondaryStorage = SqlxSecondaryStorage;

#[cfg(feature = "sqlx")]
#[async_trait::async_trait]
impl SecondaryStorage for SqlxSecondaryStorage {
    async fn get(&self, key: &str) -> Result<Option<StorageValue>> {
        let mut transaction = self.pool.begin().await.map_err(sqlx_error)?;
        let result = read_sqlx_kv(&mut transaction, self.backend, key, false).await?;
        transaction.commit().await.map_err(sqlx_error)?;
        Ok(result)
    }

    async fn set(&self, key: &str, value: StorageValue) -> Result<()> {
        let expires_at = value
            .expires_in
            .map(|ttl| now_seconds() as i64 + ttl.as_secs() as i64);
        let mut transaction = self.pool.begin().await.map_err(sqlx_error)?;
        bind_values(
            sqlx::query(&sqlx_bind_sql(
                self.backend,
                "DELETE FROM _better_auth_kv WHERE storage_key = ?",
            )),
            vec![Value::String(key.to_owned())],
        )
        .execute(&mut *transaction)
        .await
        .map_err(sqlx_error)?;
        bind_values(
            sqlx::query(&sqlx_bind_sql(
                self.backend,
                "INSERT INTO _better_auth_kv(storage_key, value_json, expires_at) VALUES (?, ?, ?)",
            )),
            vec![
                Value::String(key.to_owned()),
                Value::String(value.value.to_string()),
                expires_at.map(Value::from).unwrap_or(Value::Null),
            ],
        )
        .execute(&mut *transaction)
        .await
        .map_err(sqlx_error)?;
        transaction.commit().await.map_err(sqlx_error)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        bind_values(
            sqlx::query(&sqlx_bind_sql(
                self.backend,
                "DELETE FROM _better_auth_kv WHERE storage_key = ?",
            )),
            vec![Value::String(key.to_owned())],
        )
        .execute(&self.pool)
        .await
        .map_err(sqlx_error)?;
        Ok(())
    }

    async fn increment(&self, key: &str, amount: i64, expires_in: Duration) -> Result<i64> {
        let mut transaction = self.pool.begin().await.map_err(sqlx_error)?;
        let existing = read_sqlx_kv(&mut transaction, self.backend, key, true).await?;
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
        bind_values(
            sqlx::query(&sqlx_bind_sql(
                self.backend,
                "DELETE FROM _better_auth_kv WHERE storage_key = ?",
            )),
            vec![Value::String(key.to_owned())],
        )
        .execute(&mut *transaction)
        .await
        .map_err(sqlx_error)?;
        bind_values(
            sqlx::query(&sqlx_bind_sql(
                self.backend,
                "INSERT INTO _better_auth_kv(storage_key, value_json, expires_at) VALUES (?, ?, ?)",
            )),
            vec![
                Value::String(key.to_owned()),
                Value::from(next).to_string().into(),
                Value::from(expires_at),
            ],
        )
        .execute(&mut *transaction)
        .await
        .map_err(sqlx_error)?;
        transaction.commit().await.map_err(sqlx_error)?;
        Ok(next)
    }

    async fn get_and_delete(&self, key: &str) -> Result<Option<StorageValue>> {
        let mut transaction = self.pool.begin().await.map_err(sqlx_error)?;
        let result = read_sqlx_kv(&mut transaction, self.backend, key, true).await?;
        bind_values(
            sqlx::query(&sqlx_bind_sql(
                self.backend,
                "DELETE FROM _better_auth_kv WHERE storage_key = ?",
            )),
            vec![Value::String(key.to_owned())],
        )
        .execute(&mut *transaction)
        .await
        .map_err(sqlx_error)?;
        transaction.commit().await.map_err(sqlx_error)?;
        Ok(result)
    }
}

#[cfg(feature = "sqlx")]
async fn read_sqlx_kv(
    transaction: &mut sqlx::Transaction<'_, sqlx::Any>,
    backend: SqlxBackend,
    key: &str,
    for_update: bool,
) -> Result<Option<StorageValue>> {
    let query = if for_update {
        "SELECT value_json, expires_at FROM _better_auth_kv WHERE storage_key = ? FOR UPDATE"
    } else {
        "SELECT value_json, expires_at FROM _better_auth_kv WHERE storage_key = ?"
    };
    let row = bind_values(
        sqlx::query(&sqlx_bind_sql(backend, query)),
        vec![Value::String(key.to_owned())],
    )
    .fetch_optional(&mut **transaction)
    .await
    .map_err(sqlx_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let raw = row.try_get::<String, _>("value_json").map_err(sqlx_error)?;
    let expires_at = row
        .try_get::<Option<i64>, _>("expires_at")
        .map_err(sqlx_error)?;
    let now = now_seconds() as i64;
    if expires_at.is_some_and(|expires_at| expires_at <= now) {
        return Ok(None);
    }
    Ok(Some(StorageValue {
        value: serde_json::from_str(&raw).map_err(json_error)?,
        expires_in: expires_at.map(|expires_at| Duration::from_secs((expires_at - now) as u64)),
    }))
}

#[cfg(feature = "sqlx")]
fn record_object(record: &Value) -> Result<&Map<String, Value>> {
    record
        .as_object()
        .ok_or_else(|| AuthError::Adapter("database records must be JSON objects".into()))
}

#[cfg(feature = "sqlx")]
fn insert_statement(
    table: &str,
    object: &Map<String, Value>,
    backend: SqlxBackend,
) -> Result<(String, Vec<Value>)> {
    let mut fields = object.keys().cloned().collect::<Vec<_>>();
    fields.sort();
    let quoted_fields = fields
        .iter()
        .map(|field| quote_identifier(field, backend))
        .collect::<Result<Vec<_>>>()?
        .join(", ");
    let placeholders = (0..fields.len())
        .map(|_| "?".to_owned())
        .collect::<Vec<_>>()
        .join(", ");
    let values = fields
        .iter()
        .map(|field| {
            object
                .get(field)
                .cloned()
                .ok_or_else(|| AuthError::Adapter("record field disappeared".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((
        format!(
            "INSERT INTO {} ({quoted_fields}) VALUES ({placeholders})",
            quote_identifier(table, backend)?
        ),
        values,
    ))
}

#[cfg(feature = "sqlx")]
fn operation_statement(
    operation: DbOperation,
    backend: SqlxBackend,
) -> Result<(String, Vec<Value>, bool)> {
    match operation {
        DbOperation::Insert { table, id, record } => {
            let record = record_with_id(record, &id)?;
            let (sql, values) = insert_statement(&table, record_object(&record)?, backend)?;
            Ok((sql, values, false))
        }
        DbOperation::InsertRecord { table, record } => {
            let (sql, values) = insert_statement(&table, record_object(&record)?, backend)?;
            Ok((sql, values, false))
        }
        DbOperation::Update { table, id, record } => {
            let (sql, values) = update_statement(
                &table,
                CoreQuery::new().eq("id", id),
                record_object(&record)?,
                backend,
            )?;
            Ok((sql, values, true))
        }
        DbOperation::UpdateWhere {
            table,
            query,
            changes,
        } => {
            let (sql, values) = update_statement(&table, query, record_object(&changes)?, backend)?;
            Ok((sql, values, false))
        }
        DbOperation::Delete { table, id } => {
            let (where_sql, values) = where_clause(&CoreQuery::new().eq("id", id), backend)?;
            Ok((
                format!(
                    "DELETE FROM {}{where_sql}",
                    quote_identifier(&table, backend)?
                ),
                values,
                false,
            ))
        }
        DbOperation::DeleteWhere { table, query } => {
            let (where_sql, values) = where_clause(&query, backend)?;
            Ok((
                format!(
                    "DELETE FROM {}{where_sql}",
                    quote_identifier(&table, backend)?
                ),
                values,
                false,
            ))
        }
    }
}

#[cfg(feature = "sqlx")]
fn update_statement(
    table: &str,
    query: CoreQuery,
    changes: &Map<String, Value>,
    backend: SqlxBackend,
) -> Result<(String, Vec<Value>)> {
    let mut fields = changes.keys().cloned().collect::<Vec<_>>();
    fields.sort();
    let assignments = fields
        .iter()
        .map(|field| Ok(format!("{} = ?", quote_identifier(field, backend)?)))
        .collect::<Result<Vec<_>>>()?
        .join(", ");
    let (where_sql, mut values) = where_clause(&query, backend)?;
    let mut change_values = fields
        .iter()
        .map(|field| {
            changes
                .get(field)
                .cloned()
                .ok_or_else(|| AuthError::Adapter("change field disappeared".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    change_values.append(&mut values);
    Ok((
        format!(
            "UPDATE {} SET {assignments}{where_sql}",
            quote_identifier(table, backend)?
        ),
        change_values,
    ))
}

#[cfg(feature = "sqlx")]
fn quote_identifier(identifier: &str, backend: SqlxBackend) -> Result<String> {
    if identifier.is_empty()
        || !identifier
            .chars()
            .all(|character| character == '_' || character.is_ascii_alphanumeric())
    {
        return Err(AuthError::Adapter(format!(
            "invalid SQL identifier: {identifier}"
        )));
    }
    Ok(match backend {
        SqlxBackend::MySql => format!("`{identifier}`"),
        SqlxBackend::Postgres => format!("\"{identifier}\""),
    })
}

#[cfg(feature = "sqlx")]
fn where_clause(query: &CoreQuery, backend: SqlxBackend) -> Result<(String, Vec<Value>)> {
    let mut values = Vec::new();
    let mut predicates = Vec::new();
    for filter in &query.filters {
        let field = quote_identifier(&filter.field, backend)?;
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
                predicates.push(format!("{field} {operator} ?"));
                values.push(filter.value.clone());
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
                            values.push(item.clone());
                            "?"
                        })
                        .collect::<Vec<_>>()
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

#[cfg(feature = "sqlx")]
fn order_clause(query: &CoreQuery, backend: SqlxBackend) -> Result<String> {
    if query.order_by.is_empty() {
        return Ok(format!(
            " ORDER BY {} ASC",
            quote_identifier("id", backend)?
        ));
    }
    let orders = query
        .order_by
        .iter()
        .map(|order| {
            let direction = match order.direction {
                OrderDirection::Asc => "ASC",
                OrderDirection::Desc => "DESC",
            };
            Ok(format!(
                "{} {direction}",
                quote_identifier(&order.field, backend)?
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(format!(" ORDER BY {}", orders.join(", ")))
}

#[cfg(feature = "sqlx")]
fn append_pagination(sql: &mut String, query: &CoreQuery, values: &mut Vec<Value>) {
    if let Some(limit) = query.limit {
        sql.push_str(" LIMIT ?");
        values.push(Value::from(limit));
    } else if query.offset.is_some() {
        sql.push_str(" LIMIT -1");
    }
    if let Some(offset) = query.offset {
        sql.push_str(" OFFSET ?");
        values.push(Value::from(offset));
    }
}

#[cfg(feature = "sqlx")]
fn bind_values<'q>(
    mut query: sqlx::query::Query<'q, sqlx::Any, AnyArguments<'q>>,
    values: Vec<Value>,
) -> sqlx::query::Query<'q, sqlx::Any, AnyArguments<'q>> {
    for value in values {
        query =
            match value {
                Value::Null => query.bind(Option::<String>::None),
                Value::Bool(value) => query.bind(value),
                Value::Number(value) => {
                    if let Some(value) = value.as_i64() {
                        query.bind(value)
                    } else if let Some(value) = value.as_f64() {
                        query.bind(value)
                    } else {
                        panic!("JSON numbers must be representable")
                    }
                }
                Value::String(value) => query.bind(value),
                Value::Array(value) => query
                    .bind(serde_json::to_string(&value).expect("JSON values must be serializable")),
                Value::Object(value) => query
                    .bind(serde_json::to_string(&value).expect("JSON values must be serializable")),
            };
    }
    query
}

#[cfg(feature = "sqlx")]
fn json_value_for_sqlx(value: &Value) -> Result<Value> {
    Ok(value.clone())
}

#[cfg(feature = "sqlx")]
fn row_to_json(row: &sqlx::any::AnyRow, table: &str, schema: &SchemaExtension) -> Result<Value> {
    let mut object = Map::new();
    for column in row.columns() {
        let name = column.name.to_string();
        let field_type = schema
            .tables
            .get(table)
            .and_then(|table| table.fields.get(name.as_str()))
            .map(|field| &field.field_type);
        object.insert(
            name.clone(),
            any_value_to_json(row, name.as_str(), field_type)?,
        );
    }
    Ok(Value::Object(object))
}

#[cfg(feature = "sqlx")]
fn any_value_to_json(
    row: &sqlx::any::AnyRow,
    index: &str,
    field_type: Option<&FieldType>,
) -> Result<Value> {
    let raw = row.try_get_raw(index).map_err(sqlx_error)?;
    if raw.is_null() {
        return Ok(Value::Null);
    }
    if matches!(field_type, Some(FieldType::Boolean)) {
        if let Ok(value) = row.try_get::<bool, _>(index) {
            return Ok(Value::Bool(value));
        }
        return Ok(Value::Bool(
            row.try_get::<i64, _>(index).map_err(sqlx_error)? != 0,
        ));
    }
    if matches!(field_type, Some(FieldType::Bytes)) {
        return Ok(Value::Array(
            row.try_get::<Vec<u8>, _>(index)
                .map_err(sqlx_error)?
                .into_iter()
                .map(Value::from)
                .collect(),
        ));
    }
    if let Ok(value) = row.try_get::<String, _>(index) {
        if matches!(field_type, Some(FieldType::Json)) {
            return serde_json::from_str(&value).map_err(json_error);
        }
        return Ok(Value::String(value));
    }
    if let Ok(value) = row.try_get::<i64, _>(index) {
        return Ok(Value::Number(value.into()));
    }
    if let Ok(value) = row.try_get::<f64, _>(index) {
        return Ok(Number::from_f64(value)
            .map(Value::Number)
            .unwrap_or(Value::Null));
    }
    Err(AuthError::Adapter(format!(
        "unsupported SQL value in column {index}"
    )))
}

#[cfg(feature = "sqlx")]
fn record_with_id(record: Value, id: &str) -> Result<Value> {
    let Value::Object(mut object) = record else {
        return Err(AuthError::Adapter(
            "database records must be JSON objects".into(),
        ));
    };
    object.insert("id".into(), Value::String(id.to_owned()));
    Ok(Value::Object(object))
}

#[cfg(feature = "sqlx")]
fn sqlx_error(error: sqlx::Error) -> AuthError {
    AuthError::Adapter(format!("SQLx adapter error: {error}"))
}

#[cfg(feature = "sqlx")]
fn sqlx_lock_error() -> AuthError {
    AuthError::Adapter("SQLx adapter schema lock poisoned".into())
}

#[cfg(feature = "sqlx")]
fn validate_sqlx_url(url: &str, backend: SqlxBackend) -> Result<()> {
    let allowed = match backend {
        SqlxBackend::Postgres => ["postgres://", "postgresql://"].as_slice(),
        SqlxBackend::MySql => ["mysql://"].as_slice(),
    };
    if !allowed.iter().any(|prefix| url.starts_with(prefix)) {
        return Err(AuthError::InvalidConfiguration(format!(
            "database URL does not match {:?}",
            allowed
        )));
    }
    Ok(())
}

#[cfg(feature = "sqlx")]
fn sqlx_bind_sql(backend: SqlxBackend, sql: &str) -> String {
    if backend == SqlxBackend::MySql {
        return sql.to_owned();
    }
    let mut output = String::with_capacity(sql.len() + 8);
    let mut parameter = 0;
    for character in sql.chars() {
        if character == '?' {
            parameter += 1;
            output.push('$');
            output.push_str(&parameter.to_string());
        } else {
            output.push(character);
        }
    }
    output
}

#[cfg(feature = "sqlx")]
fn sqlx_kv_ddl(backend: SqlxBackend) -> &'static str {
    match backend {
        SqlxBackend::Postgres => "CREATE TABLE IF NOT EXISTS _better_auth_kv (storage_key VARCHAR(255) PRIMARY KEY, value_json TEXT NOT NULL, expires_at BIGINT NULL)",
        SqlxBackend::MySql => "CREATE TABLE IF NOT EXISTS _better_auth_kv (storage_key VARCHAR(255) PRIMARY KEY, value_json TEXT NOT NULL, expires_at BIGINT NULL)",
    }
}
