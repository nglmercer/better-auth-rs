use super::common::now_seconds;
use super::sqlite_sql::{
    self, field_type, record_object, Sql, SqlParam, KV_DDL, KV_DELETE, KV_GET, KV_PURGE, KV_SET,
};
use better_auth_core::{
    adapter::{record_id, DbAdapter, DbOperation, Query, SecondaryStorage, StorageValue},
    error::{AuthError, Result},
    migration::{MigrationExecutor, MigrationPlan, SqlDialect},
    schema::{core_schema, SchemaExtension},
};
use rusqlite::{
    params, params_from_iter,
    types::{ToSqlOutput, ValueRef},
    Connection, OptionalExtension, ToSql, TransactionBehavior,
};
use serde_json::{Map, Value};
use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard, RwLock},
    time::Duration,
};

/// Distinct statements the adapters keep prepared. Auth traffic repeats a
/// small set of query shapes, so nearly every call reuses a compiled statement.
const STATEMENT_CACHE_CAPACITY: usize = 128;

fn sqlite_error(error: rusqlite::Error) -> AuthError {
    AuthError::Adapter(format!("SQLite adapter error: {error}"))
}

fn lock_error() -> AuthError {
    AuthError::Adapter("SQLite adapter lock poisoned".into())
}

impl ToSql for SqlParam {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Borrowed(match self {
            SqlParam::Null => ValueRef::Null,
            SqlParam::Integer(value) => ValueRef::Integer(*value),
            SqlParam::Real(value) => ValueRef::Real(*value),
            SqlParam::Text(value) => ValueRef::Text(value.as_bytes()),
            SqlParam::Blob(value) => ValueRef::Blob(value),
        }))
    }
}

fn from_value_ref(value: ValueRef<'_>) -> Result<SqlParam> {
    Ok(match value {
        ValueRef::Null => SqlParam::Null,
        ValueRef::Integer(value) => SqlParam::Integer(value),
        ValueRef::Real(value) => SqlParam::Real(value),
        ValueRef::Text(value) => SqlParam::Text(
            std::str::from_utf8(value)
                .map_err(|error| AuthError::Adapter(format!("SQLite text error: {error}")))?
                .to_owned(),
        ),
        ValueRef::Blob(value) => SqlParam::Blob(value.to_vec()),
    })
}

fn execute(connection: &Connection, sql: &Sql) -> Result<u64> {
    let changed = connection
        .prepare_cached(&sql.text)
        .map_err(sqlite_error)?
        .execute(params_from_iter(sql.params.iter()))
        .map_err(sqlite_error)?;
    Ok(changed as u64)
}

/// Switches a file database to write-ahead logging with `synchronous = NORMAL`.
fn enable_wal(connection: &Connection) -> Result<()> {
    connection
        .execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")
        .map_err(sqlite_error)
}

pub struct SqliteDbAdapter {
    connection: Mutex<Connection>,
    schema: RwLock<Arc<SchemaExtension>>,
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
        connection.set_prepared_statement_cache_capacity(STATEMENT_CACHE_CAPACITY);
        Ok(Self {
            connection: Mutex::new(connection),
            schema: RwLock::new(Arc::new(core_schema())),
        })
    }

    /// Switches the database file to write-ahead logging with
    /// `synchronous = NORMAL`. Commits no longer wait for a full fsync of the
    /// main database file, and readers on other connections (for example a
    /// [`SqliteSecondaryStorage`] on the same file) are not blocked by a
    /// writer. The journal mode is stored in the database file, so this is an
    /// explicit call rather than something `open` does. It has no effect on an
    /// in-memory database.
    pub fn enable_wal(&self) -> Result<()> {
        enable_wal(&*self.connection()?)
    }

    pub async fn apply_migrations(&self, plan: &MigrationPlan) -> Result<()> {
        plan.apply(self, SqlDialect::Sqlite).await
    }

    /// Registers application/plugin schema metadata so JSON and boolean
    /// values can be converted back from SQLite without guessing their type.
    pub fn register_schema(&self, schema: &SchemaExtension) -> Result<()> {
        let mut current = self.schema.write().map_err(|_| lock_error())?;
        let mut merged = SchemaExtension::clone(&current);
        merged.merge(schema)?;
        *current = Arc::new(merged);
        Ok(())
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| lock_error())
    }

    /// A cheap snapshot of the registered schema.
    fn schema(&self) -> Result<Arc<SchemaExtension>> {
        Ok(Arc::clone(&*self.schema.read().map_err(|_| lock_error())?))
    }
}

#[async_trait::async_trait]
impl MigrationExecutor for SqliteDbAdapter {
    async fn execute(&self, statement: &str) -> Result<()> {
        self.connection()?
            .execute_batch(statement)
            .map_err(sqlite_error)
    }

    async fn column_exists(&self, table: &str, column: &str) -> Result<Option<bool>> {
        let exists = self
            .connection()?
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
        let sql = sqlite_sql::select(table, &query)?;
        let schema = self.schema()?;
        let connection = self.connection()?;
        let mut statement = connection.prepare_cached(&sql.text).map_err(sqlite_error)?;
        // Resolve each column's name and declared type once, not per row.
        let columns = statement
            .column_names()
            .into_iter()
            .map(|name| (name.to_owned(), field_type(&schema, table, name)))
            .collect::<Vec<_>>();
        let mut rows = statement
            .query(params_from_iter(sql.params.iter()))
            .map_err(sqlite_error)?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let mut object = Map::new();
            for (index, (name, field_type)) in columns.iter().enumerate() {
                let value = from_value_ref(row.get_ref(index).map_err(sqlite_error)?)?;
                object.insert(name.clone(), sqlite_sql::param_to_json(value, *field_type)?);
            }
            result.push(Value::Object(object));
        }
        Ok(result)
    }

    async fn insert_record(&self, table: &str, record: Value) -> Result<Value> {
        let sql = sqlite_sql::insert(table, record_object(&record)?, &*self.schema()?)?;
        execute(&*self.connection()?, &sql)?;
        Ok(record)
    }

    async fn update_where(&self, table: &str, query: Query, changes: Value) -> Result<u64> {
        let changes = record_object(&changes)?;
        if changes.is_empty() {
            return Ok(0);
        }
        let sql = sqlite_sql::update(table, &query, changes, &*self.schema()?)?;
        execute(&*self.connection()?, &sql)
    }

    async fn delete_where(&self, table: &str, query: Query) -> Result<u64> {
        let sql = sqlite_sql::delete(table, &query)?;
        execute(&*self.connection()?, &sql)
    }

    async fn list(&self, table: &str) -> Result<Vec<(String, Value)>> {
        let records = self.find_many(table, Query::new()).await?;
        records
            .into_iter()
            .map(|record| Ok((record_id(&record)?, record)))
            .collect()
    }

    async fn transaction(&self, operations: Vec<DbOperation>) -> Result<()> {
        let schema = self.schema()?;
        // Build every statement before taking the write lock on the database.
        let statements = operations
            .into_iter()
            .map(|operation| sqlite_sql::operation(operation, &schema))
            .collect::<Result<Vec<_>>>()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        for statement in &statements {
            let Some(sql) = &statement.sql else { continue };
            if execute(&transaction, sql)? == 0 && statement.require_change {
                return Err(AuthError::NotFound);
            }
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
        self.connection()?
            .execute_batch(KV_DDL)
            .map_err(sqlite_error)
    }

    /// See [`SqliteDbAdapter::enable_wal`]. Rate-limit counters write on every
    /// request, so a file-backed store benefits the most from it.
    pub fn enable_wal(&self) -> Result<()> {
        enable_wal(&*self.connection()?)
    }

    /// Deletes every expired entry and returns how many were removed. Expired
    /// entries are otherwise only removed when their key is read again, so a
    /// long-running service should call this periodically.
    pub fn purge_expired(&self) -> Result<u64> {
        let changed = self
            .connection()?
            .prepare_cached(KV_PURGE)
            .map_err(sqlite_error)?
            .execute(params![now_seconds() as i64])
            .map_err(sqlite_error)?;
        Ok(changed as u64)
    }

    fn from_connection(connection: Connection) -> Result<Self> {
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| lock_error())
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
    static INITIALIZED: std::sync::OnceLock<std::result::Result<(), String>> =
        std::sync::OnceLock::new();
    INITIALIZED
        .get_or_init(|| {
            libsql::Database::open_in_memory()
                .map(|_| ())
                .map_err(|error| error.to_string())
        })
        .clone()
        .map_err(|error| AuthError::Adapter(format!("libSQL initialization error: {error}")))
}

#[cfg(not(feature = "libsql"))]
fn initialize_libsql_runtime() -> Result<()> {
    Ok(())
}

#[async_trait::async_trait]
impl SecondaryStorage for SqliteSecondaryStorage {
    async fn get(&self, key: &str) -> Result<Option<StorageValue>> {
        read_kv(&*self.connection()?, key)
    }

    async fn set(&self, key: &str, value: StorageValue) -> Result<()> {
        let now = now_seconds() as i64;
        let expires_at = value.expires_in.map(|ttl| sqlite_sql::expiry(now, ttl));
        write_kv(&*self.connection()?, key, &value.value, expires_at)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        delete_kv(&*self.connection()?, key)
    }

    async fn increment(&self, key: &str, amount: i64, expires_in: Duration) -> Result<i64> {
        let mut connection = self.connection()?;
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
        // A live counter keeps its window. A new or expired one starts a fresh one.
        let now = now_seconds() as i64;
        let ttl = existing
            .and_then(|value| value.expires_in)
            .unwrap_or(expires_in);
        write_kv(
            &transaction,
            key,
            &Value::from(next),
            Some(sqlite_sql::expiry(now, ttl)),
        )?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(next)
    }

    async fn get_and_delete(&self, key: &str) -> Result<Option<StorageValue>> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let result = read_kv(&transaction, key)?;
        if result.is_some() {
            delete_kv(&transaction, key)?;
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(result)
    }
}

fn write_kv(
    connection: &Connection,
    key: &str,
    value: &Value,
    expires_at: Option<i64>,
) -> Result<()> {
    connection
        .prepare_cached(KV_SET)
        .map_err(sqlite_error)?
        .execute(params![key, value.to_string(), expires_at])
        .map_err(sqlite_error)?;
    Ok(())
}

fn delete_kv(connection: &Connection, key: &str) -> Result<()> {
    connection
        .prepare_cached(KV_DELETE)
        .map_err(sqlite_error)?
        .execute(params![key])
        .map_err(sqlite_error)?;
    Ok(())
}

/// Reads a live entry. An expired entry is deleted and reported as missing.
fn read_kv(connection: &Connection, key: &str) -> Result<Option<StorageValue>> {
    let row: Option<(String, Option<i64>)> = connection
        .prepare_cached(KV_GET)
        .map_err(sqlite_error)?
        .query_row(params![key], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()
        .map_err(sqlite_error)?;
    let Some((raw, expires_at)) = row else {
        return Ok(None);
    };
    let value = sqlite_sql::kv_value(&raw, expires_at, now_seconds() as i64)?;
    if value.is_none() {
        delete_kv(connection, key)?;
    }
    Ok(value)
}
