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
use libsql::{params_from_iter, Builder, TransactionBehavior};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Map, Value};
use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::sync::{RwLock as AsyncRwLock, RwLockReadGuard};

/// How long a local connection waits for another connection's write lock on
/// the same file before failing with `SQLITE_BUSY`.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Removes one entry only if it is still expired at `?2`, so a value written
/// by another task between the read and this delete is left alone.
const KV_DELETE_EXPIRED: &str =
    "DELETE FROM _better_auth_kv WHERE storage_key = ?1 AND expires_at <= ?2";

/// Atomic read-and-remove in one statement and one round trip.
const KV_TAKE: &str =
    "DELETE FROM _better_auth_kv WHERE storage_key = ?1 RETURNING value_json, expires_at";

/// Atomic counter increment in one statement and one round trip.
/// `?1` key, `?2` amount, `?3` expiry for a fresh window, `?4` now.
/// An expired counter restarts at `?2` with a fresh window; a live one keeps
/// its window. The `WHERE` skips the update when the sum would overflow a
/// 64-bit integer, in which case no row is returned.
const KV_INCREMENT: &str = "INSERT INTO _better_auth_kv(storage_key, value_json, expires_at) \
VALUES (?1, CAST(?2 AS TEXT), ?3) \
ON CONFLICT(storage_key) DO UPDATE SET \
value_json = CASE WHEN _better_auth_kv.expires_at <= ?4 THEN excluded.value_json \
ELSE CAST(CAST(_better_auth_kv.value_json AS INTEGER) + ?2 AS TEXT) END, \
expires_at = CASE WHEN _better_auth_kv.expires_at <= ?4 THEN excluded.expires_at \
ELSE COALESCE(_better_auth_kv.expires_at, excluded.expires_at) END \
WHERE _better_auth_kv.expires_at <= ?4 \
OR typeof(CAST(_better_auth_kv.value_json AS INTEGER) + ?2) = 'integer' \
RETURNING value_json";

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

impl From<SqlParam> for libsql::Value {
    fn from(value: SqlParam) -> Self {
        match value {
            SqlParam::Null => libsql::Value::Null,
            SqlParam::Integer(value) => libsql::Value::Integer(value),
            SqlParam::Real(value) => libsql::Value::Real(value),
            SqlParam::Text(value) => libsql::Value::Text(value),
            SqlParam::Blob(value) => libsql::Value::Blob(value),
        }
    }
}

fn from_libsql(value: libsql::Value) -> SqlParam {
    match value {
        libsql::Value::Null => SqlParam::Null,
        libsql::Value::Integer(value) => SqlParam::Integer(value),
        libsql::Value::Real(value) => SqlParam::Real(value),
        libsql::Value::Text(value) => SqlParam::Text(value),
        libsql::Value::Blob(value) => SqlParam::Blob(value),
    }
}

fn bind(params: Vec<SqlParam>) -> impl libsql::params::IntoParams {
    params_from_iter(params.into_iter().map(libsql::Value::from))
}

async fn execute(connection: &libsql::Connection, sql: Sql) -> Result<u64> {
    connection
        .execute(&sql.text, bind(sql.params))
        .await
        .map_err(libsql_error)
}

/// The connection handle plus the gate that keeps transactions isolated.
///
/// A local database or embedded replica is a single SQLite connection shared
/// by every task. Without coordination, a statement from one task runs inside
/// whatever transaction another task has open on that handle (and is lost if
/// that transaction rolls back), and a second `BEGIN` fails outright. Plain
/// statements therefore hold the gate shared and a transaction holds it
/// exclusively. A remote connection opens a separate server-side stream for
/// each transaction, so it needs no gate and keeps full concurrency.
#[derive(Clone)]
struct Handle {
    // Keep the owning Database alive. libSQL's embedded-replica background
    // synchronizer is tied to this value's lifetime, not the cloned
    // Connection handle.
    _database: Arc<libsql::Database>,
    connection: libsql::Connection,
    gate: Option<Arc<AsyncRwLock<()>>>,
}

impl Handle {
    async fn connect(config: LibSqlConfig) -> Result<Self> {
        let gate = match config {
            LibSqlConfig::Remote { .. } => None,
            LibSqlConfig::Local { .. } | LibSqlConfig::RemoteReplica(_) => {
                Some(Arc::new(AsyncRwLock::new(())))
            }
        };
        let database = Arc::new(build_database(config).await?);
        let connection = database.connect().map_err(libsql_error)?;
        // A no-op for remote connections.
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(libsql_error)?;
        Ok(Self {
            _database: database,
            connection,
            gate,
        })
    }

    /// Held while a statement outside a transaction runs.
    async fn shared(&self) -> Option<RwLockReadGuard<'_, ()>> {
        match &self.gate {
            Some(gate) => Some(gate.read().await),
            None => None,
        }
    }
}

pub struct LibSqlDbAdapter {
    handle: Handle,
    schema: RwLock<Arc<SchemaExtension>>,
}

impl LibSqlDbAdapter {
    pub async fn connect(config: LibSqlConfig) -> Result<Self> {
        Ok(Self {
            handle: Handle::connect(config).await?,
            schema: RwLock::new(Arc::new(core_schema())),
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

    /// Secondary storage on the same connection as this adapter.
    pub fn secondary_storage(&self) -> LibSqlSecondaryStorage {
        LibSqlSecondaryStorage {
            handle: self.handle.clone(),
        }
    }

    pub fn register_schema(&self, schema: &SchemaExtension) -> Result<()> {
        let mut current = self.schema.write().map_err(|_| schema_lock_error())?;
        let mut merged = SchemaExtension::clone(&current);
        merged.merge(schema)?;
        *current = Arc::new(merged);
        Ok(())
    }

    pub async fn apply_migrations(&self, plan: &MigrationPlan) -> Result<()> {
        plan.apply(self, SqlDialect::Sqlite).await
    }

    /// A cheap snapshot of the registered schema.
    fn schema(&self) -> Result<Arc<SchemaExtension>> {
        Ok(Arc::clone(
            &*self.schema.read().map_err(|_| schema_lock_error())?,
        ))
    }
}

#[async_trait::async_trait]
impl MigrationExecutor for LibSqlDbAdapter {
    async fn execute(&self, statement: &str) -> Result<()> {
        let _shared = self.handle.shared().await;
        self.handle
            .connection
            .execute(statement, ())
            .await
            .map_err(libsql_error)?;
        Ok(())
    }

    async fn column_exists(&self, table: &str, column: &str) -> Result<Option<bool>> {
        let _shared = self.handle.shared().await;
        let mut rows = self
            .handle
            .connection
            .query(
                &format!(
                    "PRAGMA table_info({})",
                    sqlite_sql::quote_identifier(table)?
                ),
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
        let sql = sqlite_sql::select(table, &query)?;
        let schema = self.schema()?;
        let _shared = self.handle.shared().await;
        let mut rows = self
            .handle
            .connection
            .query(&sql.text, bind(sql.params))
            .await
            .map_err(libsql_error)?;
        // Resolve each column's name and declared type once, not per row.
        let columns = (0..rows.column_count())
            .map(|index| {
                let name = rows.column_name(index).ok_or_else(|| {
                    AuthError::Adapter("libSQL row is missing a column name".into())
                })?;
                Ok((name.to_owned(), field_type(&schema, table, name)))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().await.map_err(libsql_error)? {
            let mut object = Map::new();
            for (index, (name, field_type)) in columns.iter().enumerate() {
                let value = from_libsql(row.get_value(index as i32).map_err(libsql_error)?);
                object.insert(name.clone(), sqlite_sql::param_to_json(value, *field_type)?);
            }
            result.push(Value::Object(object));
        }
        Ok(result)
    }

    async fn insert_record(&self, table: &str, record: Value) -> Result<Value> {
        let sql = sqlite_sql::insert(table, record_object(&record)?, &*self.schema()?)?;
        let _shared = self.handle.shared().await;
        execute(&self.handle.connection, sql).await?;
        Ok(record)
    }

    async fn update_where(&self, table: &str, query: Query, changes: Value) -> Result<u64> {
        let changes = record_object(&changes)?;
        if changes.is_empty() {
            return Ok(0);
        }
        let sql = sqlite_sql::update(table, &query, changes, &*self.schema()?)?;
        let _shared = self.handle.shared().await;
        execute(&self.handle.connection, sql).await
    }

    async fn delete_where(&self, table: &str, query: Query) -> Result<u64> {
        let sql = sqlite_sql::delete(table, &query)?;
        let _shared = self.handle.shared().await;
        execute(&self.handle.connection, sql).await
    }

    async fn list(&self, table: &str) -> Result<Vec<(String, Value)>> {
        self.find_many(table, Query::new())
            .await?
            .into_iter()
            .map(|record| Ok((record_id(&record)?, record)))
            .collect()
    }

    async fn transaction(&self, operations: Vec<DbOperation>) -> Result<()> {
        let schema = self.schema()?;
        // Build every statement before taking the gate or a database lock.
        let statements = operations
            .into_iter()
            .map(|operation| sqlite_sql::operation(operation, &schema))
            .collect::<Result<Vec<_>>>()?;
        let _exclusive = match &self.handle.gate {
            Some(gate) => Some(gate.write().await),
            None => None,
        };
        let transaction = self
            .handle
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await
            .map_err(libsql_error)?;
        for statement in statements {
            let Some(sql) = statement.sql else { continue };
            let changed = match execute(&transaction, sql).await {
                Ok(changed) => changed,
                Err(error) => {
                    // Roll back before the gate is released, so the next
                    // statement on this handle cannot join this transaction.
                    let _ = transaction.rollback().await;
                    return Err(error);
                }
            };
            if changed == 0 && statement.require_change {
                let _ = transaction.rollback().await;
                return Err(AuthError::NotFound);
            }
        }
        transaction.commit().await.map_err(libsql_error)
    }
}

#[derive(Clone)]
pub struct LibSqlSecondaryStorage {
    handle: Handle,
}

impl LibSqlSecondaryStorage {
    pub async fn connect(config: LibSqlConfig) -> Result<Self> {
        Ok(Self {
            handle: Handle::connect(config).await?,
        })
    }

    /// Creates the secondary-storage table. This is intentionally explicit so
    /// connecting to a production database never changes its schema.
    pub async fn migrate(&self) -> Result<()> {
        let _shared = self.handle.shared().await;
        self.handle
            .connection
            .execute(KV_DDL, ())
            .await
            .map_err(libsql_error)?;
        Ok(())
    }

    /// Deletes every expired entry and returns how many were removed. Expired
    /// entries are otherwise only removed when their key is read again, so a
    /// long-running service should call this periodically.
    pub async fn purge_expired(&self) -> Result<u64> {
        let _shared = self.handle.shared().await;
        self.handle
            .connection
            .execute(KV_PURGE, libsql::params![now_seconds() as i64])
            .await
            .map_err(libsql_error)
    }
}

#[async_trait::async_trait]
impl SecondaryStorage for LibSqlSecondaryStorage {
    async fn get(&self, key: &str) -> Result<Option<StorageValue>> {
        let _shared = self.handle.shared().await;
        let connection = &self.handle.connection;
        let mut rows = connection
            .query(KV_GET, libsql::params![key])
            .await
            .map_err(libsql_error)?;
        let Some(row) = rows.next().await.map_err(libsql_error)? else {
            return Ok(None);
        };
        let raw: String = row.get(0).map_err(libsql_error)?;
        let expires_at: Option<i64> = row.get(1).map_err(libsql_error)?;
        drop(rows);
        let now = now_seconds() as i64;
        let value = sqlite_sql::kv_value(&raw, expires_at, now)?;
        if value.is_none() {
            connection
                .execute(KV_DELETE_EXPIRED, libsql::params![key, now])
                .await
                .map_err(libsql_error)?;
        }
        Ok(value)
    }

    async fn set(&self, key: &str, value: StorageValue) -> Result<()> {
        let now = now_seconds() as i64;
        let expires_at = value.expires_in.map(|ttl| sqlite_sql::expiry(now, ttl));
        let _shared = self.handle.shared().await;
        self.handle
            .connection
            .execute(
                KV_SET,
                libsql::params![key, value.value.to_string(), expires_at],
            )
            .await
            .map_err(libsql_error)?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let _shared = self.handle.shared().await;
        self.handle
            .connection
            .execute(KV_DELETE, libsql::params![key])
            .await
            .map_err(libsql_error)?;
        Ok(())
    }

    async fn increment(&self, key: &str, amount: i64, expires_in: Duration) -> Result<i64> {
        let now = now_seconds() as i64;
        let _shared = self.handle.shared().await;
        let mut rows = self
            .handle
            .connection
            .query(
                KV_INCREMENT,
                libsql::params![key, amount, sqlite_sql::expiry(now, expires_in), now],
            )
            .await
            .map_err(libsql_error)?;
        let Some(row) = rows.next().await.map_err(libsql_error)? else {
            return Err(AuthError::Adapter("counter overflow".into()));
        };
        let raw: String = row.get(0).map_err(libsql_error)?;
        raw.parse()
            .map_err(|_| AuthError::Adapter("counter overflow".into()))
    }

    async fn get_and_delete(&self, key: &str) -> Result<Option<StorageValue>> {
        let _shared = self.handle.shared().await;
        let mut rows = self
            .handle
            .connection
            .query(KV_TAKE, libsql::params![key])
            .await
            .map_err(libsql_error)?;
        let Some(row) = rows.next().await.map_err(libsql_error)? else {
            return Ok(None);
        };
        let raw: String = row.get(0).map_err(libsql_error)?;
        let expires_at: Option<i64> = row.get(1).map_err(libsql_error)?;
        sqlite_sql::kv_value(&raw, expires_at, now_seconds() as i64)
    }
}

fn libsql_error(error: libsql::Error) -> AuthError {
    AuthError::Adapter(format!("libSQL adapter error: {error}"))
}

fn schema_lock_error() -> AuthError {
    AuthError::Adapter("libSQL adapter schema lock poisoned".into())
}
