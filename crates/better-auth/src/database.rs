use better_auth_core::{
    adapter::{DbAdapter, DbOperation, SecondaryStorage, StorageValue},
    error::{AuthError, Result},
    migration::{MigrationExecutor, MigrationPlan, SqlDialect},
};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
#[cfg(feature = "sqlx")]
use sqlx::{Executor, Row};
use std::{
    path::Path,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub struct SqliteDbAdapter {
    connection: Mutex<Connection>,
}

impl SqliteDbAdapter {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path).map_err(sqlite_error)?;
        Self::from_connection(connection)
    }

    pub fn in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory().map_err(sqlite_error)?)
    }

    fn from_connection(connection: Connection) -> Result<Self> {
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS _better_auth_records (\
                    table_name TEXT NOT NULL,\
                    record_id TEXT NOT NULL,\
                    record_json TEXT NOT NULL,\
                    PRIMARY KEY(table_name, record_id)\
                );",
            )
            .map_err(sqlite_error)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub async fn apply_migrations(&self, plan: &MigrationPlan) -> Result<()> {
        plan.apply(self, SqlDialect::Sqlite).await
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
}

#[async_trait::async_trait]
impl DbAdapter for SqliteDbAdapter {
    async fn get(&self, table: &str, id: &str) -> Result<Option<Value>> {
        let connection = self.connection.lock().map_err(|_| lock_error())?;
        let raw: Option<String> = connection
            .query_row(
                "SELECT record_json FROM _better_auth_records WHERE table_name = ?1 AND record_id = ?2",
                params![table, id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        raw.map(|raw| serde_json::from_str(&raw).map_err(json_error))
            .transpose()
    }

    async fn insert(&self, table: &str, id: &str, record: Value) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| lock_error())?;
        connection
            .execute(
                "INSERT INTO _better_auth_records(table_name, record_id, record_json) VALUES (?1, ?2, ?3)",
                params![table, id, record.to_string()],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    async fn update(&self, table: &str, id: &str, record: Value) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| lock_error())?;
        let changed = connection
            .execute(
                "UPDATE _better_auth_records SET record_json = ?3 WHERE table_name = ?1 AND record_id = ?2",
                params![table, id, record.to_string()],
            )
            .map_err(sqlite_error)?;
        if changed == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    async fn delete(&self, table: &str, id: &str) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| lock_error())?;
        connection
            .execute(
                "DELETE FROM _better_auth_records WHERE table_name = ?1 AND record_id = ?2",
                params![table, id],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    async fn get_by_field(
        &self,
        table: &str,
        field: &str,
        value: &Value,
    ) -> Result<Option<(String, Value)>> {
        let connection = self.connection.lock().map_err(|_| lock_error())?;
        let mut statement = connection
            .prepare(
                "SELECT record_id, record_json FROM _better_auth_records WHERE table_name = ?1",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(params![table], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_error)?;
        for row in rows {
            let (id, raw) = row.map_err(sqlite_error)?;
            let record: Value = serde_json::from_str(&raw).map_err(json_error)?;
            if record.get(field) == Some(value) {
                return Ok(Some((id, record)));
            }
        }
        Ok(None)
    }

    async fn list(&self, table: &str) -> Result<Vec<(String, Value)>> {
        let connection = self.connection.lock().map_err(|_| lock_error())?;
        let mut statement = connection
            .prepare(
                "SELECT record_id, record_json FROM _better_auth_records WHERE table_name = ?1 ORDER BY record_id",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(params![table], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_error)?;
        rows.map(|row| {
            let (id, raw) = row.map_err(sqlite_error)?;
            Ok((id, serde_json::from_str(&raw).map_err(json_error)?))
        })
        .collect()
    }

    async fn transaction(&self, operations: Vec<DbOperation>) -> Result<()> {
        let mut connection = self.connection.lock().map_err(|_| lock_error())?;
        let transaction = connection.transaction().map_err(sqlite_error)?;
        for operation in operations {
            match operation {
                DbOperation::Insert { table, id, record } => {
                    transaction.execute(
                        "INSERT INTO _better_auth_records(table_name, record_id, record_json) VALUES (?1, ?2, ?3)",
                        params![table, id, record.to_string()],
                    ).map_err(sqlite_error)?;
                }
                DbOperation::Update { table, id, record } => {
                    let changed = transaction.execute(
                        "UPDATE _better_auth_records SET record_json = ?3 WHERE table_name = ?1 AND record_id = ?2",
                        params![table, id, record.to_string()],
                    ).map_err(sqlite_error)?;
                    if changed == 0 {
                        return Err(AuthError::NotFound);
                    }
                }
                DbOperation::Delete { table, id } => {
                    transaction.execute(
                        "DELETE FROM _better_auth_records WHERE table_name = ?1 AND record_id = ?2",
                        params![table, id],
                    ).map_err(sqlite_error)?;
                }
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
        Self::from_connection(Connection::open(path).map_err(sqlite_error)?)
    }

    pub fn in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory().map_err(sqlite_error)?)
    }

    fn from_connection(connection: Connection) -> Result<Self> {
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS _better_auth_kv (\
                    storage_key TEXT PRIMARY KEY,\
                    value_json TEXT NOT NULL,\
                    expires_at INTEGER\
                );",
            )
            .map_err(sqlite_error)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }
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
        connection.execute(
            "INSERT INTO _better_auth_kv(storage_key, value_json, expires_at) VALUES (?1, ?2, ?3) ON CONFLICT(storage_key) DO UPDATE SET value_json = excluded.value_json, expires_at = excluded.expires_at",
            params![key, value.value.to_string(), expires_at],
        ).map_err(sqlite_error)?;
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
        let connection = self.connection.lock().map_err(|_| lock_error())?;
        let existing = read_kv(&connection, key)?;
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
        connection.execute(
            "INSERT INTO _better_auth_kv(storage_key, value_json, expires_at) VALUES (?1, ?2, ?3) ON CONFLICT(storage_key) DO UPDATE SET value_json = excluded.value_json, expires_at = excluded.expires_at",
            params![key, Value::from(next).to_string(), expires_at],
        ).map_err(sqlite_error)?;
        Ok(next)
    }

    async fn get_and_delete(&self, key: &str) -> Result<Option<StorageValue>> {
        let mut connection = self.connection.lock().map_err(|_| lock_error())?;
        let transaction = connection.transaction().map_err(sqlite_error)?;
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

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

fn sqlite_error(error: rusqlite::Error) -> AuthError {
    AuthError::Adapter(format!("SQLite adapter error: {error}"))
}
fn json_error(error: serde_json::Error) -> AuthError {
    AuthError::Adapter(format!("SQLite JSON error: {error}"))
}
fn lock_error() -> AuthError {
    AuthError::Adapter("SQLite adapter lock poisoned".into())
}

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
}

#[cfg(feature = "sqlx")]
impl SqlxDbAdapter {
    pub async fn connect(url: &str, backend: SqlxBackend) -> Result<Self> {
        validate_sqlx_url(url, backend)?;
        sqlx::any::install_default_drivers();
        let pool = sqlx::AnyPool::connect(url).await.map_err(sqlx_error)?;
        let adapter = Self { pool };
        adapter
            .pool
            .execute(sqlx_records_ddl(backend))
            .await
            .map_err(sqlx_error)?;
        Ok(adapter)
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
}

#[cfg(feature = "sqlx")]
#[async_trait::async_trait]
impl DbAdapter for SqlxDbAdapter {
    async fn get(&self, table: &str, id: &str) -> Result<Option<Value>> {
        let row = sqlx::query(
            "SELECT record_json FROM _better_auth_records WHERE table_name = ? AND record_id = ?",
        )
        .bind(table)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(sqlx_error)?;
        row.map(|row| {
            serde_json::from_str(
                row.try_get::<String, _>("record_json")
                    .map_err(sqlx_error)?
                    .as_str(),
            )
            .map_err(json_error)
        })
        .transpose()
    }

    async fn insert(&self, table: &str, id: &str, record: Value) -> Result<()> {
        sqlx::query(
            "INSERT INTO _better_auth_records(table_name, record_id, record_json) VALUES (?, ?, ?)",
        )
        .bind(table)
        .bind(id)
        .bind(record.to_string())
        .execute(&self.pool)
        .await
        .map_err(sqlx_error)?;
        Ok(())
    }

    async fn update(&self, table: &str, id: &str, record: Value) -> Result<()> {
        let result = sqlx::query(
            "UPDATE _better_auth_records SET record_json = ? WHERE table_name = ? AND record_id = ?",
        )
        .bind(record.to_string())
        .bind(table)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(sqlx_error)?;
        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    async fn delete(&self, table: &str, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM _better_auth_records WHERE table_name = ? AND record_id = ?")
            .bind(table)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(sqlx_error)?;
        Ok(())
    }

    async fn get_by_field(
        &self,
        table: &str,
        field: &str,
        value: &Value,
    ) -> Result<Option<(String, Value)>> {
        let records = self.list(table).await?;
        Ok(records
            .into_iter()
            .find(|(_, record)| record.get(field) == Some(value)))
    }

    async fn list(&self, table: &str) -> Result<Vec<(String, Value)>> {
        let rows = sqlx::query(
            "SELECT record_id, record_json FROM _better_auth_records WHERE table_name = ? ORDER BY record_id",
        )
        .bind(table)
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_error)?;
        rows.into_iter()
            .map(|row| {
                let id = row.try_get::<String, _>("record_id").map_err(sqlx_error)?;
                let record = serde_json::from_str(
                    row.try_get::<String, _>("record_json")
                        .map_err(sqlx_error)?
                        .as_str(),
                )
                .map_err(json_error)?;
                Ok((id, record))
            })
            .collect()
    }

    async fn transaction(&self, operations: Vec<DbOperation>) -> Result<()> {
        let mut transaction = self.pool.begin().await.map_err(sqlx_error)?;
        for operation in operations {
            match operation {
                DbOperation::Insert { table, id, record } => {
                    sqlx::query(
                        "INSERT INTO _better_auth_records(table_name, record_id, record_json) VALUES (?, ?, ?)",
                    )
                    .bind(table)
                    .bind(id)
                    .bind(record.to_string())
                    .execute(&mut *transaction)
                    .await
                    .map_err(sqlx_error)?;
                }
                DbOperation::Update { table, id, record } => {
                    let result = sqlx::query(
                        "UPDATE _better_auth_records SET record_json = ? WHERE table_name = ? AND record_id = ?",
                    )
                    .bind(record.to_string())
                    .bind(table)
                    .bind(id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(sqlx_error)?;
                    if result.rows_affected() == 0 {
                        return Err(AuthError::NotFound);
                    }
                }
                DbOperation::Delete { table, id } => {
                    sqlx::query(
                        "DELETE FROM _better_auth_records WHERE table_name = ? AND record_id = ?",
                    )
                    .bind(table)
                    .bind(id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(sqlx_error)?;
                }
            }
        }
        transaction.commit().await.map_err(sqlx_error)
    }
}

#[cfg(feature = "sqlx")]
#[derive(Clone)]
pub struct SqlxSecondaryStorage {
    pool: sqlx::AnyPool,
}

#[cfg(feature = "sqlx")]
impl SqlxSecondaryStorage {
    pub async fn connect(url: &str, backend: SqlxBackend) -> Result<Self> {
        validate_sqlx_url(url, backend)?;
        sqlx::any::install_default_drivers();
        let pool = sqlx::AnyPool::connect(url).await.map_err(sqlx_error)?;
        pool.execute(sqlx_kv_ddl(backend))
            .await
            .map_err(sqlx_error)?;
        Ok(Self { pool })
    }

    pub async fn postgres(url: &str) -> Result<Self> {
        Self::connect(url, SqlxBackend::Postgres).await
    }

    pub async fn mysql(url: &str) -> Result<Self> {
        Self::connect(url, SqlxBackend::MySql).await
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
        let result = read_sqlx_kv(&mut transaction, key, false).await?;
        transaction.commit().await.map_err(sqlx_error)?;
        Ok(result)
    }

    async fn set(&self, key: &str, value: StorageValue) -> Result<()> {
        let expires_at = value
            .expires_in
            .map(|ttl| now_seconds() as i64 + ttl.as_secs() as i64);
        sqlx::query("DELETE FROM _better_auth_kv WHERE storage_key = ?")
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(sqlx_error)?;
        sqlx::query(
            "INSERT INTO _better_auth_kv(storage_key, value_json, expires_at) VALUES (?, ?, ?)",
        )
        .bind(key)
        .bind(value.value.to_string())
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(sqlx_error)?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        sqlx::query("DELETE FROM _better_auth_kv WHERE storage_key = ?")
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(sqlx_error)?;
        Ok(())
    }

    async fn increment(&self, key: &str, amount: i64, expires_in: Duration) -> Result<i64> {
        let mut transaction = self.pool.begin().await.map_err(sqlx_error)?;
        let existing = read_sqlx_kv(&mut transaction, key, true).await?;
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
        sqlx::query("DELETE FROM _better_auth_kv WHERE storage_key = ?")
            .bind(key)
            .execute(&mut *transaction)
            .await
            .map_err(sqlx_error)?;
        sqlx::query(
            "INSERT INTO _better_auth_kv(storage_key, value_json, expires_at) VALUES (?, ?, ?)",
        )
        .bind(key)
        .bind(Value::from(next).to_string())
        .bind(expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(sqlx_error)?;
        transaction.commit().await.map_err(sqlx_error)?;
        Ok(next)
    }

    async fn get_and_delete(&self, key: &str) -> Result<Option<StorageValue>> {
        let mut transaction = self.pool.begin().await.map_err(sqlx_error)?;
        let result = read_sqlx_kv(&mut transaction, key, true).await?;
        sqlx::query("DELETE FROM _better_auth_kv WHERE storage_key = ?")
            .bind(key)
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
    key: &str,
    for_update: bool,
) -> Result<Option<StorageValue>> {
    let query = if for_update {
        "SELECT value_json, expires_at FROM _better_auth_kv WHERE storage_key = ? FOR UPDATE"
    } else {
        "SELECT value_json, expires_at FROM _better_auth_kv WHERE storage_key = ?"
    };
    let row = sqlx::query(query)
        .bind(key)
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
fn sqlx_records_ddl(backend: SqlxBackend) -> &'static str {
    match backend {
        SqlxBackend::Postgres => "CREATE TABLE IF NOT EXISTS _better_auth_records (table_name VARCHAR(255) NOT NULL, record_id VARCHAR(255) NOT NULL, record_json TEXT NOT NULL, PRIMARY KEY(table_name, record_id))",
        SqlxBackend::MySql => "CREATE TABLE IF NOT EXISTS _better_auth_records (table_name VARCHAR(255) NOT NULL, record_id VARCHAR(255) NOT NULL, record_json TEXT NOT NULL, PRIMARY KEY(table_name, record_id))",
    }
}

#[cfg(feature = "sqlx")]
fn sqlx_kv_ddl(backend: SqlxBackend) -> &'static str {
    match backend {
        SqlxBackend::Postgres => "CREATE TABLE IF NOT EXISTS _better_auth_kv (storage_key VARCHAR(255) PRIMARY KEY, value_json TEXT NOT NULL, expires_at BIGINT NULL)",
        SqlxBackend::MySql => "CREATE TABLE IF NOT EXISTS _better_auth_kv (storage_key VARCHAR(255) PRIMARY KEY, value_json TEXT NOT NULL, expires_at BIGINT NULL)",
    }
}

#[cfg(feature = "sqlx")]
fn validate_sqlx_url(url: &str, backend: SqlxBackend) -> Result<()> {
    let valid = match backend {
        SqlxBackend::Postgres => url.starts_with("postgres://") || url.starts_with("postgresql://"),
        SqlxBackend::MySql => url.starts_with("mysql://"),
    };
    if valid {
        Ok(())
    } else {
        Err(AuthError::InvalidConfiguration(format!(
            "database URL does not match {:?} backend",
            backend
        )))
    }
}

#[cfg(feature = "sqlx")]
fn sqlx_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Adapter(format!("SQLx adapter error: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::adapter::{DbAdapter, DbOperation, SecondaryStorage};
    use better_auth_core::migration::MigrationPlan;

    #[tokio::test]
    async fn sqlite_db_transactions_are_atomic() {
        let adapter = SqliteDbAdapter::in_memory().unwrap();
        let result = adapter
            .transaction(vec![
                DbOperation::Insert {
                    table: "user".into(),
                    id: "one".into(),
                    record: serde_json::json!({"id":"one"}),
                },
                DbOperation::Insert {
                    table: "user".into(),
                    id: "one".into(),
                    record: serde_json::json!({"id":"duplicate"}),
                },
            ])
            .await;
        assert!(result.is_err());
        assert!(adapter.get("user", "one").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sqlite_secondary_storage_supports_increment_and_one_time_reads() {
        let storage = SqliteSecondaryStorage::in_memory().unwrap();
        assert_eq!(
            storage
                .increment("counter", 1, Duration::from_secs(60))
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            storage
                .increment("counter", 2, Duration::from_secs(60))
                .await
                .unwrap(),
            3
        );
        assert_eq!(
            storage
                .get_and_delete("counter")
                .await
                .unwrap()
                .unwrap()
                .value,
            Value::from(3)
        );
        assert!(storage.get("counter").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sqlite_migration_runner_applies_schema_sql() {
        let adapter = SqliteDbAdapter::in_memory().unwrap();
        adapter
            .apply_migrations(&MigrationPlan::from_schema(
                &better_auth_core::schema::core_schema(),
            ))
            .await
            .unwrap();
    }
}
