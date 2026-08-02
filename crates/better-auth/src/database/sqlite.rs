use super::common::{json_error, now_seconds};
use better_auth_core::{
    adapter::{DbAdapter, DbOperation, SecondaryStorage, StorageValue},
    error::{AuthError, Result},
    migration::{MigrationExecutor, MigrationPlan, SqlDialect},
};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::{
    path::Path,
    sync::Mutex,
    time::Duration,
};

fn sqlite_error(error: rusqlite::Error) -> AuthError {
    AuthError::Adapter(format!("SQLite adapter error: {error}"))
}

fn lock_error() -> AuthError {
    AuthError::Adapter("SQLite adapter lock poisoned".into())
}

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

