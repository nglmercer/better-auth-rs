use super::common::{json_error, now_seconds};
use better_auth_core::{
    adapter::{DbAdapter, DbOperation, SecondaryStorage, StorageValue},
    error::{AuthError, Result},
    migration::{MigrationExecutor, MigrationPlan, SqlDialect},
};
use serde_json::Value;
use sqlx::{Executor, Row};
use std::time::Duration;

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
}

#[cfg(feature = "sqlx")]
impl SqlxDbAdapter {
    pub async fn connect(url: &str, backend: SqlxBackend) -> Result<Self> {
        validate_sqlx_url(url, backend)?;
        sqlx::any::install_default_drivers();
        let pool = sqlx::AnyPool::connect(url).await.map_err(sqlx_error)?;
        let adapter = Self { pool, backend };
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
        let row = sqlx::query(&sqlx_bind_sql(
            self.backend,
            "SELECT record_json FROM _better_auth_records WHERE table_name = ? AND record_id = ?",
        ))
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
        sqlx::query(&sqlx_bind_sql(
            self.backend,
            "INSERT INTO _better_auth_records(table_name, record_id, record_json) VALUES (?, ?, ?)",
        ))
        .bind(table)
        .bind(id)
        .bind(record.to_string())
        .execute(&self.pool)
        .await
        .map_err(sqlx_error)?;
        Ok(())
    }

    async fn update(&self, table: &str, id: &str, record: Value) -> Result<()> {
        let result = sqlx::query(&sqlx_bind_sql(
            self.backend,
            "UPDATE _better_auth_records SET record_json = ? WHERE table_name = ? AND record_id = ?",
        ))
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
        sqlx::query(&sqlx_bind_sql(
            self.backend,
            "DELETE FROM _better_auth_records WHERE table_name = ? AND record_id = ?",
        ))
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
        let rows = sqlx::query(&sqlx_bind_sql(
            self.backend,
            "SELECT record_id, record_json FROM _better_auth_records WHERE table_name = ? ORDER BY record_id",
        ))
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
                    sqlx::query(&sqlx_bind_sql(
                        self.backend,
                        "INSERT INTO _better_auth_records(table_name, record_id, record_json) VALUES (?, ?, ?)",
                    ))
                    .bind(table)
                    .bind(id)
                    .bind(record.to_string())
                    .execute(&mut *transaction)
                    .await
                    .map_err(sqlx_error)?;
                }
                DbOperation::Update { table, id, record } => {
                    let result = sqlx::query(&sqlx_bind_sql(
                        self.backend,
                        "UPDATE _better_auth_records SET record_json = ? WHERE table_name = ? AND record_id = ?",
                    ))
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
                    sqlx::query(&sqlx_bind_sql(
                        self.backend,
                        "DELETE FROM _better_auth_records WHERE table_name = ? AND record_id = ?",
                    ))
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
    backend: SqlxBackend,
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
        Ok(Self { pool, backend })
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
        let result = read_sqlx_kv(&mut transaction, self.backend, key, false).await?;
        transaction.commit().await.map_err(sqlx_error)?;
        Ok(result)
    }

    async fn set(&self, key: &str, value: StorageValue) -> Result<()> {
        let expires_at = value
            .expires_in
            .map(|ttl| now_seconds() as i64 + ttl.as_secs() as i64);
        let mut transaction = self.pool.begin().await.map_err(sqlx_error)?;
        sqlx::query(&sqlx_bind_sql(
            self.backend,
            "DELETE FROM _better_auth_kv WHERE storage_key = ?",
        ))
        .bind(key)
        .execute(&mut *transaction)
        .await
        .map_err(sqlx_error)?;
        sqlx::query(&sqlx_bind_sql(
            self.backend,
            "INSERT INTO _better_auth_kv(storage_key, value_json, expires_at) VALUES (?, ?, ?)",
        ))
        .bind(key)
        .bind(value.value.to_string())
        .bind(expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(sqlx_error)?;
        transaction.commit().await.map_err(sqlx_error)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        sqlx::query(&sqlx_bind_sql(
            self.backend,
            "DELETE FROM _better_auth_kv WHERE storage_key = ?",
        ))
        .bind(key)
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
        sqlx::query(&sqlx_bind_sql(
            self.backend,
            "DELETE FROM _better_auth_kv WHERE storage_key = ?",
        ))
        .bind(key)
        .execute(&mut *transaction)
        .await
        .map_err(sqlx_error)?;
        sqlx::query(&sqlx_bind_sql(
            self.backend,
            "INSERT INTO _better_auth_kv(storage_key, value_json, expires_at) VALUES (?, ?, ?)",
        ))
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
        let result = read_sqlx_kv(&mut transaction, self.backend, key, true).await?;
        sqlx::query(&sqlx_bind_sql(
            self.backend,
            "DELETE FROM _better_auth_kv WHERE storage_key = ?",
        ))
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
    backend: SqlxBackend,
    key: &str,
    for_update: bool,
) -> Result<Option<StorageValue>> {
    let query = if for_update {
        "SELECT value_json, expires_at FROM _better_auth_kv WHERE storage_key = ? FOR UPDATE"
    } else {
        "SELECT value_json, expires_at FROM _better_auth_kv WHERE storage_key = ?"
    };
    let row = sqlx::query(&sqlx_bind_sql(backend, query))
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
