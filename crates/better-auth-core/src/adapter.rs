use crate::{AuthError, Result};
use async_trait::async_trait;
use serde_json::Value;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq)]
pub struct StorageValue {
    pub value: Value,
    pub expires_in: Option<Duration>,
}

impl StorageValue {
    pub fn permanent(value: Value) -> Self {
        Self {
            value,
            expires_in: None,
        }
    }

    pub fn with_ttl(value: Value, expires_in: Duration) -> Self {
        Self {
            value,
            expires_in: Some(expires_in),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum DbOperation {
    Insert {
        table: String,
        id: String,
        record: Value,
    },
    Update {
        table: String,
        id: String,
        record: Value,
    },
    Delete {
        table: String,
        id: String,
    },
}

/// Minimal relational CRUD contract. Concrete adapters own query building,
/// transactions, and database-specific typing.
#[async_trait]
pub trait DbAdapter: Send + Sync {
    async fn get(&self, table: &str, id: &str) -> Result<Option<Value>>;
    async fn insert(&self, table: &str, id: &str, record: Value) -> Result<()>;
    async fn update(&self, table: &str, id: &str, record: Value) -> Result<()>;
    async fn delete(&self, table: &str, id: &str) -> Result<()>;

    async fn get_by_field(
        &self,
        table: &str,
        field: &str,
        value: &Value,
    ) -> Result<Option<(String, Value)>>;

    async fn list(&self, table: &str) -> Result<Vec<(String, Value)>>;

    async fn transaction(&self, operations: Vec<DbOperation>) -> Result<()>;
}

/// KV storage for sessions, verification records, OAuth state, and rate-limit
/// counters. `increment` must be atomic in production adapters.
#[async_trait]
pub trait SecondaryStorage: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<StorageValue>>;
    async fn set(&self, key: &str, value: StorageValue) -> Result<()>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn increment(&self, key: &str, amount: i64, expires_in: Duration) -> Result<i64>;
    async fn get_and_delete(&self, key: &str) -> Result<Option<StorageValue>>;
}

/// Small in-memory implementations are useful for tests and examples. They
/// are intentionally kept here as explicit opt-in test infrastructure rather
/// than being a default persistence layer.
pub mod memory {
    use super::*;
    use async_trait::async_trait;
    use std::{collections::HashMap, sync::Mutex, time::Instant};

    #[derive(Default)]
    pub struct MemoryDb {
        records: Mutex<HashMap<(String, String), Value>>,
    }

    #[async_trait]
    impl DbAdapter for MemoryDb {
        async fn get(&self, table: &str, id: &str) -> Result<Option<Value>> {
            Ok(self
                .records
                .lock()
                .map_err(|_| AuthError::Adapter("memory DB lock poisoned".into()))?
                .get(&(table.into(), id.into()))
                .cloned())
        }

        async fn insert(&self, table: &str, id: &str, record: Value) -> Result<()> {
            let mut records = self
                .records
                .lock()
                .map_err(|_| AuthError::Adapter("memory DB lock poisoned".into()))?;
            let key = (table.into(), id.into());
            if records.contains_key(&key) {
                return Err(AuthError::Adapter("record already exists".into()));
            }
            records.insert(key, record);
            Ok(())
        }

        async fn update(&self, table: &str, id: &str, record: Value) -> Result<()> {
            let mut records = self
                .records
                .lock()
                .map_err(|_| AuthError::Adapter("memory DB lock poisoned".into()))?;
            let key = (table.into(), id.into());
            if !records.contains_key(&key) {
                return Err(AuthError::NotFound);
            }
            records.insert(key, record);
            Ok(())
        }

        async fn delete(&self, table: &str, id: &str) -> Result<()> {
            self.records
                .lock()
                .map_err(|_| AuthError::Adapter("memory DB lock poisoned".into()))?
                .remove(&(table.into(), id.into()));
            Ok(())
        }

        async fn get_by_field(
            &self,
            table: &str,
            field: &str,
            value: &Value,
        ) -> Result<Option<(String, Value)>> {
            let records = self
                .records
                .lock()
                .map_err(|_| AuthError::Adapter("memory DB lock poisoned".into()))?;
            Ok(records.iter().find_map(|((record_table, id), record)| {
                if record_table == table && record.get(field) == Some(value) {
                    Some((id.clone(), record.clone()))
                } else {
                    None
                }
            }))
        }

        async fn list(&self, table: &str) -> Result<Vec<(String, Value)>> {
            let records = self
                .records
                .lock()
                .map_err(|_| AuthError::Adapter("memory DB lock poisoned".into()))?;
            let mut result = records
                .iter()
                .filter(|((record_table, _), _)| record_table == table)
                .map(|((_, id), record)| (id.clone(), record.clone()))
                .collect::<Vec<_>>();
            result.sort_by(|left, right| left.0.cmp(&right.0));
            Ok(result)
        }

        async fn transaction(&self, operations: Vec<DbOperation>) -> Result<()> {
            let mut records = self
                .records
                .lock()
                .map_err(|_| AuthError::Adapter("memory DB lock poisoned".into()))?;
            let mut working = records.clone();
            for operation in operations {
                match operation {
                    DbOperation::Insert { table, id, record } => {
                        let key = (table, id);
                        if working.contains_key(&key) {
                            return Err(AuthError::Adapter("record already exists".into()));
                        }
                        working.insert(key, record);
                    }
                    DbOperation::Update { table, id, record } => {
                        let key = (table, id);
                        if !working.contains_key(&key) {
                            return Err(AuthError::NotFound);
                        }
                        working.insert(key, record);
                    }
                    DbOperation::Delete { table, id } => {
                        working.remove(&(table, id));
                    }
                }
            }
            *records = working;
            Ok(())
        }
    }

    #[derive(Default)]
    pub struct MemorySecondaryStorage {
        values: Mutex<HashMap<String, (Value, Option<Instant>)>>,
    }

    impl MemorySecondaryStorage {
        fn read_value(&self, key: &str) -> Result<Option<StorageValue>> {
            let mut values = self
                .values
                .lock()
                .map_err(|_| AuthError::Adapter("memory storage lock poisoned".into()))?;
            let Some((value, expires_at)) = values.get(key).cloned() else {
                return Ok(None);
            };
            if expires_at.is_some_and(|expires_at| expires_at <= Instant::now()) {
                values.remove(key);
                return Ok(None);
            }
            Ok(Some(StorageValue {
                value,
                expires_in: expires_at.map(|at| at.saturating_duration_since(Instant::now())),
            }))
        }
    }

    #[async_trait]
    impl SecondaryStorage for MemorySecondaryStorage {
        async fn get(&self, key: &str) -> Result<Option<StorageValue>> {
            self.read_value(key)
        }

        async fn set(&self, key: &str, value: StorageValue) -> Result<()> {
            self.values
                .lock()
                .map_err(|_| AuthError::Adapter("memory storage lock poisoned".into()))?
                .insert(
                    key.to_owned(),
                    (
                        value.value,
                        value.expires_in.map(|duration| Instant::now() + duration),
                    ),
                );
            Ok(())
        }

        async fn delete(&self, key: &str) -> Result<()> {
            self.values
                .lock()
                .map_err(|_| AuthError::Adapter("memory storage lock poisoned".into()))?
                .remove(key);
            Ok(())
        }

        async fn increment(&self, key: &str, amount: i64, expires_in: Duration) -> Result<i64> {
            let mut values = self
                .values
                .lock()
                .map_err(|_| AuthError::Adapter("memory storage lock poisoned".into()))?;
            let current = values
                .get(key)
                .and_then(|(value, expires_at)| {
                    if expires_at.is_some_and(|at| at <= Instant::now()) {
                        None
                    } else {
                        value.as_i64()
                    }
                })
                .unwrap_or(0);
            let next = current
                .checked_add(amount)
                .ok_or_else(|| AuthError::Adapter("counter overflow".into()))?;
            let now = Instant::now();
            let expiry = values
                .get(key)
                .and_then(|(_, expires_at)| *expires_at)
                .filter(|expires_at| *expires_at > now)
                .unwrap_or(now + expires_in);
            values.insert(key.to_owned(), (Value::from(next), Some(expiry)));
            Ok(next)
        }

        async fn get_and_delete(&self, key: &str) -> Result<Option<StorageValue>> {
            let result = self.read_value(key)?;
            self.delete(key).await?;
            Ok(result)
        }
    }
}
