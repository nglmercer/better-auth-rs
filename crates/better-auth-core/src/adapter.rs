use crate::{schema::SchemaExtension, AuthError, Result};
use async_trait::async_trait;
use serde_json::Value;
use std::{cmp::Ordering, time::Duration};

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
    /// Compatibility operation that addresses a row by its id.
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
    /// Relational insert operation.
    InsertRecord {
        table: String,
        record: Value,
    },
    /// Relational update operation. `changes` is a partial object.
    UpdateWhere {
        table: String,
        query: Query,
        changes: Value,
    },
    /// Relational delete operation.
    DeleteWhere {
        table: String,
        query: Query,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterOp {
    Eq,
    Ne,
    Lt,
    Lte,
    Gt,
    Gte,
    In,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Filter {
    pub field: String,
    pub op: FilterOp,
    pub value: Value,
}

impl Filter {
    pub fn new(field: impl Into<String>, op: FilterOp, value: Value) -> Self {
        Self {
            field: field.into(),
            op,
            value,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OrderDirection {
    #[default]
    Asc,
    Desc,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderBy {
    pub field: String,
    pub direction: OrderDirection,
}

impl OrderBy {
    pub fn ascending(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            direction: OrderDirection::Asc,
        }
    }

    pub fn descending(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            direction: OrderDirection::Desc,
        }
    }
}

/// Database-side filtering and pagination primitives.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Query {
    pub filters: Vec<Filter>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub order_by: Vec<OrderBy>,
}

impl Query {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn filter(mut self, field: impl Into<String>, op: FilterOp, value: Value) -> Self {
        self.filters.push(Filter::new(field, op, value));
        self
    }

    pub fn eq(self, field: impl Into<String>, value: impl Into<Value>) -> Self {
        self.filter(field, FilterOp::Eq, value.into())
    }

    pub fn ne(self, field: impl Into<String>, value: impl Into<Value>) -> Self {
        self.filter(field, FilterOp::Ne, value.into())
    }

    pub fn is_in(self, field: impl Into<String>, values: impl Into<Value>) -> Self {
        self.filter(field, FilterOp::In, values.into())
    }

    pub fn order_by(mut self, order: OrderBy) -> Self {
        self.order_by.push(order);
        self
    }

    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }
}

/// Relational CRUD contract. Concrete adapters own SQL generation,
/// transactions, and database-specific value conversion. The deprecated
/// methods below are intentionally retained as a migration bridge for older
/// plugins and applications.
#[async_trait]
pub trait DbAdapter: Send + Sync {
    /// Registers schema metadata used when converting relational values to
    /// JSON. Migration execution remains explicit for application-controlled
    /// migration ordering.
    fn register_schema(&self, _schema: &SchemaExtension) -> Result<()> {
        Ok(())
    }

    async fn find_one(&self, table: &str, query: Query) -> Result<Option<Value>>;
    async fn find_many(&self, table: &str, query: Query) -> Result<Vec<Value>>;
    async fn insert_record(&self, table: &str, record: Value) -> Result<Value>;
    async fn update_where(&self, table: &str, query: Query, changes: Value) -> Result<u64>;
    async fn delete_where(&self, table: &str, query: Query) -> Result<u64>;

    async fn transaction(&self, operations: Vec<DbOperation>) -> Result<()>;

    #[deprecated(note = "use DbAdapter::find_one with Query::eq")]
    async fn get(&self, table: &str, id: &str) -> Result<Option<Value>> {
        self.find_one(table, Query::new().eq("id", id.to_owned()))
            .await
    }

    #[deprecated(note = "use DbAdapter::insert_record")]
    async fn insert(&self, table: &str, id: &str, record: Value) -> Result<()> {
        self.insert_record(table, record_with_id(record, id)?)
            .await?;
        Ok(())
    }

    #[deprecated(note = "use DbAdapter::update_where")]
    async fn update(&self, table: &str, id: &str, record: Value) -> Result<()> {
        let changed = self
            .update_where(table, Query::new().eq("id", id.to_owned()), record)
            .await?;
        if changed == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    #[deprecated(note = "use DbAdapter::delete_where")]
    async fn delete(&self, table: &str, id: &str) -> Result<()> {
        self.delete_where(table, Query::new().eq("id", id.to_owned()))
            .await?;
        Ok(())
    }

    #[deprecated(note = "use DbAdapter::find_one with Query::eq")]
    async fn get_by_field(
        &self,
        table: &str,
        field: &str,
        value: &Value,
    ) -> Result<Option<(String, Value)>> {
        let Some(record) = self
            .find_one(table, Query::new().eq(field, value.clone()))
            .await?
        else {
            return Ok(None);
        };
        let id = record
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::Adapter("adapter result is missing string id".into()))?;
        Ok(Some((id.to_owned(), record)))
    }

    #[deprecated(note = "use DbAdapter::find_many")]
    async fn list(&self, table: &str) -> Result<Vec<(String, Value)>> {
        self.find_many(table, Query::new())
            .await?
            .into_iter()
            .map(|record| Ok((record_id(&record)?, record)))
            .collect()
    }
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

/// Extract an adapter id from a record returned by a relational adapter.
pub fn record_id(record: &Value) -> Result<String> {
    record
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AuthError::Adapter("adapter result is missing string id".into()))
}

/// Small in-memory implementations are useful for tests and examples. They
/// are intentionally kept here as explicit opt-in test infrastructure rather
/// than being a default persistence layer.

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
        async fn find_one(&self, table: &str, mut query: Query) -> Result<Option<Value>> {
            query.limit = Some(query.limit.unwrap_or(1).min(1));
            let records = self
                .records
                .lock()
                .map_err(|_| AuthError::Adapter("memory DB lock poisoned".into()))?;
            let mut result = records
                .iter()
                .filter(|((record_table, id), record)| {
                    record_table == table && matches_query(id, record, &query)
                })
                .map(|((_, id), record)| (id.clone(), record.clone()))
                .collect::<Vec<_>>();
            sort_records(&mut result, &query);
            Ok(result.into_iter().next().map(|(_, record)| record))
        }

        async fn find_many(&self, table: &str, query: Query) -> Result<Vec<Value>> {
            let records = self
                .records
                .lock()
                .map_err(|_| AuthError::Adapter("memory DB lock poisoned".into()))?;
            let mut result = records
                .iter()
                .filter(|((record_table, id), record)| {
                    record_table == table && matches_query(id, record, &query)
                })
                .map(|((_, id), record)| (id.clone(), record.clone()))
                .collect::<Vec<_>>();
            sort_records(&mut result, &query);
            let offset = query.offset.unwrap_or(0) as usize;
            Ok(result
                .into_iter()
                .skip(offset)
                .take(query.limit.unwrap_or(u32::MAX) as usize)
                .map(|(_, record)| record)
                .collect())
        }

        async fn insert_record(&self, table: &str, record: Value) -> Result<Value> {
            let id = record_id(&record)?;
            let mut records = self
                .records
                .lock()
                .map_err(|_| AuthError::Adapter("memory DB lock poisoned".into()))?;
            let key = (table.to_owned(), id);
            if records.contains_key(&key) {
                return Err(AuthError::Adapter("record already exists".into()));
            }
            records.insert(key, record.clone());
            Ok(record)
        }

        async fn update_where(&self, table: &str, query: Query, changes: Value) -> Result<u64> {
            let Value::Object(changes) = changes else {
                return Err(AuthError::Adapter(
                    "database changes must be a JSON object".into(),
                ));
            };
            let mut records = self
                .records
                .lock()
                .map_err(|_| AuthError::Adapter("memory DB lock poisoned".into()))?;
            let keys = records
                .iter()
                .filter(|((record_table, id), record)| {
                    record_table == table && matches_query(id, record, &query)
                })
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>();
            for key in &keys {
                let record = records
                    .get_mut(key)
                    .ok_or_else(|| AuthError::Adapter("memory row disappeared".into()))?;
                let Value::Object(object) = record else {
                    return Err(AuthError::Adapter("stored record is not an object".into()));
                };
                for (field, value) in &changes {
                    object.insert(field.clone(), value.clone());
                }
            }
            Ok(keys.len() as u64)
        }

        async fn delete_where(&self, table: &str, query: Query) -> Result<u64> {
            let mut records = self
                .records
                .lock()
                .map_err(|_| AuthError::Adapter("memory DB lock poisoned".into()))?;
            let keys = records
                .iter()
                .filter(|((record_table, id), record)| {
                    record_table == table && matches_query(id, record, &query)
                })
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>();
            let count = keys.len() as u64;
            for key in keys {
                records.remove(&key);
            }
            Ok(count)
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
                apply_memory_operation(&mut working, operation)?;
            }
            *records = working;
            Ok(())
        }
    }

    fn field_value<'a>(id: &str, record: &'a Value, field: &str) -> Option<&'a Value> {
        if field == "id" {
            record.get("id")
        } else {
            let _ = id;
            record.get(field)
        }
    }

    fn matches_query(id: &str, record: &Value, query: &Query) -> bool {
        query.filters.iter().all(|filter| {
            let id_value = Value::String(id.to_owned());
            let actual = if filter.field == "id" {
                record.get("id").unwrap_or(&id_value)
            } else {
                record.get(&filter.field).unwrap_or(&Value::Null)
            };
            match filter.op {
                FilterOp::Eq => actual == &filter.value,
                FilterOp::Ne => actual != &filter.value,
                FilterOp::In => filter
                    .value
                    .as_array()
                    .is_some_and(|values| values.contains(actual)),
                FilterOp::Lt | FilterOp::Lte | FilterOp::Gt | FilterOp::Gte => {
                    let ordering = compare_values(actual, &filter.value);
                    match filter.op {
                        FilterOp::Lt => ordering == Ordering::Less,
                        FilterOp::Lte => ordering != Ordering::Greater,
                        FilterOp::Gt => ordering == Ordering::Greater,
                        FilterOp::Gte => ordering != Ordering::Less,
                        _ => unreachable!(),
                    }
                }
            }
        })
    }

    fn sort_records(records: &mut [(String, Value)], query: &Query) {
        records.sort_by(|left, right| {
            if query.order_by.is_empty() {
                return left.0.cmp(&right.0);
            }
            query
                .order_by
                .iter()
                .find_map(|order| {
                    let left_value = field_value(&left.0, &left.1, &order.field);
                    let right_value = field_value(&right.0, &right.1, &order.field);
                    let ordering = compare_values(
                        left_value.unwrap_or(&Value::Null),
                        right_value.unwrap_or(&Value::Null),
                    );
                    (ordering != Ordering::Equal).then_some(match order.direction {
                        OrderDirection::Asc => ordering,
                        OrderDirection::Desc => ordering.reverse(),
                    })
                })
                .unwrap_or_else(|| left.0.cmp(&right.0))
        });
    }

    fn compare_values(left: &Value, right: &Value) -> Ordering {
        if let (Some(left), Some(right)) = (left.as_f64(), right.as_f64()) {
            return left.partial_cmp(&right).unwrap_or(Ordering::Equal);
        }
        match (left, right) {
            (Value::String(left), Value::String(right)) => left.cmp(right),
            (Value::Bool(left), Value::Bool(right)) => left.cmp(right),
            (Value::Null, Value::Null) => Ordering::Equal,
            (Value::Null, _) => Ordering::Less,
            (_, Value::Null) => Ordering::Greater,
            _ => left.to_string().cmp(&right.to_string()),
        }
    }

    fn apply_memory_operation(
        records: &mut HashMap<(String, String), Value>,
        operation: DbOperation,
    ) -> Result<()> {
        match operation {
            DbOperation::Insert { table, id, record } => {
                let key = (table, id);
                if records.contains_key(&key) {
                    return Err(AuthError::Adapter("record already exists".into()));
                }
                records.insert(key, record);
            }
            DbOperation::Update { table, id, record } => {
                let key = (table, id);
                if !records.contains_key(&key) {
                    return Err(AuthError::NotFound);
                }
                records.insert(key, record);
            }
            DbOperation::Delete { table, id } => {
                records.remove(&(table, id));
            }
            DbOperation::InsertRecord { table, record } => {
                let id = record_id(&record)?;
                let key = (table, id);
                if records.contains_key(&key) {
                    return Err(AuthError::Adapter("record already exists".into()));
                }
                records.insert(key, record);
            }
            DbOperation::UpdateWhere {
                table,
                query,
                changes,
            } => {
                let Value::Object(changes) = changes else {
                    return Err(AuthError::Adapter(
                        "database changes must be a JSON object".into(),
                    ));
                };
                let keys = records
                    .iter()
                    .filter(|((record_table, id), record)| {
                        record_table == &table && matches_query(id, record, &query)
                    })
                    .map(|(key, _)| key.clone())
                    .collect::<Vec<_>>();
                for key in keys {
                    let record = records
                        .get_mut(&key)
                        .ok_or_else(|| AuthError::Adapter("memory row disappeared".into()))?;
                    let Value::Object(object) = record else {
                        return Err(AuthError::Adapter("stored record is not an object".into()));
                    };
                    object.extend(changes.clone());
                }
            }
            DbOperation::DeleteWhere { table, query } => {
                let keys = records
                    .iter()
                    .filter(|((record_table, id), record)| {
                        record_table == &table && matches_query(id, record, &query)
                    })
                    .map(|(key, _)| key.clone())
                    .collect::<Vec<_>>();
                for key in keys {
                    records.remove(&key);
                }
            }
        }
        Ok(())
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
            let mut values = self
                .values
                .lock()
                .map_err(|_| AuthError::Adapter("memory storage lock poisoned".into()))?;
            let Some((value, expires_at)) = values.remove(key) else {
                return Ok(None);
            };
            if expires_at.is_some_and(|expires_at| expires_at <= Instant::now()) {
                return Ok(None);
            }
            Ok(Some(StorageValue {
                value,
                expires_in: expires_at.map(|at| at.saturating_duration_since(Instant::now())),
            }))
        }
    }
}
