//! SQL generation and value conversion shared by the SQLite-dialect adapters
//! (`rusqlite` and libSQL). Each adapter only maps [`SqlParam`] to and from its
//! driver's own value type and runs the statement.

use super::common::json_error;
use better_auth_core::{
    adapter::{DbOperation, FilterOp, OrderDirection, Query, StorageValue},
    error::{AuthError, Result},
    schema::{FieldType, SchemaExtension},
};
use serde_json::{Map, Number, Value};
use std::{fmt::Write as _, time::Duration};

pub(super) const KV_DDL: &str = "CREATE TABLE IF NOT EXISTS _better_auth_kv (storage_key TEXT PRIMARY KEY, value_json TEXT NOT NULL, expires_at INTEGER)";
pub(super) const KV_GET: &str =
    "SELECT value_json, expires_at FROM _better_auth_kv WHERE storage_key = ?1";
pub(super) const KV_SET: &str = "INSERT INTO _better_auth_kv(storage_key, value_json, expires_at) VALUES (?1, ?2, ?3) ON CONFLICT(storage_key) DO UPDATE SET value_json = excluded.value_json, expires_at = excluded.expires_at";
pub(super) const KV_DELETE: &str = "DELETE FROM _better_auth_kv WHERE storage_key = ?1";
/// Deletes every row whose expiry is at or before `?1` (Unix seconds).
pub(super) const KV_PURGE: &str =
    "DELETE FROM _better_auth_kv WHERE expires_at IS NOT NULL AND expires_at <= ?1";

/// A driver-neutral SQLite value.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum SqlParam {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

/// SQL text with `?N` placeholders and the values bound to them, in order.
#[derive(Debug)]
pub(super) struct Sql {
    pub text: String,
    pub params: Vec<SqlParam>,
}

pub(super) fn record_object(record: &Value) -> Result<&Map<String, Value>> {
    record
        .as_object()
        .ok_or_else(|| AuthError::Adapter("database records must be JSON objects".into()))
}

pub(super) fn field_type<'a>(
    schema: &'a SchemaExtension,
    table: &str,
    field: &str,
) -> Option<&'a FieldType> {
    schema
        .tables
        .get(table)
        .and_then(|table| table.fields.get(field))
        .map(|field| &field.field_type)
}

/// Appends a double-quoted identifier. Only `[A-Za-z0-9_]+` is accepted, so the
/// name cannot terminate the quoting or carry SQL.
fn push_identifier(sql: &mut String, identifier: &str) -> Result<()> {
    if identifier.is_empty()
        || !identifier
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        return Err(AuthError::Adapter(format!(
            "invalid SQL identifier: {identifier}"
        )));
    }
    sql.push('"');
    sql.push_str(identifier);
    sql.push('"');
    Ok(())
}

pub(super) fn quote_identifier(identifier: &str) -> Result<String> {
    let mut quoted = String::with_capacity(identifier.len() + 2);
    push_identifier(&mut quoted, identifier)?;
    Ok(quoted)
}

/// Binds `value` and appends its placeholder.
fn push_param(sql: &mut String, params: &mut Vec<SqlParam>, value: SqlParam) {
    params.push(value);
    let _ = write!(sql, "?{}", params.len());
}

fn push_where(sql: &mut String, params: &mut Vec<SqlParam>, query: &Query) -> Result<()> {
    for (index, filter) in query.filters.iter().enumerate() {
        sql.push_str(if index == 0 { " WHERE " } else { " AND " });
        if filter.op == FilterOp::In {
            let Some(items) = filter.value.as_array() else {
                return Err(AuthError::Adapter(format!(
                    "IN filter for {} must contain an array",
                    filter.field
                )));
            };
            // Validate the name even when the list is empty.
            if items.is_empty() {
                quote_identifier(&filter.field)?;
                sql.push_str("1 = 0");
                continue;
            }
            push_identifier(sql, &filter.field)?;
            sql.push_str(" IN (");
            for (position, item) in items.iter().enumerate() {
                if position > 0 {
                    sql.push_str(", ");
                }
                push_param(sql, params, json_to_param(item, None)?);
            }
            sql.push(')');
            continue;
        }
        push_identifier(sql, &filter.field)?;
        sql.push_str(match filter.op {
            FilterOp::Eq => " = ",
            FilterOp::Ne => " <> ",
            FilterOp::Lt => " < ",
            FilterOp::Lte => " <= ",
            FilterOp::Gt => " > ",
            FilterOp::Gte => " >= ",
            FilterOp::In => unreachable!("handled above"),
        });
        push_param(sql, params, json_to_param(&filter.value, None)?);
    }
    Ok(())
}

pub(super) fn select(table: &str, query: &Query) -> Result<Sql> {
    let mut text = String::from("SELECT * FROM ");
    let mut params = Vec::with_capacity(query.filters.len() + 2);
    push_identifier(&mut text, table)?;
    push_where(&mut text, &mut params, query)?;
    text.push_str(" ORDER BY ");
    if query.order_by.is_empty() {
        text.push_str("\"id\" ASC");
    }
    for (index, order) in query.order_by.iter().enumerate() {
        if index > 0 {
            text.push_str(", ");
        }
        push_identifier(&mut text, &order.field)?;
        text.push_str(match order.direction {
            OrderDirection::Asc => " ASC",
            OrderDirection::Desc => " DESC",
        });
    }
    if let Some(limit) = query.limit {
        text.push_str(" LIMIT ");
        push_param(&mut text, &mut params, SqlParam::Integer(i64::from(limit)));
    } else if query.offset.is_some() {
        text.push_str(" LIMIT -1");
    }
    if let Some(offset) = query.offset {
        text.push_str(" OFFSET ");
        push_param(&mut text, &mut params, SqlParam::Integer(i64::from(offset)));
    }
    Ok(Sql { text, params })
}

pub(super) fn insert(
    table: &str,
    record: &Map<String, Value>,
    schema: &SchemaExtension,
) -> Result<Sql> {
    let mut text = String::from("INSERT INTO ");
    let mut params = Vec::with_capacity(record.len());
    push_identifier(&mut text, table)?;
    if record.is_empty() {
        return Err(AuthError::Adapter("cannot insert an empty record".into()));
    }
    text.push_str(" (");
    let mut placeholders = String::new();
    for (index, (field, value)) in record.iter().enumerate() {
        if index > 0 {
            text.push_str(", ");
            placeholders.push_str(", ");
        }
        push_identifier(&mut text, field)?;
        push_param(
            &mut placeholders,
            &mut params,
            json_to_param(value, field_type(schema, table, field))?,
        );
    }
    text.push_str(") VALUES (");
    text.push_str(&placeholders);
    text.push(')');
    Ok(Sql { text, params })
}

/// `changes` must not be empty; callers treat an empty change set as a no-op.
pub(super) fn update(
    table: &str,
    query: &Query,
    changes: &Map<String, Value>,
    schema: &SchemaExtension,
) -> Result<Sql> {
    let mut text = String::from("UPDATE ");
    let mut params = Vec::with_capacity(changes.len() + query.filters.len());
    push_identifier(&mut text, table)?;
    text.push_str(" SET ");
    for (index, (field, value)) in changes.iter().enumerate() {
        if index > 0 {
            text.push_str(", ");
        }
        push_identifier(&mut text, field)?;
        text.push_str(" = ");
        push_param(
            &mut text,
            &mut params,
            json_to_param(value, field_type(schema, table, field))?,
        );
    }
    push_where(&mut text, &mut params, query)?;
    Ok(Sql { text, params })
}

pub(super) fn delete(table: &str, query: &Query) -> Result<Sql> {
    let mut text = String::from("DELETE FROM ");
    let mut params = Vec::with_capacity(query.filters.len());
    push_identifier(&mut text, table)?;
    push_where(&mut text, &mut params, query)?;
    Ok(Sql { text, params })
}

/// One statement of a transaction.
pub(super) struct OperationSql {
    /// `None` when the operation has nothing to execute (an empty change set).
    pub sql: Option<Sql>,
    /// The operation fails with `NotFound` when it changes no row.
    pub require_change: bool,
}

pub(super) fn operation(operation: DbOperation, schema: &SchemaExtension) -> Result<OperationSql> {
    let (sql, require_change) = match operation {
        DbOperation::Insert { table, id, record } => {
            let Value::Object(mut object) = record else {
                return Err(AuthError::Adapter(
                    "database records must be JSON objects".into(),
                ));
            };
            object.insert("id".into(), Value::String(id));
            (Some(insert(&table, &object, schema)?), false)
        }
        DbOperation::InsertRecord { table, record } => (
            Some(insert(&table, record_object(&record)?, schema)?),
            false,
        ),
        DbOperation::Update { table, id, record } => {
            let changes = record_object(&record)?;
            if changes.is_empty() {
                // Nothing to write, but the row must still exist. An `id = id`
                // assignment keeps the "changed rows" check meaningful.
                let mut no_op = Map::new();
                no_op.insert("id".into(), Value::String(id.clone()));
                (
                    Some(update(&table, &Query::new().eq("id", id), &no_op, schema)?),
                    true,
                )
            } else {
                (
                    Some(update(&table, &Query::new().eq("id", id), changes, schema)?),
                    true,
                )
            }
        }
        DbOperation::UpdateWhere {
            table,
            query,
            changes,
        } => {
            let changes = record_object(&changes)?;
            if changes.is_empty() {
                (None, false)
            } else {
                (Some(update(&table, &query, changes, schema)?), false)
            }
        }
        DbOperation::Delete { table, id } => {
            (Some(delete(&table, &Query::new().eq("id", id))?), false)
        }
        DbOperation::DeleteWhere { table, query } => (Some(delete(&table, &query)?), false),
    };
    Ok(OperationSql {
        sql,
        require_change,
    })
}

pub(super) fn json_to_param(value: &Value, field_type: Option<&FieldType>) -> Result<SqlParam> {
    if value.is_null() {
        return Ok(SqlParam::Null);
    }
    match field_type {
        Some(FieldType::Boolean) => {
            Ok(SqlParam::Integer(i64::from(value.as_bool().ok_or_else(
                || AuthError::Adapter("expected a boolean value".into()),
            )?)))
        }
        Some(FieldType::Bytes) => Ok(SqlParam::Blob(
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
        _ => match value {
            Value::String(value) => Ok(SqlParam::Text(value.clone())),
            Value::Bool(value) => Ok(SqlParam::Integer(i64::from(*value))),
            Value::Number(value) => value
                .as_i64()
                .map(SqlParam::Integer)
                .or_else(|| value.as_f64().map(SqlParam::Real))
                .ok_or_else(|| AuthError::Adapter("unsupported JSON number".into())),
            Value::Array(_) | Value::Object(_) => Ok(SqlParam::Text(
                serde_json::to_string(value).map_err(json_error)?,
            )),
            Value::Null => Ok(SqlParam::Null),
        },
    }
}

pub(super) fn param_to_json(value: SqlParam, field_type: Option<&FieldType>) -> Result<Value> {
    Ok(match value {
        SqlParam::Null => Value::Null,
        SqlParam::Integer(value) if matches!(field_type, Some(FieldType::Boolean)) => {
            Value::Bool(value != 0)
        }
        SqlParam::Integer(value) => Value::Number(value.into()),
        SqlParam::Real(value) => Number::from_f64(value)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        SqlParam::Text(text) if matches!(field_type, Some(FieldType::Json)) => {
            serde_json::from_str(&text).map_err(json_error)?
        }
        SqlParam::Text(text) => Value::String(text),
        SqlParam::Blob(bytes) => Value::Array(bytes.into_iter().map(Value::from).collect()),
    })
}

/// Unix seconds at which a value with this TTL expires. Whole seconds only,
/// like the other adapters: a sub-second TTL is already expired.
pub(super) fn expiry(now: i64, ttl: Duration) -> i64 {
    now.saturating_add(i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX))
}

/// Decodes a stored KV row. Returns `None` when the row has expired.
pub(super) fn kv_value(
    raw: &str,
    expires_at: Option<i64>,
    now: i64,
) -> Result<Option<StorageValue>> {
    if expires_at.is_some_and(|expires_at| expires_at <= now) {
        return Ok(None);
    }
    Ok(Some(StorageValue {
        value: serde_json::from_str(raw).map_err(json_error)?,
        expires_in: expires_at
            .map(|expires_at| Duration::from_secs(u64::try_from(expires_at - now).unwrap_or(0))),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::{adapter::OrderBy, schema::core_schema};
    use serde_json::json;

    #[test]
    fn update_numbers_where_placeholders_after_assignments() {
        let schema = core_schema();
        let changes = json!({"name": "New", "email_verified": true});
        let sql = update(
            "user",
            &Query::new()
                .eq("id", "u1")
                .is_in("email", json!(["a@example.com", "b@example.com"])),
            changes.as_object().unwrap(),
            &schema,
        )
        .unwrap();
        assert_eq!(
            sql.text,
            "UPDATE \"user\" SET \"email_verified\" = ?1, \"name\" = ?2 WHERE \"id\" = ?3 AND \"email\" IN (?4, ?5)"
        );
        assert_eq!(sql.params.len(), 5);
        assert_eq!(sql.params[0], SqlParam::Integer(1));
    }

    #[test]
    fn select_applies_default_order_and_unbounded_offset() {
        let sql = select("user", &Query::new().offset(5)).unwrap();
        assert_eq!(
            sql.text,
            "SELECT * FROM \"user\" ORDER BY \"id\" ASC LIMIT -1 OFFSET ?1"
        );
        let sql = select(
            "user",
            &Query::new()
                .is_in("id", json!([]))
                .order_by(OrderBy::descending("email"))
                .limit(1),
        )
        .unwrap();
        assert_eq!(
            sql.text,
            "SELECT * FROM \"user\" WHERE 1 = 0 ORDER BY \"email\" DESC LIMIT ?1"
        );
    }

    #[test]
    fn identifiers_cannot_carry_sql() {
        assert!(select("user\"; DROP TABLE user; --", &Query::new()).is_err());
        assert!(select("user", &Query::new().eq("id\" OR 1=1 --", "x")).is_err());
        assert!(select("user", &Query::new().is_in("bad name", json!([]))).is_err());
        assert!(delete("", &Query::new()).is_err());
    }
}
