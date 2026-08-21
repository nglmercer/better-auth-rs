mod common;
#[cfg(feature = "libsql")]
mod libsql;
#[cfg(feature = "sqlite")]
mod sqlite;
#[cfg(feature = "sqlx")]
mod sqlx;

#[cfg(feature = "libsql")]
pub use libsql::{LibSqlConfig, LibSqlDbAdapter, LibSqlSecondaryStorage, RemoteReplica};
#[cfg(feature = "sqlite")]
pub use sqlite::{SqliteDbAdapter, SqliteSecondaryStorage};
#[cfg(feature = "sqlx")]
pub use sqlx::{
    MySqlDbAdapter, MySqlSecondaryStorage, PostgresDbAdapter, PostgresSecondaryStorage,
    SqlxBackend, SqlxDbAdapter, SqlxSecondaryStorage,
};

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::adapter::{DbAdapter, DbOperation, OrderBy, Query, SecondaryStorage};
    use better_auth_core::migration::{MigrationExecutor, MigrationPlan, SqlDialect};
    use serde_json::Value;
    use std::{sync::Arc, time::Duration};

    async fn adapter_conformance(adapter: &dyn DbAdapter) {
        let prefix = format!("conformance-{}", uuid::Uuid::new_v4());
        let first_id = format!("{prefix}-one");
        let second_id = format!("{prefix}-two");
        for (id, email) in [
            (&first_id, format!("{prefix}-one@example.com")),
            (&second_id, format!("{prefix}-two@example.com")),
        ] {
            adapter
                .insert_record(
                    "user",
                    serde_json::json!({
                        "id": id,
                        "email": email,
                        "name": id,
                        "email_verified": false,
                        "additional_fields": {}
                    }),
                )
                .await
                .unwrap();
        }
        let rows = adapter
            .find_many(
                "user",
                Query::new()
                    .is_in(
                        "id",
                        serde_json::json!([first_id.clone(), second_id.clone()]),
                    )
                    .order_by(OrderBy::descending("email"))
                    .limit(1),
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], second_id);

        assert_eq!(
            adapter
                .update_where(
                    "user",
                    Query::new().eq("id", first_id.clone()),
                    serde_json::json!({"name": "Updated"}),
                )
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            adapter
                .find_one("user", Query::new().eq("id", first_id.clone()))
                .await
                .unwrap()
                .unwrap()["name"],
            "Updated"
        );

        let rollback_id = format!("{prefix}-rollback");
        assert!(adapter
            .transaction(vec![
                DbOperation::InsertRecord {
                    table: "user".into(),
                    record: serde_json::json!({
                        "id": rollback_id,
                        "email": format!("{prefix}-rollback@example.com"),
                        "name": "Rollback",
                        "email_verified": false,
                        "additional_fields": {}
                    }),
                },
                DbOperation::InsertRecord {
                    table: "user".into(),
                    record: serde_json::json!({
                        "id": format!("{prefix}-duplicate"),
                        "email": format!("{prefix}-one@example.com"),
                        "name": "Duplicate",
                        "email_verified": false,
                        "additional_fields": {}
                    }),
                },
            ])
            .await
            .is_err());
        assert!(adapter
            .find_one("user", Query::new().eq("id", format!("{prefix}-rollback")),)
            .await
            .unwrap()
            .is_none());

        assert_eq!(
            adapter
                .delete_where("user", Query::new().eq("id", first_id))
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            adapter
                .delete_where("user", Query::new().eq("id", second_id))
                .await
                .unwrap(),
            1
        );
    }

    async fn secondary_storage_conformance(storage: Arc<dyn SecondaryStorage>) {
        let counter_key = format!("conformance-counter-{}", uuid::Uuid::new_v4());
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let storage = Arc::clone(&storage);
            let key = counter_key.clone();
            tasks.push(tokio::spawn(async move {
                storage.increment(&key, 1, Duration::from_secs(60)).await
            }));
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(
            storage.get(&counter_key).await.unwrap().unwrap().value,
            Value::from(16)
        );
        assert!(storage
            .get_and_delete(&counter_key)
            .await
            .unwrap()
            .is_some());
        assert!(storage
            .get_and_delete(&counter_key)
            .await
            .unwrap()
            .is_none());

        let expiring_key = format!("conformance-expiry-{}", uuid::Uuid::new_v4());
        storage
            .set(
                &expiring_key,
                better_auth_core::StorageValue::with_ttl(
                    Value::String("temporary".into()),
                    Duration::from_millis(1),
                ),
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(storage.get(&expiring_key).await.unwrap().is_none());
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_db_transactions_are_atomic() {
        let adapter = SqliteDbAdapter::in_memory().unwrap();
        adapter
            .apply_migrations(&MigrationPlan::from_schema(
                &better_auth_core::schema::core_schema(),
            ))
            .await
            .unwrap();
        let result = adapter
            .transaction(vec![
                DbOperation::InsertRecord {
                    table: "user".into(),
                    record: serde_json::json!({
                        "id":"one",
                        "email":"one@example.com",
                        "name":"One",
                        "email_verified":false,
                        "additional_fields": {}
                    }),
                },
                DbOperation::InsertRecord {
                    table: "user".into(),
                    record: serde_json::json!({
                        "id":"one",
                        "email":"duplicate@example.com",
                        "name":"Duplicate",
                        "email_verified":false,
                        "additional_fields": {}
                    }),
                },
            ])
            .await;
        assert!(result.is_err());
        assert!(adapter
            .find_one("user", Query::new().eq("id", "one"))
            .await
            .unwrap()
            .is_none());
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_connection_does_not_apply_schema_implicitly() {
        let adapter = SqliteDbAdapter::in_memory().unwrap();
        assert!(adapter.find_many("user", Query::new()).await.is_err());
        adapter
            .apply_migrations(&MigrationPlan::from_schema(
                &better_auth_core::schema::core_schema(),
            ))
            .await
            .unwrap();
        assert!(adapter
            .find_many("user", Query::new())
            .await
            .unwrap()
            .is_empty());
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_secondary_storage_supports_increment_and_one_time_reads() {
        let storage = SqliteSecondaryStorage::in_memory().unwrap();
        storage.migrate().unwrap();
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

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_migration_runner_applies_schema_sql() {
        let adapter = SqliteDbAdapter::in_memory().unwrap();
        let plan = MigrationPlan::from_schema(&better_auth_core::schema::core_schema());
        adapter.apply_migrations(&plan).await.unwrap();
        adapter.apply_migrations(&plan).await.unwrap();
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_schema_diff_adds_missing_columns_idempotently() {
        let path =
            std::env::temp_dir().join(format!("better-auth-migration-{}.db", uuid::Uuid::new_v4()));
        let mut previous = better_auth_core::schema::core_schema();
        previous
            .tables
            .get_mut("user")
            .unwrap()
            .fields
            .remove("additional_fields");
        let adapter = SqliteDbAdapter::open(&path).unwrap();
        adapter
            .apply_migrations(&MigrationPlan::from_schema(
                &better_auth_core::schema::core_schema(),
            ))
            .await
            .unwrap();
        adapter
            .execute("ALTER TABLE \"user\" DROP COLUMN \"additional_fields\";")
            .await
            .unwrap();
        drop(adapter);
        let adapter = SqliteDbAdapter::open(&path).unwrap();
        let desired = better_auth_core::schema::core_schema();
        let plan = MigrationPlan::diff(&previous, &desired).unwrap();
        adapter.apply_migrations(&plan).await.unwrap();
        adapter.apply_migrations(&plan).await.unwrap();
        adapter
            .insert_record(
                "user",
                serde_json::json!({
                    "id": "migrated",
                    "email": "migrated@example.com",
                    "name": "Migrated",
                    "email_verified": false,
                    "additional_fields": {"country": "PE"}
                }),
            )
            .await
            .unwrap();
        assert_eq!(
            adapter
                .find_one("user", Query::new().eq("id", "migrated"))
                .await
                .unwrap()
                .unwrap()["additional_fields"]["country"],
            "PE"
        );
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_queries_are_executed_by_the_database() {
        let adapter = SqliteDbAdapter::in_memory().unwrap();
        adapter
            .apply_migrations(&MigrationPlan::from_schema(
                &better_auth_core::schema::core_schema(),
            ))
            .await
            .unwrap();
        adapter_conformance(&adapter).await;
        for (id, email) in [
            ("query-one", "one@example.com"),
            ("query-two", "two@example.com"),
        ] {
            adapter
                .insert_record(
                    "user",
                    serde_json::json!({
                        "id": id,
                        "email": email,
                        "name": id,
                        "email_verified": false,
                        "additional_fields": {}
                    }),
                )
                .await
                .unwrap();
        }
        let rows = adapter
            .find_many(
                "user",
                Query::new()
                    .is_in(
                        "email",
                        serde_json::json!(["one@example.com", "two@example.com"]),
                    )
                    .order_by(OrderBy::descending("email"))
                    .limit(1),
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["email"], "two@example.com");
    }

    #[cfg(feature = "libsql")]
    #[tokio::test]
    async fn libsql_local_adapter_uses_relational_tables_and_atomic_kv() {
        let adapter = LibSqlDbAdapter::local(":memory:").await.unwrap();
        adapter
            .apply_migrations(&MigrationPlan::from_schema(
                &better_auth_core::schema::core_schema(),
            ))
            .await
            .unwrap();
        adapter_conformance(&adapter).await;
        adapter
            .insert_record(
                "user",
                serde_json::json!({
                    "id":"libsql-user",
                    "email":"libsql@example.com",
                    "name":"LibSQL",
                    "email_verified":false
                }),
            )
            .await
            .unwrap();
        let user = adapter
            .find_one("user", Query::new().eq("email", "libsql@example.com"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user["id"], "libsql-user");
        assert_eq!(
            adapter
                .update_where(
                    "user",
                    Query::new().eq("id", "libsql-user"),
                    serde_json::json!({"name":"Updated"})
                )
                .await
                .unwrap(),
            1
        );

        let storage = adapter.secondary_storage();
        storage.migrate().await.unwrap();
        secondary_storage_conformance(Arc::new(storage)).await;
    }

    #[cfg(feature = "libsql")]
    #[tokio::test]
    async fn libsql_remote_conformance_when_configured() {
        let (Ok(url), Ok(token)) = (
            std::env::var("BETTER_AUTH_TEST_LIBSQL_URL"),
            std::env::var("BETTER_AUTH_TEST_LIBSQL_TOKEN"),
        ) else {
            return;
        };
        let adapter = LibSqlDbAdapter::remote(&url, secrecy::SecretString::from(token))
            .await
            .unwrap();
        adapter
            .apply_migrations(&MigrationPlan::from_schema(
                &better_auth_core::schema::core_schema(),
            ))
            .await
            .unwrap();
        adapter_conformance(&adapter).await;
        let storage = adapter.secondary_storage();
        storage.migrate().await.unwrap();
        secondary_storage_conformance(Arc::new(storage)).await;
    }

    #[cfg(feature = "sqlx")]
    #[tokio::test]
    async fn sqlx_postgres_conformance_when_configured() {
        let Ok(url) = std::env::var("BETTER_AUTH_TEST_POSTGRES_URL") else {
            return;
        };
        let adapter = SqlxDbAdapter::postgres(&url).await.unwrap();
        adapter
            .apply_migrations(
                &MigrationPlan::from_schema(&better_auth_core::schema::core_schema()),
                SqlDialect::Postgres,
            )
            .await
            .unwrap();
        adapter_conformance(&adapter).await;
        let storage = SqlxSecondaryStorage::postgres(&url).await.unwrap();
        storage.migrate().await.unwrap();
        secondary_storage_conformance(Arc::new(storage)).await;
    }

    #[cfg(feature = "sqlx")]
    #[tokio::test]
    async fn sqlx_mysql_conformance_when_configured() {
        let Ok(url) = std::env::var("BETTER_AUTH_TEST_MYSQL_URL") else {
            return;
        };
        let adapter = SqlxDbAdapter::mysql(&url).await.unwrap();
        adapter
            .apply_migrations(
                &MigrationPlan::from_schema(&better_auth_core::schema::core_schema()),
                SqlDialect::MySql,
            )
            .await
            .unwrap();
        adapter_conformance(&adapter).await;
        let storage = SqlxSecondaryStorage::mysql(&url).await.unwrap();
        storage.migrate().await.unwrap();
        secondary_storage_conformance(Arc::new(storage)).await;
    }
}
