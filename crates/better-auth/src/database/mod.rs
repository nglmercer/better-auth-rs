mod common;
mod sqlite;
#[cfg(feature = "sqlx")]
mod sqlx;

pub use sqlite::{SqliteDbAdapter, SqliteSecondaryStorage};
#[cfg(feature = "sqlx")]
pub use sqlx::{
    MySqlDbAdapter, MySqlSecondaryStorage, PostgresDbAdapter, PostgresSecondaryStorage,
    SqlxBackend, SqlxDbAdapter, SqlxSecondaryStorage,
};

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

    #[cfg(feature = "sqlx")]
    #[tokio::test]
    async fn sqlx_postgres_conformance_when_configured() {
        let Ok(url) = std::env::var("BETTER_AUTH_TEST_POSTGRES_URL") else {
            return;
        };
        let adapter = SqlxDbAdapter::postgres(&url).await.unwrap();
        let id = format!("conformance-{}", uuid::Uuid::new_v4());
        adapter
            .insert(
                "user",
                &id,
                serde_json::json!({"id": id.clone(), "email": "pg@example.com"}),
            )
            .await
            .unwrap();
        assert_eq!(
            adapter
                .get_by_field("user", "email", &serde_json::json!("pg@example.com"))
                .await
                .unwrap()
                .unwrap()
                .0,
            id
        );
        adapter
            .update(
                "user",
                &id,
                serde_json::json!({"id": id.clone(), "email": "updated@example.com"}),
            )
            .await
            .unwrap();
        adapter.delete("user", &id).await.unwrap();
        let storage = SqlxSecondaryStorage::postgres(&url).await.unwrap();
        assert_eq!(
            storage
                .increment("conformance-counter", 1, Duration::from_secs(60))
                .await
                .unwrap(),
            1
        );
    }

    #[cfg(feature = "sqlx")]
    #[tokio::test]
    async fn sqlx_mysql_conformance_when_configured() {
        let Ok(url) = std::env::var("BETTER_AUTH_TEST_MYSQL_URL") else {
            return;
        };
        let adapter = SqlxDbAdapter::mysql(&url).await.unwrap();
        let id = format!("conformance-{}", uuid::Uuid::new_v4());
        adapter
            .insert(
                "user",
                &id,
                serde_json::json!({"id": id.clone(), "email": "mysql@example.com"}),
            )
            .await
            .unwrap();
        assert!(adapter.get("user", &id).await.unwrap().is_some());
        adapter.delete("user", &id).await.unwrap();
    }
}


