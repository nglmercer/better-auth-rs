//! Backward-compatibility fixtures.
//!
//! Each fixture was produced by an earlier build and is checked in. A change
//! that breaks one of these would strand data that users already store: password
//! hashes, signed envelopes and database schemas. Fixtures change only through
//! the `regenerate_goldens` test, and that change must be called out in CHANGELOG.md.

use better_auth::{cookies::SecretKeySet, password::verify_password};
use better_auth_core::{
    migration::{MigrationPlan, SqlDialect},
    options::AuthOptions,
    schema::core_schema,
};
use std::{fs, path::PathBuf};

const COMPAT_SECRET: &str = "compat-secret-0123456789abcdefghij";
const COMPAT_PASSWORD: &str = "correct horse battery staple";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/compat")
        .join(name)
}

fn dialects() -> [(&'static str, SqlDialect); 3] {
    [
        ("sqlite", SqlDialect::Sqlite),
        ("postgres", SqlDialect::Postgres),
        ("mysql", SqlDialect::MySql),
    ]
}

fn schema_sql(dialect: SqlDialect) -> String {
    MigrationPlan::from_schema(&core_schema())
        .sql(dialect)
        .join("\n")
        + "\n"
}

fn signed_envelope() -> String {
    let options = AuthOptions {
        secret: COMPAT_SECRET.into(),
        ..AuthOptions::default()
    };
    let keys = SecretKeySet::from_options(&options).unwrap();
    keys.sign("compat-payload").unwrap()
}

#[test]
fn stored_password_hash_still_verifies() {
    let stored = fs::read_to_string(fixture("password.hash")).unwrap();
    assert!(verify_password(COMPAT_PASSWORD, stored.trim()).unwrap());
    assert!(!verify_password("wrong password value", stored.trim()).unwrap());
}

#[test]
fn signed_envelope_format_is_unchanged() {
    let stored = fs::read_to_string(fixture("envelope.txt")).unwrap();
    assert_eq!(signed_envelope(), stored.trim());
    let options = AuthOptions {
        secret: COMPAT_SECRET.into(),
        ..AuthOptions::default()
    };
    let keys = SecretKeySet::from_options(&options).unwrap();
    assert_eq!(keys.verify(stored.trim()).unwrap(), "compat-payload");
}

#[test]
fn core_schema_sql_is_unchanged_for_every_dialect() {
    for (name, dialect) in dialects() {
        let stored = fs::read_to_string(fixture(&format!("core_schema.{name}.sql"))).unwrap();
        assert_eq!(schema_sql(dialect), stored, "schema drift for {name}");
    }
}

/// Rewrites every fixture. Run it only when a breaking change is intended:
/// `cargo test -p better-auth --test compat -- --ignored regenerate_goldens`
#[test]
#[ignore]
fn regenerate_goldens() {
    let hash = better_auth::password::hash_password(COMPAT_PASSWORD).unwrap();
    fs::write(fixture("password.hash"), format!("{hash}\n")).unwrap();
    fs::write(fixture("envelope.txt"), format!("{}\n", signed_envelope())).unwrap();
    for (name, dialect) in dialects() {
        fs::write(
            fixture(&format!("core_schema.{name}.sql")),
            schema_sql(dialect),
        )
        .unwrap();
    }
}
