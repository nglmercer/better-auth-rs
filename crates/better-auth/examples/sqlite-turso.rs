//! Email/password auth on SQLite or Turso, end to end, with no web server.
//!
//! The same flow runs on three backends. Only `open_backend` differs:
//!
//! ```sh
//! # SQLite file through rusqlite (the default `sqlite` feature)
//! cargo run -p better-auth --example sqlite-turso
//!
//! # libSQL file (Turso's SQLite fork, embedded)
//! AUTH_BACKEND=libsql cargo run -p better-auth --example sqlite-turso --features libsql
//!
//! # Remote Turso database
//! TURSO_DATABASE_URL=libsql://<db>-<org>.turso.io TURSO_AUTH_TOKEN=<token> \
//!   cargo run -p better-auth --example sqlite-turso --features libsql
//! ```
//!
//! `AUTH_DB_PATH` overrides the file used by the two local backends.

use better_auth::{
    core::{
        adapter::{DbAdapter, SecondaryStorage},
        migration::MigrationPlan,
        options::{AuthOptions, BaseUrl, PasswordHashOptions},
    },
    AuthContext, EmailPasswordService, RateLimitPolicy, RateLimiter, SessionTransport, SignInInput,
    SignUpInput, SqliteDbAdapter, SqliteSecondaryStorage,
};
use http::HeaderMap;
use std::{path::PathBuf, sync::Arc, time::Duration};

type AnyError = Box<dyn std::error::Error>;

/// What the rest of the example needs from a backend. The auth services only
/// ever see the two trait objects; migration and cleanup are adapter-specific.
struct Backend {
    name: &'static str,
    database: Arc<dyn DbAdapter>,
    storage: Arc<dyn SecondaryStorage>,
    kind: Kind,
}

enum Kind {
    Sqlite {
        database: Arc<SqliteDbAdapter>,
        storage: Arc<SqliteSecondaryStorage>,
    },
    #[cfg(feature = "libsql")]
    LibSql {
        database: Arc<better_auth::LibSqlDbAdapter>,
        storage: Arc<better_auth::LibSqlSecondaryStorage>,
    },
}

impl Backend {
    /// Connecting never changes a database. Creating tables and indexes is an
    /// explicit step that an application runs at deployment time.
    async fn migrate(&self, plan: &MigrationPlan) -> Result<(), AnyError> {
        match &self.kind {
            Kind::Sqlite { database, storage } => {
                database.apply_migrations(plan).await?;
                storage.migrate()?;
            }
            #[cfg(feature = "libsql")]
            Kind::LibSql { database, storage } => {
                database.apply_migrations(plan).await?;
                storage.migrate().await?;
            }
        }
        Ok(())
    }

    /// Expired rate-limit counters and tokens are only removed when their key
    /// is read again. A service should run this on a timer.
    async fn purge_expired(&self) -> Result<u64, AnyError> {
        Ok(match &self.kind {
            Kind::Sqlite { storage, .. } => storage.purge_expired()?,
            #[cfg(feature = "libsql")]
            Kind::LibSql { storage, .. } => storage.purge_expired().await?,
        })
    }
}

fn database_path() -> PathBuf {
    std::env::var_os("AUTH_DB_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("better-auth-example.db"))
}

fn open_sqlite() -> Result<Backend, AnyError> {
    let path = database_path();
    println!("database file: {}", path.display());
    // The adapter and the secondary storage each hold their own connection to
    // the same file. Write-ahead logging lets one read while the other writes
    // and makes commits much cheaper; it is stored in the file, so it is an
    // explicit call.
    let database = Arc::new(SqliteDbAdapter::open(&path)?);
    database.enable_wal()?;
    let storage = Arc::new(SqliteSecondaryStorage::open(&path)?);
    storage.enable_wal()?;
    Ok(Backend {
        name: "SQLite (rusqlite)",
        database: database.clone(),
        storage: storage.clone(),
        kind: Kind::Sqlite { database, storage },
    })
}

#[cfg(feature = "libsql")]
async fn open_libsql() -> Result<Backend, AnyError> {
    use better_auth::LibSqlDbAdapter;

    let (name, database) = match (
        std::env::var("TURSO_DATABASE_URL"),
        std::env::var("TURSO_AUTH_TOKEN"),
    ) {
        (Ok(url), Ok(token)) => (
            "Turso (remote libSQL)",
            LibSqlDbAdapter::remote(url, token).await?,
        ),
        _ => {
            let path = database_path();
            println!("database file: {}", path.display());
            ("libSQL (local file)", LibSqlDbAdapter::local(path).await?)
        }
    };
    let database = Arc::new(database);
    // Shares the adapter's connection, so one Turso connection serves both.
    let storage = Arc::new(database.secondary_storage());
    Ok(Backend {
        name,
        database: database.clone(),
        storage: storage.clone(),
        kind: Kind::LibSql { database, storage },
    })
}

async fn open_backend() -> Result<Backend, AnyError> {
    let wants_libsql = std::env::var("AUTH_BACKEND").is_ok_and(|value| value == "libsql")
        || std::env::var_os("TURSO_DATABASE_URL").is_some();
    if !wants_libsql {
        return open_sqlite();
    }
    #[cfg(feature = "libsql")]
    {
        open_libsql().await
    }
    #[cfg(not(feature = "libsql"))]
    {
        Err("the libSQL and Turso backends need `--features libsql`".into())
    }
}

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    let backend = open_backend().await?;
    println!("backend: {}", backend.name);

    let context = AuthContext::builder(AuthOptions {
        // Read the secret from the environment in a real deployment.
        secret: "sqlite-turso-example-secret-0123456789".into(),
        base_url: Some(BaseUrl::Static("https://example.com".into())),
        // Keep the demo quick. Production should keep the default cost.
        password_hash: PasswordHashOptions {
            scrypt_log_n: 13,
            ..PasswordHashOptions::default()
        },
        ..AuthOptions::default()
    })
    .database(backend.database.clone())
    .secondary_storage(Some(backend.storage.clone()))
    .build()?;

    // Idempotent: safe to run on every deployment.
    backend.migrate(&context.migration_plan()).await?;

    let auth = EmailPasswordService::new(context)?;
    // A fresh address per run, so the example can be run repeatedly against
    // the same database.
    let email = format!("ada-{}@example.com", uuid_like());
    let password = "correct horse battery staple";

    let signed_up = auth
        .sign_up(
            SignUpInput {
                email: email.clone(),
                name: "Ada".into(),
                password: password.into(),
            },
            true,
        )
        .await?;
    println!(
        "signed up:  {} ({})",
        signed_up.user.email, signed_up.user.id
    );

    let signed_in = auth
        .sign_in(
            SignInInput {
                email: email.clone(),
                password: password.into(),
            },
            true,
        )
        .await?;
    println!("signed in:  session {}", signed_in.session.id);

    // Resolve the session the way a native client would present it.
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        format!("Bearer {}", signed_in.session_token).parse()?,
    );
    let principal = auth
        .sessions()
        .resolve_with_transport(&headers, true, SessionTransport::Bearer)
        .await?
        .ok_or("the new session did not resolve")?;
    println!("resolved:   {}", principal.user.email);

    let wrong = auth
        .sign_in(
            SignInInput {
                email: email.clone(),
                password: "not the password".into(),
            },
            true,
        )
        .await;
    println!("wrong password rejected: {}", wrong.is_err());

    // Rate limiting counts in the secondary storage, atomically.
    let limiter = RateLimiter::new(backend.storage.clone(), "example");
    let policy = RateLimitPolicy::new("sign-in", 3, Duration::from_secs(60))?;
    for attempt in 1..=4 {
        let decision = limiter.check(&policy, &email).await?;
        println!(
            "rate limit: attempt {attempt} allowed={} remaining={}",
            decision.allowed, decision.remaining
        );
    }

    let revoked = auth
        .sessions()
        .revoke_all_for_user(&principal.user.id)
        .await?;
    println!("revoked {revoked} session(s)");
    println!("purged {} expired key(s)", backend.purge_expired().await?);
    Ok(())
}

/// A short unique suffix without pulling a dependency into the example.
fn uuid_like() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    format!("{nanos:x}")
}
