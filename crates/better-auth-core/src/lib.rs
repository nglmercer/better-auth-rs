//! Shared contracts for the Rust Better Auth implementation.
//!
//! The crate deliberately contains no web-framework integration. Adapters and
//! plugins can depend on these types without pulling in Axum, Actix, or a
//! particular database client.

pub mod adapter;
pub mod error;
pub mod migration;
pub mod options;
pub mod plugin;
pub mod schema;

pub use adapter::{DbAdapter, DbOperation, SecondaryStorage, StorageValue};
pub use error::{AuthError, Result};
pub use migration::{MigrationExecutor, MigrationPlan, MigrationStep, SqlDialect};
pub use options::{AuthOptions, BaseUrl, CookieCacheStrategy, SessionOptions};
pub use plugin::{Endpoint, Hook, Plugin, PluginRegistry};
pub use schema::{SchemaExtension, TableSchema};
