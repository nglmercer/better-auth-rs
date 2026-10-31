//! Shared contracts for the Rust Better Auth implementation.
//!
//! The crate deliberately contains no web-framework integration. Adapters and
//! plugins can depend on these types without pulling in Axum, Actix, or a
//! particular database client.

// `async-trait` 0.1.91+ adds `#[must_use]` to every async trait method. Those
// methods already return `Result`, so clippy's `double_must_use` reports each
// generated trait method. The attribute is macro-generated, not authored here.
#![allow(clippy::double_must_use)]

pub mod adapter;
pub mod error;
pub mod migration;
pub mod options;
pub mod plugin;
pub mod schema;

pub use adapter::{
    record_id, DbAdapter, DbOperation, Filter, FilterOp, OrderBy, OrderDirection, Query,
    SecondaryStorage, StorageValue,
};
pub use error::{AuthError, Result};
pub use migration::{MigrationExecutor, MigrationPlan, MigrationStep, SqlDialect};
pub use options::{
    AuthOptions, BaseUrl, CookieCacheOptions, CookieCacheStrategy, CookieOptions, CookieSameSite,
    PasswordHashOptions, SessionOptions,
};
pub use plugin::{
    Endpoint, EndpointHandler, EndpointRequest, EndpointResponse, ExecutableEndpoint, Hook, Plugin,
    PluginRegistry,
};
pub use schema::{FieldSchema, FieldType, SchemaExtension, TableSchema};
