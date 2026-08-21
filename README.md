# Better Auth for Rust

This repository is the initial Rust rewrite foundation described by the
attached architecture roadmap. It is framework-neutral: an Axum, Actix, or
other integration can translate its native requests into `RequestMetadata` and
use the same auth context and security behavior.

## Workspace layout

- `crates/better-auth-core` contains shared options, adapter traits, schema
  definitions, and the plugin registry.
- `crates/better-auth` contains the runtime `AuthContext`, per-request base URL
  resolution, cookies, secret rotation, scrypt password hashing, and CSRF/IP
  helpers.

## Current implementation

The workspace now covers all roadmap phases at a framework-neutral baseline:

- configuration validation and the no-durable-store cookie-cache defaults;
- static, request-derived, and allowed-host dynamic base URLs;
- relational and secondary-storage adapter contracts, including TTL and atomic
  increment semantics, database-side filtering, ordering, pagination, and
  transaction operations;
- core schema plus conflict-safe plugin schema merging;
- plugin endpoints, hooks, and error-code aggregation;
- versioned HMAC envelopes for direct secret-version lookup during rotation;
- scrypt password hashing;
- SameSite=Lax session-cookie construction;
- Origin, Fetch Metadata, trusted-proxy, and trusted-IP-header helpers.
- email/password sign-up and sign-in, persisted sessions, cookie lookup, and
  sign-out on top of the adapter contract.
- JWT/JWE cookie-cache codecs with key-version lookup and session refresh.
- purpose-bound email verification and password-reset tokens.
- rate-limit enforcement backed by atomic secondary-storage increments.
- OAuth authorization state, PKCE, generic HTTPS provider exchange, and
  Google/GitHub provider presets, configurable OIDC ID-token validation, and
  encrypted provider-token envelopes.
- TOTP and one-time backup codes, organization membership, passkey challenge
  replay protection, durable WebAuthn registration/assertion verification
  through webauthn-rs, admin role guards, OIDC/SAML SSO, concrete optional
  `saml-rs` validation, SCIM filtering/PATCH/groups/bulk operations and token
  hashing, and JWT issuance.
- framework-neutral HTTP endpoints, an optional Axum adapter, and a client
  request SDK with reqwest transport, cookie-jar support, and safe retries.
- a TypeScript client package at `packages/better-auth-client` with typed
  fetch-based sign-up/sign-in, sessions, sign-out, generic requests, cookie
  credentials, structured errors, and safe retries.
- a Kotlin Multiplatform client package at `packages/better-auth-kotlin` with
  typed Ktor requests, cookie sessions, structured errors, safe retries, and
  MockEngine tests.
- SQLite relational and secondary-storage adapters, optional SQLx
  Postgres/MySQL adapters with dialect-aware placeholders, and migration
  execution. The `sqlite` feature is enabled by default; it can be disabled
  for a libSQL-only build;
- a feature-gated libSQL adapter for local databases, remote Turso connections,
  and embedded replicas;
- a standalone `SessionService`/`AuthPrincipal` API with cookie or opt-in
  bearer transport, configurable cookie policy, pluggable password providers
  with automatic rehashing, and executable plugin endpoints/lifecycle hooks.

The remaining work is deployment hardening: live MySQL conformance, signed
SAML and browser-level WebAuthn fixtures, scheduled OIDC JWKS refresh, browser
client examples, and independent security review. The contracts remain
database- and framework-neutral so these integrations do not make the core
depend on one database or web framework.

For TypeScript consumers, use the fetch-native client package first. WASM is
best reserved for optional Rust-owned pure computation or cryptography in the
browser; NAPI should be introduced later only for Node.js backend bindings.

### LibSQL/Turso

Enable the adapter explicitly and choose local or remote storage without
changing auth services:

```toml
better-auth = { version = "0.1", features = ["libsql"] }
```

```rust,no_run
use better_auth::{AuthContext, LibSqlDbAdapter};
use better_auth::core::options::AuthOptions;
use std::sync::Arc;

let db = Arc::new(LibSqlDbAdapter::local("auth.db").await?);
let secondary = Arc::new(db.secondary_storage());
let auth = AuthContext::builder(AuthOptions {
    secret: "replace-with-a-secret-at-least-32-bytes".into(),
    ..AuthOptions::default()
})
    .database(db.clone())
    .secondary_storage(Some(secondary.clone()))
    .build()?;

// Connecting does not change the database. Run this during deployment,
// before serving requests.
db.apply_migrations(&auth.migration_plan()).await?;
secondary.migrate().await?;
```

Use `LibSqlDbAdapter::remote("libsql://...", token)` for a Turso database or
`LibSqlDbAdapter::remote_replica(...)` for an embedded replica. Apply the
merged `AuthContext::migration_plan()` and secondary-storage migration during
deployment, before serving requests. `connect()` is connection-only; a
development convenience wrapper can be built by an application if it wants
automatic migrations.

For an existing password database, use `CredentialService::import` with the
stored hash unchanged. Configure a `CompositePasswordProvider` so the first
successful login verifies the legacy format and automatically replaces it with
the primary PHC hash. Password resets revoke all stored sessions for the user.

## Run and verify

This repository is a Cargo workspace of library crates. It does not define a
root binary, so `cargo run` from the repository root fails with `a bin target
must be available for cargo run`. Use the commands below instead.

### Verify the Rust application code

From the repository root, run the formatter, compiler checks, and test suite:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-features
cargo test --workspace --all-features
```

### Run the web example

The repository includes a small Axum web example with a minimalist browser
page for registration, login, and password recovery. Start it with:

```sh
cargo run -p better-auth --example web-example
```

The server binds to an available localhost port and prints lines like:

```text
READY http://127.0.0.1:43127/api/auth
WEB http://127.0.0.1:43127/
```

Open the `WEB` URL in a browser to use the register and login forms. To verify
the same client-facing endpoints with curl, replace `43127` with the port
printed by the server:

```sh
export AUTH_URL=http://127.0.0.1:43127/api/auth

# Create a user and save the session cookie.
curl -i -c /tmp/better-auth-cookies.txt \
  -H 'Content-Type: application/json' \
  -d '{"email":"demo@example.com","name":"Demo User","password":"correct horse battery staple"}' \
  "$AUTH_URL/sign-up/email"

# Log in with the same credentials and refresh the session cookie.
curl -i -b /tmp/better-auth-cookies.txt \
  -c /tmp/better-auth-cookies.txt \
  -H 'Content-Type: application/json' \
  -d '{"email":"demo@example.com","password":"correct horse battery staple"}' \
  "$AUTH_URL/sign-in/email"
```

The runnable example is intentionally an in-memory server; it is for local
verification, not production deployment. Its source is
`crates/better-auth/examples/web-example.rs`.

The example uses a lower scrypt cost (`log_n=13`) so local auth requests stay
responsive. The library default is configurable through
`AuthOptions.password_hash`; production deployments should benchmark a higher
cost for their hardware and security requirements.

### Verify the TypeScript web client against the Rust server

The client E2E suite builds the same Axum example, starts it on an ephemeral
port, and verifies registration and login over real HTTP:

```sh
cd packages/better-auth-client
npm install
npm run test:e2e
```

Run the unit and type tests as well with:

```sh
npm run test:types
npm test
```
