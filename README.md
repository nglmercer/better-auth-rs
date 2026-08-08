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
  increment semantics;
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
  execution.

The remaining work is deployment hardening: live MySQL conformance, signed
SAML and browser-level WebAuthn fixtures, scheduled OIDC JWKS refresh, browser
client examples, and independent security review. The traits remain small so
these integrations do not make the core depend on one database or web
framework.

For TypeScript consumers, use the fetch-native client package first. WASM is
best reserved for optional Rust-owned pure computation or cryptography in the
browser; NAPI should be introduced later only for Node.js backend bindings.

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

The repository includes a small Axum server that wires the Rust auth router
to an HTTP endpoint. Start it with:

```sh
cargo run -p better-auth --features axum --example client-test-server
```

The server binds to an available localhost port and prints a line like:

```text
READY http://127.0.0.1:43127/api/auth
```

Leave that terminal running. In a second terminal, replace `43127` with the
port printed by the server and verify the complete cookie-backed flow:

```sh
export AUTH_URL=http://127.0.0.1:43127/api/auth

# No session yet.
curl -s "$AUTH_URL/get-session"

# Create a user and save the session cookie.
curl -i -c /tmp/better-auth-cookies.txt \
  -H 'Content-Type: application/json' \
  -d '{"email":"demo@example.com","name":"Demo User","password":"correct horse battery staple"}' \
  "$AUTH_URL/sign-up/email"

# The saved cookie should return the new session.
curl -s -b /tmp/better-auth-cookies.txt "$AUTH_URL/get-session"

# Sign out and clear the session.
curl -i -b /tmp/better-auth-cookies.txt \
  -c /tmp/better-auth-cookies.txt \
  -X POST "$AUTH_URL/sign-out"
```

The runnable example is intentionally an in-memory test server; it is for
local verification, not production deployment. Its source is
`crates/better-auth/examples/client-test-server.rs`.

### Verify the TypeScript web client against the Rust server

The client E2E suite builds the same Axum example, starts it on an ephemeral
port, and verifies sign-up, session lookup, sign-out, and sign-in over real
HTTP:

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
