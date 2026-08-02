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
  replay protection, real WebAuthn registration/assertion verification through
  webauthn-rs, admin role guards, OIDC/SAML SSO contracts, SCIM filtering,
  pagination, bulk operations, user resources/token hashing, and JWT issuance.
- framework-neutral HTTP endpoints, an optional Axum adapter, and a client
  request SDK with reqwest transport, cookie-jar support, and safe retries.
- SQLite relational and secondary-storage adapters, optional SQLx
  Postgres/MySQL adapters, and dialect-aware migration execution.

The remaining work is protocol and deployment hardening: concrete SAML XML
canonicalization/signature adapters, full SCIM RFC 7644 surfaces, live
Postgres/MySQL conformance tests, browser-level WebAuthn tests, OIDC JWKS
discovery/rotation, and browser-specific client bindings. The traits remain
small so these integrations do not make the core depend on one database or web
framework.

## Verify

```sh
cargo fmt --all -- --check
cargo check --workspace --all-features
cargo test --workspace --all-features
```
