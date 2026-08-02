# Better Auth Rust Rewrite — Progress Report

**Report date:** 2026-08-01  
**Baseline commit:** `24dc526`  
**Current status:** All roadmap phases have a working framework-neutral baseline; production protocol hardening remains.

## Summary

The Rust rewrite has progressed from a core foundation to an end-to-end baseline. It now includes runtime context resolution, transactional adapter contracts, migrations, email/password sessions, JWT/JWE cookie caching, request security, rate limiting, OAuth/PKCE, advanced-plugin services, HTTP routing, an optional Axum adapter, and a client request SDK.

## Roadmap status

| Phase | Status | Current implementation |
|---|---|---|
| 0. Core types and traits | Complete | Options, errors, adapter contracts, schema, plugins |
| 1. AuthContext and config | Complete | Defaults, secrets, static/dynamic base URLs, allowed hosts |
| 2. Adapters and schema | Complete baseline | CRUD/KV adapters, atomic transactions, TTL, migration plan/SQL rendering, SQLite adapters |
| 3. Email/password and sessions | Complete baseline | Sign-up/sign-in, scrypt, session persistence, refresh, sign-out, JWE/JWT/opaque cookies, email verification and password reset |
| 4. CSRF and security middleware | Complete baseline | Origin, Fetch Metadata, SameSite=Lax, trusted proxy/IP handling, rate limiting |
| 5. Plugin system | Complete | Endpoint/hook/schema/error registry and conflict detection |
| 6. OAuth/social/PKCE | Complete baseline | Verification/signed-cookie state, PKCE S256, OAuth completion/account linking, HTTPS generic provider, Google/GitHub presets |
| 7. Advanced plugins | Implemented baseline | TOTP/backup codes, organizations, passkey challenges, admin roles, SSO connections, SCIM users/list pagination/tokens, JWT |
| 8. Client/framework integrations | Implemented baseline | JSON HTTP router, optional Axum adapter, request-building client SDK, reqwest transport/cookie jar |

## Verification

The latest checks are:

```text
cargo fmt --all -- --check
cargo check --workspace --all-features
cargo test --workspace --all-features
```

The latest full test run passed **30 tests**: 27 in `better-auth` and 3 in `better-auth-core`, with 0 failures. The optional Axum feature is included in the all-features check.

## Remaining production gaps

1. Passkey support currently protects challenge issuance/consumption and stores credential metadata; full WebAuthn CBOR attestation/assertion and signature-counter verification still require a WebAuthn implementation.
2. SSO currently provides validated OIDC-style connection persistence and can use the generic OAuth provider; SAML protocol handling is not included.
3. SCIM currently provides token hashing, user CRUD, and basic list pagination; full RFC 7644 filtering and bulk operations remain.
4. SQLite is implemented; Postgres/MySQL adapters and production migration runners are still needed.
5. The client SDK now owns a reqwest transport and cookie jar, but retry policy and browser-specific integration remain.
6. OAuth ID-token signature/nonce validation and provider-specific token persistence/encryption should be added before production deployment.

## Recommended release sequence

1. Add Postgres/MySQL adapters and production migration runners using the existing contracts.
2. Integrate a vetted WebAuthn implementation and add browser ceremony integration tests.
3. Complete SCIM/SAML protocol surfaces and OAuth ID-token validation.
4. Add client transport/cookie-jar support and integration tests against the Axum adapter.
5. Run security review, dependency audit, and multi-database conformance tests.
