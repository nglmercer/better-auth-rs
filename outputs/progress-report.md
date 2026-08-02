# Better Auth Rust Rewrite — Progress Report

**Report date:** 2026-08-01  
**Current commit:** `24dc526` — Add email/password sign-up, sign-in, and session management  
**Overall status:** Foundation implemented; HTTP/framework integration and advanced auth features remain.

## Executive summary

The rewrite has a working, framework-neutral Rust foundation. Core configuration, request context resolution, adapter contracts, schema/plugin aggregation, security helpers, password hashing, secure cookies, and a database-backed email/password session flow are implemented.

The project is not yet feature-complete Better Auth. OAuth/PKCE, concrete framework routers, rate-limit enforcement, JWE/JWT cookie-cache encoding, database-specific adapters, and advanced plugins are still outstanding.

## Roadmap status

| Phase | Status | Evidence / scope |
|---|---|---|
| 0. Core types and traits | Complete | `AuthOptions`, adapter traits, schema types, plugin trait, shared errors |
| 1. AuthContext and config | Complete | Defaults, secret validation, static/dynamic base URLs, allowed-host checks |
| 2. Adapters and schema | Complete at contract level | `DbAdapter`, `SecondaryStorage`, TTL/increment semantics, core schema, in-memory test adapters |
| 3. Email/password and sessions | Partial | Sign-up, sign-in, scrypt passwords, persisted sessions, signed session cookies, lookup, sign-out |
| 4. CSRF and security middleware | Partial | Origin validation, Fetch Metadata checks, SameSite=Lax cookies, trusted proxy/IP helpers |
| 5. Plugin system | Complete at foundation level | Endpoint, hook, schema, and error-code registry with conflict detection |
| 6. OAuth/social/PKCE | Not started | State, provider flows, and PKCE storage remain |
| 7. Advanced plugins | Not started | 2FA, organizations, passkeys, admin, SSO, SCIM, JWT |
| 8. Client SDK/framework integrations | Not started | Axum/Actix adapters, HTTP endpoints, and client SDK remain |

## Implemented components

- Workspace crates: `better-auth-core` and `better-auth`.
- Immutable `AuthContext` with per-request `RequestContext` cloning.
- Static, request-derived, and wildcard allowed-host base URL resolution.
- Secret validation and versioned HMAC envelopes for direct key-version lookup during rotation.
- Relational CRUD and secondary KV storage contracts.
- Core user/session/account/verification schema model.
- Plugin endpoint, hook, schema, and error-code aggregation.
- scrypt password hashing and verification.
- Cookie construction with secure prefixes, HttpOnly, SameSite=Lax, path, and max-age attributes.
- Email/password service with normalized email handling, account creation, session persistence, cookie session lookup, expiry checks, and sign-out.
- CSRF origin checks, Fetch Metadata blocking, trusted proxy header handling, and client-IP extraction.

## Verification

The current workspace passes:

```text
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
```

Test result: **12 tests passed, 0 failed** across the two crates.

## Remaining gaps and risks

1. The `CookieCacheStrategy` enum exists, but the current session cookie is a signed opaque token; JWE/JWT encoding and refresh behavior are not implemented.
2. Email/password operations are service methods, not exposed as framework HTTP endpoints yet.
3. Rate limiting is represented by the secondary-storage contract but is not enforced by request middleware.
4. The generic adapter contract has no transaction primitive. Sign-up performs best-effort user cleanup if account insertion fails.
5. Only in-memory adapters are included for tests; production database adapters are not present.
6. OAuth/social providers, state/PKCE, email verification, password reset, and advanced plugins are not implemented.

## Recommended next implementation order

1. Add an HTTP router/handler contract and an Axum adapter for the existing context and email/password service.
2. Implement session cookie-cache JWE/JWT strategies, refresh behavior, and durable-session fallback rules.
3. Add rate-limit middleware backed by atomic secondary-storage increments.
4. Add OAuth provider abstractions plus verification-table and signed-cookie state/PKCE storage.
5. Add a transaction-capable adapter API and the first production database adapter.
6. Port advanced plugins and add an integration-test matrix across framework adapters.

