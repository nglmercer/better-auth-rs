# Production configuration

This document covers an application that mounts Better Auth with the Axum helpers in
`better_auth::axum_integration`. The minimal, runnable reference is
`crates/better-auth/examples/external-axum-google.rs`. It uses in-memory storage, so
do not copy its storage choice.

Better Auth is a library. The checks below are what the library enforces and what the
deployment must provide. Nothing here is a claim of production readiness until the
security review and operational evidence exist (see `docs/roadmap-status.md`).

## Public origin and base URL

- Set `AuthOptions::base_url` to `BaseUrl::Static("https://app.example.com")`. Use
  `BaseUrl::Dynamic` only with an explicit `allowed_hosts` list.
- Every OAuth redirect URI must be HTTPS and on a trusted origin. Plain HTTP is accepted
  only for loopback hosts, and only where `OAuthService::with_loopback_redirects` is enabled
  for native clients (RFC 8252: `127.0.0.1` or `[::1]`, explicit port, callback path).
- `AuthOptions::trusted_origins` lists any additional browser origins allowed to send
  state-changing requests. The policy refuses a present `Origin` that is not trusted,
  refuses `null`, and refuses a present `Sec-Fetch-Site` other than `same-origin`,
  `same-site` or `none`. Requests with neither header are accepted only for
  non-browser clients.
- `AuthOptions::trusted_providers` restricts which social providers may link accounts.

## Proxies and client addresses

- Client IP headers (`X-Forwarded-For` and similar) are ignored by default.
- Set `advanced.trusted_proxy_headers = true` and `advanced.trusted_ip_headers` only when a
  proxy you control strips and rewrites those headers. Otherwise rate limits and audit
  data can be spoofed.
- Forwarded protocol (`X-Forwarded-Proto`) must come from the same trusted proxy.
  Configure the public origin with `BaseUrl::Static`, so the cookie and redirect scheme do
  not depend on request headers.

## Cookies and sessions

- Browser sessions use HttpOnly, SameSite=Lax cookies. Over HTTPS the name carries the
  `__Secure-` prefix. Keep `cookie.secure` unset so the scheme decides.
- `session.expires_in_seconds` bounds every session. `session.update_age_seconds` controls
  when a session is renewed. Revocation is checked against the database on every
  request, including requests that carry a cookie-cache value. Without a database
  (`has_database = false`), cookie-cache sessions cannot be revoked; do not run that mode
  for sign-in.
- Native clients use explicit bearer tokens only. In Axum, the route must use
  `NativeAuthUser`; `AuthUser` ignores the `Authorization` header. Store tokens in the
  operating system keychain, not in plain files.

## Secrets

- `AuthOptions::secret` must be at least 32 bytes and come from a secret store, never from
  source control.
- Rotate with `secret_version` and `secret_rotation`: the new version signs, and old
  versions still verify until they are removed. Two-factor secrets are re-sealed under the
  current version the next time they are read.
- Provider tokens are sealed with AES-GCM. Retention rules for them are not implemented
  (see roadmap item D).

## Google sign-in

- Use `HttpOAuthProvider::google_with_jwks(client_id, client_secret).await` at startup so a
  broken Google JWKS endpoint stops the boot.
- Keys refresh on schedule (`JwksRefreshPolicy::refresh_after`, default 1 hour) and when a
  token names an unknown key ID. Keys that cannot be refreshed are trusted for at most
  `max_stale` (default 24 hours), then every ID token is refused.
- Retired keys remain trusted until the next refresh. This matches token lifetime.
- The One Tap validator is supplied by the application and does not refresh its keys.

## Storage

- Use a relational adapter (PostgreSQL, MySQL, SQLite or libSQL) and secondary storage
  for OAuth state and rate limits. OAuth state requires secondary storage in every mode.
- Migrations create missing tables only. Adding a column to an existing table requires an
  explicit change; see the **Compatibility** entries in `CHANGELOG.md`.
- The PostgreSQL session and second-factor suites run when
  `BETTER_AUTH_TEST_POSTGRES_URL` is set (see `docs/live-tests.md`).

## Rate limits and abuse controls

- Sign-in attempts are rate limited per account and per client address. Sign-in and
  verification budgets are enforced with atomic counters in secondary storage.
- Turnstile and breached-password checks are available. Choose fail-open or fail-closed
  explicitly.

## Errors and logs

- Route errors return a fixed message. Internal errors do not include provider responses,
  tokens or stack detail.
- The Axum extractors return `{"error": "unauthorized" | "forbidden" | ...}` with the
  matching status code and nothing else.
- Tracing events for JWKS refresh failures name the failure without key material or
  response bodies.

## Not covered by this document

- Multi-region deployment, rolling restarts and soak tests (roadmap P5-03).
- MySQL live conformance in CI.
- Independent security review (roadmap P5-01 and the readiness section of
  `docs/roadmap-status.md`).
