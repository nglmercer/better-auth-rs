# Changelog

This project follows the policy in [docs/governance/RELEASE.md](docs/governance/RELEASE.md).
Entries group changes under the version they ship in. Changes that alter stored
data (password hashes, signed envelopes, database schema) are marked **Compatibility**.

## Unreleased

### Security
- OAuth provider endpoints (token, userinfo, authorization, verified emails, JWKS) must be
  public HTTPS hosts. Credentials in the URL, `localhost`, and private, loopback, link-local
  (including cloud metadata), shared and unspecified addresses are refused.
- Passkey registration and SCIM requests count against the per-client rate limit.
- Two-factor secrets record the key version that sealed them. A secret read under an old version
  is re-sealed under the current one.
- JWT signing keys can be rotated. The old key stays published until it is retired.
- SCIM groups are scoped to one organization, the same as SCIM users. A group's members must
  belong to that organization, and removing a user removes them from its groups.
- The sign-in path refuses a session planted before sign-in, and a password registered before the
  mailbox was proven stops working when the mailbox is proven.
- A central access table states what each route requires (`route_access`). Anonymous
  callers are refused on every route that needs a session, and non-administrators on every
  admin route except the permission check. The gate runs before routing.
- The origin policy is explicit. `Origin: null` is refused. `Sec-Fetch-Site` must be
  `same-origin`, `same-site` or `none`, and any other value is refused. When the two
  disagree, the request is refused.
- SCIM Users are scoped to one organization. A create never takes over an existing account,
  a user shared with another organization cannot be renamed, deactivated or re-addressed from
  that organization, and PATCH cannot set a role.
- OAuth state is single use in every mode. The signed-cookie mode requires
  secondary storage.
- Provider email is never trusted by default. Linking an existing account needs a
  verified provider email and a verified local email.
- Google ID tokens are validated, including the authorized party for
  multi-audience tokens. GitHub email comes from `/user/emails`. Facebook never
  reports a verified email.
- Two-factor sign-in returns a challenge instead of a session. TOTP steps and
  backup codes are single use. TOTP secrets are encrypted at rest.
- Redirect URIs for social sign-in must be trusted HTTPS.
- Plugin endpoints require a session unless marked public. Admin routes check the
  administrator role.
- Internal errors return a generic message with a request ID.
- Password policy: 8 to 128 characters.
- Cookie encryption uses a random nonce per envelope. Previously it used UUID bytes.

### Added
- SCIM Groups routes at `/scim/v2/Groups`, scoped to the token's organization.
- `JwtSigner::rotate` and `JwtSigner::retire`, and `JwtSigner::current_kid`.
- `docs/operations/ABUSE_TESTS.md`, an index of the abuse tests by attack.
- SCIM Users routes under `/scim/v2/Users`, and `POST /scim/generate-token` for organization admins.
  Groups and bulk are not mounted.
- A Playwright browser suite in `e2e/`, seven tests, run against the example in test mode.
- `POST /magic-link/verify` consumes a magic link and signs in. `GET /magic-link/verify` shows
  a confirmation page and changes nothing. Sign-in links accept a `callbackURL` that must be a
  path on this site.
- Account and session management routes, password change with session revocation.
- Email delivery for reset and verification links through `EmailSender`.
- Magic-link and email one-time-code sign-in.
- Username plugin, API keys, one-time tokens.
- Social sign-in routes for Google, GitHub and Facebook.
- Idempotency-Key handling for POST requests.
- `GET /ready`, `GET /metrics` (opt-in), request IDs, metrics counters.
- Admin routes: list users, set role, revoke sessions.
- Admin moderation routes: `/admin/ban-user`, `/admin/unban-user`,
  `/admin/list-user-sessions`, `/admin/revoke-user-session`,
  `/admin/revoke-user-sessions`, `/admin/remove-user`. A ban ends sessions and
  refuses sign-in and existing sessions while it is active.
- Routes matching upstream paths: `GET /ok`, `POST /get-session`, `POST /verify-password`,
  `POST /is-username-available`, `POST /unlink-account`, `POST /two-factor/get-totp-uri`
  and `POST /two-factor/generate-backup-codes`. The last two need the password again and
  send `Cache-Control: no-store`.
- Organization routes: get, update (name and slug), delete, leave, list, cancel and reject
  invitations, list a user's invitations, and slug checks. Deleting an organization removes
  its memberships and invitations in one transaction.
- `POST /organization/has-permission` checks a permission map against the built-in roles.
- `POST /sign-in/social` starts a social sign-in and returns the provider URL as JSON.
  The GET redirect shares the same code.
- Admin user operations: `POST /admin/create-user`, `GET /admin/get-user`, `POST /admin/update-user`,
  `POST /admin/set-user-password`, `POST /admin/has-permission`.
- Email change by code: `POST /email-otp/request-email-change` (session) and `POST /email-otp/change-email`.
  `POST /email-otp/check-verification-otp` checks a code without spending it.
- `GET /error` renders an escaped error page. `GET /organization/get-full-organization` and
  `GET /organization/get-invitation` read organizations; invitations are shown to owners and admins.
- Organization teams: create, list, rename, remove, add and remove members, list members,
  and a user's teams. Team members must already belong to the organization.
- Email codes by purpose: `POST /email-otp/send-verification-otp` (sign-in, email verification,
  password reset), `POST /sign-in/email-otp`, `POST /email-otp/verify-email`,
  `POST /forget-password/email-otp`, `POST /email-otp/request-password-reset` and
  `POST /email-otp/reset-password`. A code works only for the purpose it was issued for.
- Passkey routes under `/passkey/*`: registration, discoverable sign-in, list,
  rename and delete. Enabled with `AuthRouter::with_passkeys()`. Requires a
  static base URL (its host is the RP ID) and secondary storage.
- `SmtpEmailSender`: SMTP delivery over implicit TLS or STARTTLS, with AUTH PLAIN and
  message headers checked against injection. Credentials are never sent without TLS.
- Embedded libSQL runs the shared adapter and secondary-storage contract in every
  test run.

### Changed
- Sign-in with an enabled second factor returns `{two_factor_required, challenge_token}`.
- Sign-up returns 400 for a duplicate email even when two requests race.
- MySQL: booleans are stored as `BIGINT`; string keys as `VARCHAR(512)`.
- Axum example mounts the whole `/api/auth` prefix through the router.

### Fixed
- PostgreSQL and MySQL counters no longer fail under concurrent first increments.
- Failed session hooks no longer leave orphan sessions.
- A failed `after_user_create` hook no longer leaves an account behind.

### Compatibility
- OAuth provider endpoints on private or loopback addresses are no longer accepted. An identity
  provider on an internal network needs a public HTTPS name in front of it.
- Two-factor records gain a `secret_version` field. Records without it are opened under the current
  key, as before. Rotate the secret only after upgrading.
- SCIM PATCH refuses `role`. A client that sent it now gets 400.
- Magic links no longer sign in on GET. A client that followed the old GET redirect must POST the
  token to `/magic-link/verify`. The confirmation page is a form that does that.
- Anonymous requests to routes that need a session now get 401 before routing, so a probe cannot
  tell a missing route from a protected one.
- Minimum supported Rust version is now 1.89, raised from 1.88. The optional `saml` feature
  needs `aes` 0.9.3, which requires rustc 1.89.
- The admin plugin adds `banned`, `ban_reason` and `ban_expires` to the `user` table.
  The migration layer creates tables but cannot add columns to existing ones, so a
  database created before this change needs them added by hand, for example
  `ALTER TABLE "user" ADD COLUMN banned BOOLEAN`, plus `ban_reason` (text) and
  `ban_expires` (integer seconds). Until they exist, banning a user fails with a
  database error, and no account is treated as banned.
- Password hashes, signed envelopes and the core schema SQL are unchanged. Golden
  fixtures in `crates/better-auth/tests/compat/` check them.
- MySQL schema changed from `TINYINT(1)` to `BIGINT` for booleans and from `TEXT` to
  `VARCHAR(512)` for string keys. Databases created by the previous build keep
  their old column types.
