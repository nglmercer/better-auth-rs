# Upstream pin: Better Auth (TypeScript)

This file records the upstream TypeScript release that Rust parity claims are
measured against. Parity is per feature and per pinned version. No claim in
this repository means unconditional cross-version parity.

## Pinned release

| Field | Value |
|---|---|
| Repository | <https://github.com/better-auth/better-auth> |
| Tag | `v1.7.14` |
| Commit | `a936663d3a3c811af82ee9e9418d986f70662d9b` |
| Published | 2026-10-26 (latest stable release at pin time) |
| Pinned on | 2026-10-30 |

Pre-releases such as `v1.8.0-beta.*` exist upstream and are **not** pinned.
Bumping the pin is a separate change: it must update this file, the matrix in
[MATRIX.md](MATRIX.md), and any tests that assert upstream behavior.

## Plugin set at the pin

Official plugin directories under `packages/better-auth/src/plugins/` at
`v1.7.14`:

`access`, `additional-fields`, `admin`, `anonymous`, `bearer`, `captcha`,
`custom-session`, `device-authorization`, `email-otp`, `generic-oauth`,
`haveibeenpwned`, `jwt`, `last-login-method`, `magic-link`, `multi-session`,
`oauth-popup`, `oauth-proxy`, `one-tap`, `one-time-token`, `open-api`,
`organization`, `phone-number`, `siwe`, `test-utils`, `two-factor`, `username`.

Plugins that ship as separate upstream packages (SSO, SCIM, passkey) are not in
that directory. They are tracked in [MATRIX.md](MATRIX.md) under their own
heading so they are not mistaken for core plugins.

## Supported surface

The Rust workspace targets a framework-neutral core. The HTTP router
(`crates/better-auth/src/router.rs`) mounts these upstream-compatible routes:

- `POST /sign-up/email`
- `POST /sign-in/email`
- `GET /get-session`
- `POST /sign-out`
- `POST /verify-email`
- `POST /request-password-reset`
- `POST /reset-password`

Plus the OAuth begin/complete service for Google, GitHub and generic HTTPS
providers. Request and response shapes for these routes are Rust-owned and are
**not yet** proven byte-compatible with the pinned TypeScript server. A
compatibility suite against this pin is roadmap item Phase 8.

## Deliberate deviations

These differ from upstream on purpose. They are security decisions, not gaps:

- **OAuth account linking is fail-closed.** An existing local user is linked to
  a provider identity only when the provider email is verified **and** the
  local account's email is verified. Upstream behavior is not used here.
- **Missing `email_verified` is treated as `false`**, never `true`.
- **GitHub email proof** comes from `/user/emails` (verified primary email),
  not from `/user` alone.
- **OAuth state is single-use in every mode**, and the signed-cookie mode
  requires secondary storage for the single-use marker.
- **Two-factor sign-in returns a challenge, not a session.** Password sign-in
  answers `200 {"two_factor_required": true, "challenge_token": …}` for a user
  with an enabled second factor. The challenge is completed at
  `POST /two-factor/verify`. The challenge lives five minutes and allows five
  wrong codes. Each TOTP time step and each backup code is accepted once.
- **Internal errors return `500 internal server error`** with an
  `x-request-id`. The detail is only in the server log under that ID.
- **Passwords must be 8 to 128 characters**, the NIST SP 800-63B minimum.
- **Username is case-insensitive and unique.** It is stored in normalized
  lowercase form.
- **Request bodies are capped at 2 MiB**, and oversized bodies return `413`.
- **Admin routes take snake_case bodies** (`user_id`, `ban_expires_in`), as the
  existing admin routes do, rather than upstream's camelCase. Revocation by
  session names the session by `id`, never by token, so a listing cannot be
  replayed as a credential. Ban expiry is stored as Unix seconds. The same
  applies to `totp_uri` and `backup_codes` (upstream: `totpURI`, `backupCodes`).
