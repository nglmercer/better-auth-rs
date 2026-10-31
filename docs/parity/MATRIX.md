# Parity matrix

Pinned upstream: `v1.7.14` (see [UPSTREAM.md](UPSTREAM.md)).

Status values, from lowest to highest:

- **Not started**: no Rust code.
- **Primitive only**: a helper or type exists. No routable flow.
- **Service implemented**: a Rust service handles the flow, and routes may
  exist. Client coverage is partial.
- **HTTP+SDK complete**: routes are mounted and the Rust, TypeScript and Kotlin
  clients all expose the operation.
- **E2E verified**: a browser or provider E2E test runs in CI.
- **Production validated**: independent security review and operational
  evidence exist.

No row is above **Service implemented**. Nothing here is marked
production-ready. Per-item roadmap status is in [../roadmap-status.md](../roadmap-status.md).

Evidence paths are relative to `crates/better-auth/src/` unless stated.

## Upstream plugins at v1.7.14

| Plugin | Status | Evidence | Gaps |
|---|---|---|---|
| core email/password | Service implemented | `email_password.rs`, `router.rs` (sign-up, sign-in, session, sign-out, verify, reset); `packages/better-auth-client` e2e | No Kotlin or Rust SDK coverage for every route; wire shapes not compared to upstream |
| account management (core, not an upstream plugin) | Service implemented | `account.rs`: list, revoke, change password, update name, delete, unlink (last sign-in method kept); `tests/account_parity.rs` | No email change, no provider link |
| two-factor | Service implemented | `second_factor.rs`, `router.rs`: `two_factor_challenge_gates_sessions_and_codes_are_single_use` | No trusted devices, no recovery flow, no Kotlin or Rust SDK |
| magic-link | Service implemented | `passwordless.rs`, `router.rs`: `magic_link_and_email_otp_sign_in_are_single_use_and_bounded` | Delivery needs an application transport |
| email-otp | Service implemented | `passwordless.rs`; `tests/email_otp_purposes.rs`, `tests/email_change_and_reads.rs` cover sign-in, verification, reset and email-change codes, each single use and purpose-bound, with five guesses; the check route does not spend a code | No link-based change-email, no phone-number reset |
| username | Service implemented | `username.rs`, `router.rs`: `usernames_are_unique_case_insensitively_and_sign_in`; `POST /is-username-available` (`tests/account_parity.rs`) | Availability is rate-limited per IP only, and it reveals whether a name is taken, as upstream does |
| organization | Service implemented | `plugins/organization.rs`; routes in `router.rs`; `tests/organization_routes.rs` covers slugs, update and delete by role, invitations (list, cancel, reject, accept), leave and the last-owner rule | No custom roles, no active organization, no custom roles; the permission check uses a fixed role matrix |
| admin | Service implemented | `router.rs`, `plugins/admin.rs`; `tests/admin_moderation.rs`, `tests/admin_accounts.rs` cover bans, expiry, session revocation, removal, user creation and updates, passwords, and permission checks | No impersonation, no persistent audit log |
| jwt | Service implemented | `plugins/jwt.rs` | No discovery, key rotation or routes |
| bearer | Service implemented | `session.rs`: opt-in bearer transport | Opt-in only |
| generic-oauth | Primitive only | `http_oauth.rs` presets for Google, GitHub and Facebook; `oauth.rs` state and linking tests | No provider registry or configurable profile mapping |
| access | Not started | — | — |
| additional-fields | Not started | — | — |
| anonymous | Service implemented | `router.rs`: `guest_accounts_upgrade_in_place_and_last_login_is_recorded` (`POST /sign-in/anonymous`, `POST /anonymous/upgrade`, `POST /delete-anonymous-user`) | No scheduled guest cleanup |
| captcha | Service implemented | `security_checks.rs`: Turnstile verifier with an explicit `FailureMode` | Turnstile only; no other providers |
| custom-session | Not started | — | — |
| device-authorization | Service implemented | `device_auth.rs`; `POST /device/code`, `/device/approve`, `/device/deny`, `/device/token` (RFC 8628) | No limited-input client E2E |
| haveibeenpwned | Service implemented | `security_checks.rs`: range API with SHA-1 prefix only; fail-open or fail-closed by configuration | No live API test |
| last-login-method | Service implemented | Recorded on every session-creating route; `GET /last-login-method` (`guest_accounts_upgrade_in_place_and_last_login_is_recorded`) | — |
| multi-session | Partial | `multi_session.rs`: `multi_session_keeps_accounts_in_one_browser_and_switches_between_them` | Sign-in through providers other than the password route is not covered |
| oauth-popup | Not started | — | — |
| oauth-proxy | Not started | — | — |
| one-tap | Service implemented | `one_tap.rs`: `one_tap_signs_in_verified_google_accounts_once`; keys must be loaded with `google_with_jwks` | No browser E2E |
| one-time-token | Service implemented | `one_time_token.rs`: `api_keys_and_one_time_tokens_are_owned_scoped_and_single_use` | — |
| open-api | Not started | — | — |
| phone-number | Service implemented | `phone.rs`: `phone_codes_sign_in_one_account_per_number` | Delivery is the application's `PhoneSender` |
| siwe | Service implemented | `siwe.rs` (feature `siwe`): `POST /siwe/nonce`, `POST /siwe/verify`, EIP-4361 and EIP-191 | `Expiration Time` is not enforced beyond the nonce lifetime |
| test-utils | Primitive only | `email.rs` `CapturingEmailSender`; in-memory adapters | Not a plugin |

## Separate upstream packages (not in the plugin directory)

| Package | Status | Evidence | Gaps |
|---|---|---|---|
| passkey | Service implemented | `webauthn.rs` and `router.rs` routes under `/passkey/*`; `tests/passkey_flow.rs` runs registration and sign-in with a software authenticator, including replay, cloned counters, wrong origin, cross-account and deleted credentials | Route names are not verified against the pinned upstream, because passkey ships outside the core package; no browser authenticator E2E; no SDK methods; no attestation trust policy; the two-factor gate on passkey sign-in is not tested |
| sso (OIDC) | Service implemented | `oidc.rs`: `multi_audience_tokens_require_matching_authorized_party`, signature and nonce tests; `plugins/sso.rs` | No discovery or routes; JWKS refresh is not scheduled |
| sso (SAML) | Primitive only | `saml_rs_integration.rs` (optional `saml` feature) | No signed fixtures, no enterprise IdP E2E |
| scim | Service implemented | `plugins/scim/` (filter, PATCH, groups, bulk, hashed tokens) | No HTTP routes; no live interoperability tests |

## Security items that affect these claims

| Item | Evidence |
|---|---|
| OAuth state single use, redirect allowlist | `oauth.rs`: `signed_cookie_state_is_single_use_with_storage`, `redirect_uri_must_be_https_and_trusted` |
| Provider email trust | `http_oauth.rs`: `verified_primary_email_is_preferred`, `google_preset_fails_closed_without_loaded_signing_keys`; `oauth.rs`: linking tests |
| Two-factor gate | `router.rs`: `two_factor_challenge_gates_sessions_and_codes_are_single_use` |
| Errors and body limits | `router.rs`: `internal_errors_do_not_leak_details`, `axum_adapter_rejects_oversized_bodies_instead_of_emptying_them` |
| Plugin endpoint access and origin | `router.rs`: `plugin_endpoint_access_levels_are_enforced_before_the_handler`, `plugin_endpoints_enforce_the_same_origin_policy` |
| Rate limits | `router.rs`: `sign_in_budget_applies_per_account_even_without_a_client_ip` |
| Sign-up race and live databases | `email_password.rs`: `concurrent_sign_up_with_one_email_creates_exactly_one_account`; `tests/live_database_flow.rs` |
