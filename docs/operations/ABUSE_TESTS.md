# Abuse and security tests

These are the tests that try to break the server. Each row names an attack and the test that
refuses it. Run them all with `cargo test --workspace --all-features`. The browser cases run
with `npx playwright test` in `e2e/`.

| Attack or failure | Covered by |
|---|---|
| OAuth state replay, forged callbacks, redirect manipulation | `oauth.rs` tests (`signed_cookie_state_is_single_use_with_storage`, `redirect_uri_must_be_https_and_trusted`), `tests/oauth_fixture.rs` |
| Account takeover by linking a provider to an existing account, or by registering a victim's address before the victim proves the mailbox | `router.rs` (`social_sign_in_redirects_with_server_side_state_and_rejects_forged_callbacks`), `tests/account_takeover.rs` |
| Password reset and magic-link replay | `tests/email_otp_purposes.rs`, `tests/magic_link.rs` (single use), Playwright `a reset token cannot be used twice` in `e2e/tests/web-auth.spec.ts` |
| Two-factor bypass and code replay | `router.rs` (`two_factor_challenge_gates_sessions_and_codes_are_single_use`), `tests/account_parity.rs` (backup codes rotate) |
| Session fixation (a session planted in the browser) | `tests/security_abuse.rs` (`a_session_planted_in_the_browser_is_not_adopted_at_sign_in`) |
| Forged requests from another site | `tests/csrf_policy.rs`, `tests/magic_link.rs` (foreign origin), Playwright `requests from another site are refused` |
| Anonymous or non-admin access to protected routes | `tests/route_policy.rs` |
| Server-side request forgery through provider or JWKS endpoints | `tests/ssrf_guard.rs` |
| Client-address spoofing when no proxy is trusted | `tests/security_abuse.rs` (`client_addresses_are_not_read_from_headers_unless_a_proxy_is_trusted`) |
| Tenant access across organizations (teams, invitations, SCIM users and groups) | `tests/organization_routes.rs`, `tests/organization_teams.rs`, `tests/scim_routes.rs`, `tests/scim_groups.rs` |
| SCIM privilege escalation (setting a role) and account takeover by SCIM create | `tests/scim_routes.rs` (`scim_cannot_set_roles_and_a_shared_user_is_protected_across_organizations`) |
| Token forgery and expiry for JWTs, and tokens with an unknown key ID | `jwt_signing.rs` tests |
| Key rotation: a retired key stops verifying, the current key cannot be retired | `jwt_signing.rs` (`rotation_keeps_old_tokens_valid_until_the_old_key_is_retired`) |
| Second-factor secret rotation and re-sealing | `tests/secret_rotation.rs` |
| Brute force of codes and passwords | Rate limits on sign-in, reset, verify, OTP, magic link, passkeys and SCIM requests (`enforce_action_limit`); `router.rs` tests |
| Hostile input to parsers (control characters, quotes, percent escapes, long values) | `tests/input_properties.rs` (deterministic, fixed seed, every public route) |
| Oversized bodies and malformed JSON | `router.rs` tests (2 MiB cap, 413) |

Not yet covered: a real network attacker against a deployed proxy, timing analysis of hashing
under load, and a fuzzer that runs unbounded. Those need a staging environment.
