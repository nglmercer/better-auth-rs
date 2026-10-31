# Deferred upstream endpoints

Every upstream core endpoint is either mounted or listed here with a reason. The
list is checked by `tools/parity/check_deferred.py` in CI. Remove a row when its
route is mounted, and add a row with a reason when a new upstream endpoint is missing.

| Plugin | Method | Path | Reason |
|---|---|---|---|
| admin | POST | `/admin/impersonate-user` | Impersonation needs a security policy and an audit log first (roadmap P4-05). |
| admin | POST | `/admin/stop-impersonating` | Impersonation needs a security policy and an audit log first (roadmap P4-05). |
| core | GET | `/account-info` | Needs profile lookups at the provider, which need stored provider tokens (roadmap P2-06). |
| core | POST | `/callback/:id` | Provider form_post callbacks need a route shape and provider validation not built yet (roadmap P2-05). |
| core | POST | `/change-email` | Upstream sends a verification link to the new address. This crate uses codes instead (see /email-otp/request-email-change). The link flow is not built. |
| core | GET | `/delete-user/callback` | Consumes a token on GET, which is a state change on a safe method (roadmap P1-02). |
| core | POST | `/get-access-token` | Provider access-token retrieval needs the token lifecycle (roadmap P2-06). |
| core | POST | `/link-social` | Linking a provider to an existing account needs the provider flow with linking state (roadmap P2-02). |
| core | POST | `/refresh-token` | Provider token refresh needs the token lifecycle (roadmap P2-06). |
| core | GET | `/reset-password/:token` | Path-parameter routes are not supported by the router yet (roadmap P4-01), and the callback page is not built. |
| core | POST | `/update-session` | Sessions have no updatable fields. This needs a session schema decision. |
| core | GET | `/verify-email` | Consumes a token on GET, which is a state change on a safe method (roadmap P1-02). The POST form is mounted. |
| oauth-popup | GET | `/oauth-popup/start` | The popup return flow is not built (roadmap P2-05). |
| oauth-proxy | GET | `/oauth-proxy-callback` | The OAuth proxy is a Phase 7 item and is not built. |
| one-time-token | GET | `/one-time-token/generate` | Creates a token on GET, which is a state change on a safe method (roadmap P1-02). The POST form is mounted. |
| open-api | GET | `/open-api/generate-schema` | Upstream generates a schema for its own plugin set. This crate publishes its own document at /openapi.json, so this route would describe something else. |
| organization | POST | `/organization/create-role` | Custom roles change the enforcement model, so they need a design decision first (roadmap P4-04). |
| organization | POST | `/organization/delete-role` | Custom roles change the enforcement model, so they need a design decision first (roadmap P4-04). |
| organization | GET | `/organization/get-active-member` | The active organization needs a session field, which needs a session schema decision (roadmap P4-04). |
| organization | GET | `/organization/get-active-member-role` | The active organization needs a session field, which needs a session schema decision (roadmap P4-04). |
| organization | GET | `/organization/get-role` | Custom roles change the enforcement model, so they need a design decision first (roadmap P4-04). |
| organization | GET | `/organization/list-roles` | Custom roles change the enforcement model, so they need a design decision first (roadmap P4-04). |
| organization | POST | `/organization/set-active` | The active organization needs a session field, which needs a session schema decision (roadmap P4-04). |
| organization | POST | `/organization/set-active-team` | The active team needs a session field, which needs a session schema decision (roadmap P4-04). |
| organization | POST | `/organization/update-role` | Custom roles change the enforcement model, so they need a design decision first (roadmap P4-04). |
| phone-number | POST | `/phone-number/request-password-reset` | Phone-based password reset needs a password on accounts that sign in by phone. That is not designed. |
| phone-number | POST | `/phone-number/reset-password` | Phone-based password reset needs a password on accounts that sign in by phone. That is not designed. |
| phone-number | POST | `/sign-in/phone-number` | Upstream signs in with a phone number and a password. This crate signs in with phone codes (/phone-number/verify). A password variant is not designed. |
| two-factor | POST | `/two-factor/send-otp` | A second factor by one-time code is not built. This crate has TOTP and backup codes. |
| two-factor | POST | `/two-factor/verify-backup-code` | Upstream completes a challenge from a cookie. This crate completes it from a challenge token in the body. An alias would mislead, so the route is deferred (roadmap P4-02). |
| two-factor | POST | `/two-factor/verify-otp` | A second factor by one-time code is not built. This crate has TOTP and backup codes. |
| two-factor | POST | `/two-factor/verify-totp` | Upstream completes a challenge from a cookie. This crate completes it from a challenge token in the body. An alias would mislead, so the route is deferred (roadmap P4-02). |
