//! A framework-neutral Rust foundation for Better Auth.
//!
//! This crate owns runtime state and security behavior while framework
//! adapters are expected to translate their request/response types into the
//! small http types used here.

// `async-trait` 0.1.91+ adds `#[must_use]` to every async trait method. Those
// methods already return `Result`, so clippy's `double_must_use` reports each
// generated trait method. The attribute is macro-generated, not authored here.
#![allow(clippy::double_must_use)]

#[cfg(feature = "full")]
pub mod account;
#[cfg(feature = "full")]
pub mod api_key;
#[cfg(feature = "axum")]
pub mod axum_integration;
#[cfg(feature = "full")]
pub mod client;
#[cfg(feature = "full")]
pub mod context;
#[cfg(feature = "full")]
pub mod cookies;
#[cfg(feature = "full")]
pub mod database;
pub mod desktop;
#[cfg(feature = "full")]
pub mod device_auth;
#[cfg(feature = "full")]
pub mod email;
#[cfg(feature = "full")]
pub mod email_password;
#[cfg(feature = "full")]
pub mod hooks;
#[cfg(feature = "full")]
pub mod http_oauth;
#[cfg(feature = "full")]
pub mod jwks;
#[cfg(feature = "full")]
pub mod jwt;
#[cfg(feature = "full")]
pub mod jwt_signing;
#[cfg(feature = "full")]
pub mod multi_session;
#[cfg(feature = "full")]
pub mod oauth;
#[cfg(feature = "full")]
pub mod oidc;
#[cfg(feature = "full")]
pub mod one_tap;
#[cfg(feature = "full")]
pub mod one_time_token;
#[cfg(feature = "full")]
pub mod openapi;
#[cfg(feature = "full")]
pub mod password;
#[cfg(feature = "full")]
pub mod passwordless;
#[cfg(feature = "full")]
pub mod phone;
#[cfg(feature = "full")]
pub mod plugins;
#[cfg(feature = "full")]
pub mod rate_limit;
#[cfg(feature = "full")]
pub mod router;
#[cfg(feature = "saml")]
pub mod saml_rs_integration;
#[cfg(feature = "full")]
pub mod second_factor;
#[cfg(feature = "full")]
pub mod security;
#[cfg(feature = "full")]
pub mod security_checks;
#[cfg(feature = "full")]
pub mod session;
#[cfg(feature = "siwe")]
pub mod siwe;
#[cfg(feature = "full")]
pub mod smtp;
#[cfg(feature = "full")]
pub mod sso;
#[cfg(feature = "full")]
pub mod username;
#[cfg(feature = "full")]
pub mod verification;
#[cfg(feature = "full")]
pub mod webauthn;

#[cfg(feature = "full")]
pub use account::{AccountService, LinkedAccount, RevokeOutcome, SessionSummary};
pub use better_auth_core as core;
#[cfg(feature = "full")]
pub use client::{AuthClient, RetryPolicy};
#[cfg(feature = "full")]
pub use context::{AuthContext, AuthContextBuilder, RequestContext, RequestMetadata};
#[cfg(feature = "full")]
pub use cookies::{
    session_cookie_from_options, session_cookie_name, AuthCookie, CookieCacheClaims,
    CookieCacheCodec, CookieSameSite, SecretKeySet,
};
#[cfg(feature = "libsql")]
pub use database::{LibSqlConfig, LibSqlDbAdapter, LibSqlSecondaryStorage, RemoteReplica};
#[cfg(feature = "sqlx")]
pub use database::{
    MySqlDbAdapter, MySqlSecondaryStorage, PostgresDbAdapter, PostgresSecondaryStorage,
    SqlxBackend, SqlxDbAdapter, SqlxSecondaryStorage,
};
#[cfg(feature = "sqlite")]
pub use database::{SqliteDbAdapter, SqliteSecondaryStorage};
#[cfg(feature = "full")]
pub use desktop::DesktopHandoffService;
pub use desktop::{
    loopback_callback_url, validate_loopback_redirect_uri, HandoffRequest,
    LoopbackCallbackReceiver, RedeemRequest,
};
#[cfg(feature = "full")]
pub use email_password::{
    AuthResult, CredentialService, EmailPasswordService, ImportCredential, SignInInput,
    SignUpInput, User,
};
#[cfg(feature = "full")]
pub use hooks::AuthHooks;
#[cfg(feature = "full")]
pub use http_oauth::HttpOAuthProvider;
#[cfg(feature = "full")]
pub use jwks::{JwksIdTokenVerifier, JwksRefreshPolicy};
#[cfg(feature = "full")]
pub use jwt::JwtService;
#[cfg(feature = "full")]
pub use oauth::{
    OAuthAuthorization, OAuthProvider, OAuthProviderConfig, OAuthService, OAuthStateManager,
    OAuthStateStorage, OAuthTokens, OAuthUserProfile, OAuthUserProvisioner, PkcePair,
    ProviderTokenVault,
};
#[cfg(feature = "full")]
pub use oidc::{OidcClaims, OidcIdTokenValidator};
#[cfg(feature = "full")]
pub use password::{
    hash_password, hash_password_async, hash_password_with_options, verify_password,
    verify_password_async, CompositePasswordProvider, PasswordProvider, PasswordVerification,
    ScryptPhcPasswordProvider,
};
#[cfg(feature = "full")]
pub use plugins::{
    generate_scim_token, generate_totp_secret, totp_code, verify_scim_token, verify_totp,
    AdminGuard, AdminPlugin, AdminService, AnonymousPlugin, ApiKeyPlugin, BackupCodeSet,
    DeviceAuthorizationPlugin, EmailOtpPlugin, LastLoginMethodPlugin, MagicLinkPlugin,
    MultiSessionPlugin, OneTapPlugin, OneTimeTokenPlugin, Organization, OrganizationMember,
    OrganizationPlugin, OrganizationService, PasskeyChallenge, PasskeyPlugin, PasskeyService,
    ScimBulkOperation, ScimBulkResponse, ScimGroup, ScimGroupMember, ScimPatchOperation,
    ScimPlugin, ScimService, ScimTokenRecord, SiwePlugin, SsoConnectionConfig,
    SsoConnectionService, SsoPlugin, TotpSecret, TwoFactorPlugin, UsernamePlugin, API_KEY_PLUGIN,
};
#[cfg(feature = "full")]
pub use rate_limit::{RateLimitDecision, RateLimitPolicy, RateLimiter};
#[cfg(feature = "full")]
pub use router::{AuthRouter, HttpRequest, HttpResponse};
#[cfg(feature = "saml")]
pub use saml_rs_integration::{SamlRsIdentity, SamlRsServiceProvider, SamlRsStarted};
#[cfg(feature = "full")]
pub use security::{check_csrf, extract_client_ip};
#[cfg(feature = "full")]
pub use session::{AuthPrincipal, SessionService, SessionTransport};
#[cfg(feature = "full")]
pub use sso::{
    SamlAssertion, SamlAssertionValidator, SamlAuthorizationRequest, SamlIdentity, SamlProvider,
    SamlResponse, SamlSignatureVerifier, SamlValidationConfig, SsoProtocol, ValidatedSamlProvider,
};
#[cfg(feature = "full")]
pub use verification::{EmailVerificationService, PasswordResetService, VerificationService};
#[cfg(feature = "full")]
pub use webauthn::{DbPasskeyStore, StoredPasskey, WebAuthnAuthenticationResult, WebAuthnService};
