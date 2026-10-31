//! A framework-neutral Rust foundation for Better Auth.
//!
//! This crate owns runtime state and security behavior while framework
//! adapters are expected to translate their request/response types into the
//! small http types used here.

// `async-trait` 0.1.91+ adds `#[must_use]` to every async trait method. Those
// methods already return `Result`, so clippy's `double_must_use` reports each
// generated trait method. The attribute is macro-generated, not authored here.
#![allow(clippy::double_must_use)]

pub mod account;
pub mod api_key;
pub mod client;
pub mod context;
pub mod cookies;
pub mod database;
pub mod device_auth;
pub mod email;
pub mod email_password;
pub mod hooks;
pub mod http_oauth;
pub mod jwt;
pub mod jwt_signing;
pub mod multi_session;
pub mod oauth;
pub mod oidc;
pub mod one_tap;
pub mod one_time_token;
pub mod openapi;
pub mod password;
pub mod passwordless;
pub mod phone;
pub mod plugins;
pub mod rate_limit;
pub mod router;
#[cfg(feature = "saml")]
pub mod saml_rs_integration;
pub mod second_factor;
pub mod security;
pub mod security_checks;
pub mod session;
#[cfg(feature = "siwe")]
pub mod siwe;
pub mod smtp;
pub mod sso;
pub mod username;
pub mod verification;
pub mod webauthn;

pub use account::{AccountService, LinkedAccount, RevokeOutcome, SessionSummary};
pub use better_auth_core as core;
pub use client::{AuthClient, RetryPolicy};
pub use context::{AuthContext, AuthContextBuilder, RequestContext, RequestMetadata};
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
pub use email_password::{
    AuthResult, CredentialService, EmailPasswordService, ImportCredential, SignInInput,
    SignUpInput, User,
};
pub use hooks::AuthHooks;
pub use http_oauth::HttpOAuthProvider;
pub use jwt::JwtService;
pub use oauth::{
    OAuthAuthorization, OAuthProvider, OAuthProviderConfig, OAuthService, OAuthStateManager,
    OAuthStateStorage, OAuthTokens, OAuthUserProfile, OAuthUserProvisioner, PkcePair,
    ProviderTokenVault,
};
pub use oidc::{OidcClaims, OidcIdTokenValidator};
pub use password::{
    hash_password, hash_password_async, hash_password_with_options, verify_password,
    verify_password_async, CompositePasswordProvider, PasswordProvider, PasswordVerification,
    ScryptPhcPasswordProvider,
};
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
pub use rate_limit::{RateLimitDecision, RateLimitPolicy, RateLimiter};
pub use router::{AuthRouter, HttpRequest, HttpResponse};
#[cfg(feature = "saml")]
pub use saml_rs_integration::{SamlRsIdentity, SamlRsServiceProvider, SamlRsStarted};
pub use security::{check_csrf, extract_client_ip};
pub use session::{AuthPrincipal, SessionService, SessionTransport};
pub use sso::{
    SamlAssertion, SamlAssertionValidator, SamlAuthorizationRequest, SamlIdentity, SamlProvider,
    SamlResponse, SamlSignatureVerifier, SamlValidationConfig, SsoProtocol, ValidatedSamlProvider,
};
pub use verification::{EmailVerificationService, PasswordResetService, VerificationService};
pub use webauthn::{DbPasskeyStore, StoredPasskey, WebAuthnAuthenticationResult, WebAuthnService};
