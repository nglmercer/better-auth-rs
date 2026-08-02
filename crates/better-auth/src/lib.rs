//! A framework-neutral Rust foundation for Better Auth.
//!
//! This crate owns runtime state and security behavior while framework
//! adapters are expected to translate their request/response types into the
//! small http types used here.

pub mod client;
pub mod context;
pub mod cookies;
pub mod email_password;
pub mod http_oauth;
pub mod jwt;
pub mod oauth;
pub mod password;
pub mod plugins;
pub mod rate_limit;
pub mod router;
pub mod security;

pub use better_auth_core as core;
pub use client::AuthClient;
pub use context::{AuthContext, RequestContext, RequestMetadata};
pub use cookies::{AuthCookie, CookieCacheClaims, CookieCacheCodec, CookieSameSite, SecretKeySet};
pub use email_password::{AuthResult, EmailPasswordService, SignInInput, SignUpInput, User};
pub use http_oauth::HttpOAuthProvider;
pub use jwt::JwtService;
pub use oauth::{
    OAuthAuthorization, OAuthProvider, OAuthProviderConfig, OAuthService, OAuthStateManager,
    OAuthStateStorage, OAuthTokens, OAuthUserProfile, PkcePair,
};
pub use password::{hash_password, verify_password};
pub use plugins::{
    generate_scim_token, generate_totp_secret, totp_code, verify_scim_token, verify_totp,
    AdminGuard, AdminPlugin, BackupCodeSet, Organization, OrganizationMember, OrganizationPlugin,
    OrganizationService, PasskeyChallenge, PasskeyPlugin, PasskeyService, ScimPlugin,
    SsoConnectionConfig, SsoPlugin, TotpSecret, TwoFactorPlugin,
};
pub use rate_limit::{RateLimitDecision, RateLimitPolicy, RateLimiter};
pub use router::{AuthRouter, HttpRequest, HttpResponse};
pub use security::{check_csrf, extract_client_ip};
