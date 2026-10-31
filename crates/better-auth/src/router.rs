use crate::{
    account::AccountService,
    api_key::ApiKeyService,
    check_csrf,
    context::{AuthContext, RequestMetadata},
    cookies::{session_cookie_name, AuthCookie, SecretKeySet},
    device_auth::{DeviceAuthService, PollOutcome},
    email::{
        email_change_code_message, email_otp_message, email_verification_code_message,
        magic_link_message, password_reset_code_message, password_reset_message,
        verification_message, EmailMessage, EmailSender,
    },
    email_password::{
        has_plugin, normalize_email, two_factor_required, validate_password, Session, User,
        TWO_FACTOR_PLUGIN,
    },
    email_password::{
        AuthResult, CredentialService, EmailPasswordService, ImportCredential, SignInInput,
        SignUpInput,
    },
    http_oauth::HttpOAuthProvider,
    multi_session::remember,
    oauth::{OAuthService, OAuthStateStorage},
    oidc::OidcIdTokenValidator,
    one_tap::OneTapService,
    one_time_token::OneTimeTokenService,
    passwordless::{EmailOtpPurpose, PasswordlessService},
    plugins::USERNAME_PLUGIN,
    plugins::{AdminGuard, AdminService, OrganizationService, API_KEY_PLUGIN},
    rate_limit::{RateLimitPolicy, RateLimiter},
    second_factor::SecondFactorService,
    security_checks::{BreachChecker, CaptchaVerifier, FailureMode},
    username::{normalize_username, UsernameService},
    verification::{EmailVerificationService, PasswordResetService},
    webauthn::{credential_key_from_response, DbPasskeyStore, StoredPasskey, WebAuthnService},
};
use better_auth_core::{
    adapter::{DbOperation, Query, SecondaryStorage},
    error::{AuthError, Result},
    plugin::{EndpointAccess, EndpointRequest, HookRequest, HookResponse},
};
use http::{header, HeaderMap, Method, StatusCode, Uri};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn new(method: Method, uri: Uri, headers: HeaderMap, body: impl Into<Vec<u8>>) -> Self {
        Self {
            method,
            uri,
            headers,
            body: body.into(),
        }
    }

    fn metadata(&self) -> RequestMetadata {
        RequestMetadata::new(self.method.clone(), self.uri.clone(), self.headers.clone())
    }
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn json(status: StatusCode, value: impl Serialize) -> Self {
        let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"null".to_vec());
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        Self {
            status,
            headers,
            body,
        }
    }

    pub fn error(status: StatusCode, message: impl Into<String>) -> Self {
        Self::json(status, json!({ "error": message.into() }))
    }

    fn with_cookie(mut self, value: String) -> Self {
        if let Ok(value) = value.parse() {
            self.headers.append(header::SET_COOKIE, value);
        }
        self
    }
}

#[derive(Clone)]
pub struct AuthRouter {
    context: AuthContext,
    email_password: EmailPasswordService,
    account: AccountService,
    second_factor: Option<SecondFactorService>,
    passwordless: Option<PasswordlessService>,
    usernames: UsernameService,
    metrics: Arc<Metrics>,
    metrics_endpoint: bool,
    breach: Option<(Arc<dyn BreachChecker>, FailureMode)>,
    one_tap: Option<OneTapService>,
    phone_sender: Option<Arc<dyn crate::phone::PhoneSender>>,
    jwt: Option<crate::jwt_signing::JwtSigner>,
    #[cfg(feature = "siwe")]
    siwe: Option<crate::siwe::SiweService>,
    captcha: Option<(Arc<dyn CaptchaVerifier>, FailureMode)>,
    social: Option<SocialSignIn>,
    rate_limiter: Option<RateLimiter>,
    sign_in_policy: Option<RateLimitPolicy>,
    email_verification: Option<EmailVerificationService>,
    password_reset: Option<PasswordResetService>,
    admin_roles: Vec<String>,
    email_sender: Option<Arc<dyn EmailSender>>,
    passkeys: Option<Arc<WebAuthnService>>,
}

impl AuthRouter {
    pub fn new(context: AuthContext) -> Result<Self> {
        let email_password = EmailPasswordService::new(context.clone())?;
        let account = AccountService::new(context.clone())?;
        // Missing secondary storage is reported when a second-factor route or
        // challenge is used, so the router still starts for other flows.
        let second_factor = SecondFactorService::new(context.clone()).ok();
        let passwordless = PasswordlessService::new(context.clone()).ok();
        let usernames = UsernameService::new(context.clone());
        // A wallet names the host it is signing in to, so the expected domain is
        // the configured origin's host, with its port when one is present.
        #[cfg(feature = "siwe")]
        let siwe = context
            .base_origin()
            .and_then(|origin| url::Url::parse(&origin).ok())
            .and_then(|url| {
                let host = url.host_str()?.to_owned();
                Some(match url.port() {
                    Some(port) => format!("{host}:{port}"),
                    None => host,
                })
            })
            .and_then(|domain| crate::siwe::SiweService::new(context.clone(), domain).ok());
        Ok(Self {
            context,
            email_password,
            account,
            second_factor,
            passwordless,
            usernames,
            metrics: Arc::new(Metrics::default()),
            metrics_endpoint: false,
            breach: None,
            one_tap: None,
            phone_sender: None,
            jwt: None,
            #[cfg(feature = "siwe")]
            siwe,
            captcha: None,
            social: None,
            rate_limiter: None,
            sign_in_policy: None,
            email_verification: None,
            password_reset: None,
            admin_roles: vec!["admin".into()],
            email_sender: None,
            passkeys: None,
        })
    }

    /// Enables email delivery for password reset and verification links. The
    /// links point at the configured static base URL, so it must be set.
    pub fn with_email_sender(mut self, sender: Arc<dyn EmailSender>) -> Result<Self> {
        if self.context.base_origin().is_none() {
            return Err(AuthError::InvalidConfiguration(
                "email links require a static base URL".into(),
            ));
        }
        self.email_sender = Some(sender);
        Ok(self)
    }

    fn app_url(&self, path: &str, token: &str) -> Result<String> {
        let origin = self
            .context
            .base_origin()
            .ok_or_else(|| AuthError::InvalidConfiguration("base URL is not configured".into()))?;
        Ok(format!("{origin}{path}?token={token}"))
    }

    /// Enables social sign-in with the given providers. Each provider gets
    /// `GET /sign-in/social/{id}` and `GET /callback/{id}`. Redirect URIs are
    /// built from the static base URL, so that must be configured.
    pub fn with_social_providers(mut self, providers: Vec<HttpOAuthProvider>) -> Result<Self> {
        if self.context.base_origin().is_none() {
            return Err(AuthError::InvalidConfiguration(
                "social sign-in requires a static base URL".into(),
            ));
        }
        let registry = SocialRegistry::default();
        for provider in providers {
            registry.register(provider)?;
        }
        let service = OAuthService::new(self.context.clone(), OAuthStateStorage::Verification)?;
        self.social = Some(SocialSignIn { service, registry });
        Ok(self)
    }

    /// The registry behind social sign-in. Providers registered through it after
    /// the router starts are served immediately.
    pub fn social_registry(&self) -> Option<SocialRegistry> {
        self.social.as_ref().map(|social| social.registry.clone())
    }

    /// Refuses passwords that appear in known breaches on sign-up, reset and
    /// change. `mode` decides what happens when the checker cannot answer.
    pub fn with_breach_check(mut self, checker: Arc<dyn BreachChecker>, mode: FailureMode) -> Self {
        self.breach = Some((checker, mode));
        self
    }

    /// Requires a CAPTCHA response in the `x-captcha-response` header on sign-up,
    /// sign-in and password-reset requests.
    pub fn with_captcha(mut self, verifier: Arc<dyn CaptchaVerifier>, mode: FailureMode) -> Self {
        self.captcha = Some((verifier, mode));
        self
    }

    /// Enables Google One Tap at `POST /one-tap/callback`. The validator must hold
    /// Google's signing keys, and secondary storage is required for replay checks.
    pub fn with_one_tap(mut self, validator: OidcIdTokenValidator) -> Result<Self> {
        self.one_tap = Some(OneTapService::new(self.context.clone(), validator)?);
        Ok(self)
    }

    /// Enables asymmetric JWTs: `GET /token` issues one to the signed-in user,
    /// and `GET /jwks` and `GET /.well-known/jwks.json` publish the public key.
    pub fn with_jwt(mut self, signer: crate::jwt_signing::JwtSigner) -> Self {
        self.jwt = Some(signer);
        self
    }

    /// Enables SMS sign-in codes through `sender`.
    pub fn with_phone_sender(mut self, sender: Arc<dyn crate::phone::PhoneSender>) -> Self {
        self.phone_sender = Some(sender);
        self
    }

    /// Enables passkey routes. The static base URL names the WebAuthn relying
    /// party: its host is the RP ID, and the full URL is the only origin a
    /// ceremony accepts. Ceremony state lives in secondary storage, so any node
    /// can finish a ceremony that another node started.
    pub fn with_passkeys(mut self) -> Result<Self> {
        let origin = self.context.base_origin().ok_or_else(|| {
            AuthError::InvalidConfiguration("passkeys need a static base URL".into())
        })?;
        let url = url::Url::parse(&origin)
            .map_err(|error| AuthError::InvalidConfiguration(format!("base URL: {error}")))?;
        let rp_id = url
            .host_str()
            .ok_or_else(|| AuthError::InvalidConfiguration("passkeys need a base URL host".into()))?
            .to_owned();
        let storage = self.context.secondary_storage.clone().ok_or_else(|| {
            AuthError::InvalidConfiguration("passkeys need secondary storage".into())
        })?;
        self.passkeys = Some(Arc::new(
            WebAuthnService::new(&rp_id, url, PASSKEY_RP_NAME)?.with_state_storage(storage),
        ));
        Ok(self)
    }

    /// Exposes `GET /metrics` with the counter snapshot as JSON. Off by default,
    /// because the counters describe traffic and should sit behind the same
    /// network controls as operator endpoints.
    pub fn with_metrics_endpoint(mut self) -> Self {
        self.metrics_endpoint = true;
        self
    }

    /// Snapshot of request counters since the router was created.
    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Roles that satisfy `EndpointAccess::Admin`. Defaults to `admin`.
    pub fn with_admin_roles(mut self, roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.admin_roles = roles.into_iter().map(Into::into).collect();
        self
    }

    fn passkey_service(&self) -> Result<&WebAuthnService> {
        self.passkeys.as_deref().ok_or_else(|| {
            AuthError::InvalidConfiguration("call with_passkeys() to enable passkey routes".into())
        })
    }

    fn passkey_store(&self) -> DbPasskeyStore {
        DbPasskeyStore::new(self.context.adapter.clone())
    }

    async fn user_by_id(&self, user_id: &str) -> Result<Option<User>> {
        self.context
            .adapter
            .find_one("user", Query::new().eq("id", user_id.to_owned()))
            .await?
            .map(|value| {
                serde_json::from_value(value).map_err(|e| AuthError::Adapter(e.to_string()))
            })
            .transpose()
    }

    /// Email of the signed-in user, used as the account key for re-auth limits.
    async fn session_email(&self, headers: &HeaderMap, secure_cookie: bool) -> Result<String> {
        self.email_password
            .session_from_cookie(headers, secure_cookie)
            .await?
            .map(|(user, _)| user.email)
            .ok_or(AuthError::Unauthorized)
    }

    /// Completes a password sign-in. A user with an enabled second factor gets a
    /// challenge, and the session is created only after the challenge passes.
    async fn finish_password_sign_in(
        &self,
        user: User,
        secure_cookie: bool,
        method: &str,
    ) -> Result<HttpResponse> {
        if two_factor_required(&self.context, &user.id).await? {
            let service = self.second_factor.as_ref().ok_or_else(|| {
                AuthError::InvalidConfiguration("two-factor requires secondary storage".into())
            })?;
            let token = service.create_challenge(&user.id).await?;
            return Ok(HttpResponse::json(
                StatusCode::OK,
                json!({"two_factor_required": true, "challenge_token": token}),
            ));
        }
        let result = self.complete_session(user, secure_cookie, method).await?;
        Ok(auth_result_response(StatusCode::OK, result))
    }

    /// Creates the session and records how the user signed in. The method is
    /// stored only when the last-login plugin is registered.
    async fn complete_session(
        &self,
        user: User,
        secure_cookie: bool,
        method: &str,
    ) -> Result<AuthResult> {
        let result = self
            .email_password
            .complete_sign_in(user, secure_cookie)
            .await?;
        self.record_login_method(&result.user.id, method).await?;
        Ok(result)
    }

    async fn record_login_method(&self, user_id: &str, method: &str) -> Result<()> {
        if !has_plugin(&self.context, LAST_LOGIN_PLUGIN) {
            return Ok(());
        }
        self.context
            .adapter
            .update_where(
                "user",
                Query::new().eq("id", user_id.to_owned()),
                json!({"last_login_method": method}),
            )
            .await?;
        Ok(())
    }

    async fn is_anonymous(&self, user_id: &str) -> Result<bool> {
        Ok(self
            .context
            .adapter
            .find_one("user", Query::new().eq("id", user_id.to_owned()))
            .await?
            .and_then(|user| user.get("is_anonymous").and_then(Value::as_bool))
            .unwrap_or(false))
    }

    async fn check_password_breach(&self, password: &str) -> Result<()> {
        let Some((checker, mode)) = &self.breach else {
            return Ok(());
        };
        match checker.breach_count(password).await {
            Ok(0) => Ok(()),
            Ok(_) => Err(AuthError::InvalidRequest(
                "this password appears in a known data breach; choose another".into(),
            )),
            Err(_) if *mode == FailureMode::FailOpen => Ok(()),
            Err(_) => Err(AuthError::Forbidden(
                "password check is unavailable; try again later".into(),
            )),
        }
    }

    async fn check_captcha(
        &self,
        headers: &HeaderMap,
        request_context: &crate::context::RequestContext,
    ) -> Result<()> {
        let Some((verifier, mode)) = &self.captcha else {
            return Ok(());
        };
        let response = headers
            .get("x-captcha-response")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AuthError::Forbidden("captcha response is required".into()))?;
        match verifier.verify(response, request_context.client_ip).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(AuthError::Forbidden("captcha verification failed".into())),
            Err(_) if *mode == FailureMode::FailOpen => Ok(()),
            Err(_) => Err(AuthError::Forbidden(
                "captcha check is unavailable; try again later".into(),
            )),
        }
    }

    /// Issues and delivers an emailed code for `purpose`. Verification and reset codes
    /// go out only to an address with an account, and every case gets the same
    /// answer, so the response never reveals which addresses have accounts.
    async fn send_purpose_otp(
        &self,
        request_context: &crate::context::RequestContext,
        purpose: EmailOtpPurpose,
        email: &str,
    ) -> Result<()> {
        if purpose == EmailOtpPurpose::EmailChange {
            return Err(AuthError::InvalidRequest(
                "email change codes are requested with a session".into(),
            ));
        }
        let to = email.trim().to_ascii_lowercase();
        self.enforce_action_limit(request_context, "email-otp-send", Some(&to))
            .await?;
        let has_account = self
            .context
            .adapter
            .find_one("user", Query::new().eq("email", to.clone()))
            .await?
            .is_some();
        if purpose != EmailOtpPurpose::SignIn && !has_account {
            return Ok(());
        }
        let sender = self.sender()?;
        let code = self.passwordless()?.issue_purpose_otp(purpose, &to).await?;
        let message = match purpose {
            EmailOtpPurpose::SignIn => email_otp_message(&to, &code),
            EmailOtpPurpose::EmailVerification => email_verification_code_message(&to, &code),
            EmailOtpPurpose::PasswordReset => password_reset_code_message(&to, &code),
            EmailOtpPurpose::EmailChange => email_change_code_message(&to, &code),
        };
        deliver(sender.as_ref(), message).await;
        Ok(())
    }

    /// Whether a user holds `email`. Callers that act on the answer must be authenticated.
    async fn user_exists_with_email(&self, email: &str) -> Result<bool> {
        Ok(self
            .context
            .adapter
            .find_one("user", Query::new().eq("email", email.to_owned()))
            .await?
            .is_some())
    }

    /// Starts a social sign-in with provider `id` and returns the provider's
    /// authorization URL.
    async fn social_begin(&self, id: &str, secure_cookie: bool) -> Result<String> {
        let social = self.social.as_ref().ok_or(AuthError::NotFound)?;
        let provider = social.registry.get(id).ok_or(AuthError::NotFound)?;
        let redirect_uri = social_callback_url(&self.context, id);
        let authorization = social
            .service
            .begin(&provider.config()?, &redirect_uri, secure_cookie)
            .await?;
        Ok(authorization.authorization_url.to_string())
    }

    fn passwordless(&self) -> Result<&PasswordlessService> {
        self.passwordless.as_ref().ok_or_else(|| {
            AuthError::InvalidConfiguration(
                "passwordless sign-in requires secondary storage".into(),
            )
        })
    }

    fn sender(&self) -> Result<Arc<dyn EmailSender>> {
        self.email_sender.clone().ok_or_else(|| {
            AuthError::InvalidConfiguration("this flow needs an email sender".into())
        })
    }

    /// URL of an API route with the one-time token, built on the static origin.
    fn api_url(&self, path: &str, token: &str) -> Result<String> {
        let origin = self
            .context
            .base_origin()
            .ok_or_else(|| AuthError::InvalidConfiguration("base URL is not configured".into()))?;
        let base_path = self.context.options.base_path.trim_end_matches('/');
        Ok(format!("{origin}{base_path}{path}?token={token}"))
    }

    fn one_time_tokens(&self) -> Result<OneTimeTokenService> {
        let storage = self.context.secondary_storage.clone().ok_or_else(|| {
            AuthError::InvalidConfiguration("one-time tokens require secondary storage".into())
        })?;
        Ok(OneTimeTokenService::new(storage))
    }

    #[cfg(feature = "siwe")]
    fn siwe_service(&self) -> Result<&crate::siwe::SiweService> {
        self.siwe.as_ref().ok_or_else(|| {
            AuthError::InvalidConfiguration("SIWE requires secondary storage".into())
        })
    }

    fn organizations(&self) -> OrganizationService {
        OrganizationService::new(self.context.adapter.clone())
    }

    /// The session token of the request's active session, when it is valid.
    async fn active_session_token(
        &self,
        headers: &HeaderMap,
        secure_cookie: bool,
    ) -> Result<Option<String>> {
        if !has_plugin(&self.context, MULTI_SESSION_PLUGIN) {
            return Ok(None);
        }
        let name = session_cookie_name(&self.context.options.cookie, secure_cookie);
        let Some(token) = crate::cookies::request_cookies(headers).get(&name).cloned() else {
            return Ok(None);
        };
        Ok(self
            .session_for_token(&token, secure_cookie)
            .await?
            .map(|_| token))
    }

    /// Resolves a stored account. Stored values are the session cookie values, so
    /// they are checked the way the cookie transport checks them.
    async fn session_for_token(
        &self,
        value: &str,
        secure_cookie: bool,
    ) -> Result<Option<(User, Session)>> {
        let name = session_cookie_name(&self.context.options.cookie, secure_cookie);
        let mut headers = HeaderMap::new();
        let cookie = format!("{name}={value}")
            .parse()
            .map_err(|_| AuthError::Unauthorized)?;
        headers.insert(header::COOKIE, cookie);
        Ok(self
            .email_password
            .sessions()
            .resolve_with_transport(
                &headers,
                secure_cookie,
                crate::session::SessionTransport::Cookie,
            )
            .await?
            .map(|principal| (principal.user, principal.session)))
    }

    fn stored_account_tokens(&self, headers: &HeaderMap, secure_cookie: bool) -> Vec<String> {
        let keys = match SecretKeySet::from_options(&self.context.options) {
            Ok(keys) => keys,
            Err(_) => return Vec::new(),
        };
        crate::multi_session::read_tokens(&keys, headers, secure_cookie)
    }

    /// Every account in the browser, the active one first.
    fn account_tokens(
        &self,
        headers: &HeaderMap,
        secure_cookie: bool,
        active: &str,
    ) -> Vec<String> {
        let mut tokens = vec![active.to_owned()];
        for token in self.stored_account_tokens(headers, secure_cookie) {
            if !tokens.contains(&token) {
                tokens.push(token);
            }
        }
        tokens
    }

    /// Keeps the previous account when a new sign-in replaces the active session.
    fn remember_account(
        &self,
        response: &mut HttpResponse,
        headers: &HeaderMap,
        secure_cookie: bool,
        previous: &str,
    ) -> Result<()> {
        let name = session_cookie_name(&self.context.options.cookie, secure_cookie);
        let issued_session = response
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|value| {
                value
                    .to_str()
                    .is_ok_and(|v| v.starts_with(&format!("{name}=")))
            });
        if !issued_session {
            return Ok(());
        }
        let tokens = remember(
            &self.stored_account_tokens(headers, secure_cookie),
            previous,
        );
        self.push_multi_cookie(response, &tokens, secure_cookie)
    }

    fn push_multi_cookie(
        &self,
        response: &mut HttpResponse,
        tokens: &[String],
        secure_cookie: bool,
    ) -> Result<()> {
        let keys = SecretKeySet::from_options(&self.context.options)?;
        let cookie = crate::multi_session::write_cookie(
            &keys,
            tokens,
            secure_cookie,
            &self.context.options.cookie,
        )?;
        response.headers.append(
            header::SET_COOKIE,
            cookie
                .to_set_cookie_header()
                .parse()
                .map_err(|_| AuthError::Adapter("cookie header".into()))?,
        );
        Ok(())
    }

    /// Makes `active` the session cookie and stores `others` in the account cookie.
    fn push_session_cookies(
        &self,
        response: &mut HttpResponse,
        active: &str,
        others: &[String],
        previous_active: &str,
        secure_cookie: bool,
    ) -> Result<()> {
        let cookie = AuthCookie::session_with_options(
            active,
            secure_cookie,
            &self.context.options.cookie,
            self.context.options.session.expires_in_seconds,
        );
        response.headers.append(
            header::SET_COOKIE,
            cookie
                .to_set_cookie_header()
                .parse()
                .map_err(|_| AuthError::Adapter("cookie header".into()))?,
        );
        // A switch keeps the account being left. A revoke passes "" so the
        // revoked account is not kept.
        let mut stored = Vec::new();
        if !previous_active.is_empty() {
            stored.push(previous_active.to_owned());
        }
        stored.extend(
            others
                .iter()
                .filter(|token| token.as_str() != previous_active)
                .cloned(),
        );
        stored.truncate(crate::multi_session::MAX_ACCOUNTS);
        self.push_multi_cookie(response, &stored, secure_cookie)
    }

    fn device_auth(&self) -> Result<DeviceAuthService> {
        // The verification page is the public URL where users approve codes.
        let origin = self
            .context
            .base_origin()
            .ok_or_else(|| AuthError::InvalidConfiguration("base URL is not configured".into()))?;
        let base_path = self.context.options.base_path.trim_end_matches('/');
        Ok(DeviceAuthService::new(
            self.context.clone(),
            format!("{origin}{base_path}/device"),
        ))
    }

    fn api_keys(&self) -> Result<ApiKeyService> {
        ApiKeyService::new(self.context.clone())
    }

    fn admin_service(&self) -> AdminService {
        AdminService::new(
            self.context.adapter.clone(),
            AdminGuard::new(self.admin_roles.clone()),
        )
    }

    fn second_factor(&self) -> Result<&SecondFactorService> {
        self.second_factor.as_ref().ok_or_else(|| {
            AuthError::InvalidConfiguration("two-factor requires secondary storage".into())
        })
    }

    async fn current_user(
        &self,
        headers: &HeaderMap,
        secure_cookie: bool,
    ) -> Result<(User, Session)> {
        self.email_password
            .session_from_cookie(headers, secure_cookie)
            .await?
            .ok_or(AuthError::Unauthorized)
    }

    async fn is_admin(&self, user_id: &str) -> Result<bool> {
        let role = self
            .context
            .adapter
            .find_one("user", Query::new().eq("id", user_id.to_owned()))
            .await?
            .and_then(|user| user.get("role").and_then(Value::as_str).map(str::to_owned));
        Ok(role.is_some_and(|role| self.admin_roles.contains(&role)))
    }

    pub fn with_verification_services(mut self) -> Result<Self> {
        if let Some(storage) = self.context.secondary_storage.clone() {
            self.email_verification = Some(EmailVerificationService::new(
                self.context.clone(),
                storage.clone(),
            ));
            self.password_reset = Some(PasswordResetService::new(self.context.clone(), storage)?);
        }
        Ok(self)
    }

    pub fn with_sign_in_rate_limit(
        mut self,
        limiter: RateLimiter,
        policy: RateLimitPolicy,
    ) -> Self {
        self.rate_limiter = Some(limiter);
        self.sign_in_policy = Some(policy);
        self
    }

    pub async fn handle(&self, request: HttpRequest) -> HttpResponse {
        if request.method == Method::POST {
            if let Some(key) = request
                .headers
                .get(IDEMPOTENCY_KEY_HEADER)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
            {
                if let Some(storage) = self.context.secondary_storage.clone() {
                    return self.handle_idempotent(request, &key, storage).await;
                }
            }
        }
        self.process(request).await
    }

    /// Runs a POST at most once per `Idempotency-Key`. The scope is the path,
    /// the caller's cookie and the key, so one caller cannot replay another's
    /// response. A reused key with a different body is refused.
    async fn handle_idempotent(
        &self,
        request: HttpRequest,
        key: &str,
        storage: Arc<dyn SecondaryStorage>,
    ) -> HttpResponse {
        let cookie = request
            .headers
            .get(header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let scope = hex_digest(&[request.uri.path(), "\0", &cookie, "\0", key]);
        let record_key = format!("idempotency:{scope}");
        let claim_key = format!("idempotency-claim:{scope}");
        let body_digest = hex_digest(&[std::str::from_utf8(&request.body).unwrap_or("")]);

        if let Ok(Some(stored)) = storage.get(&record_key).await {
            let Some(record) = stored_response_from_value(&stored.value) else {
                return HttpResponse::error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error",
                );
            };
            if record.body_digest != body_digest {
                return HttpResponse::error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Idempotency-Key was already used with a different request",
                );
            }
            return record.into_response();
        }
        // Only one request may run at a time for a key. The claim expires, so a
        // crashed request cannot block its key forever.
        let claimed = storage
            .increment(&claim_key, 1, IDEMPOTENCY_CLAIM_TTL)
            .await
            .unwrap_or(0);
        if claimed != 1 {
            return HttpResponse::error(
                StatusCode::CONFLICT,
                "a request with this Idempotency-Key is already in progress",
            );
        }

        let response = self.process(request).await;
        if response.status.is_server_error() {
            // Nothing is stored for a server error, so the caller may retry.
            let _ = storage.delete(&claim_key).await;
            return response;
        }
        let record = StoredResponse::from_response(&response, body_digest);
        let _ = storage
            .set(
                &record_key,
                better_auth_core::adapter::StorageValue::with_ttl(
                    record.to_value(),
                    IDEMPOTENCY_RECORD_TTL,
                ),
            )
            .await;
        response
    }

    async fn process(&self, request: HttpRequest) -> HttpResponse {
        // Every response, including failures, carries an ID that operators can
        // match to the server-side log line for the same request.
        let request_id = Uuid::new_v4().to_string();
        let method = request.method.clone();
        // The query string is never logged: magic-link and reset tokens travel there.
        let path = request.uri.path().to_owned();
        let mut response = self.handle_with_id(request, &request_id).await;
        if let Ok(value) = request_id.parse() {
            response.headers.insert(REQUEST_ID_HEADER, value);
        }
        self.metrics.record(response.status);
        tracing::info!(
            request_id = %request_id,
            method = %method,
            path = %path,
            status = response.status.as_u16(),
            "auth request"
        );
        response
    }

    async fn handle_with_id(&self, request: HttpRequest, request_id: &str) -> HttpResponse {
        let hook_request = HookRequest {
            method: request.method.clone(),
            path: request.uri.path().to_owned(),
            headers: request.headers.clone(),
            body: serde_json::from_slice(&request.body).ok(),
        };
        for hook in self.context.plugins.hooks() {
            if let Err(error) = hook.on_request(&hook_request).await {
                return error_response(error, request_id);
            }
        }

        let mut response = match self.handle_result(request).await {
            Ok(response) => response,
            Err(error) => error_response(error, request_id),
        };
        let hook_response = HookResponse {
            status: response.status,
            headers: response.headers.clone(),
        };
        for hook in self.context.plugins.hooks() {
            if let Err(error) = hook.on_response(&hook_request, &hook_response).await {
                response = error_response(error, request_id);
                break;
            }
        }
        response
    }

    async fn handle_result(&self, request: HttpRequest) -> Result<HttpResponse> {
        let request_context = self.context.resolve_request(&request.metadata())?;
        let path = request.uri.path();
        let base_path = self.context.options.base_path.trim_end_matches('/');
        let endpoint_path_name = path
            .strip_prefix(base_path)
            .unwrap_or(path)
            .trim_end_matches('/');
        let secure_cookie = request_context
            .base_url
            .as_ref()
            .is_some_and(|url| url.scheme() == "https");

        if let Some(endpoint) = self
            .context
            .plugins
            .endpoint_handlers()
            .iter()
            .find(|registered| {
                registered.endpoint.method == request.method
                    && registered.endpoint.path == endpoint_path_name
            })
        {
            // Plugin handlers get the same origin and Fetch Metadata policy as
            // built-in state-changing routes; safe methods pass through.
            check_csrf(&request_context, &request.metadata())?;
            // Access is enforced before any handler code runs. The default
            // access level requires a session.
            let user_id = match endpoint.endpoint.access {
                EndpointAccess::Public => None,
                access => {
                    let Some((user, _session)) = self
                        .email_password
                        .session_from_cookie(&request.headers, secure_cookie)
                        .await?
                    else {
                        return Err(AuthError::Unauthorized);
                    };
                    if access == EndpointAccess::Admin && !self.is_admin(&user.id).await? {
                        return Err(AuthError::Forbidden("administrator role required".into()));
                    }
                    Some(user.id)
                }
            };
            let response = endpoint
                .handler
                .handle(EndpointRequest {
                    method: request.method.clone(),
                    path: endpoint_path_name.to_owned(),
                    headers: request.headers.clone(),
                    body: request.body.clone(),
                    user_id,
                })
                .await?;
            return Ok(HttpResponse {
                status: response.status,
                headers: response.headers,
                body: response.body,
            });
        }

        match (request.method.clone(), endpoint_path_name) {
            (Method::POST, "/sign-up/email") => {
                check_csrf(&request_context, &request.metadata())?;
                self.check_captcha(&request.headers, &request_context)
                    .await?;
                let input: SignUpInput = parse_json(&request.body)?;
                self.check_password_breach(&input.password).await?;
                self.enforce_action_limit(&request_context, "sign-up", Some(&input.email))
                    .await?;
                let result = self.email_password.sign_up(input, secure_cookie).await?;
                Ok(auth_result_response(StatusCode::OK, result))
            }
            (Method::POST, "/sign-in/email") => {
                check_csrf(&request_context, &request.metadata())?;
                self.check_captcha(&request.headers, &request_context)
                    .await?;
                let input: SignInInput = parse_json(&request.body)?;
                self.enforce_action_limit(&request_context, "sign-in", Some(&input.email))
                    .await?;
                let user = self.email_password.verify_credentials(input).await?;
                let previous = self
                    .active_session_token(&request.headers, secure_cookie)
                    .await?;
                let mut response = self
                    .finish_password_sign_in(user, secure_cookie, "email")
                    .await?;
                if let Some(previous) = previous {
                    self.remember_account(
                        &mut response,
                        &request.headers,
                        secure_cookie,
                        &previous,
                    )?;
                }
                Ok(response)
            }

            (Method::GET, "/multi-session/list-device-sessions") => {
                require_plugin(&self.context, MULTI_SESSION_PLUGIN)?;
                let (_, _) = self.current_user(&request.headers, secure_cookie).await?;
                let active = self
                    .active_session_token(&request.headers, secure_cookie)
                    .await?
                    .ok_or(AuthError::Unauthorized)?;
                let mut sessions = Vec::new();
                for token in self.account_tokens(&request.headers, secure_cookie, &active) {
                    if let Some((user, session)) =
                        self.session_for_token(&token, secure_cookie).await?
                    {
                        sessions.push(json!({
                            "user": user,
                            "session": session,
                            "current": token == active,
                        }));
                    }
                }
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "sessions": sessions }),
                ))
            }
            (Method::POST, "/multi-session/set-active") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, MULTI_SESSION_PLUGIN)?;
                let input: SessionTokenInput = parse_json(&request.body)?;
                let (_, _) = self.current_user(&request.headers, secure_cookie).await?;
                let active = self
                    .active_session_token(&request.headers, secure_cookie)
                    .await?
                    .ok_or(AuthError::Unauthorized)?;
                let stored = self.stored_account_tokens(&request.headers, secure_cookie);
                if input.session_token == active || !stored.contains(&input.session_token) {
                    return Err(AuthError::NotFound);
                }
                // The target must still be a live session, not just a token in the cookie.
                if self
                    .session_for_token(&input.session_token, secure_cookie)
                    .await?
                    .is_none()
                {
                    return Err(AuthError::NotFound);
                }
                let others: Vec<String> = stored
                    .into_iter()
                    .filter(|token| *token != input.session_token)
                    .collect();
                let mut response = HttpResponse::json(StatusCode::OK, json!({"active": true}));
                self.push_session_cookies(
                    &mut response,
                    &input.session_token,
                    &others,
                    &active,
                    secure_cookie,
                )?;
                Ok(response)
            }
            (Method::POST, "/multi-session/revoke") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, MULTI_SESSION_PLUGIN)?;
                let input: SessionTokenInput = parse_json(&request.body)?;
                let (_, _) = self.current_user(&request.headers, secure_cookie).await?;
                let active = self
                    .active_session_token(&request.headers, secure_cookie)
                    .await?
                    .ok_or(AuthError::Unauthorized)?;
                let stored = self.stored_account_tokens(&request.headers, secure_cookie);
                if input.session_token != active && !stored.contains(&input.session_token) {
                    return Err(AuthError::NotFound);
                }
                if let Some((_, session)) = self
                    .session_for_token(&input.session_token, secure_cookie)
                    .await?
                {
                    self.email_password.sessions().discard(&session.id).await?;
                }
                let remaining: Vec<String> = stored
                    .into_iter()
                    .filter(|token| *token != input.session_token)
                    .collect();
                let mut response = HttpResponse::json(StatusCode::OK, json!({"revoked": true}));
                if input.session_token == active {
                    match remaining.first().cloned() {
                        Some(next) => {
                            self.push_session_cookies(
                                &mut response,
                                &next,
                                &remaining[1..],
                                "",
                                secure_cookie,
                            )?;
                        }
                        None => {
                            let cookie = self
                                .email_password
                                .sign_out(&request.headers, secure_cookie)
                                .await?;
                            response.headers.append(
                                header::SET_COOKIE,
                                cookie
                                    .to_set_cookie_header()
                                    .parse()
                                    .map_err(|_| AuthError::Adapter("cookie header".into()))?,
                            );
                            self.push_multi_cookie(&mut response, &[], secure_cookie)?;
                        }
                    }
                } else {
                    self.push_multi_cookie(&mut response, &remaining, secure_cookie)?;
                }
                Ok(response)
            }
            (Method::POST, "/sign-in/username") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, USERNAME_PLUGIN)?;
                let input: UsernameSignInInput = parse_json(&request.body)?;
                self.enforce_action_limit(
                    &request_context,
                    "sign-in-username",
                    Some(&input.username),
                )
                .await?;
                let user = self
                    .usernames
                    .find_user(&input.username)
                    .await?
                    .ok_or(AuthError::Unauthorized)?;
                // Credentials are checked through the email path, so both
                // routes share one password check and one second-factor gate.
                let user = self
                    .email_password
                    .verify_credentials(SignInInput {
                        email: user.email,
                        password: input.password,
                    })
                    .await?;
                self.finish_password_sign_in(user, secure_cookie, "username")
                    .await
            }
            (Method::POST, "/username/set") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, USERNAME_PLUGIN)?;
                let input: UsernameSetInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let username = self.usernames.set(&user.id, &input.username).await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "username": username }),
                ))
            }
            (Method::POST, "/two-factor/enable") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, TWO_FACTOR_PLUGIN)?;
                let input: PasswordInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                self.enforce_action_limit(&request_context, "two-factor-enable", Some(&user.email))
                    .await?;
                self.account
                    .verify_current_password(&user, &input.password)
                    .await?;
                let enrollment = self.second_factor()?.begin_enrollment(&user).await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({
                        "secret": enrollment.secret,
                        "totp_uri": enrollment.totp_uri,
                        "backup_codes": enrollment.backup_codes,
                    }),
                ))
            }
            (Method::POST, "/two-factor/confirm") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, TWO_FACTOR_PLUGIN)?;
                let input: CodeInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                self.enforce_action_limit(
                    &request_context,
                    "two-factor-confirm",
                    Some(&user.email),
                )
                .await?;
                self.second_factor()?
                    .confirm_enrollment(&user.id, &input.code)
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({"enabled": true})))
            }
            (Method::POST, "/two-factor/disable") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, TWO_FACTOR_PLUGIN)?;
                let input: PasswordInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                self.enforce_action_limit(
                    &request_context,
                    "two-factor-disable",
                    Some(&user.email),
                )
                .await?;
                self.account
                    .verify_current_password(&user, &input.password)
                    .await?;
                self.second_factor()?.disable(&user.id).await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({"enabled": false}),
                ))
            }
            (Method::POST, "/verify-password") => {
                check_csrf(&request_context, &request.metadata())?;
                let input: PasswordInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                self.enforce_action_limit(&request_context, "verify-password", Some(&user.email))
                    .await?;
                self.account
                    .verify_current_password(&user, &input.password)
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({"status": true})))
            }
            (Method::POST, "/is-username-available") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, USERNAME_PLUGIN)?;
                let input: UsernameAvailabilityInput = parse_json(&request.body)?;
                // Invalid names are refused with the same rules sign-up applies.
                normalize_username(&input.username)?;
                self.enforce_action_limit(&request_context, "username-availability", None)
                    .await?;
                let taken = self.usernames.find_user(&input.username).await?.is_some();
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({"available": !taken}),
                ))
            }
            (Method::POST, "/two-factor/get-totp-uri") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, TWO_FACTOR_PLUGIN)?;
                let input: PasswordInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                self.enforce_action_limit(
                    &request_context,
                    "two-factor-totp-uri",
                    Some(&user.email),
                )
                .await?;
                self.account
                    .verify_current_password(&user, &input.password)
                    .await?;
                let totp_uri = self.second_factor()?.totp_uri(&user).await?;
                let mut response =
                    HttpResponse::json(StatusCode::OK, json!({ "totp_uri": totp_uri }));
                response.headers.insert(
                    header::CACHE_CONTROL,
                    "no-store".parse().expect("static header"),
                );
                Ok(response)
            }
            (Method::POST, "/two-factor/generate-backup-codes") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, TWO_FACTOR_PLUGIN)?;
                let input: PasswordInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                self.enforce_action_limit(
                    &request_context,
                    "two-factor-backup-codes",
                    Some(&user.email),
                )
                .await?;
                self.account
                    .verify_current_password(&user, &input.password)
                    .await?;
                let backup_codes = self
                    .second_factor()?
                    .regenerate_backup_codes(&user.id)
                    .await?;
                let mut response =
                    HttpResponse::json(StatusCode::OK, json!({ "backup_codes": backup_codes }));
                response.headers.insert(
                    header::CACHE_CONTROL,
                    "no-store".parse().expect("static header"),
                );
                Ok(response)
            }
            (Method::POST, "/unlink-account") => {
                check_csrf(&request_context, &request.metadata())?;
                let input: UnlinkAccountInput = parse_json(&request.body)?;
                self.account
                    .unlink_account(&request.headers, secure_cookie, &input.provider_id)
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({"status": true})))
            }
            (Method::POST, "/two-factor/verify") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, TWO_FACTOR_PLUGIN)?;
                let input: ChallengeInput = parse_json(&request.body)?;
                self.enforce_action_limit(&request_context, "two-factor-verify", None)
                    .await?;
                let service = self.second_factor()?;
                let user_id = service
                    .complete_challenge(&input.challenge_token, &input.code)
                    .await?;
                let user = self
                    .context
                    .adapter
                    .find_one("user", Query::new().eq("id", user_id))
                    .await?
                    .ok_or(AuthError::Unauthorized)?;
                let user: User = serde_json::from_value(user)
                    .map_err(|error| AuthError::Adapter(error.to_string()))?;
                let result = self
                    .complete_session(user, secure_cookie, "two-factor")
                    .await?;
                Ok(auth_result_response(StatusCode::OK, result))
            }
            (Method::GET, "/ok") => Ok(HttpResponse::json(StatusCode::OK, json!({"ok": true}))),
            (Method::GET, "/get-session") | (Method::POST, "/get-session") => {
                if request.method == Method::POST {
                    // POST takes the same route as GET for clients that send a body.
                    // It can refresh the session cookie, so it gets the origin check.
                    check_csrf(&request_context, &request.metadata())?;
                }
                let result = self
                    .email_password
                    .session_from_cookie(&request.headers, secure_cookie)
                    .await?;
                let has_session = result.is_some();
                let mut response = match result {
                    Some((user, session)) => HttpResponse::json(
                        StatusCode::OK,
                        json!({"user": user, "session": session}),
                    ),
                    None => HttpResponse::json(StatusCode::OK, Value::Null),
                };
                if has_session {
                    if let Some(cookie) = self
                        .email_password
                        .refresh_session_cookie(&request.headers, secure_cookie)
                        .await?
                    {
                        response = response.with_cookie(cookie.to_set_cookie_header());
                    }
                }
                Ok(response)
            }
            (Method::POST, "/sign-out") => {
                check_csrf(&request_context, &request.metadata())?;
                let cookie = self
                    .email_password
                    .sign_out(&request.headers, secure_cookie)
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({}))
                    .with_cookie(cookie.to_set_cookie_header()))
            }
            (Method::POST, "/verify-email") => {
                check_csrf(&request_context, &request.metadata())?;
                self.enforce_action_limit(&request_context, "verify-email", None)
                    .await?;
                let input: TokenInput = parse_json(&request.body)?;
                let service = self.email_verification.as_ref().ok_or_else(|| {
                    AuthError::InvalidConfiguration("verification storage is not configured".into())
                })?;
                let verified = service.verify(&input.token).await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({"verified": verified}),
                ))
            }
            (Method::POST, "/request-password-reset") => {
                check_csrf(&request_context, &request.metadata())?;
                self.check_captcha(&request.headers, &request_context)
                    .await?;
                let input: EmailInput = parse_json(&request.body)?;
                self.enforce_action_limit(
                    &request_context,
                    "request-password-reset",
                    Some(&input.email),
                )
                .await?;
                let service = self.password_reset.as_ref().ok_or_else(|| {
                    AuthError::InvalidConfiguration("verification storage is not configured".into())
                })?;
                // The response is identical whether or not the account exists,
                // so delivery must not change what the caller sees.
                if let Some(token) = service
                    .issue(&input.email, std::time::Duration::from_secs(15 * 60))
                    .await?
                {
                    if let Some(sender) = &self.email_sender {
                        let url = self.app_url("/reset-password", &token)?;
                        let to = input.email.trim().to_ascii_lowercase();
                        deliver(sender.as_ref(), password_reset_message(&to, &url)).await;
                    }
                }
                Ok(HttpResponse::json(StatusCode::OK, json!({"sent": true})))
            }
            (Method::POST, "/reset-password") => {
                check_csrf(&request_context, &request.metadata())?;
                self.enforce_action_limit(&request_context, "reset-password", None)
                    .await?;
                let input: PasswordResetInput = parse_json(&request.body)?;
                self.check_password_breach(&input.new_password).await?;
                let service = self.password_reset.as_ref().ok_or_else(|| {
                    AuthError::InvalidConfiguration("verification storage is not configured".into())
                })?;
                let reset = service.reset(&input.token, &input.new_password).await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({"reset": reset})))
            }
            (Method::GET, "/list-sessions") => {
                let sessions = self
                    .account
                    .list_sessions(&request.headers, secure_cookie)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "sessions": sessions }),
                ))
            }
            (Method::POST, "/revoke-session") => {
                check_csrf(&request_context, &request.metadata())?;
                let input: SessionIdInput = parse_json(&request.body)?;
                let outcome = self
                    .account
                    .revoke_session(&request.headers, secure_cookie, &input.id)
                    .await?;
                let response =
                    HttpResponse::json(StatusCode::OK, json!({ "revoked": outcome.revoked }));
                Ok(match outcome.cookie {
                    Some(cookie) => response.with_cookie(cookie.to_set_cookie_header()),
                    None => response,
                })
            }
            (Method::POST, "/revoke-other-sessions") => {
                check_csrf(&request_context, &request.metadata())?;
                let revoked = self
                    .account
                    .revoke_other_sessions(&request.headers, secure_cookie)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "revoked": revoked }),
                ))
            }
            (Method::POST, "/revoke-sessions") => {
                check_csrf(&request_context, &request.metadata())?;
                let cookie = self
                    .account
                    .revoke_all_sessions(&request.headers, secure_cookie)
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({}))
                    .with_cookie(cookie.to_set_cookie_header()))
            }
            (Method::POST, "/send-verification-email") => {
                check_csrf(&request_context, &request.metadata())?;
                let (user, _) = self
                    .email_password
                    .session_from_cookie(&request.headers, secure_cookie)
                    .await?
                    .ok_or(AuthError::Unauthorized)?;
                if !user.email_verified {
                    let service = self.email_verification.as_ref().ok_or_else(|| {
                        AuthError::InvalidConfiguration(
                            "verification storage is not configured".into(),
                        )
                    })?;
                    let token = service
                        .issue(&user.id, std::time::Duration::from_secs(24 * 60 * 60))
                        .await?;
                    if let Some(sender) = &self.email_sender {
                        let url = self.app_url("/verify-email", &token)?;
                        deliver(sender.as_ref(), verification_message(&user.email, &url)).await;
                    }
                }
                Ok(HttpResponse::json(StatusCode::OK, json!({"sent": true})))
            }
            (Method::GET, path) if path.starts_with("/sign-in/social/") => {
                let id = &path["/sign-in/social/".len()..];
                // The state lives in secondary storage; the browser only gets the
                // provider redirect. A state cookie would be a second copy.
                let url = self.social_begin(id, secure_cookie).await?;
                let mut response = HttpResponse {
                    status: StatusCode::FOUND,
                    headers: HeaderMap::new(),
                    body: Vec::new(),
                };
                response.headers.insert(
                    header::LOCATION,
                    url.parse()
                        .map_err(|_| AuthError::Adapter("invalid authorization URL".into()))?,
                );
                Ok(response)
            }
            (Method::POST, "/sign-in/social") => {
                check_csrf(&request_context, &request.metadata())?;
                self.enforce_action_limit(&request_context, "social-sign-in", None)
                    .await?;
                let input: SocialSignInInput = parse_json(&request.body)?;
                let url = self.social_begin(&input.provider, secure_cookie).await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({"url": url, "redirect": false}),
                ))
            }
            (Method::GET, path) if path.starts_with("/callback/") => {
                let id = &path["/callback/".len()..];
                let social = self.social.as_ref().ok_or(AuthError::NotFound)?;
                let provider = social.registry.get(id).ok_or(AuthError::NotFound)?;
                let params = query_params(&request.uri);
                if let Some(error) = params.get("error") {
                    return Ok(HttpResponse::error(
                        StatusCode::BAD_REQUEST,
                        format!("provider returned an error: {error}"),
                    ));
                }
                let (Some(code), Some(state)) = (params.get("code"), params.get("state")) else {
                    return Ok(HttpResponse::error(
                        StatusCode::BAD_REQUEST,
                        "callback requires code and state",
                    ));
                };
                let result = social
                    .service
                    .complete(&provider, code, state, None, secure_cookie)
                    .await?;
                self.record_login_method(&result.user.id, &format!("social:{id}"))
                    .await?;
                let mut response = HttpResponse {
                    status: StatusCode::FOUND,
                    headers: HeaderMap::new(),
                    body: Vec::new(),
                };
                response
                    .headers
                    .insert(header::LOCATION, "/".parse().expect("static location"));
                Ok(response.with_cookie(result.cookie.to_set_cookie_header()))
            }
            (Method::GET, "/admin/list-users") => {
                require_plugin(&self.context, ADMIN_PLUGIN)?;
                let (actor, _) = self.current_user(&request.headers, secure_cookie).await?;
                let params = query_params(&request.uri);
                let limit = params
                    .get("limit")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(50);
                let offset = params
                    .get("offset")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
                let users = self
                    .admin_service()
                    .list_users(&actor.id, limit, offset)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "users": users }),
                ))
            }
            (Method::POST, "/admin/set-role") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ADMIN_PLUGIN)?;
                let input: SetRoleInput = parse_json(&request.body)?;
                let (actor, _) = self.current_user(&request.headers, secure_cookie).await?;
                self.admin_service()
                    .set_role(&actor.id, &input.user_id, &input.role)
                    .await?;
                tracing::info!(
                    actor_id = %actor.id,
                    target_id = %input.user_id,
                    role = %input.role,
                    "admin changed a user role"
                );
                Ok(HttpResponse::json(StatusCode::OK, json!({"updated": true})))
            }
            (Method::POST, "/admin/ban-user") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ADMIN_PLUGIN)?;
                let input: BanUserInput = parse_json(&request.body)?;
                let (actor, _) = self.current_user(&request.headers, secure_cookie).await?;
                let user = self
                    .admin_service()
                    .ban_user(
                        &actor.id,
                        &input.user_id,
                        input.ban_reason.as_deref(),
                        input.ban_expires_in,
                    )
                    .await?;
                tracing::info!(
                    actor_id = %actor.id,
                    target_id = %input.user_id,
                    expires_in = ?input.ban_expires_in,
                    "admin banned a user"
                );
                Ok(HttpResponse::json(StatusCode::OK, json!({ "user": user })))
            }
            (Method::POST, "/admin/unban-user") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ADMIN_PLUGIN)?;
                let input: TargetUserInput = parse_json(&request.body)?;
                let (actor, _) = self.current_user(&request.headers, secure_cookie).await?;
                let user = self
                    .admin_service()
                    .unban_user(&actor.id, &input.user_id)
                    .await?;
                tracing::info!(actor_id = %actor.id, target_id = %input.user_id, "admin lifted a ban");
                Ok(HttpResponse::json(StatusCode::OK, json!({ "user": user })))
            }
            (Method::POST, "/admin/list-user-sessions") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ADMIN_PLUGIN)?;
                let input: TargetUserInput = parse_json(&request.body)?;
                let (actor, _) = self.current_user(&request.headers, secure_cookie).await?;
                let sessions = self
                    .admin_service()
                    .list_user_sessions(&actor.id, &input.user_id)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "sessions": sessions }),
                ))
            }
            (Method::POST, "/admin/revoke-user-session") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ADMIN_PLUGIN)?;
                let input: SessionIdInput = parse_json(&request.body)?;
                let (actor, _) = self.current_user(&request.headers, secure_cookie).await?;
                let revoked = self
                    .admin_service()
                    .revoke_user_session(&actor.id, &input.id)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "revoked": revoked }),
                ))
            }
            (Method::POST, "/admin/remove-user") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ADMIN_PLUGIN)?;
                let input: TargetUserInput = parse_json(&request.body)?;
                let (actor, _) = self.current_user(&request.headers, secure_cookie).await?;
                self.admin_service()
                    .remove_user(&actor.id, &input.user_id)
                    .await?;
                tracing::info!(actor_id = %actor.id, target_id = %input.user_id, "admin removed a user");
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "removed": true }),
                ))
            }
            (Method::POST, "/admin/revoke-sessions")
            | (Method::POST, "/admin/revoke-user-sessions") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ADMIN_PLUGIN)?;
                let input: TargetUserInput = parse_json(&request.body)?;
                let (actor, _) = self.current_user(&request.headers, secure_cookie).await?;
                let revoked = self
                    .admin_service()
                    .revoke_user_sessions(&actor.id, &input.user_id)
                    .await?;
                tracing::info!(
                    actor_id = %actor.id,
                    target_id = %input.user_id,
                    revoked,
                    "admin revoked a user's sessions"
                );
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "revoked": revoked }),
                ))
            }
            (Method::POST, "/sign-in/magic-link") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, MAGIC_LINK_PLUGIN)?;
                let input: EmailInput = parse_json(&request.body)?;
                self.enforce_action_limit(&request_context, "magic-link", Some(&input.email))
                    .await?;
                let sender = self.sender()?;
                let to = input.email.trim().to_ascii_lowercase();
                let token = self.passwordless()?.issue_magic_link(&to).await?;
                let link = self.api_url("/magic-link/verify", &token)?;
                deliver(sender.as_ref(), magic_link_message(&to, &link)).await;
                Ok(HttpResponse::json(StatusCode::OK, json!({"sent": true})))
            }
            (Method::GET, "/magic-link/verify") => {
                require_plugin(&self.context, MAGIC_LINK_PLUGIN)?;
                let token = query_params(&request.uri)
                    .get("token")
                    .cloned()
                    .ok_or_else(|| AuthError::InvalidRequest("token is required".into()))?;
                let user = self.passwordless()?.consume_magic_link(&token).await?;
                let result = self
                    .complete_session(user, secure_cookie, "magic-link")
                    .await?;
                let mut response = HttpResponse {
                    status: StatusCode::FOUND,
                    headers: HeaderMap::new(),
                    body: Vec::new(),
                };
                response
                    .headers
                    .insert(header::LOCATION, "/".parse().expect("static location"));
                Ok(response.with_cookie(result.cookie.to_set_cookie_header()))
            }
            (Method::POST, "/email-otp/send") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, EMAIL_OTP_PLUGIN)?;
                let input: EmailInput = parse_json(&request.body)?;
                self.enforce_action_limit(&request_context, "email-otp-send", Some(&input.email))
                    .await?;
                let sender = self.sender()?;
                let to = input.email.trim().to_ascii_lowercase();
                let code = self.passwordless()?.issue_email_otp(&to).await?;
                deliver(sender.as_ref(), email_otp_message(&to, &code)).await;
                Ok(HttpResponse::json(StatusCode::OK, json!({"sent": true})))
            }
            (Method::POST, "/admin/create-user") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ADMIN_PLUGIN)?;
                let input: CreateUserInput = parse_json(&request.body)?;
                let (actor, _) = self.current_user(&request.headers, secure_cookie).await?;
                self.admin_service().ensure_admin(&actor.id).await?;
                crate::email_password::validate_password(&input.password)?;
                let password_hash = self.context.password_provider.hash(&input.password).await?;
                let created = CredentialService::new(self.context.clone())
                    .import(ImportCredential {
                        id: None,
                        email: input.email.clone(),
                        name: input.name.clone(),
                        email_verified: false,
                        password_hash,
                        additional_fields: Default::default(),
                    })
                    .await?;
                let user = match input.role {
                    Some(role) => {
                        self.admin_service()
                            .update_user(&actor.id, &created.id, None, Some(&role))
                            .await?
                    }
                    None => {
                        self.admin_service()
                            .get_user(&actor.id, &created.id)
                            .await?
                    }
                };
                tracing::info!(actor_id = %actor.id, target_id = %created.id, "admin created a user");
                Ok(HttpResponse::json(StatusCode::OK, json!({ "user": user })))
            }
            (Method::GET, "/admin/get-user") => {
                require_plugin(&self.context, ADMIN_PLUGIN)?;
                let (actor, _) = self.current_user(&request.headers, secure_cookie).await?;
                let user_id = query_params(&request.uri)
                    .get("id")
                    .cloned()
                    .unwrap_or_default();
                let user = self.admin_service().get_user(&actor.id, &user_id).await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({ "user": user })))
            }
            (Method::POST, "/admin/update-user") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ADMIN_PLUGIN)?;
                let input: AdminUpdateUserInput = parse_json(&request.body)?;
                let (actor, _) = self.current_user(&request.headers, secure_cookie).await?;
                let user = self
                    .admin_service()
                    .update_user(
                        &actor.id,
                        &input.user_id,
                        input.name.as_deref(),
                        input.role.as_deref(),
                    )
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({ "user": user })))
            }
            (Method::POST, "/admin/set-user-password") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ADMIN_PLUGIN)?;
                let input: SetUserPasswordInput = parse_json(&request.body)?;
                let (actor, _) = self.current_user(&request.headers, secure_cookie).await?;
                self.admin_service().ensure_admin(&actor.id).await?;
                self.admin_service()
                    .get_user(&actor.id, &input.user_id)
                    .await?;
                let service = self.password_reset.as_ref().ok_or_else(|| {
                    AuthError::InvalidConfiguration(
                        "setting a password requires secondary storage".into(),
                    )
                })?;
                // Ends the user's sessions, as a password reset does.
                service
                    .reset_for_user(&input.user_id, &input.password)
                    .await?;
                tracing::info!(actor_id = %actor.id, target_id = %input.user_id, "admin set a user's password");
                Ok(HttpResponse::json(StatusCode::OK, json!({"status": true})))
            }
            (Method::POST, "/admin/has-permission") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ADMIN_PLUGIN)?;
                let input: AdminPermissionInput = parse_json(&request.body)?;
                let (actor, _) = self.current_user(&request.headers, secure_cookie).await?;
                let success = self.is_admin(&actor.id).await?
                    && crate::plugins::admin_grants(&input.permission);
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "success": success }),
                ))
            }
            (Method::GET, "/error") => {
                let error = query_params(&request.uri)
                    .get("error")
                    .cloned()
                    .unwrap_or_else(|| "unknown_error".into());
                let page = format!(
                    "<!doctype html><html><head><meta charset=\"utf-8\"><title>Authentication error</title></head><body><h1>Authentication error</h1><p>{}</p></body></html>",
                    html_escape(&error)
                );
                let mut response = HttpResponse {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                    body: page.into_bytes(),
                };
                response.headers.insert(
                    header::CONTENT_TYPE,
                    "text/html; charset=utf-8".parse().expect("static header"),
                );
                Ok(response)
            }
            (Method::POST, "/email-otp/request-email-change") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, EMAIL_OTP_PLUGIN)?;
                let input: RequestEmailChangeInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let to = input.new_email.trim().to_ascii_lowercase();
                self.enforce_action_limit(&request_context, "email-otp-send", Some(&to))
                    .await?;
                if to == user.email {
                    return Err(AuthError::InvalidRequest(
                        "that is already your address".into(),
                    ));
                }
                if self.user_exists_with_email(&to).await? {
                    return Err(AuthError::InvalidRequest("email is already in use".into()));
                }
                let sender = self.sender()?;
                let code = self
                    .passwordless()?
                    .issue_purpose_otp(EmailOtpPurpose::EmailChange, &to)
                    .await?;
                deliver(sender.as_ref(), email_change_code_message(&to, &code)).await;
                Ok(HttpResponse::json(StatusCode::OK, json!({"sent": true})))
            }
            (Method::POST, "/email-otp/change-email") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, EMAIL_OTP_PLUGIN)?;
                let input: ChangeEmailInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let to = input.new_email.trim().to_ascii_lowercase();
                self.enforce_action_limit(&request_context, "email-otp-verify", Some(&to))
                    .await?;
                if to == user.email {
                    return Err(AuthError::InvalidRequest(
                        "that is already your address".into(),
                    ));
                }
                // Checked before the code is spent, so a taken address does not burn it.
                if self.user_exists_with_email(&to).await? {
                    return Err(AuthError::InvalidRequest("email is already in use".into()));
                }
                if !self
                    .passwordless()?
                    .take_purpose_otp(EmailOtpPurpose::EmailChange, &to, &input.otp)
                    .await?
                {
                    return Err(AuthError::Unauthorized);
                }
                // The code was sent to the new address, so the address is verified.
                let updated = self
                    .context
                    .adapter
                    .update_where(
                        "user",
                        Query::new().eq("id", user.id.clone()),
                        json!({"email": to, "email_verified": true}),
                    )
                    .await?;
                if updated == 0 {
                    return Err(AuthError::NotFound);
                }
                Ok(HttpResponse::json(StatusCode::OK, json!({"status": true})))
            }
            (Method::POST, "/email-otp/check-verification-otp") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, EMAIL_OTP_PLUGIN)?;
                let input: CheckOtpInput = parse_json(&request.body)?;
                let purpose = EmailOtpPurpose::parse(&input.kind)?;
                if purpose == EmailOtpPurpose::EmailChange {
                    return Err(AuthError::InvalidRequest(
                        "check email change codes with a session".into(),
                    ));
                }
                self.enforce_action_limit(&request_context, "email-otp-verify", Some(&input.email))
                    .await?;
                if !self
                    .passwordless()?
                    .check_purpose_otp(purpose, &input.email, &input.otp)
                    .await?
                {
                    return Err(AuthError::Unauthorized);
                }
                Ok(HttpResponse::json(StatusCode::OK, json!({"success": true})))
            }
            (Method::GET, "/organization/get-full-organization") => {
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let organization_id = query_params(&request.uri)
                    .get("organization_id")
                    .cloned()
                    .unwrap_or_default();
                let full = self
                    .organizations()
                    .get_full(&organization_id, &user.id)
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, full))
            }
            (Method::GET, "/organization/get-invitation") => {
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let params = query_params(&request.uri);
                let organization_id = params.get("organization_id").cloned().unwrap_or_default();
                let invitation_id = params.get("invitation_id").cloned().unwrap_or_default();
                let invitation = self
                    .organizations()
                    .get_invitation(&organization_id, &user.id, &invitation_id)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "invitation": invitation }),
                ))
            }
            (Method::POST, "/email-otp/send-verification-otp") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, EMAIL_OTP_PLUGIN)?;
                let input: SendVerificationOtpInput = parse_json(&request.body)?;
                let purpose = EmailOtpPurpose::parse(&input.kind)?;
                self.send_purpose_otp(&request_context, purpose, &input.email)
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({"sent": true})))
            }
            (Method::POST, "/forget-password/email-otp")
            | (Method::POST, "/email-otp/request-password-reset") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, EMAIL_OTP_PLUGIN)?;
                let input: EmailInput = parse_json(&request.body)?;
                self.send_purpose_otp(
                    &request_context,
                    EmailOtpPurpose::PasswordReset,
                    &input.email,
                )
                .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({"sent": true})))
            }
            (Method::POST, "/sign-in/email-otp") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, EMAIL_OTP_PLUGIN)?;
                let input: OtpSignInInput = parse_json(&request.body)?;
                self.enforce_action_limit(&request_context, "email-otp-verify", Some(&input.email))
                    .await?;
                let user = self
                    .passwordless()?
                    .verify_email_otp(&input.email, &input.otp)
                    .await?;
                let result = self
                    .complete_session(user, secure_cookie, "email-otp")
                    .await?;
                Ok(auth_result_response(StatusCode::OK, result))
            }
            (Method::POST, "/email-otp/verify-email") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, EMAIL_OTP_PLUGIN)?;
                let input: OtpSignInInput = parse_json(&request.body)?;
                self.enforce_action_limit(&request_context, "email-otp-verify", Some(&input.email))
                    .await?;
                let email = input.email.trim().to_ascii_lowercase();
                if !self
                    .passwordless()?
                    .take_purpose_otp(EmailOtpPurpose::EmailVerification, &email, &input.otp)
                    .await?
                {
                    return Err(AuthError::Unauthorized);
                }
                let updated = self
                    .context
                    .adapter
                    .update_where(
                        "user",
                        Query::new().eq("email", email),
                        json!({"email_verified": true}),
                    )
                    .await?;
                if updated == 0 {
                    return Err(AuthError::Unauthorized);
                }
                Ok(HttpResponse::json(StatusCode::OK, json!({"status": true})))
            }
            (Method::POST, "/email-otp/reset-password") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, EMAIL_OTP_PLUGIN)?;
                let input: OtpResetInput = parse_json(&request.body)?;
                // Checked before the code is spent, so a weak password cannot burn it.
                crate::email_password::validate_password(&input.password)?;
                self.enforce_action_limit(&request_context, "email-otp-reset", Some(&input.email))
                    .await?;
                let email = input.email.trim().to_ascii_lowercase();
                if !self
                    .passwordless()?
                    .take_purpose_otp(EmailOtpPurpose::PasswordReset, &email, &input.otp)
                    .await?
                {
                    return Err(AuthError::Unauthorized);
                }
                let user_id = self
                    .context
                    .adapter
                    .find_one("user", Query::new().eq("email", email))
                    .await?
                    .and_then(|user| user["id"].as_str().map(str::to_owned))
                    .ok_or(AuthError::Unauthorized)?;
                let service = self.password_reset.as_ref().ok_or_else(|| {
                    AuthError::InvalidConfiguration(
                        "password reset requires secondary storage".into(),
                    )
                })?;
                service.reset_for_user(&user_id, &input.password).await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({"status": true})))
            }
            (Method::POST, "/email-otp/verify") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, EMAIL_OTP_PLUGIN)?;
                let input: EmailOtpVerifyInput = parse_json(&request.body)?;
                self.enforce_action_limit(&request_context, "email-otp-verify", Some(&input.email))
                    .await?;
                let user = self
                    .passwordless()?
                    .verify_email_otp(&input.email, &input.code)
                    .await?;
                let result = self
                    .complete_session(user, secure_cookie, "email-otp")
                    .await?;
                Ok(auth_result_response(StatusCode::OK, result))
            }
            (Method::GET, "/metrics") if self.metrics_endpoint => {
                Ok(HttpResponse::json(StatusCode::OK, self.metrics.snapshot()))
            }
            (Method::GET, "/ready") => {
                // Readiness means the database answers a query, not just that the process runs.
                match self
                    .context
                    .adapter
                    .find_many("user", Query::new().limit(1))
                    .await
                {
                    Ok(_) => Ok(HttpResponse::json(
                        StatusCode::OK,
                        json!({"status": "ready"}),
                    )),
                    Err(_) => Ok(HttpResponse::json(
                        StatusCode::SERVICE_UNAVAILABLE,
                        json!({"status": "unavailable"}),
                    )),
                }
            }
            (Method::POST, "/api-key/create") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, API_KEY_PLUGIN)?;
                let input: CreateApiKeyInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let created = self
                    .api_keys()?
                    .create(
                        &user.id,
                        &input.name,
                        &input.scopes.unwrap_or_default(),
                        input.expires_in.map(std::time::Duration::from_secs),
                    )
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({"key": created.key, "api_key": created.view}),
                ))
            }
            (Method::GET, "/api-key/list") => {
                require_plugin(&self.context, API_KEY_PLUGIN)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let keys = self.api_keys()?.list(&user.id).await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "api_keys": keys }),
                ))
            }
            (Method::POST, "/api-key/revoke") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, API_KEY_PLUGIN)?;
                let input: ApiKeyIdInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let revoked = self.api_keys()?.revoke(&user.id, &input.id).await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "revoked": revoked }),
                ))
            }
            (Method::GET, "/api-key/verify") => {
                require_plugin(&self.context, API_KEY_PLUGIN)?;
                let presented = request
                    .headers
                    .get("x-api-key")
                    .and_then(|value| value.to_str().ok())
                    .ok_or(AuthError::Unauthorized)?;
                let key = self.api_keys()?.authenticate(presented, None).await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({"user_id": key.user_id, "key_id": key.key_id, "scopes": key.scopes}),
                ))
            }
            (Method::POST, "/one-time-token/generate") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ONE_TIME_TOKEN_PLUGIN)?;
                let input: OneTimeTokenGenerateInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let token = self
                    .one_time_tokens()?
                    .generate(
                        &user.id,
                        &input.purpose,
                        std::time::Duration::from_secs(input.expires_in),
                    )
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "token": token }),
                ))
            }
            (Method::POST, "/one-time-token/verify") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ONE_TIME_TOKEN_PLUGIN)?;
                let input: OneTimeTokenUseInput = parse_json(&request.body)?;
                self.enforce_action_limit(&request_context, "one-time-token-verify", None)
                    .await?;
                let user_id = self
                    .one_time_tokens()?
                    .verify(&input.purpose, &input.token)
                    .await?
                    .ok_or(AuthError::Unauthorized)?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "user_id": user_id }),
                ))
            }
            (Method::POST, "/one-time-token/revoke") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ONE_TIME_TOKEN_PLUGIN)?;
                let input: OneTimeTokenUseInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let revoked = self
                    .one_time_tokens()?
                    .revoke(&user.id, &input.purpose, &input.token)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "revoked": revoked }),
                ))
            }
            (Method::POST, "/passkey/generate-register-options") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, PASSKEY_PLUGIN)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let existing = self.passkey_store().list_for_user(&user.id).await?;
                let (transaction_id, options) = self
                    .passkey_service()?
                    .start_registration_persisted(
                        passkey_user_handle(&user.id),
                        &user.email,
                        &user.name,
                        existing
                            .into_iter()
                            .map(|stored| stored.credential)
                            .collect(),
                    )
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({"transaction_id": transaction_id, "options": options}),
                ))
            }
            (Method::POST, "/passkey/verify-registration") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, PASSKEY_PLUGIN)?;
                let input: PasskeyRegisterInput = parse_json(&request.body)?;
                let name = input.name.as_deref().map(passkey_name).transpose()?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let credential = self
                    .passkey_service()?
                    .finish_registration_persisted(
                        &input.transaction_id,
                        passkey_user_handle(&user.id),
                        input.response,
                    )
                    .await?;
                let stored = self
                    .passkey_store()
                    .insert(&user.id, name.as_deref(), &credential)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({"passkey": stored.view()}),
                ))
            }
            (Method::POST, "/passkey/generate-authenticate-options") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, PASSKEY_PLUGIN)?;
                self.enforce_action_limit(&request_context, "passkey-options", None)
                    .await?;
                let (transaction_id, options) = self
                    .passkey_service()?
                    .start_discoverable_persisted()
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({"transaction_id": transaction_id, "options": options}),
                ))
            }
            (Method::POST, "/passkey/verify-authentication") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, PASSKEY_PLUGIN)?;
                let input: PasskeyVerifyInput = parse_json(&request.body)?;
                self.enforce_action_limit(&request_context, "passkey-verify", None)
                    .await?;
                let service = self.passkey_service()?;
                let store = self.passkey_store();
                // The response names its credential before it is verified. That
                // credential is the only one the verification may use.
                let credential_id = credential_key_from_response(&input.response)?;
                let mut stored = store
                    .find_by_credential(&credential_id)
                    .await?
                    .ok_or(AuthError::Unauthorized)?;
                service
                    .finish_discoverable_persisted(
                        &input.transaction_id,
                        input.response,
                        &mut stored.credential,
                    )
                    .await?;
                // Persist the advanced signature counter so a cloned authenticator
                // replaying an old counter is refused on its next sign-in.
                store
                    .update_credential(&stored.id, &stored.credential)
                    .await?;
                let user = self
                    .user_by_id(&stored.user_id)
                    .await?
                    .ok_or(AuthError::Unauthorized)?;
                self.finish_password_sign_in(user, secure_cookie, "passkey")
                    .await
            }
            (Method::GET, "/passkey/list-user-passkeys") => {
                require_plugin(&self.context, PASSKEY_PLUGIN)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let passkeys: Vec<Value> = self
                    .passkey_store()
                    .list_for_user(&user.id)
                    .await?
                    .iter()
                    .map(StoredPasskey::view)
                    .collect();
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({"passkeys": passkeys}),
                ))
            }
            (Method::POST, "/passkey/update-passkey") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, PASSKEY_PLUGIN)?;
                let input: PasskeyRenameInput = parse_json(&request.body)?;
                let name = passkey_name(&input.name)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let updated = self
                    .passkey_store()
                    .rename(&user.id, &input.id, &name)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "updated": updated }),
                ))
            }
            (Method::POST, "/passkey/delete-passkey") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, PASSKEY_PLUGIN)?;
                let input: PasskeyIdInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let deleted = self.passkey_store().delete(&user.id, &input.id).await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "deleted": deleted }),
                ))
            }
            (Method::POST, "/device/code") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, DEVICE_PLUGIN)?;
                let input: DeviceCodeInput = parse_json(&request.body)?;
                self.enforce_action_limit(&request_context, "device-code", None)
                    .await?;
                let grant = self.device_auth()?.start(&input.client_id).await?;
                Ok(HttpResponse::json(StatusCode::OK, grant))
            }
            (Method::GET, "/device") => {
                require_plugin(&self.context, DEVICE_PLUGIN)?;
                let user_code = query_params(&request.uri)
                    .get("user_code")
                    .cloned()
                    .unwrap_or_default();
                let pending = self.device_auth()?.is_pending(&user_code).await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({"user_code": user_code, "pending": pending}),
                ))
            }
            (Method::POST, "/device/approve") | (Method::POST, "/device/deny") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, DEVICE_PLUGIN)?;
                let input: UserCodeInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                self.enforce_action_limit(&request_context, "device-decide", Some(&user.email))
                    .await?;
                let service = self.device_auth()?;
                let changed = if endpoint_path_name == "/device/approve" {
                    service.approve(&user.id, &input.user_code).await?
                } else {
                    service.deny(&input.user_code).await?
                };
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "changed": changed }),
                ))
            }
            (Method::POST, "/device/token") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, DEVICE_PLUGIN)?;
                let input: DeviceTokenInput = parse_json(&request.body)?;
                if input.grant_type != DEVICE_GRANT_TYPE {
                    return Ok(device_error("unsupported_grant_type"));
                }
                self.enforce_action_limit(&request_context, "device-token", None)
                    .await?;
                match self
                    .device_auth()?
                    .poll(&input.device_code, &input.client_id)
                    .await
                {
                    Ok(PollOutcome::Pending) => Ok(device_error("authorization_pending")),
                    Ok(PollOutcome::SlowDown) => Ok(device_error("slow_down")),
                    Ok(PollOutcome::AccessDenied) => Ok(device_error("access_denied")),
                    Ok(PollOutcome::Expired) => Ok(device_error("expired_token")),
                    Ok(PollOutcome::Approved { user_id }) => {
                        let user = self
                            .context
                            .adapter
                            .find_one("user", Query::new().eq("id", user_id))
                            .await?
                            .ok_or(AuthError::Unauthorized)?;
                        let user: User = serde_json::from_value(user)
                            .map_err(|error| AuthError::Adapter(error.to_string()))?;
                        let result = self
                            .complete_session(user, secure_cookie, "device-authorization")
                            .await?;
                        Ok(HttpResponse::json(
                            StatusCode::OK,
                            json!({
                                "access_token": result.session_token,
                                "token_type": "Bearer",
                                "expires_in": self.context.options.session.expires_in_seconds,
                            }),
                        ))
                    }
                    Err(AuthError::Unauthorized) => Ok(device_error("invalid_grant")),
                    Err(error) => Err(error),
                }
            }
            (Method::POST, "/sign-in/anonymous") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ANONYMOUS_PLUGIN)?;
                self.enforce_action_limit(&request_context, "anonymous-sign-in", None)
                    .await?;
                // The address is synthetic and reserved for `.invalid`, so it can
                // never receive mail and never collides with a real account.
                let id = Uuid::new_v4().to_string();
                let user = User {
                    id: id.clone(),
                    email: format!("anonymous-{id}@anonymous.invalid"),
                    name: "Guest".into(),
                    email_verified: false,
                    image: None,
                    additional_fields: serde_json::Map::new(),
                };
                let mut record = serde_json::to_value(&user)
                    .map_err(|error| AuthError::Adapter(error.to_string()))?;
                record["is_anonymous"] = json!(true);
                self.context.adapter.insert_record("user", record).await?;
                let result = self
                    .complete_session(user, secure_cookie, "anonymous")
                    .await?;
                Ok(auth_result_response(StatusCode::OK, result))
            }
            (Method::POST, "/anonymous/upgrade") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ANONYMOUS_PLUGIN)?;
                let input: UpgradeInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                if !self.is_anonymous(&user.id).await? {
                    return Err(AuthError::Forbidden(
                        "only guest accounts can be upgraded".into(),
                    ));
                }
                let email = normalize_email(&input.email)?;
                validate_password(&input.password)?;
                if self
                    .context
                    .adapter
                    .find_one("user", Query::new().eq("email", email.clone()))
                    .await?
                    .is_some()
                {
                    return Err(AuthError::InvalidRequest(
                        "email is already registered".into(),
                    ));
                }
                let hash = self.context.password_provider.hash(&input.password).await?;
                // The user id stays the same, so everything the guest created stays attached.
                self.context
                    .adapter
                    .transaction(vec![
                        DbOperation::UpdateWhere {
                            table: "user".into(),
                            query: Query::new().eq("id", user.id.clone()),
                            changes: json!({
                                "email": email,
                                "name": input.name,
                                "is_anonymous": false,
                            }),
                        },
                        DbOperation::InsertRecord {
                            table: "account".into(),
                            record: json!({
                                "id": format!("{}:credential", user.id),
                                "user_id": user.id,
                                "provider_id": "credential",
                                "account_id": email,
                                "password_hash": hash,
                            }),
                        },
                    ])
                    .await?;
                let stored = self
                    .context
                    .adapter
                    .find_one("user", Query::new().eq("id", user.id.clone()))
                    .await?
                    .ok_or(AuthError::NotFound)?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "user": stored }),
                ))
            }
            (Method::POST, "/delete-anonymous-user") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ANONYMOUS_PLUGIN)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                if !self.is_anonymous(&user.id).await? {
                    return Err(AuthError::Forbidden(
                        "only guest accounts can be deleted here".into(),
                    ));
                }
                self.context
                    .adapter
                    .transaction(vec![
                        DbOperation::DeleteWhere {
                            table: "session".into(),
                            query: Query::new().eq("user_id", user.id.clone()),
                        },
                        DbOperation::DeleteWhere {
                            table: "account".into(),
                            query: Query::new().eq("user_id", user.id.clone()),
                        },
                        DbOperation::DeleteWhere {
                            table: "user".into(),
                            query: Query::new().eq("id", user.id.clone()),
                        },
                    ])
                    .await?;
                let cookie = self
                    .email_password
                    .sign_out(&request.headers, secure_cookie)
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({}))
                    .with_cookie(cookie.to_set_cookie_header()))
            }
            (Method::GET, "/last-login-method") => {
                require_plugin(&self.context, LAST_LOGIN_PLUGIN)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let method = self
                    .context
                    .adapter
                    .find_one("user", Query::new().eq("id", user.id.clone()))
                    .await?
                    .and_then(|row| row.get("last_login_method").cloned())
                    .unwrap_or(Value::Null);
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "method": method }),
                ))
            }
            (Method::POST, "/one-tap/callback") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ONE_TAP_PLUGIN)?;
                let input: OneTapInput = parse_json(&request.body)?;
                self.enforce_action_limit(&request_context, "one-tap", None)
                    .await?;
                let service = self.one_tap.as_ref().ok_or_else(|| {
                    AuthError::InvalidConfiguration("one-tap is not configured".into())
                })?;
                let user = service.sign_in(&input.credential).await?;
                let result = self
                    .complete_session(user, secure_cookie, "one-tap")
                    .await?;
                Ok(auth_result_response(StatusCode::OK, result))
            }
            #[cfg(feature = "siwe")]
            (Method::POST, "/siwe/nonce") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, SIWE_PLUGIN)?;
                self.enforce_action_limit(&request_context, "siwe-nonce", None)
                    .await?;
                let nonce = self.siwe_service()?.issue_nonce().await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "nonce": nonce }),
                ))
            }
            #[cfg(feature = "siwe")]
            (Method::POST, "/siwe/verify") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, SIWE_PLUGIN)?;
                let input: SiweVerifyInput = parse_json(&request.body)?;
                self.enforce_action_limit(&request_context, "siwe-verify", None)
                    .await?;
                let user = self
                    .siwe_service()?
                    .verify(&input.message, &input.signature)
                    .await?;
                let result = self.complete_session(user, secure_cookie, "siwe").await?;
                Ok(auth_result_response(StatusCode::OK, result))
            }
            (Method::POST, "/phone-number/send-otp") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, PHONE_PLUGIN)?;
                let input: PhoneInput = parse_json(&request.body)?;
                let phone = crate::phone::normalize_phone(&input.phone)?;
                self.enforce_action_limit(&request_context, "phone-otp-send", Some(&phone))
                    .await?;
                let sender = self.phone_sender.clone().ok_or_else(|| {
                    AuthError::InvalidConfiguration("phone sign-in needs a phone sender".into())
                })?;
                let code = self.passwordless()?.issue_phone_otp(&phone).await?;
                // Delivery failures are not reported, so the response does not reveal
                // whether the number is registered.
                let _ = sender.send_code(&phone, &code).await;
                Ok(HttpResponse::json(StatusCode::OK, json!({"sent": true})))
            }
            (Method::POST, "/phone-number/verify") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, PHONE_PLUGIN)?;
                let input: PhoneVerifyInput = parse_json(&request.body)?;
                let phone = crate::phone::normalize_phone(&input.phone)?;
                self.enforce_action_limit(&request_context, "phone-otp-verify", Some(&phone))
                    .await?;
                let user = self
                    .passwordless()?
                    .verify_phone_otp(&phone, &input.code)
                    .await?;
                let result = self
                    .complete_session(user, secure_cookie, "phone-number")
                    .await?;
                Ok(auth_result_response(StatusCode::OK, result))
            }
            (Method::GET, "/organization/list") => {
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let organizations = self.organizations().list_for_user(&user.id).await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "organizations": organizations }),
                ))
            }
            (Method::POST, "/organization/create") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let input: OrganizationNameInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let organization = self.organizations().create(&input.name, &user.id).await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "organization": organization }),
                ))
            }
            (Method::GET, "/organization/list-members") => {
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let organization_id = query_params(&request.uri)
                    .get("organization_id")
                    .cloned()
                    .unwrap_or_default();
                let members = self
                    .organizations()
                    .members(&organization_id, &user.id)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "members": members }),
                ))
            }
            (Method::POST, "/organization/invite-member") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let input: InviteInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                self.enforce_action_limit(
                    &request_context,
                    "organization-invite",
                    Some(&user.email),
                )
                .await?;
                let sender = self.sender()?;
                let token = random_invitation_token();
                let invitation = self
                    .organizations()
                    .invite(
                        &input.organization_id,
                        &user.id,
                        &input.email,
                        &input.role,
                        &token,
                    )
                    .await?;
                let message = EmailMessage {
                    to: invitation.email.clone(),
                    subject: "You have been invited to an organization".into(),
                    text: format!(
                        "You were invited as {}. Accept with this one-time token, valid for 7 days:\n{}\n",
                        invitation.role, invitation.token
                    ),
                };
                deliver(sender.as_ref(), message).await;
                Ok(HttpResponse::json(StatusCode::OK, json!({"invited": true})))
            }
            (Method::POST, "/organization/accept-invitation") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let input: TokenInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let member = self
                    .organizations()
                    .accept(&user.id, &user.email, &input.token)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "member": member }),
                ))
            }
            (Method::POST, "/organization/remove-member") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let input: MemberTargetInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                self.organizations()
                    .remove_member(&input.organization_id, &user.id, &input.user_id)
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({"removed": true})))
            }
            (Method::POST, "/organization/update-member-role") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let input: MemberRoleInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                self.organizations()
                    .set_role(
                        &input.organization_id,
                        &user.id,
                        &input.user_id,
                        &input.role,
                    )
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({"updated": true})))
            }
            (Method::GET, "/organization/get-organization") => {
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let organization_id = query_params(&request.uri)
                    .get("organization_id")
                    .cloned()
                    .unwrap_or_default();
                let organization = self.organizations().get(&organization_id, &user.id).await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "organization": organization }),
                ))
            }
            (Method::POST, "/organization/update") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let input: UpdateOrganizationInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let organization = self
                    .organizations()
                    .update(
                        &input.organization_id,
                        &user.id,
                        input.name.as_deref(),
                        input.slug.as_deref(),
                    )
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "organization": organization }),
                ))
            }
            (Method::POST, "/organization/delete") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let input: OrganizationIdInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                self.organizations()
                    .delete(&input.organization_id, &user.id)
                    .await?;
                tracing::info!(actor_id = %user.id, organization_id = %input.organization_id, "organization deleted");
                Ok(HttpResponse::json(StatusCode::OK, json!({"deleted": true})))
            }
            (Method::POST, "/organization/leave") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let input: OrganizationIdInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                self.organizations()
                    .leave(&input.organization_id, &user.id)
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({"left": true})))
            }
            (Method::GET, "/organization/list-invitations") => {
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let organization_id = query_params(&request.uri)
                    .get("organization_id")
                    .cloned()
                    .unwrap_or_default();
                let invitations = self
                    .organizations()
                    .list_invitations(&organization_id, &user.id)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "invitations": invitations }),
                ))
            }
            (Method::POST, "/organization/cancel-invitation") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let input: CancelInvitationInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let cancelled = self
                    .organizations()
                    .cancel_invitation(&input.organization_id, &user.id, &input.invitation_id)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "cancelled": cancelled }),
                ))
            }
            (Method::POST, "/organization/reject-invitation") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let input: InvitationIdInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let rejected = self
                    .organizations()
                    .reject_invitation(&user.email, &input.invitation_id)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "rejected": rejected }),
                ))
            }
            (Method::GET, "/organization/list-user-invitations") => {
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let invitations = self
                    .organizations()
                    .list_user_invitations(&user.email)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "invitations": invitations }),
                ))
            }
            (Method::POST, "/organization/check-slug") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let input: SlugInput = parse_json(&request.body)?;
                let _ = self.current_user(&request.headers, secure_cookie).await?;
                let available = self.organizations().slug_available(&input.slug).await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "available": available }),
                ))
            }
            (Method::POST, "/organization/has-permission") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let input: HasPermissionInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let allowed = self
                    .organizations()
                    .has_permission(&input.organization_id, &user.id, &input.permission)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "success": allowed }),
                ))
            }
            (Method::GET, "/organization/list-teams") => {
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let organization_id = query_params(&request.uri)
                    .get("organization_id")
                    .cloned()
                    .unwrap_or_default();
                let teams = self
                    .organizations()
                    .list_teams(&organization_id, &user.id)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "teams": teams }),
                ))
            }
            (Method::POST, "/organization/create-team") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let input: CreateTeamInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let team = self
                    .organizations()
                    .create_team(&input.organization_id, &user.id, &input.name)
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({ "team": team })))
            }
            (Method::POST, "/organization/update-team") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let input: UpdateTeamInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let team = self
                    .organizations()
                    .update_team(
                        &input.organization_id,
                        &user.id,
                        &input.team_id,
                        &input.name,
                    )
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({ "team": team })))
            }
            (Method::POST, "/organization/remove-team") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let input: TeamIdInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                self.organizations()
                    .remove_team(&input.organization_id, &user.id, &input.team_id)
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({"removed": true})))
            }
            (Method::POST, "/organization/add-team-member") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let input: TeamMemberInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                self.organizations()
                    .add_team_member(
                        &input.organization_id,
                        &user.id,
                        &input.team_id,
                        &input.user_id,
                    )
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({"added": true})))
            }
            (Method::POST, "/organization/remove-team-member") => {
                check_csrf(&request_context, &request.metadata())?;
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let input: TeamMemberInput = parse_json(&request.body)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let removed = self
                    .organizations()
                    .remove_team_member(
                        &input.organization_id,
                        &user.id,
                        &input.team_id,
                        &input.user_id,
                    )
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "removed": removed }),
                ))
            }
            (Method::GET, "/organization/list-team-members") => {
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let params = query_params(&request.uri);
                let organization_id = params.get("organization_id").cloned().unwrap_or_default();
                let team_id = params.get("team_id").cloned().unwrap_or_default();
                let members = self
                    .organizations()
                    .list_team_members(&organization_id, &user.id, &team_id)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "members": members }),
                ))
            }
            (Method::GET, "/organization/list-user-teams") => {
                require_plugin(&self.context, ORGANIZATION_PLUGIN)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let teams = self.organizations().list_user_teams(&user.id).await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "teams": teams }),
                ))
            }
            (Method::GET, "/jwks") | (Method::GET, "/.well-known/jwks.json") => {
                let signer = self.jwt.as_ref().ok_or(AuthError::NotFound)?;
                Ok(HttpResponse::json(StatusCode::OK, signer.jwks()))
            }
            (Method::GET, "/token") => {
                let signer = self.jwt.as_ref().ok_or(AuthError::NotFound)?;
                let (user, _) = self.current_user(&request.headers, secure_cookie).await?;
                let mut claims = serde_json::Map::new();
                claims.insert("email".into(), json!(user.email));
                claims.insert("name".into(), json!(user.name));
                claims.insert("email_verified".into(), json!(user.email_verified));
                let token = signer.issue(&user.id, claims, JWT_TTL_SECONDS)?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "token": token, "expires_in": JWT_TTL_SECONDS }),
                ))
            }
            (Method::GET, "/openapi.json") => {
                let origin = self.context.base_origin().unwrap_or_default();
                let base_path = self.context.options.base_path.trim_end_matches('/');
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    crate::openapi::document(&format!("{origin}{base_path}")),
                ))
            }
            (Method::GET, "/health") => {
                Ok(HttpResponse::json(StatusCode::OK, json!({"status": "ok"})))
            }
            (Method::GET, "/list-accounts") => {
                let accounts = self
                    .account
                    .list_accounts(&request.headers, secure_cookie)
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "accounts": accounts }),
                ))
            }
            (Method::POST, "/change-password") => {
                check_csrf(&request_context, &request.metadata())?;
                let input: ChangePasswordInput = parse_json(&request.body)?;
                self.check_password_breach(&input.new_password).await?;
                let email = self.session_email(&request.headers, secure_cookie).await?;
                self.enforce_action_limit(&request_context, "change-password", Some(&email))
                    .await?;
                let revoked = self
                    .account
                    .change_password(
                        &request.headers,
                        secure_cookie,
                        &input.current_password,
                        &input.new_password,
                    )
                    .await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({ "changed": true, "revoked_sessions": revoked }),
                ))
            }
            (Method::POST, "/update-user") => {
                check_csrf(&request_context, &request.metadata())?;
                let input: UpdateUserInput = parse_json(&request.body)?;
                let user = self
                    .account
                    .update_user(&request.headers, secure_cookie, &input.name)
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({ "user": user })))
            }
            (Method::POST, "/delete-user") => {
                check_csrf(&request_context, &request.metadata())?;
                let input: PasswordInput = parse_json(&request.body)?;
                let email = self.session_email(&request.headers, secure_cookie).await?;
                self.enforce_action_limit(&request_context, "delete-user", Some(&email))
                    .await?;
                let cookie = self
                    .account
                    .delete_user(&request.headers, secure_cookie, &input.password)
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({}))
                    .with_cookie(cookie.to_set_cookie_header()))
            }
            _ if endpoint_path_name.starts_with('/') => Err(AuthError::NotFound),
            _ => Err(AuthError::NotFound),
        }
    }

    /// Enforces the configured budget once per client IP (when a trusted proxy
    /// supplies one) and once per account identifier, each under the action's
    /// own bucket. Without a client IP no shared fallback bucket is used: one
    /// caller could otherwise exhaust it and lock every user out.
    async fn enforce_action_limit(
        &self,
        request_context: &crate::context::RequestContext,
        action: &str,
        account: Option<&str>,
    ) -> Result<()> {
        let (Some(limiter), Some(policy)) = (&self.rate_limiter, &self.sign_in_policy) else {
            return Ok(());
        };
        let policy = RateLimitPolicy {
            name: action.to_owned(),
            ..policy.clone()
        };
        if let Some(ip) = request_context.client_ip {
            limiter.enforce(&policy, &format!("ip:{ip}")).await?;
        }
        if let Some(account) = account {
            let account = account.trim().to_ascii_lowercase();
            limiter
                .enforce(&policy, &format!("account:{account}"))
                .await?;
        }
        Ok(())
    }
}

/// Social providers that can sign users in. Clones share the same providers, so
/// a provider registered later is visible to the router and to every clone of it.
#[derive(Clone, Default)]
pub struct SocialRegistry {
    providers: Arc<std::sync::RwLock<Vec<HttpOAuthProvider>>>,
}

impl SocialRegistry {
    pub fn register(&self, provider: HttpOAuthProvider) -> Result<()> {
        let mut providers = self
            .providers
            .write()
            .map_err(|_| AuthError::Adapter("social provider registry lock poisoned".into()))?;
        if providers
            .iter()
            .any(|existing| existing.id() == provider.id())
        {
            return Err(AuthError::InvalidConfiguration(format!(
                "duplicate social provider {}",
                provider.id()
            )));
        }
        providers.push(provider);
        Ok(())
    }

    /// Removes a provider. Returns `false` when it was not registered.
    pub fn unregister(&self, id: &str) -> bool {
        let Ok(mut providers) = self.providers.write() else {
            return false;
        };
        let before = providers.len();
        providers.retain(|provider| provider.id() != id);
        providers.len() != before
    }

    pub fn get(&self, id: &str) -> Option<HttpOAuthProvider> {
        self.providers
            .read()
            .ok()?
            .iter()
            .find(|provider| provider.id() == id)
            .cloned()
    }

    pub fn ids(&self) -> Vec<String> {
        self.providers
            .read()
            .map(|providers| providers.iter().map(|p| p.id().to_owned()).collect())
            .unwrap_or_default()
    }
}

#[derive(Clone)]
struct SocialSignIn {
    service: OAuthService,
    registry: SocialRegistry,
}

fn social_callback_url(context: &AuthContext, id: &str) -> String {
    let origin = context.base_origin().unwrap_or_default();
    let base_path = context.options.base_path.trim_end_matches('/');
    format!("{origin}{base_path}/callback/{id}")
}

#[derive(serde::Deserialize)]
struct SessionIdInput {
    id: String,
}

#[derive(serde::Deserialize)]
struct ChangePasswordInput {
    current_password: String,
    new_password: String,
}

#[derive(serde::Deserialize)]
struct UpdateUserInput {
    name: String,
}

#[derive(serde::Deserialize)]
struct PasswordInput {
    password: String,
}

#[derive(serde::Deserialize)]
struct SetRoleInput {
    user_id: String,
    role: String,
}

#[derive(serde::Deserialize)]
struct TargetUserInput {
    user_id: String,
}

#[derive(serde::Deserialize)]
struct BanUserInput {
    user_id: String,
    ban_reason: Option<String>,
    ban_expires_in: Option<u64>,
}

const ADMIN_PLUGIN: &str = "admin";
const PASSKEY_PLUGIN: &str = "passkey";
const PASSKEY_RP_NAME: &str = "Better Auth";
const PASSKEY_NAME_MAX_CHARS: usize = 64;
/// Namespace for passkey user handles. Changing it would orphan every passkey,
/// because the authenticator keeps the handle it was given at registration.
const PASSKEY_HANDLE_NAMESPACE: Uuid = Uuid::from_u128(0x6f1c_2a9e_4b7d_4c3a_9e21_5a8d_0f3b_7c42);
const ONE_TIME_TOKEN_PLUGIN: &str = "one-time-token";
const MAGIC_LINK_PLUGIN: &str = "magic-link";

#[derive(serde::Deserialize)]
struct UsernameSetInput {
    username: String,
}

#[derive(serde::Deserialize)]
struct UsernameSignInInput {
    username: String,
    password: String,
}
const EMAIL_OTP_PLUGIN: &str = "email-otp";

#[derive(serde::Deserialize)]
struct EmailOtpVerifyInput {
    email: String,
    code: String,
}

fn query_params(uri: &Uri) -> HashMap<String, String> {
    uri.query()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_default()
}

#[derive(serde::Deserialize)]
struct CreateApiKeyInput {
    name: String,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(serde::Deserialize)]
struct ApiKeyIdInput {
    id: String,
}

#[derive(serde::Deserialize)]
struct OneTimeTokenGenerateInput {
    purpose: String,
    expires_in: u64,
}

#[derive(serde::Deserialize)]
struct PasskeyRegisterInput {
    transaction_id: String,
    response: Value,
    name: Option<String>,
}

#[derive(serde::Deserialize)]
struct PasskeyVerifyInput {
    transaction_id: String,
    response: Value,
}

#[derive(serde::Deserialize)]
struct PasskeyRenameInput {
    id: String,
    name: String,
}

#[derive(serde::Deserialize)]
struct UsernameAvailabilityInput {
    username: String,
}

#[derive(serde::Deserialize)]
struct UnlinkAccountInput {
    provider_id: String,
}

#[derive(serde::Deserialize)]
struct PasskeyIdInput {
    id: String,
}

#[derive(serde::Deserialize)]
struct OneTimeTokenUseInput {
    purpose: String,
    token: String,
}

#[derive(serde::Deserialize)]
struct DeviceCodeInput {
    client_id: String,
}

#[derive(serde::Deserialize)]
struct UserCodeInput {
    user_code: String,
}

#[derive(serde::Deserialize)]
struct DeviceTokenInput {
    grant_type: String,
    device_code: String,
    client_id: String,
}

const DEVICE_PLUGIN: &str = "device-authorization";
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// RFC 8628 error responses are JSON with an `error` code, not a bare status.
fn device_error(code: &str) -> HttpResponse {
    HttpResponse::json(StatusCode::BAD_REQUEST, json!({"error": code}))
}

#[derive(serde::Deserialize)]
struct UpgradeInput {
    email: String,
    password: String,
    name: String,
}

const ANONYMOUS_PLUGIN: &str = "anonymous";
const LAST_LOGIN_PLUGIN: &str = "last-login-method";

#[derive(serde::Deserialize)]
struct OneTapInput {
    credential: String,
}

const ONE_TAP_PLUGIN: &str = "one-tap";
const MULTI_SESSION_PLUGIN: &str = "multi-session";

#[derive(serde::Deserialize)]
struct SessionTokenInput {
    session_token: String,
}
const JWT_TTL_SECONDS: u64 = 15 * 60;
const ORGANIZATION_PLUGIN: &str = "organization";

#[derive(serde::Deserialize)]
struct OrganizationNameInput {
    name: String,
}

#[derive(serde::Deserialize)]
struct InviteInput {
    organization_id: String,
    email: String,
    role: String,
}

#[derive(serde::Deserialize)]
struct MemberTargetInput {
    organization_id: String,
    user_id: String,
}

#[derive(serde::Deserialize)]
struct SendVerificationOtpInput {
    email: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(serde::Deserialize)]
struct OtpSignInInput {
    email: String,
    otp: String,
}

#[derive(serde::Deserialize)]
struct OtpResetInput {
    email: String,
    otp: String,
    password: String,
}

#[derive(serde::Deserialize)]
struct CreateTeamInput {
    organization_id: String,
    name: String,
}

#[derive(serde::Deserialize)]
struct UpdateTeamInput {
    organization_id: String,
    team_id: String,
    name: String,
}

#[derive(serde::Deserialize)]
struct TeamIdInput {
    organization_id: String,
    team_id: String,
}

#[derive(serde::Deserialize)]
struct TeamMemberInput {
    organization_id: String,
    team_id: String,
    user_id: String,
}

#[derive(serde::Deserialize)]
struct CreateUserInput {
    email: String,
    name: String,
    password: String,
    role: Option<String>,
}

#[derive(serde::Deserialize)]
struct AdminUpdateUserInput {
    user_id: String,
    name: Option<String>,
    role: Option<String>,
}

#[derive(serde::Deserialize)]
struct SetUserPasswordInput {
    user_id: String,
    password: String,
}

#[derive(serde::Deserialize)]
struct AdminPermissionInput {
    permission: std::collections::BTreeMap<String, Vec<String>>,
}

#[derive(serde::Deserialize)]
struct RequestEmailChangeInput {
    new_email: String,
}

#[derive(serde::Deserialize)]
struct ChangeEmailInput {
    new_email: String,
    otp: String,
}

#[derive(serde::Deserialize)]
struct CheckOtpInput {
    email: String,
    #[serde(rename = "type")]
    kind: String,
    otp: String,
}

/// Escapes text for an HTML body.
fn html_escape(text: &str) -> String {
    text.chars()
        .map(|character| match character {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&#x27;".to_owned(),
            other => other.to_string(),
        })
        .collect()
}

#[derive(serde::Deserialize)]
struct SocialSignInInput {
    provider: String,
}

#[derive(serde::Deserialize)]
struct HasPermissionInput {
    organization_id: String,
    permission: std::collections::BTreeMap<String, Vec<String>>,
}

#[derive(serde::Deserialize)]
struct OrganizationIdInput {
    organization_id: String,
}

#[derive(serde::Deserialize)]
struct UpdateOrganizationInput {
    organization_id: String,
    name: Option<String>,
    slug: Option<String>,
}

#[derive(serde::Deserialize)]
struct CancelInvitationInput {
    organization_id: String,
    invitation_id: String,
}

#[derive(serde::Deserialize)]
struct InvitationIdInput {
    invitation_id: String,
}

#[derive(serde::Deserialize)]
struct SlugInput {
    slug: String,
}

#[derive(serde::Deserialize)]
struct MemberRoleInput {
    organization_id: String,
    user_id: String,
    role: String,
}

/// 256 bits from the OS RNG, base64url encoded.
fn random_invitation_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("operating system random source is unavailable");
    data_encoding::BASE64URL_NOPAD.encode(&bytes)
}
const PHONE_PLUGIN: &str = "phone-number";

#[derive(serde::Deserialize)]
struct PhoneInput {
    phone: String,
}

#[derive(serde::Deserialize)]
struct PhoneVerifyInput {
    phone: String,
    code: String,
}
#[cfg(feature = "siwe")]
const SIWE_PLUGIN: &str = "siwe";

#[cfg(feature = "siwe")]
#[derive(serde::Deserialize)]
struct SiweVerifyInput {
    message: String,
    signature: String,
}

#[derive(serde::Deserialize)]
struct CodeInput {
    code: String,
}

#[derive(serde::Deserialize)]
struct ChallengeInput {
    challenge_token: String,
    code: String,
}

/// The WebAuthn user handle for a user. It is derived from the user ID, so it is
/// stable across sessions and does not expose the ID to authenticators.
fn passkey_user_handle(user_id: &str) -> Uuid {
    Uuid::new_v5(&PASSKEY_HANDLE_NAMESPACE, user_id.as_bytes())
}

/// A passkey's display name: trimmed, non-empty and bounded.
fn passkey_name(name: &str) -> Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.chars().count() > PASSKEY_NAME_MAX_CHARS {
        return Err(AuthError::InvalidRequest(format!(
            "passkey name must be 1 to {PASSKEY_NAME_MAX_CHARS} characters"
        )));
    }
    Ok(trimmed.to_owned())
}

fn require_plugin(context: &AuthContext, name: &str) -> Result<()> {
    if has_plugin(context, name) {
        Ok(())
    } else {
        Err(AuthError::NotFound)
    }
}

#[derive(serde::Deserialize)]
struct TokenInput {
    token: String,
}

#[derive(serde::Deserialize)]
struct EmailInput {
    email: String,
}

#[derive(serde::Deserialize)]
struct PasswordResetInput {
    token: String,
    new_password: String,
}

/// Best-effort delivery with bounded retries. A final failure is not reported
/// to the caller, because that would reveal which addresses have accounts.
async fn deliver(sender: &dyn EmailSender, message: EmailMessage) {
    const ATTEMPTS: usize = 3;
    for _ in 0..ATTEMPTS {
        if sender.send(message.clone()).await.is_ok() {
            return;
        }
    }
}

fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body)
        .map_err(|error| AuthError::InvalidRequest(format!("invalid JSON body: {error}")))
}

fn auth_result_response(status: StatusCode, result: AuthResult) -> HttpResponse {
    HttpResponse::json(
        status,
        json!({"user": result.user, "session": result.session}),
    )
    .with_cookie(result.cookie.to_set_cookie_header())
}

pub(crate) const REQUEST_ID_HEADER: &str = "x-request-id";
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const IDEMPOTENCY_CLAIM_TTL: std::time::Duration = std::time::Duration::from_secs(60);
const IDEMPOTENCY_RECORD_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

fn hex_digest(parts: &[&str]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A response kept for replay. Only the status and the headers that matter for
/// the client are stored, together with the body, as text.
struct StoredResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
    body_digest: String,
}

impl StoredResponse {
    fn from_response(response: &HttpResponse, body_digest: String) -> Self {
        let headers = response
            .headers
            .iter()
            .filter(|(name, _)| {
                matches!(
                    name.as_str(),
                    "content-type" | "location" | "set-cookie" | "x-request-id"
                )
            })
            .filter_map(|(name, value)| {
                Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
            })
            .collect();
        Self {
            status: response.status.as_u16(),
            headers,
            body: String::from_utf8_lossy(&response.body).into_owned(),
            body_digest,
        }
    }

    fn to_value(&self) -> Value {
        json!({
            "status": self.status,
            "headers": self.headers,
            "body": self.body,
            "body_digest": self.body_digest,
        })
    }

    fn into_response(self) -> HttpResponse {
        let mut headers = HeaderMap::new();
        for (name, value) in self.headers {
            if let (Ok(name), Ok(value)) = (
                header::HeaderName::from_bytes(name.as_bytes()),
                value.parse(),
            ) {
                headers.append(name, value);
            }
        }
        headers.insert(
            "idempotent-replayed",
            "true".parse().expect("static header"),
        );
        HttpResponse {
            status: StatusCode::from_u16(self.status).unwrap_or(StatusCode::OK),
            headers,
            body: self.body.into_bytes(),
        }
    }
}

fn stored_response_from_value(value: &Value) -> Option<StoredResponse> {
    Some(StoredResponse {
        status: u16::try_from(value.get("status")?.as_u64()?).ok()?,
        headers: value
            .get("headers")?
            .as_array()?
            .iter()
            .filter_map(|pair| {
                let pair = pair.as_array()?;
                Some((
                    pair.first()?.as_str()?.to_owned(),
                    pair.get(1)?.as_str()?.to_owned(),
                ))
            })
            .collect(),
        body: value.get("body")?.as_str()?.to_owned(),
        body_digest: value.get("body_digest")?.as_str()?.to_owned(),
    })
}

/// Request counters. Labels are fixed status classes, so cardinality stays bounded.
#[derive(Default)]
pub struct Metrics {
    requests: std::sync::atomic::AtomicU64,
    success: std::sync::atomic::AtomicU64,
    redirect: std::sync::atomic::AtomicU64,
    client_error: std::sync::atomic::AtomicU64,
    server_error: std::sync::atomic::AtomicU64,
    rate_limited: std::sync::atomic::AtomicU64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct MetricsSnapshot {
    pub requests: u64,
    pub success: u64,
    pub redirect: u64,
    pub client_error: u64,
    pub server_error: u64,
    pub rate_limited: u64,
}

impl Metrics {
    fn record(&self, status: StatusCode) {
        use std::sync::atomic::Ordering::Relaxed;
        self.requests.fetch_add(1, Relaxed);
        let bucket = match status.as_u16() {
            429 => {
                self.rate_limited.fetch_add(1, Relaxed);
                &self.client_error
            }
            200..=299 => &self.success,
            300..=399 => &self.redirect,
            400..=499 => &self.client_error,
            _ => &self.server_error,
        };
        bucket.fetch_add(1, Relaxed);
    }

    fn snapshot(&self) -> MetricsSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        MetricsSnapshot {
            requests: self.requests.load(Relaxed),
            success: self.success.load(Relaxed),
            redirect: self.redirect.load(Relaxed),
            client_error: self.client_error.load(Relaxed),
            server_error: self.server_error.load(Relaxed),
            rate_limited: self.rate_limited.load(Relaxed),
        }
    }
}

fn error_response(error: AuthError, request_id: &str) -> HttpResponse {
    match error {
        AuthError::InvalidRequest(message) => HttpResponse::error(StatusCode::BAD_REQUEST, message),
        AuthError::Unauthorized => HttpResponse::error(StatusCode::UNAUTHORIZED, "unauthorized"),
        AuthError::Forbidden(message) => HttpResponse::error(StatusCode::FORBIDDEN, message),
        AuthError::NotFound => HttpResponse::error(StatusCode::NOT_FOUND, "not found"),
        AuthError::RateLimited {
            retry_after_seconds,
        } => {
            let mut response = HttpResponse::error(StatusCode::TOO_MANY_REQUESTS, "rate limited");
            response.headers.insert(
                header::RETRY_AFTER,
                retry_after_seconds.to_string().parse().unwrap(),
            );
            response
        }
        // Internal details (SQL, configuration, key material) stay out of the
        // response body. The server log carries them under the request ID.
        internal => {
            tracing::error!(request_id, error = %internal, "internal auth error");
            HttpResponse::json(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "internal server error", "request_id": request_id}),
            )
        }
    }
}

#[cfg(feature = "axum")]
pub mod axum_adapter {
    use super::{AuthRouter, HttpRequest, HttpResponse};
    use axum::{
        body::{to_bytes, Body},
        extract::State,
        response::IntoResponse,
    };
    use http::{Request, StatusCode};
    use std::sync::Arc;

    /// Upper bound for buffered request bodies. Oversized or unreadable bodies
    /// are rejected rather than replaced with an empty body.
    pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

    pub async fn handler(
        State(router): State<Arc<AuthRouter>>,
        request: Request<Body>,
    ) -> impl IntoResponse {
        let (parts, body) = request.into_parts();
        let body = match to_bytes(body, MAX_BODY_BYTES).await {
            Ok(body) => body,
            Err(_) => {
                let rejected = HttpResponse::error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body is too large or could not be read",
                );
                return (rejected.status, rejected.headers, rejected.body);
            }
        };
        let response: HttpResponse = router
            .handle(HttpRequest::new(
                parts.method,
                parts.uri,
                parts.headers,
                body.to_vec(),
            ))
            .await;
        (response.status, response.headers, response.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::{adapter::memory::MemoryDb, options::AuthOptions};
    use std::sync::Arc;

    fn router() -> AuthRouter {
        AuthRouter::new(
            AuthContext::new(
                AuthOptions {
                    secret: "r".repeat(32),
                    base_url: Some(better_auth_core::options::BaseUrl::Static(
                        "https://example.com".into(),
                    )),
                    has_database: true,
                    ..AuthOptions::default()
                },
                Arc::new(MemoryDb::default()),
                None,
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn router_exposes_signup_and_session_endpoints() {
        let router = router();
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://example.com".parse().unwrap());
        let response = router
            .handle(HttpRequest::new(
                Method::POST,
                "/api/auth/sign-up/email".parse().unwrap(),
                headers,
                br#"{"email":"router@example.com","name":"Router","password":"correct horse battery staple"}"#,
            ))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.headers.contains_key(header::SET_COOKIE));
    }

    #[cfg(feature = "axum")]
    #[tokio::test]
    async fn axum_adapter_bridges_native_requests_and_responses() {
        use axum::{body::Body, extract::State, response::IntoResponse};
        use http::Request;

        let router = Arc::new(router());
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/auth/sign-up/email")
            .header(header::ORIGIN, "https://example.com")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"email":"axum@example.com","name":"Axum","password":"correct horse battery staple"}"#,
            ))
            .unwrap();
        let response = axum_adapter::handler(State(router), request)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::SET_COOKIE).is_some());
    }

    #[tokio::test]
    async fn plugin_endpoint_access_levels_are_enforced_before_the_handler() {
        let context = AuthContext::new(
            AuthOptions {
                secret: "r".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            None,
            vec![Arc::new(EchoPlugin)],
        )
        .unwrap();
        let router = AuthRouter::new(context.clone()).unwrap();
        let origin = |mut headers: HeaderMap| {
            headers.insert(header::ORIGIN, "https://example.com".parse().unwrap());
            headers
        };
        let signup = router
            .handle(HttpRequest::new(
                Method::POST,
                "/api/auth/sign-up/email".parse().unwrap(),
                origin(HeaderMap::new()),
                br#"{"email":"plain@example.com","name":"Plain","password":"correct horse battery staple"}"#
                    .to_vec(),
            ))
            .await;
        assert_eq!(signup.status, StatusCode::OK);
        let set_cookie = signup
            .headers
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        let cookie = set_cookie.split(';').next().unwrap().to_owned();
        let call = |path: &str, cookie: Option<&str>| {
            let mut headers = origin(HeaderMap::new());
            if let Some(cookie) = cookie {
                headers.insert(header::COOKIE, cookie.parse().unwrap());
            }
            HttpRequest::new(
                Method::POST,
                format!("/api/auth{path}").parse().unwrap(),
                headers,
                Vec::new(),
            )
        };
        // Public needs no session.
        assert_eq!(
            router.handle(call("/echo", None)).await.status,
            StatusCode::OK
        );
        // Default access needs a session.
        assert_eq!(
            router.handle(call("/private", None)).await.status,
            StatusCode::UNAUTHORIZED
        );
        let private = router.handle(call("/private", Some(&cookie))).await;
        assert_eq!(private.status, StatusCode::OK);
        let body: Value = serde_json::from_slice(&private.body).unwrap();
        assert!(body["user_id"].is_string());
        // Admin access needs an administrator role stored on the user.
        assert_eq!(
            router
                .handle(call("/admin-only", Some(&cookie)))
                .await
                .status,
            StatusCode::FORBIDDEN
        );
        let user_id = body["user_id"].as_str().unwrap().to_owned();
        context
            .adapter
            .update_where(
                "user",
                Query::new().eq("id", user_id),
                json!({"role": "admin"}),
            )
            .await
            .unwrap();
        assert_eq!(
            router
                .handle(call("/admin-only", Some(&cookie)))
                .await
                .status,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn sign_in_budget_applies_per_account_even_without_a_client_ip() {
        use crate::rate_limit::{RateLimitPolicy, RateLimiter};
        use better_auth_core::adapter::memory::{MemoryDb, MemorySecondaryStorage};
        use std::time::Duration;

        let context = AuthContext::new(
            AuthOptions {
                secret: "r".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(MemoryDb::default()),
            None,
            Vec::new(),
        )
        .unwrap();
        let router = AuthRouter::new(context).unwrap().with_sign_in_rate_limit(
            RateLimiter::new(Arc::new(MemorySecondaryStorage::default()), "test"),
            RateLimitPolicy::new("unused", 2, Duration::from_secs(60)).unwrap(),
        );
        let attempt = |email: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::ORIGIN, "https://example.com".parse().unwrap());
            headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
            let body = format!(r#"{{"email":"{email}","password":"wrong password value"}}"#);
            HttpRequest::new(
                Method::POST,
                "/api/auth/sign-in/email".parse().unwrap(),
                headers,
                body.into_bytes(),
            )
        };
        assert_eq!(
            router.handle(attempt("victim@example.com")).await.status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            router.handle(attempt("victim@example.com")).await.status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            router.handle(attempt("victim@example.com")).await.status,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            router.handle(attempt("other@example.com")).await.status,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn internal_errors_do_not_leak_details() {
        let response = error_response(
            AuthError::Adapter("SQLSTATE 23505 duplicate key on user.email".into()),
            "req-123",
        );
        assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
        let body = String::from_utf8(response.body).unwrap();
        assert!(!body.contains("SQLSTATE"));
        assert!(body.contains("internal server error"));
        assert!(body.contains("req-123"));
    }

    fn account_router() -> AuthRouter {
        let context = AuthContext::new(
            AuthOptions {
                secret: "a".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            None,
            Vec::new(),
        )
        .unwrap();
        AuthRouter::new(context).unwrap()
    }

    /// Sends one request through the router. A cookie, when given, is sent as
    /// the `Cookie` header and the JSON body (if any) is parsed from the response.
    async fn send(
        router: &AuthRouter,
        method: Method,
        path: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> (StatusCode, Value, Option<String>) {
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://example.com".parse().unwrap());
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        if let Some(cookie) = cookie {
            headers.insert(header::COOKIE, cookie.parse().unwrap());
        }
        let payload = if body.is_null() {
            Vec::new()
        } else {
            body.to_string().into_bytes()
        };
        let response = router
            .handle(HttpRequest::new(
                method,
                format!("/api/auth{path}").parse().unwrap(),
                headers,
                payload,
            ))
            .await;
        let set_cookie = response
            .headers
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let json = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
        (response.status, json, set_cookie)
    }

    fn session_cookie(set_cookie: Option<String>) -> String {
        set_cookie
            .expect("expected a Set-Cookie header")
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    #[tokio::test]
    async fn account_routes_scope_sessions_and_reauthenticate_sensitive_changes() {
        const PASSWORD: &str = "correct horse battery staple";
        let router = account_router();
        let (_, _, set) = send(
            &router,
            Method::POST,
            "/sign-up/email",
            None,
            json!({"email":"owner@example.com","name":"Owner","password":PASSWORD}),
        )
        .await;
        let first = session_cookie(set);
        let (_, _, set) = send(
            &router,
            Method::POST,
            "/sign-in/email",
            None,
            json!({"email":"owner@example.com","password":PASSWORD}),
        )
        .await;
        session_cookie(set);

        // Both sessions are listed; only the caller's own cookie is "current".
        let (status, body, _) = send(
            &router,
            Method::GET,
            "/list-sessions",
            Some(&first),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let sessions = body["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions.iter().filter(|s| s["current"] == true).count(), 1);
        let second_id = sessions.iter().find(|s| s["current"] == false).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();

        // Another user cannot revoke this session, and learns nothing about it.
        let (_, _, set) = send(
            &router,
            Method::POST,
            "/sign-up/email",
            None,
            json!({"email":"intruder@example.com","name":"Intruder","password":PASSWORD}),
        )
        .await;
        let intruder = session_cookie(set);
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/revoke-session",
            Some(&intruder),
            json!({"id": second_id}),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // The owner can revoke the other session.
        let (status, body, _) = send(
            &router,
            Method::POST,
            "/revoke-session",
            Some(&first),
            json!({"id": second_id}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["revoked"], 1);
        let (_, body, _) = send(
            &router,
            Method::GET,
            "/list-sessions",
            Some(&first),
            Value::Null,
        )
        .await;
        assert_eq!(body["sessions"].as_array().unwrap().len(), 1);

        // Wrong current password is refused and nothing is revoked.
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/change-password",
            Some(&first),
            json!({"current_password":"wrong password here","new_password":"another long passphrase"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = send(
            &router,
            Method::GET,
            "/get-session",
            Some(&first),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Weak new password is refused by the shared password policy.
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/change-password",
            Some(&first),
            json!({"current_password":PASSWORD,"new_password":"short"}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Changing the password revokes other sessions and the old password stops working.
        let (_, _, set) = send(
            &router,
            Method::POST,
            "/sign-in/email",
            None,
            json!({"email":"owner@example.com","password":PASSWORD}),
        )
        .await;
        let third = session_cookie(set);
        let (status, body, _) = send(
            &router,
            Method::POST,
            "/change-password",
            Some(&first),
            json!({"current_password":PASSWORD,"new_password":"another long passphrase"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["revoked_sessions"], 1);
        let (status, _, _) = send(
            &router,
            Method::GET,
            "/get-session",
            Some(&third),
            Value::Null,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "GET returns 200 with null when no session"
        );
        let (_, body, _) = send(
            &router,
            Method::GET,
            "/get-session",
            Some(&third),
            Value::Null,
        )
        .await;
        assert!(body.is_null(), "revoked session must not resolve");
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/sign-in/email",
            None,
            json!({"email":"owner@example.com","password":PASSWORD}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Profile update and linked accounts.
        let (status, body, _) = send(
            &router,
            Method::POST,
            "/update-user",
            Some(&first),
            json!({"name":"Renamed"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["user"]["name"], "Renamed");
        let (_, body, _) = send(
            &router,
            Method::GET,
            "/list-accounts",
            Some(&first),
            Value::Null,
        )
        .await;
        let accounts = body["accounts"].as_array().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0]["provider_id"], "credential");
        assert!(accounts[0].get("password_hash").is_none());

        // Account deletion requires the password and clears the session.
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/delete-user",
            Some(&first),
            json!({"password":"wrong password here"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, set) = send(
            &router,
            Method::POST,
            "/delete-user",
            Some(&first),
            json!({"password":"another long passphrase"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(set.is_some(), "deletion must clear the session cookie");
        let (_, body, _) = send(
            &router,
            Method::GET,
            "/get-session",
            Some(&first),
            Value::Null,
        )
        .await;
        assert!(body.is_null());
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/sign-in/email",
            None,
            json!({"email":"owner@example.com","password":"another long passphrase"}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    fn token_from_message(text: &str) -> String {
        let start = text.find("token=").expect("message has a token") + "token=".len();
        text[start..]
            .chars()
            .take_while(|c| !c.is_whitespace())
            .collect()
    }

    #[tokio::test]
    async fn reset_and_verification_emails_are_delivered_and_single_use() {
        use crate::email::CapturingEmailSender;
        use better_auth_core::adapter::memory::MemorySecondaryStorage;

        const PASSWORD: &str = "correct horse battery staple";
        let context = AuthContext::new(
            AuthOptions {
                secret: "e".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            Some(Arc::new(MemorySecondaryStorage::default())),
            Vec::new(),
        )
        .unwrap();
        let sender = Arc::new(CapturingEmailSender::default());
        let router = AuthRouter::new(context)
            .unwrap()
            .with_verification_services()
            .unwrap()
            .with_email_sender(sender.clone())
            .unwrap();

        let (status, _, set) = send(
            &router,
            Method::POST,
            "/sign-up/email",
            None,
            json!({"email":"owner@example.com","name":"Owner","password":PASSWORD}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let cookie = session_cookie(set);

        // Verification email goes to the signed-in user.
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/send-verification-email",
            Some(&cookie),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let verify = sender.last().expect("verification email");
        assert_eq!(verify.to, "owner@example.com");
        assert!(verify
            .text
            .contains("https://example.com/verify-email?token="));
        let (_, body, _) = send(
            &router,
            Method::POST,
            "/verify-email",
            None,
            json!({"token": token_from_message(&verify.text)}),
        )
        .await;
        assert_eq!(body["verified"], true);

        // Reset email exists only for a real account, and the response never differs.
        let (status, existing_body, _) = send(
            &router,
            Method::POST,
            "/request-password-reset",
            None,
            json!({"email":"owner@example.com"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, unknown_body, _) = send(
            &router,
            Method::POST,
            "/request-password-reset",
            None,
            json!({"email":"nobody@example.com"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(existing_body, unknown_body);
        let messages = sender.messages();
        assert_eq!(
            messages
                .iter()
                .filter(|m| m.subject.starts_with("Reset"))
                .count(),
            1,
            "only the existing account receives a reset email"
        );

        // The emailed token resets the password once.
        let reset = messages
            .iter()
            .find(|m| m.subject.starts_with("Reset"))
            .unwrap();
        let token = token_from_message(&reset.text);
        let (_, body, _) = send(
            &router,
            Method::POST,
            "/reset-password",
            None,
            json!({"token": token.clone(), "new_password": "another long passphrase"}),
        )
        .await;
        assert_eq!(body["reset"], true);
        let (_, body, _) = send(
            &router,
            Method::POST,
            "/reset-password",
            None,
            json!({"token": token, "new_password": "yet another long passphrase"}),
        )
        .await;
        assert_eq!(body["reset"], false);
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/sign-in/email",
            None,
            json!({"email":"owner@example.com","password":"another long passphrase"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn two_factor_challenge_gates_sessions_and_codes_are_single_use() {
        use crate::plugins::{totp_code, TwoFactorPlugin};
        use better_auth_core::adapter::memory::MemorySecondaryStorage;

        const PASSWORD: &str = "correct horse battery staple";
        let context = AuthContext::new(
            AuthOptions {
                secret: "f".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            Some(Arc::new(MemorySecondaryStorage::default())),
            vec![Arc::new(TwoFactorPlugin)],
        )
        .unwrap();
        let router = AuthRouter::new(context).unwrap();
        let (_, _, set) = send(
            &router,
            Method::POST,
            "/sign-up/email",
            None,
            json!({"email":"mfa@example.com","name":"Mfa","password":PASSWORD}),
        )
        .await;
        let cookie = session_cookie(set);

        // Enrollment needs the password. The backup codes are shown only once.
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/two-factor/enable",
            Some(&cookie),
            json!({"password":"wrong password here"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, body, _) = send(
            &router,
            Method::POST,
            "/two-factor/enable",
            Some(&cookie),
            json!({"password":PASSWORD}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let secret = body["secret"].as_str().unwrap().to_owned();
        let backup: Vec<String> = body["backup_codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|code| code.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(backup.len(), 10);
        // Codes are derived from the current step at each check, so the test
        // stays inside the drift window however long the flow takes.
        let code_now =
            |offset: u64| totp_code(&secret, (now_seconds() / 30 + offset) * 30, 30, 6).unwrap();

        // Confirmation needs a valid code and then enables the second factor.
        let confirmed = code_now(0);
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/two-factor/confirm",
            Some(&cookie),
            json!({"code":"000000"}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/two-factor/confirm",
            Some(&cookie),
            json!({"code": confirmed.clone()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Sign-in returns a challenge and no session cookie.
        let (status, body, set) = send(
            &router,
            Method::POST,
            "/sign-in/email",
            None,
            json!({"email":"mfa@example.com","password":PASSWORD}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(set.is_none(), "no session before the second factor");
        assert_eq!(body["two_factor_required"], true);
        let challenge_a = body["challenge_token"].as_str().unwrap().to_owned();

        // The code confirmed above already claimed its time step, so it is refused.
        let (status, _, set) = send(
            &router,
            Method::POST,
            "/two-factor/verify",
            None,
            json!({"challenge_token": challenge_a.clone(), "code": confirmed}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(set.is_none());

        // A new time step completes the challenge, which then cannot be reused.
        let (status, _, set) = send(
            &router,
            Method::POST,
            "/two-factor/verify",
            None,
            json!({"challenge_token": challenge_a.clone(), "code": code_now(1)}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(set.is_some(), "successful challenge issues a session");
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/two-factor/verify",
            None,
            json!({"challenge_token": challenge_a, "code": backup[0].clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a challenge is consumed on success"
        );

        // A backup code works once, even across challenges.
        let challenge_b = sign_in_challenge(&router, PASSWORD).await;
        let (status, _, set) = send(
            &router,
            Method::POST,
            "/two-factor/verify",
            None,
            json!({"challenge_token": challenge_b, "code": backup[0].clone()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(set.is_some());
        let challenge_c = sign_in_challenge(&router, PASSWORD).await;
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/two-factor/verify",
            None,
            json!({"challenge_token": challenge_c, "code": backup[0].clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a backup code is single use"
        );

        // A wrong code does not end the challenge; the right one still works.
        let challenge_d = sign_in_challenge(&router, PASSWORD).await;
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/two-factor/verify",
            None,
            json!({"challenge_token": challenge_d.clone(), "code": "000000"}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/two-factor/verify",
            None,
            json!({"challenge_token": challenge_d, "code": backup[1].clone()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Disabling needs the password. Afterwards sign-in issues a session directly.
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/two-factor/disable",
            Some(&cookie),
            json!({"password":"wrong password here"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/two-factor/disable",
            Some(&cookie),
            json!({"password":PASSWORD}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body, set) = send(
            &router,
            Method::POST,
            "/sign-in/email",
            None,
            json!({"email":"mfa@example.com","password":PASSWORD}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.get("two_factor_required").is_none());
        assert!(set.is_some());
    }

    async fn sign_in_challenge(router: &AuthRouter, password: &str) -> String {
        let (_, body, _) = send(
            router,
            Method::POST,
            "/sign-in/email",
            None,
            json!({"email":"mfa@example.com","password":password}),
        )
        .await;
        body["challenge_token"].as_str().unwrap().to_owned()
    }

    fn now_seconds() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[tokio::test]
    async fn social_sign_in_redirects_with_server_side_state_and_rejects_forged_callbacks() {
        use crate::http_oauth::HttpOAuthProvider;
        let context = AuthContext::new(
            AuthOptions {
                secret: "s".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            Some(Arc::new(
                better_auth_core::adapter::memory::MemorySecondaryStorage::default(),
            )),
            Vec::new(),
        )
        .unwrap();
        let router = AuthRouter::new(context)
            .unwrap()
            .with_social_providers(vec![
                HttpOAuthProvider::google("client-1", "secret").unwrap()
            ])
            .unwrap();
        let get = |path: &str| {
            HttpRequest::new(
                Method::GET,
                format!("/api/auth{path}").parse().unwrap(),
                HeaderMap::new(),
                Vec::new(),
            )
        };

        let begin = router.handle(get("/sign-in/social/google")).await;
        assert_eq!(begin.status, StatusCode::FOUND);
        let location = begin
            .headers
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        let url = url::Url::parse(location).unwrap();
        assert_eq!(url.host_str(), Some("accounts.google.com"));
        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(params["client_id"], "client-1");
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(
            params["redirect_uri"],
            "https://example.com/api/auth/callback/google"
        );
        assert!(!params["state"].is_empty());
        assert!(!params["nonce"].is_empty());

        assert_eq!(
            router.handle(get("/sign-in/social/unknown")).await.status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            router
                .handle(get("/callback/google?error=access_denied"))
                .await
                .status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            router.handle(get("/callback/google")).await.status,
            StatusCode::BAD_REQUEST
        );
        // A state the server never issued is refused before any token exchange.
        assert_eq!(
            router
                .handle(get("/callback/google?code=abc&state=forged"))
                .await
                .status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(router.handle(get("/health")).await.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_routes_require_an_administrator_and_hide_credentials() {
        use crate::plugins::AdminPlugin;

        const PASSWORD: &str = "correct horse battery staple";
        let context = AuthContext::new(
            AuthOptions {
                secret: "m".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            None,
            vec![Arc::new(AdminPlugin)],
        )
        .unwrap();
        let router = AuthRouter::new(context.clone()).unwrap();
        let (_, admin_body, admin_set) = send(
            &router,
            Method::POST,
            "/sign-up/email",
            None,
            json!({"email":"root@example.com","name":"Root","password":PASSWORD}),
        )
        .await;
        let admin_cookie = session_cookie(admin_set);
        let admin_id = admin_body["user"]["id"].as_str().unwrap().to_owned();
        context
            .adapter
            .update_where(
                "user",
                Query::new().eq("id", admin_id.clone()),
                json!({"role": "admin"}),
            )
            .await
            .unwrap();
        let (_, target_body, target_set) = send(
            &router,
            Method::POST,
            "/sign-up/email",
            None,
            json!({"email":"member@example.com","name":"Member","password":PASSWORD}),
        )
        .await;
        let member_cookie = session_cookie(target_set);
        let member_id = target_body["user"]["id"].as_str().unwrap().to_owned();

        // Ordinary users are refused on every admin route.
        let (status, _, _) = send(
            &router,
            Method::GET,
            "/admin/list-users",
            Some(&member_cookie),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/admin/set-role",
            Some(&member_cookie),
            json!({"user_id": member_id, "role": "admin"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // The administrator lists users without any credential material.
        let (status, body, _) = send(
            &router,
            Method::GET,
            "/admin/list-users",
            Some(&admin_cookie),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let users = body["users"].as_array().unwrap();
        assert_eq!(users.len(), 2);
        assert!(users.iter().all(|user| user.get("password_hash").is_none()));

        // Role changes and forced sign-out work for the administrator.
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/admin/set-role",
            Some(&admin_cookie),
            json!({"user_id": member_id, "role": "editor"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let stored = context
            .adapter
            .find_one("user", Query::new().eq("id", member_id.clone()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored["role"], "editor");
        let (status, body, _) = send(
            &router,
            Method::POST,
            "/admin/revoke-sessions",
            Some(&admin_cookie),
            json!({"user_id": member_id}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["revoked"], 1);
        let (_, body, _) = send(
            &router,
            Method::GET,
            "/get-session",
            Some(&member_cookie),
            Value::Null,
        )
        .await;
        assert!(body.is_null());
    }

    #[tokio::test]
    async fn admin_routes_are_absent_without_the_admin_plugin() {
        let router = account_router();
        let (status, _, _) =
            send(&router, Method::GET, "/admin/list-users", None, Value::Null).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn magic_link_and_email_otp_sign_in_are_single_use_and_bounded() {
        use crate::email::CapturingEmailSender;
        use crate::plugins::{EmailOtpPlugin, MagicLinkPlugin};
        use better_auth_core::adapter::memory::MemorySecondaryStorage;

        let context = AuthContext::new(
            AuthOptions {
                secret: "w".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            Some(Arc::new(MemorySecondaryStorage::default())),
            vec![Arc::new(MagicLinkPlugin), Arc::new(EmailOtpPlugin)],
        )
        .unwrap();
        let sender = Arc::new(CapturingEmailSender::default());
        let router = AuthRouter::new(context)
            .unwrap()
            .with_email_sender(sender.clone())
            .unwrap();

        // Magic link: the response is uniform, the link works once, and the
        // first use creates a verified account.
        let (status, body, _) = send(
            &router,
            Method::POST,
            "/sign-in/magic-link",
            None,
            json!({"email":"New.Person@example.com"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["sent"], true);
        let message = sender.last().unwrap();
        assert_eq!(message.to, "new.person@example.com");
        assert!(message
            .text
            .contains("https://example.com/api/auth/magic-link/verify?token="));
        let link_token = token_from_message(&message.text);
        let verify_uri = format!("/magic-link/verify?token={link_token}");
        let (status, _, set) = send(&router, Method::GET, &verify_uri, None, Value::Null).await;
        assert_eq!(status, StatusCode::FOUND);
        assert!(set.is_some(), "a valid link issues a session");
        let (status, _, _) = send(&router, Method::GET, &verify_uri, None, Value::Null).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "a link is single use");

        // Email code: wrong guesses use up the budget, so even the right code
        // is then refused until a new code is sent.
        send(
            &router,
            Method::POST,
            "/email-otp/send",
            None,
            json!({"email":"otp@example.com"}),
        )
        .await;
        let code = sender
            .last()
            .unwrap()
            .text
            .split("code is ")
            .nth(1)
            .unwrap()
            .chars()
            .take(6)
            .collect::<String>();
        let wrong = format!("{}{}", (code.as_bytes()[0] - b'0' + 1) % 10, &code[1..]);
        for _ in 0..5 {
            let (status, _, _) = send(
                &router,
                Method::POST,
                "/email-otp/verify",
                None,
                json!({"email":"otp@example.com","code":wrong}),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/email-otp/verify",
            None,
            json!({"email":"otp@example.com","code":code}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the attempt budget is spent"
        );

        // A new code signs in once.
        send(
            &router,
            Method::POST,
            "/email-otp/send",
            None,
            json!({"email":"otp@example.com"}),
        )
        .await;
        let code = sender
            .last()
            .unwrap()
            .text
            .split("code is ")
            .nth(1)
            .unwrap()
            .chars()
            .take(6)
            .collect::<String>();
        let (status, body, set) = send(
            &router,
            Method::POST,
            "/email-otp/verify",
            None,
            json!({"email":"otp@example.com","code":code.clone()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["user"]["email"], "otp@example.com");
        assert!(set.is_some());
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/email-otp/verify",
            None,
            json!({"email":"otp@example.com","code":code}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "a code is one time");
    }

    #[tokio::test]
    async fn usernames_are_unique_case_insensitively_and_sign_in() {
        use crate::plugins::UsernamePlugin;

        const PASSWORD: &str = "correct horse battery staple";
        let context = AuthContext::new(
            AuthOptions {
                secret: "u".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            None,
            vec![Arc::new(UsernamePlugin)],
        )
        .unwrap();
        let router = AuthRouter::new(context).unwrap();
        let (_, _, set) = send(
            &router,
            Method::POST,
            "/sign-up/email",
            None,
            json!({"email":"alice@example.com","name":"Alice","password":PASSWORD}),
        )
        .await;
        let alice = session_cookie(set);
        let (_, _, set) = send(
            &router,
            Method::POST,
            "/sign-up/email",
            None,
            json!({"email":"bob@example.com","name":"Bob","password":PASSWORD}),
        )
        .await;
        let bob = session_cookie(set);

        let (status, body, _) = send(
            &router,
            Method::POST,
            "/username/set",
            Some(&alice),
            json!({"username":"Alice_01"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["username"], "alice_01");
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/username/set",
            Some(&bob),
            json!({"username":"ALICE_01"}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "taken case-insensitively");
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/username/set",
            Some(&alice),
            json!({"username":"alice_01"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "re-setting one's own name is fine");
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/username/set",
            Some(&alice),
            json!({"username":"x"}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "too short");

        let (status, _, set) = send(
            &router,
            Method::POST,
            "/sign-in/username",
            None,
            json!({"username":"ALICE_01","password":PASSWORD}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(set.is_some());
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/sign-in/username",
            None,
            json!({"username":"alice_01","password":"wrong password here"}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/sign-in/username",
            None,
            json!({"username":"nobody","password":PASSWORD}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn readiness_and_metrics_track_requests_without_exposing_secrets() {
        let router = account_router();
        let (status, body, _) = send(&router, Method::GET, "/ready", None, Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ready");
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/sign-in/email",
            None,
            json!({"email":"nobody@example.com","password":"wrong password here"}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let snapshot = router.metrics();
        assert_eq!(snapshot.requests, 2);
        assert_eq!(snapshot.success, 1);
        assert_eq!(snapshot.client_error, 1);
        // The metrics route is off unless the operator enables it.
        let (status, _, _) = send(&router, Method::GET, "/metrics", None, Value::Null).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let router = router.with_metrics_endpoint();
        let (status, body, _) = send(&router, Method::GET, "/metrics", None, Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.get("requests").is_some());
    }

    #[tokio::test]
    async fn api_keys_and_one_time_tokens_are_owned_scoped_and_single_use() {
        use crate::api_key::ApiKeyService;
        use crate::plugins::{ApiKeyPlugin, OneTimeTokenPlugin};
        use better_auth_core::adapter::memory::MemorySecondaryStorage;

        const PASSWORD: &str = "correct horse battery staple";
        let context = AuthContext::new(
            AuthOptions {
                secret: "k".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            Some(Arc::new(MemorySecondaryStorage::default())),
            vec![Arc::new(ApiKeyPlugin), Arc::new(OneTimeTokenPlugin)],
        )
        .unwrap();
        let router = AuthRouter::new(context.clone()).unwrap();
        let (_, owner_body, set) = send(
            &router,
            Method::POST,
            "/sign-up/email",
            None,
            json!({"email":"owner@example.com","name":"Owner","password":PASSWORD}),
        )
        .await;
        let owner = session_cookie(set);
        let owner_id = owner_body["user"]["id"].as_str().unwrap().to_owned();
        let (_, _, set) = send(
            &router,
            Method::POST,
            "/sign-up/email",
            None,
            json!({"email":"other@example.com","name":"Other","password":PASSWORD}),
        )
        .await;
        let other = session_cookie(set);

        // Creation returns the plaintext key once, and listing never shows it again.
        let (status, body, _) = send(
            &router,
            Method::POST,
            "/api-key/create",
            Some(&owner),
            json!({"name":"ci","scopes":["orders:read"],"expires_in":3600}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let key = body["key"].as_str().unwrap().to_owned();
        assert!(key.starts_with("ba_"));
        let key_id = body["api_key"]["id"].as_str().unwrap().to_owned();
        let (_, listed, _) = send(
            &router,
            Method::GET,
            "/api-key/list",
            Some(&owner),
            Value::Null,
        )
        .await;
        let listed_keys = listed["api_keys"].as_array().unwrap();
        assert_eq!(listed_keys.len(), 1);
        assert!(!listed.to_string().contains(&key));

        // The key authenticates as its owner, with its scopes.
        let verify = |presented: &str| {
            let mut headers = HeaderMap::new();
            headers.insert("x-api-key", presented.parse().unwrap());
            HttpRequest::new(
                Method::GET,
                "/api/auth/api-key/verify".parse().unwrap(),
                headers,
                Vec::new(),
            )
        };
        let ok = router.handle(verify(&key)).await;
        assert_eq!(ok.status, StatusCode::OK);
        let body: Value = serde_json::from_slice(&ok.body).unwrap();
        assert_eq!(body["user_id"], owner_id);
        assert_eq!(
            router.handle(verify("ba_wrong_key")).await.status,
            StatusCode::UNAUTHORIZED
        );

        // Scopes are enforced by the service.
        let service = ApiKeyService::new(context.clone()).unwrap();
        assert!(service
            .authenticate(&key, Some("orders:read"))
            .await
            .is_ok());
        assert!(matches!(
            service.authenticate(&key, Some("billing:write")).await,
            Err(better_auth_core::error::AuthError::Forbidden(_))
        ));

        // Another user cannot see or revoke the key.
        let (_, body, _) = send(
            &router,
            Method::GET,
            "/api-key/list",
            Some(&other),
            Value::Null,
        )
        .await;
        assert!(body["api_keys"].as_array().unwrap().is_empty());
        let (_, body, _) = send(
            &router,
            Method::POST,
            "/api-key/revoke",
            Some(&other),
            json!({"id": key_id}),
        )
        .await;
        assert_eq!(body["revoked"], false);

        // The owner revokes it, and it stops working at once.
        let (_, body, _) = send(
            &router,
            Method::POST,
            "/api-key/revoke",
            Some(&owner),
            json!({"id": key_id}),
        )
        .await;
        assert_eq!(body["revoked"], true);
        assert_eq!(
            router.handle(verify(&key)).await.status,
            StatusCode::UNAUTHORIZED
        );

        // One-time tokens: purpose-bound, owner-revocable, single use.
        let (status, body, _) = send(
            &router,
            Method::POST,
            "/one-time-token/generate",
            Some(&owner),
            json!({"purpose":"device-link","expires_in":60}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let token = body["token"].as_str().unwrap().to_owned();
        let (_, body, _) = send(
            &router,
            Method::POST,
            "/one-time-token/revoke",
            Some(&other),
            json!({"purpose":"device-link","token":token.clone()}),
        )
        .await;
        assert_eq!(body["revoked"], false);
        let (status, body, _) = send(
            &router,
            Method::POST,
            "/one-time-token/verify",
            None,
            json!({"purpose":"device-link","token":token.clone()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["user_id"], owner_id);
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/one-time-token/verify",
            None,
            json!({"purpose":"device-link","token":token}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a one-time token is single use"
        );
    }

    #[tokio::test]
    async fn idempotency_key_runs_a_post_once_and_refuses_key_reuse_with_a_new_body() {
        use better_auth_core::adapter::memory::MemorySecondaryStorage;

        let context = AuthContext::new(
            AuthOptions {
                secret: "i".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            Some(Arc::new(MemorySecondaryStorage::default())),
            Vec::new(),
        )
        .unwrap();
        let router = Arc::new(AuthRouter::new(context.clone()).unwrap());
        let signup = |email: &str, key: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::ORIGIN, "https://example.com".parse().unwrap());
            headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
            headers.insert("idempotency-key", key.parse().unwrap());
            let body = format!(
                r#"{{"email":"{email}","name":"Idem","password":"correct horse battery staple"}}"#
            );
            HttpRequest::new(
                Method::POST,
                "/api/auth/sign-up/email".parse().unwrap(),
                headers,
                body.into_bytes(),
            )
        };
        let users = |context: &AuthContext| {
            let adapter = context.adapter.clone();
            async move { adapter.find_many("user", Query::new()).await.unwrap().len() }
        };

        let first = router.handle(signup("once@example.com", "key-1")).await;
        assert_eq!(first.status, StatusCode::OK);
        let replay = router.handle(signup("once@example.com", "key-1")).await;
        assert_eq!(replay.status, StatusCode::OK);
        assert_eq!(
            replay.body, first.body,
            "the replay returns the stored response"
        );
        assert_eq!(replay.headers.get("idempotent-replayed").unwrap(), "true");
        assert_eq!(
            replay.headers.get(header::SET_COOKIE),
            first.headers.get(header::SET_COOKIE)
        );
        assert_eq!(
            users(&context).await,
            1,
            "the replay did not create a second account"
        );

        // The same key with a different body is refused, not silently answered.
        let conflicting = router.handle(signup("other@example.com", "key-1")).await;
        assert_eq!(conflicting.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(users(&context).await, 1);

        // Two identical requests in flight: one creates the account, and none fails with 5xx.
        let (a, b) = tokio::join!(
            router.handle(signup("race@example.com", "key-2")),
            router.handle(signup("race@example.com", "key-2"))
        );
        for response in [&a, &b] {
            assert!(
                response.status == StatusCode::OK || response.status == StatusCode::CONFLICT,
                "unexpected status {}",
                response.status
            );
        }
        assert_eq!(users(&context).await, 2);
    }

    #[tokio::test]
    async fn device_flow_polls_per_rfc_and_redeems_an_approval_once() {
        use crate::plugins::DeviceAuthorizationPlugin;
        use better_auth_core::adapter::memory::MemorySecondaryStorage;

        const PASSWORD: &str = "correct horse battery staple";
        let context = AuthContext::new(
            AuthOptions {
                secret: "d".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            Some(Arc::new(MemorySecondaryStorage::default())),
            vec![Arc::new(DeviceAuthorizationPlugin)],
        )
        .unwrap();
        let router = AuthRouter::new(context).unwrap();
        let (_, _, set) = send(
            &router,
            Method::POST,
            "/sign-up/email",
            None,
            json!({"email":"device@example.com","name":"Device","password":PASSWORD}),
        )
        .await;
        let owner = session_cookie(set);
        let grant_type = "urn:ietf:params:oauth:grant-type:device_code";
        let poll = |device_code: &str, client: &str| json!({"grant_type": grant_type, "device_code": device_code, "client_id": client});

        let (status, grant, _) = send(
            &router,
            Method::POST,
            "/device/code",
            None,
            json!({"client_id":"cli-1"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let device_code = grant["device_code"].as_str().unwrap().to_owned();
        let user_code = grant["user_code"].as_str().unwrap().to_owned();
        assert_eq!(user_code.len(), 9, "XXXX-XXXX");
        assert_eq!(grant["interval"], 5);

        // Pending, then slow down when polled again too soon.
        let (status, body, _) = send(
            &router,
            Method::POST,
            "/device/token",
            None,
            poll(&device_code, "cli-1"),
        )
        .await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("authorization_pending"))
        );
        let (_, body, _) = send(
            &router,
            Method::POST,
            "/device/token",
            None,
            poll(&device_code, "cli-1"),
        )
        .await;
        assert_eq!(body["error"], "slow_down");
        // A different client cannot use the code.
        let (_, body, _) = send(
            &router,
            Method::POST,
            "/device/token",
            None,
            poll(&device_code, "cli-2"),
        )
        .await;
        assert_eq!(body["error"], "invalid_grant");

        // Approval needs a signed-in user, and the code is looked up in any form.
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/device/approve",
            None,
            json!({"user_code": user_code}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let typed = user_code.to_ascii_lowercase().replace('-', "");
        let (_, body, _) = send(
            &router,
            Method::POST,
            "/device/approve",
            Some(&owner),
            json!({"user_code": typed}),
        )
        .await;
        assert_eq!(body["changed"], true);
        let (_, body, _) = send(
            &router,
            Method::POST,
            "/device/approve",
            Some(&owner),
            json!({"user_code": user_code}),
        )
        .await;
        assert_eq!(
            body["changed"], false,
            "a decided code cannot be approved again"
        );

        // The approved code redeems once, for a session token.
        let (status, body, _) = send(
            &router,
            Method::POST,
            "/device/token",
            None,
            poll(&device_code, "cli-1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["token_type"], "Bearer");
        assert!(!body["access_token"].as_str().unwrap().is_empty());
        let (status, body, _) = send(
            &router,
            Method::POST,
            "/device/token",
            None,
            poll(&device_code, "cli-1"),
        )
        .await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_grant"))
        );

        // A denied code reports access_denied.
        let (_, grant, _) = send(
            &router,
            Method::POST,
            "/device/code",
            None,
            json!({"client_id":"cli-1"}),
        )
        .await;
        let denied_code = grant["device_code"].as_str().unwrap().to_owned();
        let denied_user = grant["user_code"].as_str().unwrap().to_owned();
        let (_, body, _) = send(
            &router,
            Method::POST,
            "/device/deny",
            Some(&owner),
            json!({"user_code": denied_user}),
        )
        .await;
        assert_eq!(body["changed"], true);
        let (_, body, _) = send(
            &router,
            Method::POST,
            "/device/token",
            None,
            poll(&denied_code, "cli-1"),
        )
        .await;
        assert_eq!(body["error"], "access_denied");

        // Unknown grant types are refused by name.
        let (_, body, _) = send(
            &router,
            Method::POST,
            "/device/token",
            None,
            json!({"grant_type":"password","device_code":"x","client_id":"cli-1"}),
        )
        .await;
        assert_eq!(body["error"], "unsupported_grant_type");
    }

    #[tokio::test]
    async fn guest_accounts_upgrade_in_place_and_last_login_is_recorded() {
        use crate::plugins::{AnonymousPlugin, LastLoginMethodPlugin};

        const PASSWORD: &str = "correct horse battery staple";
        let context = AuthContext::new(
            AuthOptions {
                secret: "a".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            None,
            vec![Arc::new(AnonymousPlugin), Arc::new(LastLoginMethodPlugin)],
        )
        .unwrap();
        let router = AuthRouter::new(context.clone()).unwrap();

        // A guest session, with the sign-in recorded as "anonymous".
        let (status, body, set) = send(
            &router,
            Method::POST,
            "/sign-in/anonymous",
            None,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let guest_cookie = session_cookie(set);
        let guest_id = body["user"]["id"].as_str().unwrap().to_owned();
        let (_, body, _) = send(
            &router,
            Method::GET,
            "/last-login-method",
            Some(&guest_cookie),
            Value::Null,
        )
        .await;
        assert_eq!(body["method"], "anonymous");

        // Upgrading keeps the same user id and the guest's session.
        let (status, body, _) = send(
            &router,
            Method::POST,
            "/anonymous/upgrade",
            Some(&guest_cookie),
            json!({"email":"guest@example.com","password":PASSWORD,"name":"Grace"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["user"]["id"], guest_id);
        assert_eq!(body["user"]["is_anonymous"], false);
        let (status, _, set) = send(
            &router,
            Method::POST,
            "/sign-in/email",
            None,
            json!({"email":"guest@example.com","password":PASSWORD}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let signed_in_cookie = session_cookie(set);
        let (_, body, _) = send(
            &router,
            Method::GET,
            "/last-login-method",
            Some(&signed_in_cookie),
            Value::Null,
        )
        .await;
        assert_eq!(body["method"], "email");

        // A permanent account cannot be "upgraded" again.
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/anonymous/upgrade",
            Some(&signed_in_cookie),
            json!({"email":"second@example.com","password":PASSWORD,"name":"Again"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Guests can be deleted, and the cookie is cleared.
        let (_, body, set) = send(
            &router,
            Method::POST,
            "/sign-in/anonymous",
            None,
            Value::Null,
        )
        .await;
        let second_guest = session_cookie(set);
        let second_id = body["user"]["id"].as_str().unwrap().to_owned();
        let (status, _, set) = send(
            &router,
            Method::POST,
            "/delete-anonymous-user",
            Some(&second_guest),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(set.is_some());
        let remaining = context
            .adapter
            .find_one("user", Query::new().eq("id", second_id))
            .await
            .unwrap();
        assert!(remaining.is_none());
        // A permanent account cannot be deleted through the guest route.
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/delete-anonymous-user",
            Some(&signed_in_cookie),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    struct FixedBreaches;

    #[async_trait::async_trait]
    impl crate::security_checks::BreachChecker for FixedBreaches {
        async fn breach_count(&self, password: &str) -> better_auth_core::error::Result<u64> {
            Ok(if password == "password123" { 5 } else { 0 })
        }
    }

    struct BrokenBreaches;

    #[async_trait::async_trait]
    impl crate::security_checks::BreachChecker for BrokenBreaches {
        async fn breach_count(&self, _password: &str) -> better_auth_core::error::Result<u64> {
            Err(AuthError::Plugin("provider unreachable".into()))
        }
    }

    struct GoodCaptcha;

    #[async_trait::async_trait]
    impl crate::security_checks::CaptchaVerifier for GoodCaptcha {
        async fn verify(
            &self,
            response: &str,
            _remote_ip: Option<std::net::IpAddr>,
        ) -> better_auth_core::error::Result<bool> {
            Ok(response == "good-token")
        }
    }

    #[tokio::test]
    async fn breach_and_captcha_checks_follow_their_failure_mode() {
        use crate::security_checks::FailureMode;

        let context = || {
            AuthContext::new(
                AuthOptions {
                    secret: "c".repeat(32),
                    base_url: Some(better_auth_core::options::BaseUrl::Static(
                        "https://example.com".into(),
                    )),
                    has_database: true,
                    ..AuthOptions::default()
                },
                Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
                None,
                Vec::new(),
            )
            .unwrap()
        };
        let signup = |captcha: Option<&str>, password: &str, email: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::ORIGIN, "https://example.com".parse().unwrap());
            headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
            if let Some(token) = captcha {
                headers.insert("x-captcha-response", token.parse().unwrap());
            }
            HttpRequest::new(
                Method::POST,
                "/api/auth/sign-up/email".parse().unwrap(),
                headers,
                json!({"email": email, "name": "Check", "password": password})
                    .to_string()
                    .into_bytes(),
            )
        };

        let router = AuthRouter::new(context())
            .unwrap()
            .with_captcha(Arc::new(GoodCaptcha), FailureMode::FailClosed)
            .with_breach_check(Arc::new(FixedBreaches), FailureMode::FailClosed);
        assert_eq!(
            router
                .handle(signup(None, "fine password here", "a@example.com"))
                .await
                .status,
            StatusCode::FORBIDDEN,
            "captcha is required"
        );
        assert_eq!(
            router
                .handle(signup(Some("bad"), "fine password here", "a@example.com"))
                .await
                .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            router
                .handle(signup(Some("good-token"), "password123", "b@example.com"))
                .await
                .status,
            StatusCode::BAD_REQUEST,
            "a breached password is refused"
        );
        assert_eq!(
            router
                .handle(signup(
                    Some("good-token"),
                    "fine password here",
                    "c@example.com"
                ))
                .await
                .status,
            StatusCode::OK
        );

        // An unreachable breach checker refuses sign-up in fail-closed mode...
        let closed = AuthRouter::new(context())
            .unwrap()
            .with_breach_check(Arc::new(BrokenBreaches), FailureMode::FailClosed);
        assert_eq!(
            closed
                .handle(signup(None, "fine password here", "d@example.com"))
                .await
                .status,
            StatusCode::FORBIDDEN
        );
        // ...and allows it in fail-open mode.
        let open = AuthRouter::new(context())
            .unwrap()
            .with_breach_check(Arc::new(BrokenBreaches), FailureMode::FailOpen);
        assert_eq!(
            open.handle(signup(None, "fine password here", "e@example.com"))
                .await
                .status,
            StatusCode::OK
        );
    }

    fn signed_google_credential(email: &str, verified: bool, audience: &str, sub: &str) -> String {
        use jsonwebtoken::{encode, EncodingKey, Header};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut header = Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some("google-test".into());
        encode(
            &header,
            &json!({
                "iss": "https://accounts.google.com",
                "aud": audience,
                "sub": sub,
                "iat": now,
                "exp": now + 300,
                "email": email,
                "email_verified": verified,
                "name": "One Tap",
            }),
            &EncodingKey::from_secret(b"one-tap-test-secret"),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn one_tap_signs_in_verified_google_accounts_once() {
        use crate::oidc::OidcIdTokenValidator;
        use crate::plugins::OneTapPlugin;
        use better_auth_core::adapter::memory::MemorySecondaryStorage;

        let context = AuthContext::new(
            AuthOptions {
                secret: "t".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            Some(Arc::new(MemorySecondaryStorage::default())),
            vec![Arc::new(OneTapPlugin)],
        )
        .unwrap();
        let validator = OidcIdTokenValidator::new("https://accounts.google.com", "client-1")
            .add_test_hs_key("google-test", b"one-tap-test-secret");
        let router = AuthRouter::new(context.clone())
            .unwrap()
            .with_one_tap(validator)
            .unwrap();
        let post = |credential: &str| {
            HttpRequest::new(
                Method::POST,
                "/api/auth/one-tap/callback".parse().unwrap(),
                origin_headers_for_one_tap(),
                json!({ "credential": credential }).to_string().into_bytes(),
            )
        };

        let token = signed_google_credential("person@example.com", true, "client-1", "google-123");
        let response = router.handle(post(&token)).await;
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.headers.get(header::SET_COOKIE).is_some());
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["user"]["email"], "person@example.com");
        assert_eq!(body["user"]["email_verified"], true);
        assert_eq!(
            router.handle(post(&token)).await.status,
            StatusCode::UNAUTHORIZED,
            "single use"
        );

        let unverified =
            signed_google_credential("other@example.com", false, "client-1", "google-456");
        assert_eq!(
            router.handle(post(&unverified)).await.status,
            StatusCode::FORBIDDEN
        );
        let wrong_audience =
            signed_google_credential("third@example.com", true, "other-client", "google-789");
        assert_eq!(
            router.handle(post(&wrong_audience)).await.status,
            StatusCode::UNAUTHORIZED
        );
        let users = context
            .adapter
            .find_many("user", Query::new())
            .await
            .unwrap();
        assert_eq!(users.len(), 1, "rejected credentials create no account");
    }

    fn origin_headers_for_one_tap() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://example.com".parse().unwrap());
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        headers
    }

    #[tokio::test]
    async fn a_mailbox_proof_removes_a_password_set_before_the_proof() {
        use crate::plugins::MagicLinkPlugin;
        use better_auth_core::adapter::memory::MemorySecondaryStorage;

        const PASSWORD: &str = "correct horse battery staple";
        let context = AuthContext::new(
            AuthOptions {
                secret: "p".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            Some(Arc::new(MemorySecondaryStorage::default())),
            vec![Arc::new(MagicLinkPlugin)],
        )
        .unwrap();
        let sender = Arc::new(crate::email::CapturingEmailSender::default());
        let router = AuthRouter::new(context)
            .unwrap()
            .with_email_sender(sender.clone())
            .unwrap();

        // Someone registers the victim's address with their own password. It stays unverified.
        let (status, _, set) = send(
            &router,
            Method::POST,
            "/sign-up/email",
            None,
            json!({"email":"victim@example.com","name":"Attacker","password":PASSWORD}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let attacker_session = session_cookie(set);

        // The victim later proves the mailbox with a magic link.
        send(
            &router,
            Method::POST,
            "/sign-in/magic-link",
            None,
            json!({"email":"victim@example.com"}),
        )
        .await;
        let link = token_from_message(&sender.last().unwrap().text);
        let (status, _, _) = send(
            &router,
            Method::GET,
            &format!("/magic-link/verify?token={link}"),
            None,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::FOUND);

        // The password chosen before the proof no longer works, and its session is gone.
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/sign-in/email",
            None,
            json!({"email":"victim@example.com","password":PASSWORD}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (_, body, _) = send(
            &router,
            Method::GET,
            "/get-session",
            Some(&attacker_session),
            Value::Null,
        )
        .await;
        assert!(body.is_null());
    }

    #[cfg(feature = "siwe")]
    #[tokio::test]
    async fn siwe_signs_in_a_wallet_once_per_nonce() {
        use crate::plugins::SiwePlugin;
        use better_auth_core::adapter::memory::MemorySecondaryStorage;
        use k256::ecdsa::SigningKey;
        use sha3::{Digest, Keccak256};

        let context = AuthContext::new(
            AuthOptions {
                secret: "s".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            Some(Arc::new(MemorySecondaryStorage::default())),
            vec![Arc::new(SiwePlugin)],
        )
        .unwrap();
        let router = AuthRouter::new(context).unwrap();
        let key = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let address = format!(
            "0x{}",
            Keccak256::digest(&point.as_bytes()[1..])[12..]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let sign = |text: &str| {
            let prefixed = format!("\x19Ethereum Signed Message:\n{}{}", text.len(), text);
            let (signature, recovery) = key
                .sign_prehash_recoverable(&Keccak256::digest(prefixed.as_bytes()))
                .unwrap();
            let mut bytes = signature.to_bytes().to_vec();
            bytes.push(recovery.to_byte() + 27);
            format!(
                "0x{}",
                bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
            )
        };
        let message = |domain: &str, nonce: &str| {
            format!(
                "{domain} wants you to sign in with your Ethereum account:\n{address}\n\n\
                 Sign in.\n\nURI: https://{domain}\nVersion: 1\nChain ID: 1\nNonce: {nonce}\n\
                 Issued At: 2026-01-01T00:00:00Z"
            )
        };
        let nonce_of = |body: &Value| body["nonce"].as_str().unwrap().to_owned();

        let (status, body, _) = send(&router, Method::POST, "/siwe/nonce", None, Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        let nonce = nonce_of(&body);
        let text = message("example.com", &nonce);
        let signature = sign(&text);

        // A valid signature over a fresh nonce signs the wallet in.
        let (status, body, set) = send(
            &router,
            Method::POST,
            "/siwe/verify",
            None,
            json!({"message": text, "signature": signature}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(set.is_some());
        assert_eq!(body["user"]["name"], address);

        // The same signed message cannot be replayed.
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/siwe/verify",
            None,
            json!({"message": text, "signature": signature}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // A message for another domain is refused, even with a valid signature.
        let (_, body, _) = send(&router, Method::POST, "/siwe/nonce", None, Value::Null).await;
        let other = message("phish.example", &nonce_of(&body));
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/siwe/verify",
            None,
            json!({"message": other, "signature": sign(&other)}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // A signature from a different key is refused.
        let (_, body, _) = send(&router, Method::POST, "/siwe/nonce", None, Value::Null).await;
        let text = message("example.com", &nonce_of(&body));
        let mut forged = sign(&text);
        let last = forged.pop().unwrap();
        forged.push(if last == '0' { '1' } else { '0' });
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/siwe/verify",
            None,
            json!({"message": text, "signature": forged}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn phone_codes_sign_in_one_account_per_number() {
        use crate::phone::CapturingPhoneSender;
        use crate::plugins::PhoneNumberPlugin;
        use better_auth_core::adapter::memory::MemorySecondaryStorage;

        let context = AuthContext::new(
            AuthOptions {
                secret: "h".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            Some(Arc::new(MemorySecondaryStorage::default())),
            vec![Arc::new(PhoneNumberPlugin)],
        )
        .unwrap();
        let sender = Arc::new(CapturingPhoneSender::default());
        let router = AuthRouter::new(context.clone())
            .unwrap()
            .with_phone_sender(sender.clone());

        let (status, _, _) = send(
            &router,
            Method::POST,
            "/phone-number/send-otp",
            None,
            json!({"phone": "15550109999"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a country code is required"
        );

        let (status, body, _) = send(
            &router,
            Method::POST,
            "/phone-number/send-otp",
            None,
            json!({"phone": "+1 555 010 9999"}),
        )
        .await;
        assert_eq!(
            (status, body["sent"].as_bool()),
            (StatusCode::OK, Some(true))
        );
        let code = sender.last_code().unwrap();
        let wrong = if code == "000000" { "111111" } else { "000000" };
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/phone-number/verify",
            None,
            json!({"phone": "+15550109999", "code": wrong}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, body, set) = send(
            &router,
            Method::POST,
            "/phone-number/verify",
            None,
            json!({"phone": "+15550109999", "code": code.clone()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(set.is_some());
        let first_id = body["user"]["id"].as_str().unwrap().to_owned();
        assert_eq!(body["user"]["name"], "+15550109999");
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/phone-number/verify",
            None,
            json!({"phone": "+15550109999", "code": code}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "a code is single use");

        // The same number signs in to the same account.
        send(
            &router,
            Method::POST,
            "/phone-number/send-otp",
            None,
            json!({"phone": "+15550109999"}),
        )
        .await;
        let (status, body, _) = send(
            &router,
            Method::POST,
            "/phone-number/verify",
            None,
            json!({"phone": "+15550109999", "code": sender.last_code().unwrap()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["user"]["id"], first_id);
        assert_eq!(
            context
                .adapter
                .find_many("user", Query::new())
                .await
                .unwrap()
                .len(),
            1
        );
    }

    /// Signs a user up and returns the session cookie and the user id.
    async fn sign_up_for_test(router: &AuthRouter, email: &str) -> (String, String) {
        let (_, body, set) = send(
            router,
            Method::POST,
            "/sign-up/email",
            None,
            json!({"email": email, "name": "Org", "password": "correct horse battery staple"}),
        )
        .await;
        (
            session_cookie(set),
            body["user"]["id"].as_str().unwrap().to_owned(),
        )
    }

    #[tokio::test]
    async fn organizations_enforce_roles_tenant_isolation_and_single_use_invitations() {
        use crate::email::CapturingEmailSender;
        use crate::plugins::OrganizationPlugin;

        let context = AuthContext::new(
            AuthOptions {
                secret: "o".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            None,
            vec![Arc::new(OrganizationPlugin)],
        )
        .unwrap();
        let sender = Arc::new(CapturingEmailSender::default());
        let router = AuthRouter::new(context)
            .unwrap()
            .with_email_sender(sender.clone())
            .unwrap();
        let (owner, owner_id) = sign_up_for_test(&router, "owner@example.com").await;
        let (member, member_id) = sign_up_for_test(&router, "member@example.com").await;
        let (outsider, _) = sign_up_for_test(&router, "outsider@example.com").await;

        let (status, body, _) = send(
            &router,
            Method::POST,
            "/organization/create",
            Some(&owner),
            json!({"name": "Acme Inc"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let org = body["organization"]["id"].as_str().unwrap().to_owned();
        let (_, body, _) = send(
            &router,
            Method::GET,
            "/organization/list",
            Some(&owner),
            Value::Null,
        )
        .await;
        assert_eq!(body["organizations"].as_array().unwrap().len(), 1);

        // Outsiders cannot see the organization at all.
        let (status, _, _) = send(
            &router,
            Method::GET,
            &format!("/organization/list-members?organization_id={org}"),
            Some(&outsider),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // The owner invites by email. The token goes to the invitee, not into the response.
        let (status, body, _) = send(
            &router,
            Method::POST,
            "/organization/invite-member",
            Some(&owner),
            json!({"organization_id": org, "email": "member@example.com", "role": "member"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.to_string().contains("token"));
        let invite = sender.last().unwrap();
        assert_eq!(invite.to, "member@example.com");
        let token = invite.text.lines().nth(1).unwrap().to_owned();

        // Owners cannot grant ownership through invitations.
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/organization/invite-member",
            Some(&owner),
            json!({"organization_id": org, "email": "x@example.com", "role": "owner"}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Only the invited address can accept, and only once.
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/organization/accept-invitation",
            Some(&outsider),
            json!({"token": token}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/organization/accept-invitation",
            Some(&member),
            json!({"token": token}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/organization/accept-invitation",
            Some(&member),
            json!({"token": token}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // A plain member cannot manage the organization.
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/organization/invite-member",
            Some(&member),
            json!({"organization_id": org, "email": "y@example.com", "role": "member"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Promotion, removal, and the last-owner rule.
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/organization/update-member-role",
            Some(&owner),
            json!({"organization_id": org, "user_id": member_id, "role": "admin"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/organization/remove-member",
            Some(&owner),
            json!({"organization_id": org, "user_id": owner_id}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "the last owner stays");
        let (status, body, _) = send(
            &router,
            Method::GET,
            &format!("/organization/list-members?organization_id={org}"),
            Some(&member),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["members"].as_array().unwrap().len(), 2);
        let (status, _, _) = send(
            &router,
            Method::POST,
            "/organization/remove-member",
            Some(&member),
            json!({"organization_id": org, "user_id": owner_id}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "an admin cannot remove an owner"
        );
    }

    #[tokio::test]
    async fn jwt_tokens_verify_against_the_published_jwks() {
        use crate::jwt_signing::JwtSigner;

        const PASSWORD: &str = "correct horse battery staple";
        const KEY: &str = include_str!("../tests/fixtures/jwt_test_rsa_private.pem");
        let context = AuthContext::new(
            AuthOptions {
                secret: "j".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            None,
            Vec::new(),
        )
        .unwrap();
        let signer = JwtSigner::from_rsa_pem("k1", "https://example.com", "api", KEY).unwrap();
        let router = AuthRouter::new(context).unwrap().with_jwt(signer);
        let (_, body, set) = send(
            &router,
            Method::POST,
            "/sign-up/email",
            None,
            json!({"email":"jwt@example.com","name":"Jwt","password":PASSWORD}),
        )
        .await;
        let cookie = session_cookie(set);
        let user_id = body["user"]["id"].as_str().unwrap().to_owned();

        let (status, jwks, _) = send(&router, Method::GET, "/jwks", None, Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(jwks["keys"][0]["kty"], "RSA");
        let (status, same, _) = send(
            &router,
            Method::GET,
            "/.well-known/jwks.json",
            None,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(same, jwks);

        let (status, _, _) = send(&router, Method::GET, "/token", None, Value::Null).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "tokens need a session");
        let (status, body, _) =
            send(&router, Method::GET, "/token", Some(&cookie), Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        let token = body["token"].as_str().unwrap();

        // A relying party verifies the token with the published key alone.
        let jwk = &jwks["keys"][0];
        let key = jsonwebtoken::DecodingKey::from_rsa_components(
            jwk["n"].as_str().unwrap(),
            jwk["e"].as_str().unwrap(),
        )
        .unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&["api"]);
        validation.set_issuer(&["https://example.com"]);
        let claims = jsonwebtoken::decode::<Value>(token, &key, &validation)
            .unwrap()
            .claims;
        assert_eq!(claims["sub"], user_id);
        assert_eq!(claims["email"], "jwt@example.com");
    }

    /// Value of the named cookie from every `Set-Cookie` header in the response.
    fn cookie_value(response: &HttpResponse, name: &str) -> Option<String> {
        response
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(|value| {
                let pair = value.split(';').next()?;
                let (key, val) = pair.split_once('=')?;
                (key == name).then(|| val.to_owned())
            })
    }

    async fn send_with_cookies(
        router: &AuthRouter,
        method: Method,
        path: &str,
        cookies: &[(&str, &str)],
        body: Value,
    ) -> (StatusCode, Value, HttpResponse) {
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://example.com".parse().unwrap());
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        if !cookies.is_empty() {
            let cookie = cookies
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            headers.insert(header::COOKIE, cookie.parse().unwrap());
        }
        let payload = if body.is_null() {
            Vec::new()
        } else {
            body.to_string().into_bytes()
        };
        let response = router
            .handle(HttpRequest::new(
                method,
                format!("/api/auth{path}").parse().unwrap(),
                headers,
                payload,
            ))
            .await;
        let json = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
        (response.status, json, response)
    }

    #[tokio::test]
    async fn multi_session_keeps_accounts_in_one_browser_and_switches_between_them() {
        use crate::plugins::MultiSessionPlugin;
        use better_auth_core::adapter::memory::MemorySecondaryStorage;

        const PASSWORD: &str = "correct horse battery staple";
        let context = AuthContext::new(
            AuthOptions {
                secret: "m".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            Some(Arc::new(MemorySecondaryStorage::default())),
            vec![Arc::new(MultiSessionPlugin)],
        )
        .unwrap();
        let router = AuthRouter::new(context).unwrap();
        let (session_a, _) = sign_up_for_test(&router, "alpha@example.com").await;
        let (session_b, _) = sign_up_for_test(&router, "bravo@example.com").await;
        // Over HTTPS the session cookie carries the __Secure- prefix.
        let session_name = session_a.split_once('=').unwrap().0.to_owned();
        let prefix = session_name
            .strip_suffix("better-auth.session_token")
            .unwrap()
            .to_owned();
        let session_name = format!("{prefix}better-auth.session_token");
        let multi_name = format!("{prefix}better-auth.multi_session");
        let token_a = session_a.split_once('=').unwrap().1.to_owned();
        let token_b = session_b.split_once('=').unwrap().1.to_owned();

        // Signing in as B while A is active keeps A in the browser's account list.
        let (status, _, response) = send_with_cookies(
            &router,
            Method::POST,
            "/sign-in/email",
            &[(&session_name, &token_a)],
            json!({"email":"bravo@example.com","password":PASSWORD}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let active_b = cookie_value(&response, &session_name).unwrap();
        let stored = cookie_value(&response, &multi_name).unwrap();
        assert_ne!(
            active_b, token_a,
            "the new sign-in replaces the active session"
        );

        // Both accounts are listed, and only the active one is marked current.
        let (status, body, _) = send_with_cookies(
            &router,
            Method::GET,
            "/multi-session/list-device-sessions",
            &[(&session_name, &active_b), (&multi_name, &stored)],
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let sessions = body["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions.iter().filter(|s| s["current"] == true).count(), 1);
        assert!(
            !body.to_string().contains(&token_a),
            "tokens are not exposed"
        );

        // Switching makes A active again and keeps B in the list.
        let (status, _, response) = send_with_cookies(
            &router,
            Method::POST,
            "/multi-session/set-active",
            &[(&session_name, &active_b), (&multi_name, &stored)],
            json!({"session_token": token_a}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(cookie_value(&response, &session_name).unwrap(), token_a);
        let stored_after_switch = cookie_value(&response, &multi_name).unwrap();

        // Revoking the active account promotes the other one.
        let (status, _, response) = send_with_cookies(
            &router,
            Method::POST,
            "/multi-session/revoke",
            &[
                (&session_name, &token_a),
                (&multi_name, &stored_after_switch),
            ],
            json!({"session_token": token_a}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(cookie_value(&response, &session_name).unwrap(), active_b);
        let stored_after_revoke = cookie_value(&response, &multi_name).unwrap();
        let (_, body, _) = send_with_cookies(
            &router,
            Method::GET,
            "/get-session",
            &[(&session_name, &active_b)],
            Value::Null,
        )
        .await;
        assert_eq!(body["user"]["email"], "bravo@example.com");

        // Revoking the last account clears the session.
        let (status, _, response) = send_with_cookies(
            &router,
            Method::POST,
            "/multi-session/revoke",
            &[
                (&session_name, &active_b),
                (&multi_name, &stored_after_revoke),
            ],
            json!({"session_token": active_b}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            response
                .headers
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|v| {
                    v.to_str().is_ok_and(|v| {
                        v.starts_with("better-auth.session_token=;") || v.contains("Max-Age=0")
                    })
                }),
            "the session cookie is cleared"
        );

        // A forged account cookie is ignored: its tokens are not trusted.
        let (fresh, _) = sign_up_for_test(&router, "charlie@example.com").await;
        let fresh_token = fresh.split_once('=').unwrap().1.to_owned();
        let (status, _, _) = send_with_cookies(
            &router,
            Method::POST,
            "/multi-session/set-active",
            &[(&session_name, &fresh_token), (&multi_name, "forged-value")],
            json!({"session_token": token_b}),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn social_providers_can_be_registered_and_removed_at_runtime() {
        use crate::http_oauth::HttpOAuthProvider;
        let context = AuthContext::new(
            AuthOptions {
                secret: "r".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                has_database: true,
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            Some(Arc::new(
                better_auth_core::adapter::memory::MemorySecondaryStorage::default(),
            )),
            Vec::new(),
        )
        .unwrap();
        let router = AuthRouter::new(context)
            .unwrap()
            .with_social_providers(Vec::new())
            .unwrap();
        let registry = router.social_registry().unwrap();
        let begin = |path: &str| {
            HttpRequest::new(
                Method::GET,
                format!("/api/auth{path}").parse().unwrap(),
                HeaderMap::new(),
                Vec::new(),
            )
        };
        assert_eq!(
            router.handle(begin("/sign-in/social/github")).await.status,
            StatusCode::NOT_FOUND
        );

        // A clone of the router sees the provider that the original registers.
        let clone = router.clone();
        registry
            .register(HttpOAuthProvider::github("client-1", "secret").unwrap())
            .unwrap();
        assert_eq!(registry.ids(), vec!["github".to_owned()]);
        let response = clone.handle(begin("/sign-in/social/github")).await;
        assert_eq!(response.status, StatusCode::FOUND);
        assert!(response
            .headers
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("https://github.com/login/oauth/authorize"));

        assert!(
            registry
                .register(HttpOAuthProvider::github("client-2", "secret").unwrap())
                .is_err(),
            "a duplicate id is refused"
        );
        assert!(registry.unregister("github"));
        assert_eq!(
            router.handle(begin("/sign-in/social/github")).await.status,
            StatusCode::NOT_FOUND
        );
    }

    struct EchoEndpoint;

    #[async_trait::async_trait]
    impl better_auth_core::plugin::EndpointHandler for EchoEndpoint {
        async fn handle(
            &self,
            request: better_auth_core::plugin::EndpointRequest,
        ) -> better_auth_core::error::Result<better_auth_core::plugin::EndpointResponse> {
            Ok(better_auth_core::plugin::EndpointResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: json!({ "user_id": request.user_id })
                    .to_string()
                    .into_bytes(),
            })
        }
    }

    struct EchoPlugin;

    impl better_auth_core::plugin::Plugin for EchoPlugin {
        fn name(&self) -> &'static str {
            "echo"
        }

        fn endpoint_handlers(&self) -> Vec<better_auth_core::plugin::ExecutableEndpoint> {
            use better_auth_core::plugin::{Endpoint, EndpointAccess};
            vec![
                Endpoint::new(Method::POST, "/echo", "test echo")
                    .with_access(EndpointAccess::Public)
                    .with_handler(Arc::new(EchoEndpoint)),
                Endpoint::new(Method::POST, "/private", "session required")
                    .with_handler(Arc::new(EchoEndpoint)),
                Endpoint::new(Method::POST, "/admin-only", "admin required")
                    .with_access(EndpointAccess::Admin)
                    .with_handler(Arc::new(EchoEndpoint)),
            ]
        }
    }

    #[tokio::test]
    async fn plugin_endpoints_enforce_the_same_origin_policy() {
        let context = AuthContext::new(
            AuthOptions {
                secret: "r".repeat(32),
                base_url: Some(better_auth_core::options::BaseUrl::Static(
                    "https://example.com".into(),
                )),
                ..AuthOptions::default()
            },
            Arc::new(better_auth_core::adapter::memory::MemoryDb::default()),
            None,
            vec![Arc::new(EchoPlugin)],
        )
        .unwrap();
        let router = AuthRouter::new(context).unwrap();
        let request = |origin: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::ORIGIN, origin.parse().unwrap());
            HttpRequest::new(
                Method::POST,
                "/api/auth/echo".parse().unwrap(),
                headers,
                Vec::new(),
            )
        };
        let trusted = router.handle(request("https://example.com")).await;
        assert_eq!(trusted.status, StatusCode::OK);
        let cross_site = router.handle(request("https://evil.example")).await;
        assert_eq!(cross_site.status, StatusCode::FORBIDDEN);
    }

    #[cfg(feature = "axum")]
    #[tokio::test]
    async fn axum_adapter_rejects_oversized_bodies_instead_of_emptying_them() {
        use axum::{body::Body, extract::State, response::IntoResponse};
        use http::Request;

        let router = Arc::new(router());
        let oversized = vec![b' '; axum_adapter::MAX_BODY_BYTES + 1];
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/auth/sign-up/email")
            .header(header::ORIGIN, "https://example.com")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(oversized))
            .unwrap();
        let response = axum_adapter::handler(State(router), request)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
