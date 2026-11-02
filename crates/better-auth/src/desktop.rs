//! Login for native (desktop) clients. Library pieces only: no UI, no browser launch,
//! and nothing specific to one application.
//!
//! - [`validate_loopback_redirect_uri`] and [`LoopbackCallbackReceiver`] implement the
//!   loopback redirect of RFC 8252. The receiver accepts one valid callback, checks the
//!   client's `state` in constant time, and has an explicit timeout and cancellation.
//! - [`DesktopHandoffService`] is the backend-mediated exchange. After the browser has a
//!   session, the backend issues a single-use code bound to the client's PKCE challenge,
//!   client ID and redirect URI. The native client redeems it with its verifier and
//!   receives an opt-in bearer session. Codes are stored hashed and consumed atomically.
//!
//! A code that fails verification is still consumed. A legitimate client must then start
//! over, which keeps an intercepted code from being retried.

use crate::{
    context::AuthContext,
    email_password::{AuthResult, User},
    session::SessionService,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use better_auth_core::{
    adapter::{Query, SecondaryStorage, StorageValue},
    error::{AuthError, Result},
};
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use url::Url;
use uuid::Uuid;

/// Longest lifetime a handoff code may be given.
pub const HANDOFF_MAX_TTL: Duration = Duration::from_secs(120);
const HANDOFF_PREFIX: &str = "desktop:handoff:";
const MAX_HEAD_BYTES: usize = 8 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(5);

fn invalid(message: &str) -> AuthError {
    AuthError::InvalidRequest(message.into())
}

/// Whether `url` names a loopback IP literal over plain HTTP, which RFC 8252 allows for native clients.
pub fn is_loopback_redirect(url: &Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))
}

/// Accepts `http://127.0.0.1:<port>/<path>` and `http://[::1]:<port>/<path>` only. The port
/// must be explicit and non-zero, and the path must not be empty or `/`. Userinfo, query
/// and fragment are refused. `localhost` is refused because it can resolve to other hosts.
pub fn validate_loopback_redirect_uri(uri: &str) -> Result<Url> {
    let url = Url::parse(uri).map_err(|_| invalid("redirect URI is not a valid URL"))?;
    if !is_loopback_redirect(&url) {
        return Err(invalid(
            "native redirect URI must use http://127.0.0.1 or http://[::1]",
        ));
    }
    if url.port().is_none_or(|port| port == 0) {
        return Err(invalid("native redirect URI must name an explicit port"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("redirect URI must not contain credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid("redirect URI must not contain a query or fragment"));
    }
    if url.path().is_empty() || url.path() == "/" {
        return Err(invalid("redirect URI must include a callback path"));
    }
    Ok(url)
}

/// Adds the authorization code and state to a validated loopback redirect URI.
pub fn loopback_callback_url(redirect_uri: &str, code: &str, state: &str) -> Result<String> {
    let mut url = validate_loopback_redirect_uri(redirect_uri)?;
    url.query_pairs_mut()
        .append_pair("code", code)
        .append_pair("state", state);
    Ok(url.to_string())
}

fn valid_verifier(verifier: &str) -> bool {
    // RFC 7636: 43 to 128 unreserved characters.
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
}

fn valid_challenge(challenge: &str) -> bool {
    // An S256 challenge is the 32-byte SHA-256 digest, base64url-encoded without padding.
    challenge.len() == 43
        && challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

enum Outcome {
    Ignored,
    Code(String),
    Denied,
}

/// Listens on `127.0.0.1` for one authorization callback. Requests that do not match
/// the path, the Host header, or the expected `state` get an error response and are
/// otherwise ignored, so a stray or forged request cannot end the login.
pub struct LoopbackCallbackReceiver {
    listener: TcpListener,
    port: u16,
    path: String,
    expected_state: String,
}

impl LoopbackCallbackReceiver {
    /// Binds an ephemeral loopback port. `expected_state` is the client's own random
    /// value, at least 16 bytes.
    pub async fn bind(path: &str, expected_state: &str) -> Result<Self> {
        if !path.starts_with('/') || path.contains(['?', '#']) {
            return Err(invalid("callback path must be an absolute path"));
        }
        if expected_state.len() < 16 {
            return Err(invalid("state must be at least 16 bytes"));
        }
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| AuthError::Adapter("could not bind loopback listener".into()))?;
        let port = listener
            .local_addr()
            .map_err(|_| AuthError::Adapter("loopback listener has no address".into()))?
            .port();
        Ok(Self {
            listener,
            port,
            path: path.into(),
            expected_state: expected_state.into(),
        })
    }

    /// The redirect URI to register in the authorization request.
    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}{}", self.port, self.path)
    }

    /// Waits for the callback and returns the authorization code. Fails at `timeout`, when
    /// the provider reports an error, or when `cancel` is sent or dropped.
    pub async fn receive(self, timeout: Duration, cancel: oneshot::Receiver<()>) -> Result<String> {
        tokio::select! {
            outcome = tokio::time::timeout(timeout, self.accept_code()) => match outcome {
                Ok(result) => result,
                Err(_) => Err(AuthError::InvalidRequest("loopback callback timed out".into())),
            },
            _ = cancel => Err(AuthError::InvalidRequest("loopback login was cancelled".into())),
        }
    }

    async fn accept_code(&self) -> Result<String> {
        loop {
            let stream = match self.listener.accept().await {
                Ok((stream, _)) => stream,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
            match self.handle(stream).await {
                Outcome::Code(code) => return Ok(code),
                Outcome::Denied => return Err(invalid("login was not completed by the provider")),
                Outcome::Ignored => {}
            }
        }
    }

    async fn handle(&self, mut stream: TcpStream) -> Outcome {
        let head = match tokio::time::timeout(READ_TIMEOUT, read_head(&mut stream)).await {
            Ok(Some(head)) => head,
            _ => {
                respond(&mut stream, 400, "bad request").await;
                return Outcome::Ignored;
            }
        };
        let mut lines = head.split("\r\n");
        let mut request_line = lines.next().unwrap_or("").split(' ');
        let (method, target, version) = (
            request_line.next(),
            request_line.next(),
            request_line.next(),
        );
        let host_ok = lines.any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("host")
                    && value.trim() == format!("127.0.0.1:{}", self.port)
            })
        });
        let target_url = target
            .filter(|_| method == Some("GET") && version.is_some_and(|v| v.starts_with("HTTP/1.")))
            .and_then(|target| Url::parse(&format!("http://127.0.0.1:{}{target}", self.port)).ok());
        let Some(url) = target_url.filter(|url| host_ok && url.path() == self.path) else {
            respond(&mut stream, 404, "not found").await;
            return Outcome::Ignored;
        };
        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
        if params.contains_key("error") {
            respond(
                &mut stream,
                200,
                "Sign-in was not completed. You can close this window.",
            )
            .await;
            return Outcome::Denied;
        }
        let state_ok = params.get("state").is_some_and(|state| {
            bool::from(state.as_bytes().ct_eq(self.expected_state.as_bytes()))
        });
        match params.get("code") {
            Some(code) if state_ok && !code.is_empty() && code.len() <= 2048 => {
                respond(
                    &mut stream,
                    200,
                    "Sign-in complete. You can close this window.",
                )
                .await;
                Outcome::Code(code.clone())
            }
            _ => {
                respond(&mut stream, 400, "invalid callback").await;
                Outcome::Ignored
            }
        }
    }
}

async fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            return String::from_utf8(buffer[..end].to_vec()).ok();
        }
        if buffer.len() > MAX_HEAD_BYTES {
            return None;
        }
    }
}

async fn respond(stream: &mut TcpStream, status: u16, body: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Not Found",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Cache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// What the browser-side backend asks for when it issues a handoff code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandoffRequest {
    /// Identifies the native client application. Bound to the code.
    pub client_id: String,
    /// The loopback redirect URI the code is sent to. Bound to the code.
    pub redirect_uri: String,
    /// S256 challenge of the client's PKCE verifier.
    pub code_challenge: String,
    /// How long the code can be redeemed, at most [`HANDOFF_MAX_TTL`].
    pub ttl: Duration,
}

/// What the native client sends to redeem a handoff code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedeemRequest {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    /// The PKCE verifier whose challenge was sent at issue time.
    pub code_verifier: String,
}

#[derive(Serialize, Deserialize)]
struct HandoffRecord {
    user_id: String,
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    expires_at: u64,
}

fn handoff_key(code: &str) -> String {
    let digest = Sha256::digest(code.as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{HANDOFF_PREFIX}{hex}")
}

/// Issues and redeems single-use handoff codes. Requires secondary storage.
#[derive(Clone)]
pub struct DesktopHandoffService {
    context: AuthContext,
    storage: Arc<dyn SecondaryStorage>,
}

impl DesktopHandoffService {
    pub fn new(context: AuthContext) -> Result<Self> {
        let storage = context.secondary_storage.clone().ok_or_else(|| {
            AuthError::InvalidConfiguration("desktop handoff requires secondary storage".into())
        })?;
        Ok(Self { context, storage })
    }

    /// Issues a code for the user who holds the session carried by `headers`. The caller
    /// redirects the browser to [`loopback_callback_url`] with the code.
    pub async fn issue_for_session(
        &self,
        headers: &HeaderMap,
        secure_cookie: bool,
        request: &HandoffRequest,
    ) -> Result<String> {
        let principal = SessionService::new(self.context.clone())?
            .resolve(headers, secure_cookie)
            .await?
            .ok_or(AuthError::Unauthorized)?;
        self.issue(&principal.user.id, request).await
    }

    /// Issues a code for `user_id`. The caller must already have authenticated that user.
    pub async fn issue(&self, user_id: &str, request: &HandoffRequest) -> Result<String> {
        validate_loopback_redirect_uri(&request.redirect_uri)?;
        if request.client_id.is_empty() || request.client_id.len() > 128 {
            return Err(invalid("client ID must be 1 to 128 bytes"));
        }
        if !valid_challenge(&request.code_challenge) {
            return Err(invalid("code challenge must be an S256 value"));
        }
        if request.ttl.is_zero() || request.ttl > HANDOFF_MAX_TTL {
            return Err(invalid("handoff code lifetime must be at most 120 seconds"));
        }
        let code = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let record = HandoffRecord {
            user_id: user_id.into(),
            client_id: request.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            code_challenge: request.code_challenge.clone(),
            expires_at: now_seconds() + request.ttl.as_secs(),
        };
        let value = serde_json::to_value(&record)
            .map_err(|error| AuthError::InvalidRequest(error.to_string()))?;
        self.storage
            .set(
                &handoff_key(&code),
                StorageValue::with_ttl(value, request.ttl),
            )
            .await?;
        Ok(code)
    }

    /// Redeems a code and creates a session for its user. The code is removed before any
    /// check that can fail, so it works at most once.
    pub async fn redeem(&self, request: &RedeemRequest, secure_cookie: bool) -> Result<AuthResult> {
        let stored = self
            .storage
            .get_and_delete(&handoff_key(&request.code))
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let record: HandoffRecord =
            serde_json::from_value(stored.value).map_err(|_| AuthError::Unauthorized)?;
        if now_seconds() >= record.expires_at || !valid_verifier(&request.code_verifier) {
            return Err(AuthError::Unauthorized);
        }
        let challenge_matches: bool = s256(&request.code_verifier)
            .as_bytes()
            .ct_eq(record.code_challenge.as_bytes())
            .into();
        let bound =
            request.client_id == record.client_id && request.redirect_uri == record.redirect_uri;
        if !(challenge_matches && bound) {
            return Err(AuthError::Unauthorized);
        }
        let user = self
            .load_user(&record.user_id)
            .await?
            .ok_or(AuthError::Unauthorized)?;
        SessionService::new(self.context.clone())?
            .create(user, secure_cookie)
            .await
    }

    async fn load_user(&self, user_id: &str) -> Result<Option<User>> {
        let Some(value) = self
            .context
            .adapter
            .find_one("user", Query::new().eq("id", user_id))
            .await?
        else {
            return Ok(None);
        };
        serde_json::from_value(value)
            .map(Some)
            .map_err(|error| AuthError::InvalidRequest(error.to_string()))
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_redirects_require_ip_literal_port_and_path() {
        assert!(validate_loopback_redirect_uri("http://127.0.0.1:53124/callback").is_ok());
        assert!(validate_loopback_redirect_uri("http://[::1]:8080/cb").is_ok());
        for bad in [
            "http://localhost:53124/callback",
            "https://127.0.0.1:53124/callback",
            "http://127.0.0.1/callback",
            "http://127.0.0.1:0/callback",
            "http://127.0.0.1:53124/",
            "http://127.0.0.1:53124",
            "http://127.0.0.1:53124/cb?x=1",
            "http://127.0.0.1:53124/cb#frag",
            "http://user:pw@127.0.0.1:53124/cb",
            "http://192.168.1.10:53124/callback",
            "http://evil.example:53124/callback",
        ] {
            assert!(
                validate_loopback_redirect_uri(bad).is_err(),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn pkce_shapes_are_checked_before_use() {
        let verifier = "a".repeat(43);
        assert!(valid_verifier(&verifier));
        assert!(!valid_verifier(&"a".repeat(42)));
        assert!(!valid_verifier(&format!("{}!", "a".repeat(42))));
        assert!(valid_challenge(&s256(&verifier)));
        assert!(!valid_challenge("short"));
    }

    #[test]
    fn callback_url_carries_code_and_state() {
        let url = loopback_callback_url("http://127.0.0.1:5000/cb", "code-1", "state-1").unwrap();
        assert_eq!(url, "http://127.0.0.1:5000/cb?code=code-1&state=state-1");
    }

    #[test]
    fn stored_handoff_keys_do_not_contain_the_code() {
        let key = handoff_key("secret-code");
        assert!(!key.contains("secret-code"));
        assert!(key.starts_with(HANDOFF_PREFIX));
    }
}
