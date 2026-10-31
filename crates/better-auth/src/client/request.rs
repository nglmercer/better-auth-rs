use crate::{
    email_password::{SignInInput, SignUpInput, User},
    router::{HttpRequest, HttpResponse},
};
use better_auth_core::error::{AuthError, Result};
use http::{header, HeaderMap, Method, Uri};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use url::Url;

/// Builds requests for the framework-neutral auth HTTP API.
#[derive(Clone, Debug)]
pub struct AuthClient {
    pub(super) base_url: Url,
}

impl AuthClient {
    pub fn new(base_url: Url) -> Result<Self> {
        if !matches!(base_url.scheme(), "http" | "https") || base_url.host_str().is_none() {
            return Err(AuthError::InvalidConfiguration(
                "client base URL must have an HTTP(S) host".into(),
            ));
        }
        Ok(Self { base_url })
    }

    pub fn sign_up_email(&self, input: SignUpInput) -> Result<HttpRequest> {
        self.json_request(Method::POST, "/sign-up/email", &input)
    }

    pub fn sign_in_email(&self, input: SignInInput) -> Result<HttpRequest> {
        self.json_request(Method::POST, "/sign-in/email", &input)
    }

    pub fn get_session(&self) -> Result<HttpRequest> {
        self.request(Method::GET, "/get-session", None)
    }

    pub fn sign_out(&self) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/sign-out",
            &Value::Object(Default::default()),
        )
    }

    pub fn list_sessions(&self) -> Result<HttpRequest> {
        self.request(Method::GET, "/list-sessions", None)
    }

    pub fn revoke_session(&self, id: &str) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/revoke-session",
            &serde_json::json!({ "id": id }),
        )
    }

    pub fn revoke_other_sessions(&self) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/revoke-other-sessions",
            &Value::Object(Default::default()),
        )
    }

    pub fn change_password(
        &self,
        current_password: &str,
        new_password: &str,
    ) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/change-password",
            &serde_json::json!({"current_password": current_password, "new_password": new_password}),
        )
    }

    pub fn update_user(&self, name: &str) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/update-user",
            &serde_json::json!({ "name": name }),
        )
    }

    pub fn delete_user(&self, password: &str) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/delete-user",
            &serde_json::json!({ "password": password }),
        )
    }

    pub fn list_accounts(&self) -> Result<HttpRequest> {
        self.request(Method::GET, "/list-accounts", None)
    }

    pub fn two_factor_enable(&self, password: &str) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/two-factor/enable",
            &serde_json::json!({ "password": password }),
        )
    }

    pub fn two_factor_confirm(&self, code: &str) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/two-factor/confirm",
            &serde_json::json!({ "code": code }),
        )
    }

    pub fn two_factor_verify(&self, challenge_token: &str, code: &str) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/two-factor/verify",
            &serde_json::json!({"challenge_token": challenge_token, "code": code}),
        )
    }

    pub fn two_factor_disable(&self, password: &str) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/two-factor/disable",
            &serde_json::json!({ "password": password }),
        )
    }

    pub fn magic_link_send(&self, email: &str) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/sign-in/magic-link",
            &serde_json::json!({ "email": email }),
        )
    }

    pub fn email_otp_send(&self, email: &str) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/email-otp/send",
            &serde_json::json!({ "email": email }),
        )
    }

    pub fn email_otp_verify(&self, email: &str, code: &str) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/email-otp/verify",
            &serde_json::json!({"email": email, "code": code}),
        )
    }

    pub fn sign_in_username(&self, username: &str, password: &str) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/sign-in/username",
            &serde_json::json!({"username": username, "password": password}),
        )
    }

    pub fn sign_in_anonymous(&self) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/sign-in/anonymous",
            &Value::Object(Default::default()),
        )
    }

    pub fn api_key_create(&self, name: &str, scopes: &[String]) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/api-key/create",
            &serde_json::json!({"name": name, "scopes": scopes}),
        )
    }

    pub fn api_key_list(&self) -> Result<HttpRequest> {
        self.request(Method::GET, "/api-key/list", None)
    }

    pub fn api_key_revoke(&self, id: &str) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/api-key/revoke",
            &serde_json::json!({ "id": id }),
        )
    }

    pub fn passkey_register_options(&self) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/passkey/generate-register-options",
            &Value::Object(Default::default()),
        )
    }

    pub fn passkey_verify_registration(
        &self,
        transaction_id: &str,
        response: &Value,
        name: Option<&str>,
    ) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/passkey/verify-registration",
            &serde_json::json!({
                "transaction_id": transaction_id,
                "response": response,
                "name": name,
            }),
        )
    }

    pub fn passkey_authenticate_options(&self) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/passkey/generate-authenticate-options",
            &Value::Object(Default::default()),
        )
    }

    pub fn passkey_verify_authentication(
        &self,
        transaction_id: &str,
        response: &Value,
    ) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/passkey/verify-authentication",
            &serde_json::json!({"transaction_id": transaction_id, "response": response}),
        )
    }

    pub fn passkey_list(&self) -> Result<HttpRequest> {
        self.request(Method::GET, "/passkey/list-user-passkeys", None)
    }

    pub fn passkey_rename(&self, id: &str, name: &str) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/passkey/update-passkey",
            &serde_json::json!({"id": id, "name": name}),
        )
    }

    pub fn passkey_delete(&self, id: &str) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/passkey/delete-passkey",
            &serde_json::json!({ "id": id }),
        )
    }

    pub fn device_code(&self, client_id: &str) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/device/code",
            &serde_json::json!({ "client_id": client_id }),
        )
    }

    pub fn device_token(&self, device_code: &str, client_id: &str) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/device/token",
            &serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": client_id,
            }),
        )
    }

    /// Adds an `Idempotency-Key` so a retried POST runs at most once on the server.
    pub fn with_idempotency_key(mut request: HttpRequest, key: &str) -> Result<HttpRequest> {
        request.headers.insert(
            "idempotency-key",
            key.parse().map_err(|_| {
                AuthError::InvalidRequest("idempotency key is not a valid header value".into())
            })?,
        );
        Ok(request)
    }

    pub fn parse_json<T: DeserializeOwned>(&self, response: &HttpResponse) -> Result<T> {
        serde_json::from_slice(&response.body)
            .map_err(|error| AuthError::InvalidRequest(format!("invalid auth response: {error}")))
    }

    pub fn parse_session(
        &self,
        response: &HttpResponse,
    ) -> Result<Option<(User, crate::email_password::Session)>> {
        if response.body == b"null" {
            return Ok(None);
        }
        let value: Value = self.parse_json(response)?;
        let user = serde_json::from_value(
            value
                .get("user")
                .cloned()
                .ok_or_else(|| AuthError::InvalidRequest("session response has no user".into()))?,
        )
        .map_err(|error| AuthError::InvalidRequest(format!("invalid session user: {error}")))?;
        let session =
            serde_json::from_value(value.get("session").cloned().ok_or_else(|| {
                AuthError::InvalidRequest("session response has no session".into())
            })?)
            .map_err(|error| AuthError::InvalidRequest(format!("invalid session: {error}")))?;
        Ok(Some((user, session)))
    }

    fn json_request<T: Serialize>(
        &self,
        method: Method,
        path: &str,
        value: &T,
    ) -> Result<HttpRequest> {
        let body = serde_json::to_vec(value)
            .map_err(|error| AuthError::InvalidRequest(error.to_string()))?;
        self.request(method, path, Some(body))
    }

    fn request(&self, method: Method, path: &str, body: Option<Vec<u8>>) -> Result<HttpRequest> {
        let mut url = self.base_url.clone();
        let base_path = url.path().trim_end_matches('/');
        url.set_path(&format!("{base_path}{path}"));
        let uri: Uri = url
            .as_str()
            .parse()
            .map_err(|error| AuthError::InvalidRequest(format!("invalid client URL: {error}")))?;
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, "application/json".parse().unwrap());
        if let Some(ref body) = body {
            headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
            headers.insert(
                header::CONTENT_LENGTH,
                body.len().to_string().parse().unwrap(),
            );
        }
        if method != Method::GET {
            let origin = format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default());
            headers.insert(header::ORIGIN, origin.parse().unwrap());
        }
        Ok(HttpRequest::new(
            method,
            uri,
            headers,
            body.unwrap_or_default(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_builds_same_origin_json_requests() {
        let client = AuthClient::new(Url::parse("https://example.com/api/auth").unwrap()).unwrap();
        let request = client
            .sign_in_email(SignInInput {
                email: "a@b.com".into(),
                password: "password".into(),
            })
            .unwrap();
        assert_eq!(request.method, Method::POST);
        assert_eq!(request.uri.path(), "/api/auth/sign-in/email");
        assert_eq!(
            request.headers.get(header::ORIGIN).unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn account_and_second_factor_requests_use_the_server_contract() {
        let client = AuthClient::new(Url::parse("https://example.com/api/auth").unwrap()).unwrap();
        let change = client
            .change_password("old-password-1", "new-password-2")
            .unwrap();
        assert_eq!(change.method, Method::POST);
        assert_eq!(change.uri.path(), "/api/auth/change-password");
        let body: Value = serde_json::from_slice(&change.body).unwrap();
        assert_eq!(body["current_password"], "old-password-1");
        assert_eq!(body["new_password"], "new-password-2");
        let verify = client.two_factor_verify("challenge", "123456").unwrap();
        assert_eq!(verify.uri.path(), "/api/auth/two-factor/verify");
        let token = client.device_token("device", "cli").unwrap();
        let body: Value = serde_json::from_slice(&token.body).unwrap();
        assert_eq!(
            body["grant_type"],
            "urn:ietf:params:oauth:grant-type:device_code"
        );
        let keyed = AuthClient::with_idempotency_key(client.sign_out().unwrap(), "key-1").unwrap();
        assert_eq!(keyed.headers.get("idempotency-key").unwrap(), "key-1");
    }

    #[test]
    fn passkey_requests_use_the_server_contract() {
        let client = AuthClient::new(Url::parse("https://example.com/api/auth").unwrap()).unwrap();
        let response = serde_json::json!({"id": "AQID"});
        let register = client
            .passkey_verify_registration("tx", &response, None)
            .unwrap();
        assert_eq!(register.uri.path(), "/api/auth/passkey/verify-registration");
        let body: Value = serde_json::from_slice(&register.body).unwrap();
        assert_eq!(body["transaction_id"], "tx");
        assert_eq!(body["response"]["id"], "AQID");
        let sign_in = client
            .passkey_verify_authentication("tx2", &response)
            .unwrap();
        assert_eq!(
            sign_in.uri.path(),
            "/api/auth/passkey/verify-authentication"
        );
        let rename = client.passkey_rename("p1", "Work").unwrap();
        let body: Value = serde_json::from_slice(&rename.body).unwrap();
        assert_eq!(body["id"], "p1");
        assert_eq!(body["name"], "Work");
        let list = client.passkey_list().unwrap();
        assert_eq!(list.method, Method::GET);
        assert_eq!(list.uri.path(), "/api/auth/passkey/list-user-passkeys");
    }
}
