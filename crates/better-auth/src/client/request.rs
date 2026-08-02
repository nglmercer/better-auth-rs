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
}
