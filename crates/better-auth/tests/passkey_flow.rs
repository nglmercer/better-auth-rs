//! End-to-end passkey ceremonies through the public HTTP surface, using a
//! software authenticator: a P-256 key that produces "none" attestations and
//! ES256 assertions, the same bytes a platform authenticator would send.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use better_auth::{
    context::AuthContext,
    plugins::PasskeyPlugin,
    router::{AuthRouter, HttpRequest, HttpResponse},
};
use better_auth_core::{
    adapter::memory::{MemoryDb, MemorySecondaryStorage},
    options::{AuthOptions, BaseUrl},
};
use http::{header, HeaderMap, Method, StatusCode};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};

const ORIGIN: &str = "https://example.com";
const RP_ID: &str = "example.com";
const PASSWORD: &str = "correct horse battery staple";

fn router() -> AuthRouter {
    let context = AuthContext::new(
        AuthOptions {
            secret: "p".repeat(32),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            has_database: true,
            ..AuthOptions::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        vec![Arc::new(PasskeyPlugin)],
    )
    .unwrap();
    AuthRouter::new(context).unwrap().with_passkeys().unwrap()
}

async fn call(
    router: &AuthRouter,
    method: Method,
    path: &str,
    cookie: Option<&str>,
    body: Value,
) -> HttpResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, ORIGIN.parse().unwrap());
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    if let Some(cookie) = cookie {
        headers.insert(header::COOKIE, cookie.parse().unwrap());
    }
    let payload = if body.is_null() {
        Vec::new()
    } else {
        body.to_string().into_bytes()
    };
    router
        .handle(HttpRequest::new(
            method,
            format!("/api/auth{path}").parse().unwrap(),
            headers,
            payload,
        ))
        .await
}

async fn call_json(
    router: &AuthRouter,
    method: Method,
    path: &str,
    cookie: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let response = call(router, method, path, cookie, body).await;
    let body = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
    (response.status, body)
}

/// The session cookie a response sets, as it is sent back in a `Cookie` header.
fn session_cookie(response: &HttpResponse) -> Option<String> {
    response
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.contains("session_token="))
        .map(|value| value.split(';').next().unwrap().to_owned())
}

async fn sign_up(router: &AuthRouter, email: &str) -> (String, String) {
    let response = call(
        router,
        Method::POST,
        "/sign-up/email",
        None,
        json!({"email": email, "name": "Person", "password": PASSWORD}),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    (
        session_cookie(&response).expect("sign-up sets a session"),
        body["user"]["id"].as_str().unwrap().to_owned(),
    )
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn cbor_text(text: &str) -> serde_cbor_2::Value {
    serde_cbor_2::Value::Text(text.to_owned())
}

/// A software authenticator. It owns one P-256 key and one credential ID, and
/// keeps a signature counter the way a real authenticator does.
struct Authenticator {
    key: SigningKey,
    credential_id: Vec<u8>,
    counter: u32,
    origin: String,
}

impl Authenticator {
    fn new(seed: u8) -> Self {
        Self {
            key: SigningKey::from_slice(&[seed; 32]).unwrap(),
            credential_id: vec![seed; 16],
            counter: 0,
            origin: ORIGIN.to_owned(),
        }
    }

    fn rp_hash(&self) -> Vec<u8> {
        sha256(RP_ID.as_bytes())
    }

    /// Answers a registration challenge with a "none" attestation.
    fn register(&self, options: &Value) -> Value {
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": options["publicKey"]["challenge"],
            "origin": self.origin,
            "crossOrigin": false,
        })
        .to_string();

        let point = self.key.verifying_key().to_encoded_point(false);
        let mut cose = BTreeMap::new();
        cose.insert(
            serde_cbor_2::Value::Integer(1),
            serde_cbor_2::Value::Integer(2),
        );
        cose.insert(
            serde_cbor_2::Value::Integer(3),
            serde_cbor_2::Value::Integer(-7),
        );
        cose.insert(
            serde_cbor_2::Value::Integer(-1),
            serde_cbor_2::Value::Integer(1),
        );
        cose.insert(
            serde_cbor_2::Value::Integer(-2),
            serde_cbor_2::Value::Bytes(point.x().unwrap().to_vec()),
        );
        cose.insert(
            serde_cbor_2::Value::Integer(-3),
            serde_cbor_2::Value::Bytes(point.y().unwrap().to_vec()),
        );
        let cose = serde_cbor_2::to_vec(&serde_cbor_2::Value::Map(cose)).unwrap();

        let mut auth_data = self.rp_hash();
        auth_data.push(0x45); // user present, user verified, attested credential data
        auth_data.extend(0u32.to_be_bytes());
        auth_data.extend([0u8; 16]); // AAGUID
        auth_data.extend((self.credential_id.len() as u16).to_be_bytes());
        auth_data.extend(&self.credential_id);
        auth_data.extend(cose);

        let mut attestation = BTreeMap::new();
        attestation.insert(cbor_text("fmt"), cbor_text("none"));
        attestation.insert(
            cbor_text("attStmt"),
            serde_cbor_2::Value::Map(BTreeMap::new()),
        );
        attestation.insert(cbor_text("authData"), serde_cbor_2::Value::Bytes(auth_data));
        let attestation = serde_cbor_2::to_vec(&serde_cbor_2::Value::Map(attestation)).unwrap();

        json!({
            "id": encode(&self.credential_id),
            "rawId": encode(&self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": encode(client_data.as_bytes()),
                "attestationObject": encode(&attestation),
            },
            "extensions": {},
        })
    }

    /// Answers a sign-in challenge with the next counter value.
    fn sign_in(&mut self, options: &Value) -> Value {
        self.counter += 1;
        self.assertion(options, self.counter)
    }

    fn assertion(&self, options: &Value, counter: u32) -> Value {
        let client_data = json!({
            "type": "webauthn.get",
            "challenge": options["publicKey"]["challenge"],
            "origin": self.origin,
            "crossOrigin": false,
        })
        .to_string();
        let mut auth_data = self.rp_hash();
        auth_data.push(0x05); // user present, user verified
        auth_data.extend(counter.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend(sha256(client_data.as_bytes()));
        let signature: Signature = self.key.sign(&signed);
        json!({
            "id": encode(&self.credential_id),
            "rawId": encode(&self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": encode(client_data.as_bytes()),
                "authenticatorData": encode(&auth_data),
                "signature": encode(signature.to_der().as_bytes()),
                "userHandle": null,
            },
            "extensions": {},
        })
    }
}

async fn register_options(router: &AuthRouter, cookie: &str) -> (String, Value) {
    let (status, body) = call_json(
        router,
        Method::POST,
        "/passkey/generate-register-options",
        Some(cookie),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    (body["transaction_id"].as_str().unwrap().to_owned(), body)
}

async fn verify_registration(
    router: &AuthRouter,
    cookie: &str,
    transaction_id: &str,
    response: Value,
    name: Option<&str>,
) -> (StatusCode, Value) {
    call_json(
        router,
        Method::POST,
        "/passkey/verify-registration",
        Some(cookie),
        json!({"transaction_id": transaction_id, "response": response, "name": name}),
    )
    .await
}

async fn sign_in_options(router: &AuthRouter) -> (String, Value) {
    let (status, body) = call_json(
        router,
        Method::POST,
        "/passkey/generate-authenticate-options",
        None,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    (body["transaction_id"].as_str().unwrap().to_owned(), body)
}

async fn verify_authentication(
    router: &AuthRouter,
    transaction_id: &str,
    response: Value,
) -> HttpResponse {
    call(
        router,
        Method::POST,
        "/passkey/verify-authentication",
        None,
        json!({"transaction_id": transaction_id, "response": response}),
    )
    .await
}

#[tokio::test]
async fn passkeys_register_sign_in_and_manage_credentials() {
    let router = router();
    let (owner_cookie, owner_id) = sign_up(&router, "owner@example.com").await;
    let (other_cookie, _) = sign_up(&router, "other@example.com").await;
    let mut device = Authenticator::new(7);

    // Registration belongs to a signed-in user.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/passkey/generate-register-options",
        None,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // An invalid name is refused before the ceremony is spent.
    let (transaction_id, options) = register_options(&router, &owner_cookie).await;
    let attestation = device.register(&options["options"]);
    let (status, _) = verify_registration(
        &router,
        &owner_cookie,
        &transaction_id,
        attestation.clone(),
        Some(&"x".repeat(65)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Registration stores the trimmed name, and the ceremony completes once.
    let (status, body) = verify_registration(
        &router,
        &owner_cookie,
        &transaction_id,
        attestation.clone(),
        Some("  Laptop  "),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["passkey"]["name"], "Laptop");
    let (status, _) = verify_registration(
        &router,
        &owner_cookie,
        &transaction_id,
        attestation,
        Some("Laptop"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The list shows the passkey without its key material.
    let (status, listed) = call_json(
        &router,
        Method::GET,
        "/passkey/list-user-passkeys",
        Some(&owner_cookie),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let passkeys = listed["passkeys"].as_array().unwrap();
    assert_eq!(passkeys.len(), 1);
    assert_eq!(passkeys[0]["name"], "Laptop");
    assert!(!listed.to_string().contains("credential\""));

    // The same authenticator cannot be registered to a second account.
    let (other_transaction, other_options) = register_options(&router, &other_cookie).await;
    let (status, _) = verify_registration(
        &router,
        &other_cookie,
        &other_transaction,
        device.register(&other_options["options"]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Sign-in names no account. The authenticator picks the credential.
    let (transaction_id, options) = sign_in_options(&router).await;
    let assertion = device.sign_in(&options["options"]);
    let response = verify_authentication(&router, &transaction_id, assertion).await;
    assert_eq!(response.status, StatusCode::OK);
    let owner_session = session_cookie(&response).expect("passkey sign-in sets a session");
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["user"]["id"], owner_id);
    let (status, session) = call_json(
        &router,
        Method::GET,
        "/get-session",
        Some(&owner_session),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(session["user"]["email"], "owner@example.com");

    // A sign-in transaction works once.
    let replay = device.assertion(&options["options"], device.counter);
    let response = verify_authentication(&router, &transaction_id, replay).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    // The counter advances, so the next sign-in is accepted.
    let (transaction_id, options) = sign_in_options(&router).await;
    let assertion = device.sign_in(&options["options"]);
    let response = verify_authentication(&router, &transaction_id, assertion).await;
    assert_eq!(response.status, StatusCode::OK);

    // A cloned authenticator that replays an old counter is refused.
    let mut clone = Authenticator::new(7);
    let (transaction_id, options) = sign_in_options(&router).await;
    let assertion = clone.sign_in(&options["options"]);
    let response = verify_authentication(&router, &transaction_id, assertion).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    // A response from another origin is refused.
    let mut phishing = Authenticator::new(7);
    phishing.origin = "https://evil.example".to_owned();
    phishing.counter = 100;
    let (transaction_id, options) = sign_in_options(&router).await;
    let assertion = phishing.sign_in(&options["options"]);
    let response = verify_authentication(&router, &transaction_id, assertion).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    // Another account cannot rename or delete the owner's passkey.
    let passkey_id = passkeys[0]["id"].as_str().unwrap().to_owned();
    let (status, body) = call_json(
        &router,
        Method::POST,
        "/passkey/update-passkey",
        Some(&other_cookie),
        json!({"id": passkey_id, "name": "Stolen"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["updated"], false);
    let (status, body) = call_json(
        &router,
        Method::POST,
        "/passkey/delete-passkey",
        Some(&other_cookie),
        json!({"id": passkey_id}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["deleted"], false);
    let (_, listed) = call_json(
        &router,
        Method::GET,
        "/passkey/list-user-passkeys",
        Some(&owner_cookie),
        Value::Null,
    )
    .await;
    assert_eq!(listed["passkeys"][0]["name"], "Laptop");

    // The owner renames the passkey.
    let (status, body) = call_json(
        &router,
        Method::POST,
        "/passkey/update-passkey",
        Some(&owner_cookie),
        json!({"id": passkey_id, "name": "Work key"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["updated"], true);

    // After the owner deletes it, the credential no longer signs in.
    let (status, body) = call_json(
        &router,
        Method::POST,
        "/passkey/delete-passkey",
        Some(&owner_cookie),
        json!({"id": passkey_id}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["deleted"], true);
    let (transaction_id, options) = sign_in_options(&router).await;
    let assertion = device.sign_in(&options["options"]);
    let response = verify_authentication(&router, &transaction_id, assertion).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn passkey_routes_require_the_plugin() {
    let context = AuthContext::new(
        AuthOptions {
            secret: "p".repeat(32),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            has_database: true,
            ..AuthOptions::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        Vec::new(),
    )
    .unwrap();
    let router = AuthRouter::new(context).unwrap();
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/passkey/generate-authenticate-options",
        None,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
