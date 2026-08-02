use better_auth_core::error::{AuthError, Result};
use serde_json::json;

pub(super) fn normalize_scim_attribute(attribute: &str) -> Result<String> {
    match attribute.to_ascii_lowercase().as_str() {
        "id" => Ok("id".into()),
        "username" | "emails.value" | "email" => Ok("email".into()),
        "emails" => Ok("emails".into()),
        "value" => Ok("email".into()),
        "type" => Ok("type".into()),
        "displayname" | "name" => Ok("name".into()),
        "active" => Ok("active".into()),
        _ => Err(AuthError::InvalidRequest(format!(
            "unsupported SCIM attribute: {attribute}"
        ))),
    }
}

pub(super) fn scim_attribute(user: &serde_json::Value, attribute: &str) -> Option<String> {
    if attribute == "emails" {
        return user
            .get("email")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);
    }
    if attribute == "type" {
        return user
            .get("type")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);
    }
    if attribute == "active" {
        return Some(
            user.get("active")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true)
                .to_string(),
        );
    }
    user.get(attribute)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

pub(super) fn scim_sort_value(id: &str, user: &serde_json::Value, attribute: &str) -> String {
    if attribute == "id" {
        return id.to_ascii_lowercase();
    }
    scim_attribute(user, attribute)
        .unwrap_or_default()
        .to_ascii_lowercase()
}

pub(super) fn scim_user_resource(id: &str, user: &serde_json::Value) -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": id,
        "userName": user.get("email"),
        "displayName": user.get("name"),
        "active": user.get("active").and_then(serde_json::Value::as_bool).unwrap_or(true),
        "meta": {"resourceType": "User"},
    })
}

pub(super) fn scim_user_from_resource(resource: &serde_json::Value) -> Result<serde_json::Value> {
    let email = resource
        .get("userName")
        .or_else(|| resource.get("email"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|email| email.contains('@'))
        .ok_or_else(|| AuthError::InvalidRequest("SCIM userName must be an email".into()))?;
    let name = resource
        .get("displayName")
        .or_else(|| resource.get("name"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or(email);
    Ok(json!({
        "email": email.to_ascii_lowercase(),
        "name": name.trim(),
        "email_verified": true,
        "role": "user",
        "active": resource.get("active").and_then(serde_json::Value::as_bool).unwrap_or(true),
    }))
}
