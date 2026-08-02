use super::super::shared::serialize_error;
use super::ScimPatchOperation;
use better_auth_core::error::{AuthError, Result};

pub(super) fn apply_scim_user_patch(
    mut user: serde_json::Value,
    patch: &serde_json::Value,
) -> Result<serde_json::Value> {
    if patch.is_array() {
        let operations = serde_json::from_value::<Vec<ScimPatchOperation>>(patch.clone())
            .map_err(serialize_error)?;
        for operation in operations {
            apply_scim_patch_operation(&mut user, &operation)?;
        }
        return Ok(user);
    }
    let Some(patch) = patch.as_object() else {
        return Err(AuthError::InvalidRequest(
            "SCIM patch must be an object or operation array".into(),
        ));
    };
    for (key, value) in patch {
        if matches!(key.as_str(), "id" | "schemas" | "meta") {
            continue;
        }
        apply_scim_patch_operation(
            &mut user,
            &ScimPatchOperation {
                op: "replace".into(),
                path: Some(key.clone()),
                value: Some(value.clone()),
            },
        )?;
    }
    Ok(user)
}

fn apply_scim_patch_operation(
    user: &mut serde_json::Value,
    operation: &ScimPatchOperation,
) -> Result<()> {
    let op = operation.op.to_ascii_lowercase();
    if !matches!(op.as_str(), "add" | "replace" | "remove") {
        return Err(AuthError::InvalidRequest(format!(
            "unsupported SCIM PATCH operation: {}",
            operation.op
        )));
    }
    let Some(path) = operation.path.as_deref() else {
        if op == "remove" {
            return Err(AuthError::InvalidRequest(
                "SCIM remove requires a path".into(),
            ));
        }
        let Some(value) = operation.value.as_ref() else {
            return Err(AuthError::InvalidRequest(
                "SCIM add/replace requires a value".into(),
            ));
        };
        let Some(object) = value.as_object() else {
            return Err(AuthError::InvalidRequest(
                "SCIM add/replace without path requires an object".into(),
            ));
        };
        for (key, value) in object {
            apply_scim_patch_operation(
                user,
                &ScimPatchOperation {
                    op: op.clone(),
                    path: Some(key.clone()),
                    value: Some(value.clone()),
                },
            )?;
        }
        return Ok(());
    };
    let attribute = normalize_scim_patch_attribute(path)?;
    if op == "remove" {
        if let Some(object) = user.as_object_mut() {
            object.remove(&attribute);
        }
        return Ok(());
    }
    let value = operation
        .value
        .clone()
        .ok_or_else(|| AuthError::InvalidRequest("SCIM add/replace requires a value".into()))?;
    if attribute == "email" {
        let email = value
            .as_str()
            .map(str::trim)
            .filter(|value| value.contains('@'))
            .ok_or_else(|| AuthError::InvalidRequest("SCIM userName must be an email".into()))?;
        user["email"] = email.to_ascii_lowercase().into();
    } else if attribute == "name" {
        user["name"] = value;
    } else if attribute == "active" {
        if !value.is_boolean() {
            return Err(AuthError::InvalidRequest(
                "SCIM active must be boolean".into(),
            ));
        }
        user["active"] = value;
    } else if attribute == "role" {
        user["role"] = value;
    }
    Ok(())
}

fn normalize_scim_patch_attribute(path: &str) -> Result<String> {
    let path = path.trim();
    let normalized = match path.to_ascii_lowercase().as_str() {
        "username" | "email" | "emails.value" => "email",
        "displayname" | "name" => "name",
        "active" => "active",
        "role" => "role",
        _ => {
            if path.to_ascii_lowercase().starts_with("emails[")
                && path.to_ascii_lowercase().ends_with("].value")
            {
                "email"
            } else {
                return Err(AuthError::InvalidRequest(format!(
                    "unsupported SCIM PATCH path: {path}"
                )));
            }
        }
    };
    Ok(normalized.into())
}

pub(super) fn merge_scim_patch(
    user: serde_json::Value,
    patch: &serde_json::Value,
) -> Result<serde_json::Value> {
    apply_scim_user_patch(user, patch)
}
