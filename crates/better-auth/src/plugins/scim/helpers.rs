use better_auth_core::error::{AuthError, Result};

pub(super) fn normalize_scim_path(path: &str) -> Result<String> {
    let path = if let Some(path) = path.strip_prefix("/scim/v2") {
        format!("/{}", path.trim_start_matches('/'))
    } else if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    let path = path.trim_end_matches('/');
    if path == "/Users" || path.starts_with("/Users/") {
        Ok(path.into())
    } else {
        Err(AuthError::InvalidRequest("invalid SCIM bulk path".into()))
    }
}

pub(super) fn scim_group_member_id(group_id: &str, user_id: &str) -> String {
    format!("{group_id}:{user_id}")
}

pub(super) trait ScimErrorStatus {
    fn status_code(&self) -> u16;
}

impl ScimErrorStatus for AuthError {
    fn status_code(&self) -> u16 {
        match self {
            AuthError::InvalidRequest(_) => 400,
            AuthError::Unauthorized => 401,
            AuthError::Forbidden(_) => 403,
            AuthError::NotFound => 404,
            AuthError::RateLimited { .. } => 429,
            AuthError::InvalidConfiguration(_)
            | AuthError::Adapter(_)
            | AuthError::Plugin(_)
            | AuthError::Crypto(_) => 500,
        }
    }
}
