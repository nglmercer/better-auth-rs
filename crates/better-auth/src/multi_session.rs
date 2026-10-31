//! Several signed-in accounts in one browser.
//!
//! The active account keeps the normal session cookie. Other accounts' session
//! tokens are kept in a second cookie, `better-auth.multi_session`, whose value is
//! a signed JSON array. The signature stops a browser from adding tokens that the
//! server did not issue. Each token is still checked against the session table
//! when it is used.

use crate::cookies::{AuthCookie, SecretKeySet};
use better_auth_core::error::Result;
use better_auth_core::options::{CookieOptions, CookieSameSite};
use http::HeaderMap;

/// Upper bound on accounts kept in one browser.
pub const MAX_ACCOUNTS: usize = 5;
const COOKIE: &str = "better-auth.multi_session";
const MAX_AGE_SECONDS: u64 = 30 * 24 * 60 * 60;

pub fn cookie_name(transport_secure: bool) -> String {
    let prefix = if transport_secure { "__Secure-" } else { "" };
    format!("{prefix}{COOKIE}")
}

/// Session tokens from the signed cookie. A missing or forged cookie gives an empty list.
pub fn read_tokens(
    keys: &SecretKeySet,
    headers: &HeaderMap,
    transport_secure: bool,
) -> Vec<String> {
    let cookies = crate::cookies::request_cookies(headers);
    let Some(value) = cookies.get(&cookie_name(transport_secure)) else {
        return Vec::new();
    };
    keys.verify(value)
        .ok()
        .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
        .unwrap_or_default()
}

/// The cookie that stores `tokens`. An empty list clears the cookie.
pub fn write_cookie(
    keys: &SecretKeySet,
    tokens: &[String],
    transport_secure: bool,
    options: &CookieOptions,
) -> Result<AuthCookie> {
    let name = cookie_name(transport_secure);
    let secure = options.secure.unwrap_or(transport_secure);
    if tokens.is_empty() {
        return Ok(AuthCookie::removal(name, secure, &options.path));
    }
    let value = keys.sign(&serde_json::to_string(tokens).unwrap_or_else(|_| "[]".into()))?;
    Ok(AuthCookie {
        name,
        value,
        max_age_seconds: Some(MAX_AGE_SECONDS),
        secure,
        http_only: true,
        same_site: CookieSameSite::Lax,
        path: options.path.clone(),
        domain: options.domain.clone(),
    })
}

/// Adds `token` to the front of `tokens`, dropping duplicates and the oldest entries.
pub fn remember(tokens: &[String], token: &str) -> Vec<String> {
    let mut result = vec![token.to_owned()];
    for existing in tokens {
        if existing != token && !result.contains(existing) {
            result.push(existing.clone());
        }
    }
    result.truncate(MAX_ACCOUNTS);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembered_accounts_are_unique_and_capped() {
        let mut tokens = Vec::new();
        for index in 0..10 {
            tokens = remember(&tokens, &format!("token-{index}"));
        }
        assert_eq!(tokens.len(), MAX_ACCOUNTS);
        assert_eq!(tokens[0], "token-9");
        assert_eq!(remember(&tokens, "token-7")[0], "token-7");
        assert_eq!(remember(&tokens, "token-7").len(), MAX_ACCOUNTS);
    }
}
