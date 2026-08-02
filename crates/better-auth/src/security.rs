use crate::context::{extract_ip_from_headers_public, RequestContext, RequestMetadata};
use better_auth_core::error::{AuthError, Result};
use http::{header, Method};
use std::net::IpAddr;

/// Validates origin and Fetch Metadata signals for state-changing requests.
/// Safe methods are allowed through because they must remain usable for
/// redirects and browser prefetches.
pub fn check_csrf(context: &RequestContext, request: &RequestMetadata) -> Result<()> {
    if matches!(
        request.method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    ) {
        return Ok(());
    }

    if let Some(origin) = request
        .headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        if !context.is_trusted_origin(origin) {
            return Err(AuthError::Forbidden("request origin is not trusted".into()));
        }
    }

    if let Some(fetch_site) = request
        .headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
    {
        if matches!(fetch_site, "cross-site" | "cross-origin") {
            return Err(AuthError::Forbidden("cross-site request blocked".into()));
        }
    }
    Ok(())
}

pub fn extract_client_ip(context: &RequestContext, request: &RequestMetadata) -> Option<IpAddr> {
    if context.auth.options.advanced.trusted_proxy_headers {
        extract_ip_from_headers_public(
            &request.headers,
            true,
            &context.auth.options.advanced.trusted_ip_headers,
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::AuthContext;
    use better_auth_core::{
        adapter::memory::MemoryDb,
        options::{AuthOptions, BaseUrl},
    };
    use http::{HeaderMap, Uri};
    use std::sync::Arc;

    fn context() -> RequestContext {
        let auth = AuthContext::new(
            AuthOptions {
                secret: "s".repeat(32),
                base_url: Some(BaseUrl::Static("https://example.com".into())),
                advanced: better_auth_core::options::AdvancedOptions {
                    trusted_proxy_headers: true,
                    trusted_ip_headers: vec!["x-forwarded-for".into()],
                },
                ..AuthOptions::default()
            },
            Arc::new(MemoryDb::default()),
            None,
            Vec::new(),
        )
        .unwrap();
        let request = RequestMetadata::new(Method::GET, Uri::from_static("/"), HeaderMap::new());
        auth.resolve_request(&request).unwrap()
    }

    #[test]
    fn cross_site_state_change_is_rejected() {
        let context = context();
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        let request = RequestMetadata::new(Method::POST, Uri::from_static("/sign-in"), headers);
        assert!(check_csrf(&context, &request).is_err());
    }

    #[test]
    fn same_origin_state_change_and_trusted_proxy_ip_are_allowed() {
        let context = context();
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://example.com".parse().unwrap());
        headers.insert("x-forwarded-for", "203.0.113.10, 10.0.0.1".parse().unwrap());
        let request = RequestMetadata::new(Method::POST, Uri::from_static("/sign-in"), headers);
        check_csrf(&context, &request).unwrap();
        assert_eq!(
            extract_client_ip(&context, &request).unwrap().to_string(),
            "203.0.113.10"
        );
    }

    #[test]
    fn untrusted_proxy_headers_are_ignored() {
        let mut context = context();
        context.auth.options = Arc::new(AuthOptions {
            advanced: better_auth_core::options::AdvancedOptions::default(),
            ..(*context.auth.options).clone()
        });
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.10".parse().unwrap());
        let request = RequestMetadata::new(Method::GET, Uri::from_static("/"), headers);
        assert!(extract_client_ip(&context, &request).is_none());
    }
}
