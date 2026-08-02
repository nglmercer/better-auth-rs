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
