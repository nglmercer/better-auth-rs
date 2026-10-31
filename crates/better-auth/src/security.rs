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

    // Policy for state-changing requests:
    // - Origin, when sent, must be a trusted origin. `null` (sandboxed or opaque origins)
    //   is never trusted.
    // - Sec-Fetch-Site, when sent, must be one of the values a same-site request
    //   produces. Anything else is refused, including values not in this list.
    // - When both are absent, the request is accepted. Browsers send at least one of them on
    //   every cross-origin state change, so this only applies to non-browser clients, which
    //   cannot be attacked with a victim's cookies.
    // - When they disagree (a trusted Origin with a cross-site Sec-Fetch-Site, for example), the
    //   stricter check decides, so the request is refused.
    if let Some(origin) = request
        .headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        if origin == "null" || !context.is_trusted_origin(origin) {
            return Err(AuthError::Forbidden("request origin is not trusted".into()));
        }
    }

    if let Some(fetch_site) = request
        .headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
    {
        if !matches!(fetch_site, "same-origin" | "same-site" | "none") {
            return Err(AuthError::Forbidden("cross-site request blocked".into()));
        }
    }
    Ok(())
}

/// Refuses an endpoint that could reach the operator's own network: plain HTTP, credentials in
/// the URL, `localhost` and internal-looking names, and literal addresses that are loopback,
/// private, link-local (cloud metadata addresses included), shared (CGNAT), multicast or
/// unspecified. An identity provider is a public service, so none of these is valid for one.
pub fn validate_public_https_endpoint(url: &url::Url, what: &str) -> Result<()> {
    let refuse = |reason: &str| AuthError::InvalidConfiguration(format!("{what} {reason}"));
    if url.scheme() != "https" {
        return Err(refuse("must use HTTPS"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(refuse("must not contain credentials"));
    }
    match url.host() {
        None => Err(refuse("must have a host")),
        Some(url::Host::Domain(name)) => {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            let internal = name == "localhost"
                || name.ends_with(".localhost")
                || name.ends_with(".internal")
                || name.ends_with(".local")
                || name == "metadata";
            if internal {
                Err(refuse("must not point at a local or internal host"))
            } else {
                Ok(())
            }
        }
        Some(url::Host::Ipv4(address)) => {
            if is_internal_ipv4(address) {
                Err(refuse("must not point at a private or reserved address"))
            } else {
                Ok(())
            }
        }
        Some(url::Host::Ipv6(address)) => {
            if is_internal_ipv6(address) {
                Err(refuse("must not point at a private or reserved address"))
            } else {
                Ok(())
            }
        }
    }
}

fn is_internal_ipv4(address: std::net::Ipv4Addr) -> bool {
    let [first, second, ..] = address.octets();
    address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_broadcast()
        || address.is_multicast()
        // 100.64.0.0/10, shared address space used behind carrier NAT.
        || (first == 100 && (second & 0xc0) == 64)
        // 0.0.0.0/8, "this network".
        || first == 0
}

fn is_internal_ipv6(address: std::net::Ipv6Addr) -> bool {
    let first = address.segments()[0];
    address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        // fc00::/7, unique local.
        || (first & 0xfe00) == 0xfc00
        // fe80::/10, link local.
        || (first & 0xffc0) == 0xfe80
        || address
            .to_ipv4_mapped()
            .is_some_and(is_internal_ipv4)
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
