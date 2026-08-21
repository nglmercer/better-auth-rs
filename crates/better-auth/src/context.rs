use crate::password::{PasswordProvider, ScryptPhcPasswordProvider};
use crate::{
    email_password::{Session, User},
    hooks::AuthHooks,
    session::AuthPrincipal,
};
use better_auth_core::{
    adapter::{DbAdapter, DbOperation, Query, SecondaryStorage},
    error::{AuthError, Result},
    migration::MigrationPlan,
    options::{AuthOptions, BaseUrl},
    plugin::Plugin,
    schema::{core_schema, SchemaExtension},
    PluginRegistry,
};
use http::{header, HeaderMap, Method, Uri};
use serde_json::Value;
use std::{net::IpAddr, sync::Arc};
use url::Url;

/// Immutable process-wide auth state. Request-dependent values are kept in a
/// separate RequestContext, so concurrent requests never mutate shared
/// configuration.
#[derive(Clone)]
pub struct AuthContext {
    pub options: Arc<AuthOptions>,
    pub adapter: Arc<dyn DbAdapter>,
    pub password_provider: Arc<dyn PasswordProvider>,
    pub lifecycle_hooks: Arc<Vec<Arc<dyn AuthHooks>>>,
    pub secondary_storage: Option<Arc<dyn SecondaryStorage>>,
    pub plugins: Arc<PluginRegistry>,
    pub schema: Arc<SchemaExtension>,
    pub base_url: Option<Url>,
}

impl AuthContext {
    /// Starts a context builder. Database presence is derived from whether
    /// `.database(...)` is called, so authentication cannot silently remain in
    /// cookie-only mode because a legacy boolean was omitted.
    pub fn builder(options: AuthOptions) -> AuthContextBuilder {
        AuthContextBuilder {
            options,
            adapter: None,
            secondary_storage: None,
            plugins: Vec::new(),
            password_provider: None,
            lifecycle_hooks: Vec::new(),
        }
    }

    pub fn new(
        options: AuthOptions,
        adapter: Arc<dyn DbAdapter>,
        secondary_storage: Option<Arc<dyn SecondaryStorage>>,
        plugins: Vec<Arc<dyn Plugin>>,
    ) -> Result<Self> {
        let provider = Arc::new(ScryptPhcPasswordProvider::new(
            options.password_hash.clone(),
        ));
        Self::from_parts(
            options,
            Some(adapter),
            secondary_storage,
            plugins,
            provider,
            Vec::new(),
        )
    }

    pub fn new_with_hooks(
        options: AuthOptions,
        adapter: Arc<dyn DbAdapter>,
        secondary_storage: Option<Arc<dyn SecondaryStorage>>,
        plugins: Vec<Arc<dyn Plugin>>,
        hooks: Vec<Arc<dyn AuthHooks>>,
    ) -> Result<Self> {
        let provider = Arc::new(ScryptPhcPasswordProvider::new(
            options.password_hash.clone(),
        ));
        Self::new_with_password_provider_and_hooks(
            options,
            adapter,
            secondary_storage,
            plugins,
            provider,
            hooks,
        )
    }

    pub fn new_with_password_provider(
        options: AuthOptions,
        adapter: Arc<dyn DbAdapter>,
        secondary_storage: Option<Arc<dyn SecondaryStorage>>,
        plugins: Vec<Arc<dyn Plugin>>,
        password_provider: Arc<dyn PasswordProvider>,
    ) -> Result<Self> {
        Self::new_with_password_provider_and_hooks(
            options,
            adapter,
            secondary_storage,
            plugins,
            password_provider,
            Vec::new(),
        )
    }

    pub fn new_with_password_provider_and_hooks(
        options: AuthOptions,
        adapter: Arc<dyn DbAdapter>,
        secondary_storage: Option<Arc<dyn SecondaryStorage>>,
        plugins: Vec<Arc<dyn Plugin>>,
        password_provider: Arc<dyn PasswordProvider>,
        lifecycle_hooks: Vec<Arc<dyn AuthHooks>>,
    ) -> Result<Self> {
        Self::from_parts(
            options,
            Some(adapter),
            secondary_storage,
            plugins,
            password_provider,
            lifecycle_hooks,
        )
    }

    /// Builds an auth context without a primary database. Cookie-cache
    /// sessions remain available, while database-backed services return a
    /// configuration error instead of touching an accidental adapter.
    pub fn without_database(
        options: AuthOptions,
        secondary_storage: Option<Arc<dyn SecondaryStorage>>,
        plugins: Vec<Arc<dyn Plugin>>,
    ) -> Result<Self> {
        Self::builder(options)
            .secondary_storage(secondary_storage)
            .plugins(plugins)
            .build()
    }

    fn from_parts(
        mut options: AuthOptions,
        adapter: Option<Arc<dyn DbAdapter>>,
        secondary_storage: Option<Arc<dyn SecondaryStorage>>,
        plugins: Vec<Arc<dyn Plugin>>,
        password_provider: Arc<dyn PasswordProvider>,
        lifecycle_hooks: Vec<Arc<dyn AuthHooks>>,
    ) -> Result<Self> {
        options.has_database = adapter.is_some();
        options.has_secondary_storage = secondary_storage.is_some();
        options.apply_defaults();
        options.validate()?;

        let adapter: Arc<dyn DbAdapter> = adapter.unwrap_or_else(|| Arc::new(UnavailableDbAdapter));

        let base_url = match options.base_url.as_ref() {
            Some(BaseUrl::Static(value)) => Some(build_base_url(value, &options.base_path)?),
            Some(BaseUrl::Dynamic { .. }) | None => None,
        };

        let plugins = Arc::new(PluginRegistry::build(plugins)?);
        let mut schema = core_schema();
        schema.merge(plugins.schema())?;
        adapter.register_schema(&schema)?;

        Ok(Self {
            options: Arc::new(options),
            adapter,
            password_provider,
            lifecycle_hooks: Arc::new(lifecycle_hooks),
            secondary_storage,
            plugins,
            schema: Arc::new(schema),
            base_url,
        })
    }

    pub fn base_origin(&self) -> Option<String> {
        self.base_url.as_ref().map(|url| {
            let mut origin = format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default());
            if let Some(port) = url.port() {
                origin.push(':');
                origin.push_str(&port.to_string());
            }
            origin
        })
    }

    /// Returns the migration plan for the merged core and plugin schema. The
    /// application decides when and how to apply it, which keeps startup,
    /// deployment, and multi-instance migration policy explicit.
    pub fn migration_plan(&self) -> MigrationPlan {
        MigrationPlan::from_schema(&self.schema)
    }

    pub fn migration_plan_from(&self, previous: &SchemaExtension) -> Result<MigrationPlan> {
        MigrationPlan::diff(previous, &self.schema)
    }

    pub async fn before_user_create(&self, user: &mut User) -> Result<()> {
        for hook in self.lifecycle_hooks.iter() {
            hook.before_user_create(user).await?;
        }
        Ok(())
    }

    pub async fn after_user_create(&self, user: &User) -> Result<()> {
        for hook in self.lifecycle_hooks.iter() {
            hook.after_user_create(user).await?;
        }
        Ok(())
    }

    pub async fn before_session_create(&self, user: &User) -> Result<()> {
        for hook in self.lifecycle_hooks.iter() {
            hook.before_session_create(user).await?;
        }
        Ok(())
    }

    pub async fn after_sign_in(&self, principal: &AuthPrincipal) -> Result<()> {
        for hook in self.lifecycle_hooks.iter() {
            hook.after_sign_in(principal).await?;
        }
        Ok(())
    }

    pub async fn after_password_change(&self, user_id: &str) -> Result<()> {
        for hook in self.lifecycle_hooks.iter() {
            hook.after_password_change(user_id).await?;
        }
        Ok(())
    }

    pub async fn before_user_delete(&self, user_id: &str) -> Result<()> {
        for hook in self.lifecycle_hooks.iter() {
            hook.before_user_delete(user_id).await?;
        }
        Ok(())
    }

    pub async fn after_session_create(&self, user: &User, session: &Session) -> Result<()> {
        for hook in self.lifecycle_hooks.iter() {
            hook.after_session_create(user, session).await?;
        }
        Ok(())
    }

    pub fn resolve_request(&self, request: &RequestMetadata) -> Result<RequestContext> {
        let base_url = match &self.options.base_url {
            Some(BaseUrl::Static(_)) => self.base_url.clone(),
            Some(BaseUrl::Dynamic { allowed_hosts }) => {
                let candidate = request_url(request, self.options.advanced.trusted_proxy_headers)?;
                let host = candidate
                    .host_str()
                    .ok_or_else(|| AuthError::InvalidRequest("request has no host".into()))?;
                if !allowed_hosts
                    .iter()
                    .any(|pattern| host_matches(host, pattern))
                {
                    return Err(AuthError::Forbidden("request host is not allowed".into()));
                }
                Some(build_base_url(
                    request_origin_url(&candidate).as_str(),
                    &self.options.base_path,
                )?)
            }
            None => {
                let candidate = request_url(request, self.options.advanced.trusted_proxy_headers)?;
                Some(build_base_url(
                    request_origin_url(&candidate).as_str(),
                    &self.options.base_path,
                )?)
            }
        };

        let trusted_origins = self.trusted_origins(base_url.as_ref());
        let trusted_providers = self.options.trusted_providers.clone();
        let client_ip = extract_ip_from_headers(
            &request.headers,
            self.options.advanced.trusted_proxy_headers,
            &self.options.advanced.trusted_ip_headers,
        );

        Ok(RequestContext {
            auth: self.clone(),
            base_url,
            trusted_origins,
            trusted_providers,
            client_ip,
        })
    }

    fn trusted_origins(&self, request_base: Option<&Url>) -> Vec<String> {
        let mut origins = self.options.trusted_origins.clone();
        if let Some(origin) = self.base_origin() {
            origins.push(origin);
        }
        if let Some(url) = request_base {
            let origin = origin_for_url(url);
            if !origins.iter().any(|existing| existing == &origin) {
                origins.push(origin);
            }
        }
        origins
    }
}

/// Builder for applications that want database presence to be explicit in
/// the type of configuration rather than in a separately maintained boolean.
pub struct AuthContextBuilder {
    options: AuthOptions,
    adapter: Option<Arc<dyn DbAdapter>>,
    secondary_storage: Option<Arc<dyn SecondaryStorage>>,
    plugins: Vec<Arc<dyn Plugin>>,
    password_provider: Option<Arc<dyn PasswordProvider>>,
    lifecycle_hooks: Vec<Arc<dyn AuthHooks>>,
}

impl AuthContextBuilder {
    pub fn database(mut self, adapter: Arc<dyn DbAdapter>) -> Self {
        self.adapter = Some(adapter);
        self
    }

    pub fn secondary_storage(mut self, storage: Option<Arc<dyn SecondaryStorage>>) -> Self {
        self.secondary_storage = storage;
        self
    }

    pub fn plugins(mut self, plugins: Vec<Arc<dyn Plugin>>) -> Self {
        self.plugins = plugins;
        self
    }

    pub fn password_provider(mut self, provider: Arc<dyn PasswordProvider>) -> Self {
        self.password_provider = Some(provider);
        self
    }

    pub fn hooks(mut self, hooks: Vec<Arc<dyn AuthHooks>>) -> Self {
        self.lifecycle_hooks = hooks;
        self
    }

    pub fn build(self) -> Result<AuthContext> {
        let password_provider = self.password_provider.unwrap_or_else(|| {
            Arc::new(ScryptPhcPasswordProvider::new(
                self.options.password_hash.clone(),
            ))
        });
        AuthContext::from_parts(
            self.options,
            self.adapter,
            self.secondary_storage,
            self.plugins,
            password_provider,
            self.lifecycle_hooks,
        )
    }
}

struct UnavailableDbAdapter;

#[async_trait::async_trait]
impl DbAdapter for UnavailableDbAdapter {
    async fn find_one(&self, _table: &str, _query: Query) -> Result<Option<Value>> {
        Err(no_database_error())
    }

    async fn find_many(&self, _table: &str, _query: Query) -> Result<Vec<Value>> {
        Err(no_database_error())
    }

    async fn insert_record(&self, _table: &str, _record: Value) -> Result<Value> {
        Err(no_database_error())
    }

    async fn update_where(&self, _table: &str, _query: Query, _changes: Value) -> Result<u64> {
        Err(no_database_error())
    }

    async fn delete_where(&self, _table: &str, _query: Query) -> Result<u64> {
        Err(no_database_error())
    }

    async fn transaction(&self, _operations: Vec<DbOperation>) -> Result<()> {
        Err(no_database_error())
    }
}

fn no_database_error() -> AuthError {
    AuthError::InvalidConfiguration("a primary database is not configured".into())
}

#[derive(Clone)]
pub struct RequestContext {
    pub auth: AuthContext,
    pub base_url: Option<Url>,
    pub trusted_origins: Vec<String>,
    pub trusted_providers: Vec<String>,
    pub client_ip: Option<IpAddr>,
}

impl RequestContext {
    pub fn is_trusted_origin(&self, origin: &str) -> bool {
        self.trusted_origins
            .iter()
            .any(|pattern| origin_matches(origin, pattern))
    }
}

#[derive(Clone, Debug)]
pub struct RequestMetadata {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
}

impl RequestMetadata {
    pub fn new(method: Method, uri: Uri, headers: HeaderMap) -> Self {
        Self {
            method,
            uri,
            headers,
        }
    }
}

fn build_base_url(raw: &str, base_path: &str) -> Result<Url> {
    let mut url = Url::parse(raw)
        .map_err(|error| AuthError::InvalidConfiguration(format!("invalid base URL: {error}")))?;
    if url.host_str().is_none() || !matches!(url.scheme(), "http" | "https") {
        return Err(AuthError::InvalidConfiguration(
            "base URL must use http or https and include a host".into(),
        ));
    }
    let current_path = url.path().trim_end_matches('/');
    if !current_path.ends_with(base_path) {
        let path = if current_path.is_empty() {
            base_path.to_owned()
        } else {
            format!("{current_path}{base_path}")
        };
        url.set_path(&path);
    }
    Ok(url)
}

fn request_origin_url(url: &Url) -> Url {
    let mut origin = url.clone();
    origin.set_path("/");
    origin.set_query(None);
    origin.set_fragment(None);
    origin
}

fn origin_for_url(url: &Url) -> String {
    let mut origin = format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default());
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    origin
}

fn request_url(request: &RequestMetadata, trust_proxy_headers: bool) -> Result<Url> {
    if request.uri.scheme_str().is_some() {
        let raw = request.uri.to_string();
        return Url::parse(&raw)
            .map_err(|error| AuthError::InvalidRequest(format!("invalid request URL: {error}")));
    }

    let host = header_string(&request.headers, header::HOST)
        .ok_or_else(|| AuthError::InvalidRequest("request is missing Host".into()))?;
    let scheme = if trust_proxy_headers {
        header_string(&request.headers, "x-forwarded-proto")
            .and_then(|value| value.split(',').next().map(str::trim).map(str::to_owned))
            .filter(|value| *value == "http" || *value == "https")
            .unwrap_or_else(|| "http".to_owned())
    } else {
        "http".to_owned()
    };
    let path = request
        .uri
        .path_and_query()
        .map_or("/", |value| value.as_str());
    Url::parse(&format!("{scheme}://{host}{path}"))
        .map_err(|error| AuthError::InvalidRequest(format!("invalid request host: {error}")))
}

fn header_string(headers: &HeaderMap, name: impl http::header::AsHeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn extract_ip_from_headers(
    headers: &HeaderMap,
    trust_proxy_headers: bool,
    trusted_headers: &[String],
) -> Option<IpAddr> {
    if !trust_proxy_headers {
        return None;
    }
    trusted_headers.iter().find_map(|name| {
        header_string(headers, name.as_str()).and_then(|value| {
            value
                .split(',')
                .map(str::trim)
                .find_map(|candidate| candidate.parse().ok())
        })
    })
}

pub(crate) fn extract_ip_from_headers_public(
    headers: &HeaderMap,
    trust_proxy_headers: bool,
    trusted_headers: &[String],
) -> Option<IpAddr> {
    extract_ip_from_headers(headers, trust_proxy_headers, trusted_headers)
}

fn host_matches(host: &str, pattern: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.ends_with(&format!(".{suffix}")) && host != suffix
    } else {
        host == pattern
    }
}

fn origin_matches(origin: &str, pattern: &str) -> bool {
    let origin = origin.trim_end_matches('/').to_ascii_lowercase();
    let pattern = pattern.trim().trim_end_matches('/').to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        origin.ends_with(&format!(".{suffix}"))
    } else {
        origin == pattern
    }
}

#[cfg(test)]
pub(crate) fn host_matches_public(host: &str, pattern: &str) -> bool {
    host_matches(host, pattern)
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::{adapter::memory::MemoryDb, options::AuthOptions};

    fn options() -> AuthOptions {
        AuthOptions {
            secret: "a".repeat(32),
            base_url: Some(BaseUrl::Static("https://example.com".into())),
            ..AuthOptions::default()
        }
    }

    #[test]
    fn static_base_url_includes_base_path() {
        let context =
            AuthContext::new(options(), Arc::new(MemoryDb::default()), None, Vec::new()).unwrap();
        assert_eq!(
            context.base_url.unwrap().as_str(),
            "https://example.com/api/auth"
        );
    }

    #[test]
    fn wildcard_hosts_do_not_match_the_bare_suffix() {
        assert!(host_matches_public("tenant.example.com", "*.example.com"));
        assert!(!host_matches_public("example.com", "*.example.com"));
    }

    #[test]
    fn dynamic_base_url_uses_request_origin_not_endpoint_path() {
        let options = AuthOptions {
            secret: "a".repeat(32),
            base_url: Some(BaseUrl::dynamic(["*.example.com"])),
            ..AuthOptions::default()
        };
        let context =
            AuthContext::new(options, Arc::new(MemoryDb::default()), None, Vec::new()).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "tenant.example.com".parse().unwrap());
        let request = RequestMetadata::new(
            Method::POST,
            "/api/auth/sign-in?next=%2Fdashboard".parse().unwrap(),
            headers,
        );
        let resolved = context.resolve_request(&request).unwrap();
        assert_eq!(
            resolved.base_url.unwrap().as_str(),
            "http://tenant.example.com/api/auth"
        );
    }

    #[test]
    fn cookie_cache_max_age_follows_custom_session_expiry() {
        let mut options = AuthOptions {
            secret: "a".repeat(32),
            ..AuthOptions::default()
        };
        options.session.expires_in_seconds = 900;
        options.apply_defaults();
        assert_eq!(options.session.cookie_cache.max_age_seconds, 900);
    }

    #[test]
    fn builder_derives_database_presence_from_the_adapter() {
        let without_database = AuthContext::builder(options()).build().unwrap();
        assert!(!without_database.options.has_database);

        let with_database = AuthContext::builder(options())
            .database(Arc::new(MemoryDb::default()))
            .build()
            .unwrap();
        assert!(with_database.options.has_database);
    }
}
