use crate::{error::Result, schema::SchemaExtension};
use async_trait::async_trait;
use http::{HeaderMap, Method, StatusCode};
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub method: Method,
    pub path: String,
    pub description: String,
}

impl Endpoint {
    pub fn new(method: Method, path: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            description: description.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct HookRequest {
    pub method: Method,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Option<Value>,
}

#[derive(Clone, Debug)]
pub struct HookResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
}

#[async_trait]
pub trait Hook: Send + Sync {
    async fn on_request(&self, _request: &HookRequest) -> Result<()> {
        Ok(())
    }

    async fn on_response(&self, _request: &HookRequest, _response: &HookResponse) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
pub trait Plugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn endpoints(&self) -> Vec<Endpoint> {
        Vec::new()
    }
    fn schema(&self) -> SchemaExtension {
        SchemaExtension::default()
    }
    fn error_codes(&self) -> BTreeMap<String, String> {
        BTreeMap::new()
    }
    fn hooks(&self) -> Vec<Arc<dyn Hook>> {
        Vec::new()
    }
}

#[derive(Default)]
pub struct PluginRegistry {
    plugins: Vec<Arc<dyn Plugin>>,
    endpoints: Vec<Endpoint>,
    hooks: Vec<Arc<dyn Hook>>,
    schema: SchemaExtension,
    error_codes: BTreeMap<String, String>,
}

impl PluginRegistry {
    pub fn build(plugins: Vec<Arc<dyn Plugin>>) -> Result<Self> {
        let mut registry = Self {
            plugins,
            ..Self::default()
        };
        for plugin in &registry.plugins {
            registry.endpoints.extend(plugin.endpoints());
            registry.hooks.extend(plugin.hooks());
            registry.schema.merge(&plugin.schema())?;
            for (code, message) in plugin.error_codes() {
                if registry.error_codes.insert(code.clone(), message).is_some() {
                    return Err(crate::AuthError::InvalidConfiguration(format!(
                        "duplicate plugin error code: {code}"
                    )));
                }
            }
        }
        Ok(registry)
    }

    pub fn plugins(&self) -> &[Arc<dyn Plugin>] {
        &self.plugins
    }

    pub fn endpoints(&self) -> &[Endpoint] {
        &self.endpoints
    }

    pub fn hooks(&self) -> &[Arc<dyn Hook>] {
        &self.hooks
    }

    pub fn schema(&self) -> &SchemaExtension {
        &self.schema
    }

    pub fn error_codes(&self) -> &BTreeMap<String, String> {
        &self.error_codes
    }
}

