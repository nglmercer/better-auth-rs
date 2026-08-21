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

    pub fn with_handler(self, handler: Arc<dyn EndpointHandler>) -> ExecutableEndpoint {
        ExecutableEndpoint {
            endpoint: self,
            handler,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EndpointRequest {
    pub method: Method,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct EndpointResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

#[async_trait]
pub trait EndpointHandler: Send + Sync {
    async fn handle(&self, request: EndpointRequest) -> Result<EndpointResponse>;
}

#[derive(Clone)]
pub struct ExecutableEndpoint {
    pub endpoint: Endpoint,
    pub handler: Arc<dyn EndpointHandler>,
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
    fn endpoint_handlers(&self) -> Vec<ExecutableEndpoint> {
        Vec::new()
    }
}

#[derive(Default)]
pub struct PluginRegistry {
    plugins: Vec<Arc<dyn Plugin>>,
    endpoints: Vec<Endpoint>,
    hooks: Vec<Arc<dyn Hook>>,
    endpoint_handlers: Vec<ExecutableEndpoint>,
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
            registry
                .endpoint_handlers
                .extend(plugin.endpoint_handlers());
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

    pub fn endpoint_handlers(&self) -> &[ExecutableEndpoint] {
        &self.endpoint_handlers
    }

    pub fn schema(&self) -> &SchemaExtension {
        &self.schema
    }

    pub fn error_codes(&self) -> &BTreeMap<String, String> {
        &self.error_codes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{FieldSchema, FieldType, TableSchema};

    struct TestPlugin {
        plugin_name: &'static str,
        table: &'static str,
        field_type: FieldType,
    }

    impl Plugin for TestPlugin {
        fn name(&self) -> &'static str {
            self.plugin_name
        }

        fn schema(&self) -> SchemaExtension {
            SchemaExtension::default().table(
                self.table,
                TableSchema::default()
                    .field("value", FieldSchema::required(self.field_type.clone())),
            )
        }
    }

    #[test]
    fn plugin_schema_is_merged() {
        let registry = PluginRegistry::build(vec![Arc::new(TestPlugin {
            plugin_name: "one",
            table: "plugin_state",
            field_type: FieldType::String,
        })])
        .unwrap();
        assert!(registry.schema().tables.contains_key("plugin_state"));
    }

    #[test]
    fn conflicting_plugin_schema_is_rejected() {
        let result = PluginRegistry::build(vec![
            Arc::new(TestPlugin {
                plugin_name: "one",
                table: "plugin_state",
                field_type: FieldType::String,
            }),
            Arc::new(TestPlugin {
                plugin_name: "two",
                table: "plugin_state",
                field_type: FieldType::Integer,
            }),
        ]);
        assert!(result.is_err());
    }
}
