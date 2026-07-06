use std::collections::HashMap;

use authz_types::ConfigurationModel;

use crate::generate_schema;

#[test]
fn schema_generation_includes_resources_and_actions() {
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: Some(serde_json::json!({
                "required": ["owner_id"],
                "properties": {
                    "owner_id": { "type": "string" },
                    "classification": { "type": "string" }
                }
            })),
        }],
        permissions: vec![],
        roles: vec![],
        scope_mappings: Vec::new(),
        description: None,
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    };

    let config = config.into_validated().expect("valid config");
    let schema = generate_schema(&config).expect("schema");
    assert!(schema.contains("\"Authz\""));
    assert!(schema.contains("\"entityTypes\""));
    assert!(schema.contains("\"User\""));
    assert!(schema.contains("\"Document\""));
    assert!(schema.contains("document:read"));
    assert!(schema.contains("classification"));
    assert!(schema.contains("\"required\":true"));
}
