use std::collections::HashMap;

use authz_types::ValidatedConfigurationModel;

use crate::CedarError;

/// Generate a Cedar schema from the authorization configuration model.
///
/// Generates a minimal-but-useful Cedar schema including principals,
/// organizational entities, and resource/action definitions derived from the
/// supplied configuration.
pub fn generate_schema(config: &ValidatedConfigurationModel) -> Result<String, CedarError> {
    ensure_unique_resource_entity_names(config)?;
    let mut schema_json = serde_json::json!({
        "Authz": {
            "entityTypes": {},
            "actions": {}
        }
    });

    add_principal_types(&mut schema_json);
    add_org_types(&mut schema_json);

    for rt in &config.resource_types {
        add_resource_entity_type(&mut schema_json, rt)?;
        for action in &rt.actions {
            add_action(&mut schema_json, rt.id.as_str(), &action.name);
        }
    }

    Ok(schema_json.to_string())
}

/// Base schema containing principal/org/tenant entities without any resources.
pub fn generate_base_schema() -> Result<String, CedarError> {
    let mut schema_json = serde_json::json!({
        "Authz": {
            "entityTypes": {},
            "actions": {}
        }
    });
    add_principal_types(&mut schema_json);
    add_org_types(&mut schema_json);
    Ok(schema_json.to_string())
}

/// Schema slice for a single resource type (plus base entities).
pub fn generate_schema_for_resource(
    config: &ValidatedConfigurationModel,
    resource_type_id: &str,
) -> Result<String, CedarError> {
    ensure_unique_resource_entity_names(config)?;
    let mut schema_json = serde_json::json!({
        "Authz": {
            "entityTypes": {},
            "actions": {}
        }
    });

    add_principal_types(&mut schema_json);
    add_org_types(&mut schema_json);

    let rt = config.get_resource_type(resource_type_id).ok_or_else(|| {
        CedarError::schema_generation(format!("resource type not found: {resource_type_id}"))
    })?;

    add_resource_entity_type(&mut schema_json, rt)?;
    for action in &rt.actions {
        add_action(&mut schema_json, rt.id.as_str(), &action.name);
    }

    Ok(schema_json.to_string())
}

pub(crate) fn ensure_unique_resource_entity_names(
    config: &ValidatedConfigurationModel,
) -> Result<(), CedarError> {
    let mut canonical_names = HashMap::new();
    for reserved in [
        "User",
        "Group",
        "Role",
        "ServiceAccount",
        "ApiKey",
        "Org",
        "Tenant",
    ] {
        canonical_names.insert(
            reserved.to_string(),
            "reserved Cedar entity type".to_string(),
        );
    }

    for resource_type in &config.resource_types {
        let canonical = to_pascal_case(&resource_type.id);
        if canonical.is_empty() {
            return Err(CedarError::schema_generation(format!(
                "resource type '{}' has an empty canonical Cedar entity name",
                resource_type.id
            )));
        }
        if let Some(existing) = canonical_names.insert(canonical.clone(), resource_type.id.clone())
        {
            return Err(CedarError::schema_generation(format!(
                "resource types '{}' and '{}' collide as Cedar entity type '{}'",
                existing, resource_type.id, canonical
            )));
        }
    }

    Ok(())
}

fn add_principal_types(schema: &mut serde_json::Value) {
    let mut principal_attrs = serde_json::Map::new();
    principal_attrs.insert("id".to_string(), cedar_attr(cedar_type("String"), true));
    principal_attrs.insert(
        "org_id".to_string(),
        cedar_attr(cedar_type("String"), false),
    );
    principal_attrs.insert(
        "group_id".to_string(),
        cedar_attr(cedar_type("String"), false),
    );
    schema["Authz"]["entityTypes"]["User"] = serde_json::json!({
        "memberOfTypes": ["Group", "Role", "Org", "Tenant"],
        "shape": { "type": "Record", "attributes": principal_attrs.clone() }
    });
    schema["Authz"]["entityTypes"]["Group"] = serde_json::json!({
        "memberOfTypes": ["Role", "Org", "Tenant"],
        "shape": { "type": "Record", "attributes": principal_attrs.clone() }
    });
    schema["Authz"]["entityTypes"]["Role"] = serde_json::json!({
        "memberOfTypes": ["Org", "Tenant"],
        "shape": { "type": "Record", "attributes": principal_attrs.clone() }
    });
    schema["Authz"]["entityTypes"]["ServiceAccount"] = serde_json::json!({
        "memberOfTypes": ["Tenant"],
        "shape": { "type": "Record", "attributes": principal_attrs.clone() }
    });
    schema["Authz"]["entityTypes"]["ApiKey"] = serde_json::json!({
        "memberOfTypes": ["User", "Tenant"],
        "shape": { "type": "Record", "attributes": principal_attrs }
    });
}

fn add_org_types(schema: &mut serde_json::Value) {
    schema["Authz"]["entityTypes"]["Org"] = serde_json::json!({
        "memberOfTypes": ["Tenant"],
        "shape": { "type": "Record", "attributes": {} }
    });
    schema["Authz"]["entityTypes"]["Tenant"] = serde_json::json!({
        "shape": { "type": "Record", "attributes": {} }
    });
}

fn add_resource_entity_type(
    schema: &mut serde_json::Value,
    rt: &authz_types::ResourceType,
) -> Result<(), CedarError> {
    let entity_name = to_pascal_case(&rt.id);

    let mut attributes = serde_json::Map::new();

    let required_props: std::collections::HashSet<String> = rt
        .context_schema
        .as_ref()
        .and_then(|ctx| ctx.get("required").and_then(|r| r.as_array()))
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();

    // Standard attributes used by scope conditions
    attributes.insert(
        "org_id".to_string(),
        cedar_attr(cedar_type("String"), false),
    );
    attributes.insert(
        "group_id".to_string(),
        cedar_attr(cedar_type("String"), false),
    );
    attributes.insert(
        "owner_id".to_string(),
        cedar_attr(cedar_type("String"), false),
    );
    attributes.insert(
        "shared_with".to_string(),
        cedar_attr(
            serde_json::json!({ "type": "Set", "element": cedar_type("String") }),
            false,
        ),
    );
    attributes.insert(
        "is_public".to_string(),
        cedar_attr(cedar_type("Boolean"), false),
    );
    attributes.insert(
        "org_parents".to_string(),
        cedar_attr(
            serde_json::json!({
                "type": "Set",
                "element": { "type": "String" }
            }),
            false,
        ),
    );
    attributes.insert(
        "group_parents".to_string(),
        cedar_attr(
            serde_json::json!({
                "type": "Set",
                "element": { "type": "String" }
            }),
            false,
        ),
    );

    // Merge context schema properties
    if let Some(ctx_schema) = &rt.context_schema
        && let Some(props) = ctx_schema.get("properties").and_then(|p| p.as_object())
    {
        for (name, prop_schema) in props {
            let cedar_ty = json_schema_to_cedar_type(prop_schema)?;
            let required = required_props.contains(name);
            attributes.insert(name.clone(), cedar_attr(cedar_ty, required));
        }
    }

    schema["Authz"]["entityTypes"][entity_name] = serde_json::json!({
        "memberOfTypes": ["Org", "Group", "Tenant"],
        "shape": {
            "type": "Record",
            "attributes": attributes
        }
    });

    Ok(())
}

fn add_action(schema: &mut serde_json::Value, resource_id: &str, action: &str) {
    let action_name = format!("{resource_id}:{action}");
    let resource_entity = to_pascal_case(resource_id);

    let context_schema = serde_json::json!({
        "type": "Record",
        "attributes": {
            "subject_parents": cedar_attr(
                serde_json::json!({
                    "type": "Set",
                    "element": { "type": "Entity", "name": "Authz::Role" }
                }),
                false
            ),
            "resource_parents": cedar_attr(
                serde_json::json!({
                    "type": "Set",
                    "element": { "type": "Entity", "name": "Authz::Org" }
                }),
                false
            ),
            "_authz": cedar_attr(serde_json::json!({ "type": "AuthzContext" }), true)
        }
    });

    schema["Authz"]["commonTypes"]["AuthzContext"] = internal_context_schema(&resource_entity);

    schema["Authz"]["actions"][action_name] = serde_json::json!({
        "appliesTo": {
            "principalTypes": ["User", "Group", "Role", "ApiKey"],
            "resourceTypes": [resource_entity],
            "context": context_schema
        }
    });
}

fn internal_context_schema(resource_entity: &str) -> serde_json::Value {
    let required = |value| cedar_attr(value, true);
    serde_json::json!({
        "type": "Record",
        "attributes": {
            "token_present": required(cedar_type("Boolean")),
            "token_valid": required(cedar_type("Boolean")),
            "token_resource_filter_enabled": required(cedar_type("Boolean")),
            "token_resource_filter": required(serde_json::json!({
                "type": "Set",
                "element": { "type": "Entity", "name": format!("Authz::{resource_entity}") }
            })),
            "token_org_id_present": required(cedar_type("Boolean")),
            "token_org_id": required(cedar_type("String")),
            "token_owner_org_ids": required(serde_json::json!({
                "type": "Set", "element": { "type": "String" }
            })),
            "allowed_actions": required(serde_json::json!({
                "type": "Set", "element": { "type": "String" }
            })),
            "resource_scopes": required(serde_json::json!({
                "type": "Set",
                "element": {
                    "type": "Record",
                    "attributes": {
                        "role": required(serde_json::json!({
                            "type": "Entity", "name": "Authz::Role"
                        })),
                        "resource": required(serde_json::json!({
                            "type": "Entity", "name": format!("Authz::{resource_entity}")
                        }))
                    }
                }
            })),
            "session_present": required(cedar_type("Boolean")),
            "session_acr": required(cedar_type("Long")),
            "session_amr": required(serde_json::json!({
                "type": "Set", "element": { "type": "String" }
            })),
            "session_auth_age_present": required(cedar_type("Boolean")),
            "session_auth_age_seconds": required(cedar_type("Long")),
            "session_mfa_age_present": required(cedar_type("Boolean")),
            "session_mfa_age_seconds": required(cedar_type("Long"))
        }
    })
}

fn json_schema_to_cedar_type(schema: &serde_json::Value) -> Result<serde_json::Value, CedarError> {
    match schema.get("type").and_then(|t| t.as_str()) {
        Some("string") => Ok(cedar_type("String")),
        Some("boolean") => Ok(cedar_type("Boolean")),
        Some("integer") | Some("number") => Ok(cedar_type("Long")),
        Some("array") => {
            let default_items = serde_json::json!({"type": "string"});
            let items_ref = schema.get("items").unwrap_or(&default_items);
            let item_type = json_schema_to_cedar_type(items_ref)?;
            Ok(serde_json::json!({ "type": "Set", "element": item_type }))
        }
        Some("object") => Ok(serde_json::json!({ "type": "Record", "attributes": {} })),
        _ => Ok(cedar_type("String")), // Default fallback
    }
}

fn cedar_type(name: &str) -> serde_json::Value {
    serde_json::json!({ "type": name })
}

fn cedar_attr(ty: serde_json::Value, required: bool) -> serde_json::Value {
    match ty {
        serde_json::Value::Object(mut map) => {
            map.insert("required".to_string(), serde_json::Value::Bool(required));
            serde_json::Value::Object(map)
        }
        other => serde_json::json!({ "type": other, "required": required }),
    }
}

pub(crate) fn to_pascal_case(id: &str) -> String {
    id.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(|s| {
            let mut chars = s.chars();
            match chars.next() {
                Some(first) => {
                    first.to_ascii_uppercase().to_string() + &chars.as_str().to_ascii_lowercase()
                }
                None => String::new(),
            }
        })
        .collect::<String>()
}
