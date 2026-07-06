use authz_types::ValidatedConfigurationModel;

use crate::CedarError;

/// Generate a Cedar schema from the authorization configuration model.
///
/// Generates a minimal-but-useful Cedar schema including principals,
/// organizational entities, and resource/action definitions derived from the
/// supplied configuration.
pub fn generate_schema(config: &ValidatedConfigurationModel) -> Result<String, CedarError> {
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

fn add_principal_types(schema: &mut serde_json::Value) {
    let mut principal_attrs = serde_json::Map::new();
    principal_attrs.insert("id".to_string(), cedar_attr(cedar_type("String"), false));
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
                "element": { "type": "Entity", "name": "Authz::Org" }
            }),
            false,
        ),
    );
    attributes.insert(
        "group_parents".to_string(),
        cedar_attr(
            serde_json::json!({
                "type": "Set",
                "element": { "type": "Entity", "name": "Authz::Group" }
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
            )
        }
    });

    schema["Authz"]["actions"][action_name] = serde_json::json!({
        "appliesTo": {
            "principalTypes": ["User", "Group", "Role", "ApiKey"],
            "resourceTypes": [resource_entity],
            "context": context_schema
        }
    });
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
    if !required {
        return ty;
    }

    match ty {
        serde_json::Value::Object(mut map) => {
            map.insert("required".to_string(), serde_json::Value::Bool(true));
            serde_json::Value::Object(map)
        }
        other => serde_json::json!({ "type": other, "required": true }),
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
