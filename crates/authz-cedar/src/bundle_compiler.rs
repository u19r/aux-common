use std::collections::{BTreeMap, HashMap};

use authz_types::ValidatedConfigurationModel;
use cedar_policy::{Policy, PolicyId, Template};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::{
    BundleManifest, CedarError, PolicyDocument, PolicySlice, SchemaSlice, SliceMeta,
    StaticPolicyEntry, TemplateGroup, TemplateLinkEntry, generate_base_schema,
    generate_policy_document_for_resource, generate_schema_for_resource,
    slices::{SLICE_SOFT_MAX_BYTES, enforce_size},
};

/// Compile a sharded policy bundle (per-resource slices) for a specific config
/// version.
pub fn compile_policy_bundle(
    config: &ValidatedConfigurationModel,
    version: u64,
) -> Result<CompiledBundle, CedarError> {
    let base_schema_json = generate_base_schema()?;
    enforce_size("base schema", base_schema_json.len()).map_err(CedarError::bundle_compilation)?;

    let mut schema_slices = Vec::new();
    let mut policy_slices = Vec::new();
    for rt in &config.resource_types {
        let schema_json = generate_schema_for_resource(config, &rt.id)?;
        let schema_size = schema_json.len();
        enforce_size("schema slice", schema_size).map_err(CedarError::bundle_compilation)?;
        schema_slices.push(SchemaSlice {
            resource_type: rt.id.clone(),
            schema_json,
            size_bytes: schema_size,
        });

        let policy_document = generate_policy_document_for_resource(config, &rt.id)?;
        let resource_policy_slices = split_policy_slices(&rt.id, &policy_document)?;
        policy_slices.extend(resource_policy_slices);
    }

    let mut policy_slice_counts: HashMap<String, usize> = HashMap::new();
    let manifest = BundleManifest {
        version,
        schema_slices: schema_slices
            .iter()
            .map(|s| SliceMeta {
                key: s.resource_type.clone(),
                size_bytes: s.size_bytes,
            })
            .collect(),
        policy_slices: policy_slices
            .iter()
            .map(|s| SliceMeta {
                key: {
                    let entry = policy_slice_counts
                        .entry(s.resource_type.clone())
                        .or_insert(0);
                    let key = if *entry == 0 {
                        s.resource_type.clone()
                    } else {
                        format!("{}#{entry}", s.resource_type)
                    };
                    *entry += 1;
                    key
                },
                size_bytes: s.size_bytes,
            })
            .collect(),
        compiled_at_ms: None,
    };

    Ok(CompiledBundle {
        base_schema_json,
        schema_slices,
        policy_slices,
        manifest,
        version,
    })
}

fn split_policy_slices(
    resource_type: &str,
    document: &PolicyDocument,
) -> Result<Vec<PolicySlice>, CedarError> {
    let prepared = PreparedPolicyDocument::from_policy_document(document)?;
    if prepared.template_groups.is_empty() {
        let payload = serialize_policy_payload(prepared.static_policies.as_slice(), &[]).map_err(
            |error| {
                CedarError::bundle_compilation(format!(
                    "failed serializing policy slice for resource {resource_type}: {error}"
                ))
            },
        )?;
        let size = payload.len();
        enforce_size("policy slice", size).map_err(CedarError::bundle_compilation)?;
        return Ok(vec![PolicySlice {
            resource_type: resource_type.to_string(),
            policies_json: payload,
            size_bytes: size,
        }]);
    }

    let mut slices = Vec::new();
    let mut include_static_policies = !prepared.static_policies.is_empty();
    let mut start_idx = 0_usize;
    while start_idx < prepared.template_groups.len() {
        let static_policies = if include_static_policies {
            prepared.static_policies.as_slice()
        } else {
            &[]
        };
        let mut end_idx = start_idx;
        let mut largest_fitting_chunk: Option<(usize, String)> = None;

        while end_idx < prepared.template_groups.len() {
            let candidate_payload = serialize_policy_payload(
                static_policies,
                &prepared.template_groups[start_idx..=end_idx],
            )
            .map_err(|error| {
                CedarError::bundle_compilation(format!(
                    "failed serializing policy slice for resource {resource_type}: {error}"
                ))
            })?;

            if candidate_payload.len() <= SLICE_SOFT_MAX_BYTES {
                largest_fitting_chunk = Some((end_idx, candidate_payload));
                end_idx += 1;
                continue;
            }

            if let Some((last_fit_end_idx, payload)) = largest_fitting_chunk.take() {
                let payload_size = payload.len();
                slices.push(PolicySlice {
                    resource_type: resource_type.to_string(),
                    policies_json: payload,
                    size_bytes: payload_size,
                });
                start_idx = last_fit_end_idx + 1;
                include_static_policies = false;
                continue;
            }

            if include_static_policies {
                let static_only_payload =
                    serialize_policy_payload(static_policies, &[]).map_err(|error| {
                        CedarError::bundle_compilation(format!(
                            "failed serializing policy slice for resource {resource_type}: {error}"
                        ))
                    })?;
                let static_only_size = static_only_payload.len();
                enforce_size("policy slice", static_only_size)
                    .map_err(CedarError::bundle_compilation)?;
                slices.push(PolicySlice {
                    resource_type: resource_type.to_string(),
                    policies_json: static_only_payload,
                    size_bytes: static_only_size,
                });
                include_static_policies = false;
                continue;
            }

            return Err(CedarError::bundle_compilation(format!(
                "policy slice exceeds soft limit {SLICE_SOFT_MAX_BYTES} bytes: {}",
                candidate_payload.len()
            )));
        }

        let Some((last_fit_end_idx, payload)) = largest_fitting_chunk.take() else {
            break;
        };
        let payload_size = payload.len();
        slices.push(PolicySlice {
            resource_type: resource_type.to_string(),
            policies_json: payload,
            size_bytes: payload_size,
        });
        start_idx = last_fit_end_idx + 1;
        include_static_policies = false;
    }

    if include_static_policies {
        let static_only_payload =
            serialize_policy_payload(prepared.static_policies.as_slice(), &[]).map_err(
                |error| {
                    CedarError::bundle_compilation(format!(
                        "failed serializing policy slice for resource {resource_type}: {error}"
                    ))
                },
            )?;
        let static_only_size = static_only_payload.len();
        enforce_size("policy slice", static_only_size).map_err(CedarError::bundle_compilation)?;
        slices.push(PolicySlice {
            resource_type: resource_type.to_string(),
            policies_json: static_only_payload,
            size_bytes: static_only_size,
        });
    }

    Ok(slices)
}

#[derive(Debug)]
struct PreparedPolicyDocument {
    static_policies: Vec<PreparedStaticPolicy>,
    template_groups: Vec<PreparedTemplateGroup>,
}

impl PreparedPolicyDocument {
    fn from_policy_document(document: &PolicyDocument) -> Result<Self, CedarError> {
        Ok(Self {
            static_policies: document
                .static_policies
                .iter()
                .map(PreparedStaticPolicy::from_static_policy)
                .collect::<Result<Vec<_>, _>>()?,
            template_groups: document
                .template_groups
                .iter()
                .map(PreparedTemplateGroup::from_template_group)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[derive(Debug)]
struct PreparedStaticPolicy {
    policy_id: String,
    policy_json: JsonValue,
}

impl PreparedStaticPolicy {
    fn from_static_policy(policy: &StaticPolicyEntry) -> Result<Self, CedarError> {
        let parsed_policy = Policy::parse(
            Some(PolicyId::new(policy.policy_id.clone())),
            policy.policy_text.as_str(),
        )
        .map_err(|error| CedarError::policy_generation(error.to_string()))?;
        Ok(Self {
            policy_id: policy.policy_id.clone(),
            policy_json: parsed_policy
                .to_json()
                .map_err(|error| CedarError::policy_generation(error.to_string()))?,
        })
    }
}

#[derive(Debug)]
struct PreparedTemplateGroup {
    template_id: String,
    template_json: JsonValue,
    links: Vec<PreparedTemplateLink>,
}

impl PreparedTemplateGroup {
    fn from_template_group(group: &TemplateGroup) -> Result<Self, CedarError> {
        let parsed_template = Template::parse(
            Some(PolicyId::new(group.template_id.clone())),
            group.template_text.as_str(),
        )
        .map_err(|error| CedarError::policy_generation(error.to_string()))?;
        Ok(Self {
            template_id: group.template_id.clone(),
            template_json: parsed_template
                .to_json()
                .map_err(|error| CedarError::policy_generation(error.to_string()))?,
            links: group
                .links
                .iter()
                .map(|link| PreparedTemplateLink::from_template_link(&group.template_id, link))
                .collect(),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PreparedTemplateLink {
    template_id: String,
    new_id: String,
    values: BTreeMap<String, EntityUidJson>,
}

impl PreparedTemplateLink {
    fn from_template_link(template_id: &str, link: &TemplateLinkEntry) -> Self {
        Self {
            template_id: template_id.to_string(),
            new_id: link.policy_id.clone(),
            values: BTreeMap::from([(
                "?principal".to_string(),
                EntityUidJson {
                    entity_type: "Authz::Role".to_string(),
                    id: link.role_id.clone(),
                },
            )]),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct EntityUidJson {
    #[serde(rename = "type")]
    entity_type: String,
    id: String,
}

fn serialize_policy_payload(
    static_policies: &[PreparedStaticPolicy],
    template_groups: &[PreparedTemplateGroup],
) -> Result<String, serde_json::Error> {
    let static_policies = static_policies
        .iter()
        .map(|policy| (policy.policy_id.clone(), policy.policy_json.clone()))
        .collect::<JsonMap<String, JsonValue>>();
    let templates = template_groups
        .iter()
        .map(|group| (group.template_id.clone(), group.template_json.clone()))
        .collect::<JsonMap<String, JsonValue>>();
    let template_links = template_groups
        .iter()
        .flat_map(|group| group.links.iter().cloned())
        .collect::<Vec<_>>();

    serde_json::to_string(&SerializedPolicySet {
        templates,
        static_policies,
        template_links,
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SerializedPolicySet {
    templates: JsonMap<String, JsonValue>,
    static_policies: JsonMap<String, JsonValue>,
    template_links: Vec<PreparedTemplateLink>,
}

/// Sharded compiled bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledBundle {
    pub base_schema_json: String,
    pub schema_slices: Vec<SchemaSlice>,
    pub policy_slices: Vec<PolicySlice>,
    pub manifest: BundleManifest,
    pub version: u64,
}

impl CompiledBundle {
    pub fn as_json(&self) -> Result<String, CedarError> {
        serde_json::to_string(self).map_err(|e| CedarError::bundle_compilation(e.to_string()))
    }
}
