use std::collections::HashMap;

use authz_types::ValidatedConfigurationModel;
use cedar_policy::{
    EntityId, EntityTypeName, EntityUid, Policy, PolicyId, PolicySet, SlotId, Template,
};
use serde::{Deserialize, Serialize};

use crate::{
    BundleManifest, CedarError, PolicyDocument, PolicySlice, SchemaSlice, SliceMeta,
    StaticPolicyEntry, TemplateGroup, TemplateLinkEntry, generate_base_schema,
    generate_policy_document_for_resource, generate_schema_for_resource,
    schema_generator::ensure_unique_resource_entity_names,
    slices::{SLICE_SOFT_MAX_BYTES, enforce_size},
    validation::validate_compiled_slices,
};

/// Compile a sharded policy bundle (per-resource slices) for a specific config
/// version.
pub fn compile_policy_bundle(
    config: &ValidatedConfigurationModel,
    version: u64,
) -> Result<CompiledBundle, CedarError> {
    ensure_unique_resource_entity_names(config)?;
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
    validate_compiled_slices(&schema_slices, &policy_slices)?;
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
    let prepared = NativePolicyDocument::from_policy_document(document)?;
    if prepared.template_groups.is_empty() {
        let payload = serialize_policy_payload(prepared.static_policies.as_slice(), &[])
            .map_err(|error| policy_slice_error(resource_type, error))?;
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
    'next_slice: while start_idx < prepared.template_groups.len() {
        let static_policies = if include_static_policies {
            prepared.static_policies.as_slice()
        } else {
            &[]
        };
        let mut candidate_set = policy_set_with_static_policies(static_policies)?;
        let mut end_idx = start_idx;
        let mut largest_fitting_chunk: Option<(usize, String)> = None;

        while end_idx < prepared.template_groups.len() {
            add_template_group(&mut candidate_set, &prepared.template_groups[end_idx])?;
            let candidate_payload = serialize_policy_set(&candidate_set)
                .map_err(|error| policy_slice_error(resource_type, error))?;

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
                continue 'next_slice;
            }

            if include_static_policies {
                let static_only_payload = serialize_policy_payload(static_policies, &[])
                    .map_err(|error| policy_slice_error(resource_type, error))?;
                let static_only_size = static_only_payload.len();
                enforce_size("policy slice", static_only_size)
                    .map_err(CedarError::bundle_compilation)?;
                slices.push(PolicySlice {
                    resource_type: resource_type.to_string(),
                    policies_json: static_only_payload,
                    size_bytes: static_only_size,
                });
                include_static_policies = false;
                continue 'next_slice;
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
            serialize_policy_payload(prepared.static_policies.as_slice(), &[])
                .map_err(|error| policy_slice_error(resource_type, error))?;
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
struct NativePolicyDocument {
    static_policies: Vec<Policy>,
    template_groups: Vec<NativeTemplateGroup>,
}

impl NativePolicyDocument {
    fn from_policy_document(document: &PolicyDocument) -> Result<Self, CedarError> {
        Ok(Self {
            static_policies: document
                .static_policies
                .iter()
                .map(parse_static_policy)
                .collect::<Result<Vec<_>, _>>()?,
            template_groups: document
                .template_groups
                .iter()
                .map(NativeTemplateGroup::from_template_group)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

fn parse_static_policy(policy: &StaticPolicyEntry) -> Result<Policy, CedarError> {
    Policy::parse(
        Some(PolicyId::new(policy.policy_id.clone())),
        policy.policy_text.as_str(),
    )
    .map_err(|error| CedarError::policy_generation(error.to_string()))
}

#[derive(Debug)]
struct NativeTemplateGroup {
    template: Template,
    links: Vec<NativeTemplateLink>,
}

impl NativeTemplateGroup {
    fn from_template_group(group: &TemplateGroup) -> Result<Self, CedarError> {
        let template = Template::parse(
            Some(PolicyId::new(group.template_id.clone())),
            group.template_text.as_str(),
        )
        .map_err(|error| CedarError::policy_generation(error.to_string()))?;
        Ok(Self {
            template,
            links: group
                .links
                .iter()
                .map(NativeTemplateLink::from_template_link)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[derive(Debug)]
struct NativeTemplateLink {
    policy_id: PolicyId,
    principal: EntityUid,
}

impl NativeTemplateLink {
    fn from_template_link(link: &TemplateLinkEntry) -> Result<Self, CedarError> {
        let entity_type = "Authz::Role"
            .parse::<EntityTypeName>()
            .map_err(|error| CedarError::policy_generation(error.to_string()))?;
        let entity_id = EntityId::new(link.role_id.clone());
        Ok(Self {
            policy_id: PolicyId::new(link.policy_id.clone()),
            principal: EntityUid::from_type_name_and_id(entity_type, entity_id),
        })
    }
}

fn serialize_policy_payload(
    static_policies: &[Policy],
    template_groups: &[NativeTemplateGroup],
) -> Result<String, CedarError> {
    let mut policies = policy_set_with_static_policies(static_policies)?;
    for group in template_groups {
        add_template_group(&mut policies, group)?;
    }
    serialize_policy_set(&policies)
}

fn policy_set_with_static_policies(static_policies: &[Policy]) -> Result<PolicySet, CedarError> {
    let mut policies = PolicySet::new();
    for policy in static_policies {
        policies
            .add(policy.clone())
            .map_err(|error| CedarError::policy_generation(error.to_string()))?;
    }
    Ok(policies)
}

fn add_template_group(
    policies: &mut PolicySet,
    group: &NativeTemplateGroup,
) -> Result<(), CedarError> {
    let template_id = group.template.id().clone();
    policies
        .add_template(group.template.clone())
        .map_err(|error| CedarError::policy_generation(error.to_string()))?;
    for link in &group.links {
        policies
            .link(
                template_id.clone(),
                link.policy_id.clone(),
                HashMap::from([(SlotId::principal(), link.principal.clone())]),
            )
            .map_err(|error| CedarError::policy_generation(error.to_string()))?;
    }
    Ok(())
}

fn serialize_policy_set(policies: &PolicySet) -> Result<String, CedarError> {
    let json = policies
        .clone()
        .to_json()
        .map_err(|error| CedarError::policy_generation(error.to_string()))?;
    serde_json::to_string(&json).map_err(|error| CedarError::policy_generation(error.to_string()))
}

fn policy_slice_error(resource_type: &str, error: CedarError) -> CedarError {
    CedarError::bundle_compilation(format!(
        "failed serializing policy slice for resource {resource_type}: {error}"
    ))
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
