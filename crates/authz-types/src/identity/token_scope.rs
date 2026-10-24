//! Token scoping types for API key permission ceilings.
//!
//! Effective permissions are always the intersection of user claims and
//! token scopes. Tokens can only restrict, never expand, what the user can do.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use utoipa::ToSchema;

use super::constants::{
    MAX_SCOPE_KEY_BYTES, MAX_SCOPE_MAP_ENTRIES, MAX_SCOPE_STRINGS, MAX_SCOPE_TEXT_BYTES,
    MAX_SCOPE_VALUES, MAX_SELECTED_RESOURCES,
};

/// Defines how an API token restricts the user's permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[schema(example = json!({
    "scope_type": "scope_strings",
    "scope_strings": ["doc:read", "doc:write"],
    "fine_grained": null,
    "org_id": null
}))]
pub struct TokenScopeConfig {
    /// Scoping model used by the token.
    #[serde(rename = "scope_type", default)]
    #[schema(
        value_type = String,
        default = "full_access",
        example = "scope_strings"
    )]
    scope_type: TokenScopeType,

    /// OAuth-style scope strings (coarse-grained scopes).
    #[serde(
        rename = "scope_strings",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    #[schema(max_items = 200, example = json!(["doc:read", "doc:write"]))]
    scope_strings: Vec<String>,

    /// Fine-grained per-resource permissions.
    #[serde(
        rename = "fine_grained",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(nullable = true)]
    fine_grained: Option<FineGrainedScopes>,

    /// Optional organization binding for the token (org-scoped tokens).
    #[serde(rename = "org_id", default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, min_length = 1, max_length = 58, example = "org_123")]
    org_id: Option<String>,

    /// Permission ids resolved from `scope_strings` when an API key is
    /// created.  Keeping this derived ceiling on the persisted credential
    /// prevents a later scope-mapping edit from broadening an existing key;
    /// the authorization evaluator still intersects it with the owner's
    /// current authority.
    #[serde(
        rename = "resolved_permissions",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(nullable = true, max_items = 500)]
    resolved_permissions: Option<Vec<String>>,
}

impl<'de> Deserialize<'de> for TokenScopeConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireTokenScopeConfig {
            #[serde(default)]
            scope_type: Option<TokenScopeType>,
            #[serde(default, deserialize_with = "deserialize_scope_strings")]
            scope_strings: Vec<String>,
            #[serde(default)]
            fine_grained: Option<FineGrainedScopes>,
            #[serde(default, deserialize_with = "deserialize_bounded_optional_identifier")]
            org_id: Option<String>,
            #[serde(default, deserialize_with = "deserialize_resolved_permissions")]
            resolved_permissions: Option<Vec<String>>,
        }

        let wire = WireTokenScopeConfig::deserialize(deserializer)?;
        let scope_type = match wire.scope_type {
            Some(scope_type) => scope_type,
            None if !wire.scope_strings.is_empty()
                || wire.fine_grained.is_some()
                || wire.resolved_permissions.is_some() =>
            {
                return Err(D::Error::custom(
                    "scope_type is required when restricted scope fields are present",
                ));
            }
            None => TokenScopeType::FullAccess,
        };
        Self::try_from_parts(
            scope_type,
            wire.scope_strings,
            wire.fine_grained,
            wire.org_id,
            wire.resolved_permissions,
        )
        .map_err(D::Error::custom)
    }
}

impl Default for TokenScopeConfig {
    fn default() -> Self {
        Self {
            scope_type: TokenScopeType::FullAccess,
            scope_strings: Vec::new(),
            fine_grained: None,
            org_id: None,
            resolved_permissions: None,
        }
    }
}

impl TokenScopeConfig {
    /// Create an unrestricted token scope (default behavior).
    pub fn full_access() -> Self {
        Self::default()
    }

    /// Create and validate a coarse-grained scope configuration.
    pub fn with_scopes(scopes: Vec<String>) -> Result<Self, crate::ValidationError> {
        Self::try_from_parts(TokenScopeType::ScopeStrings, scopes, None, None, None)
    }

    /// Create and validate a fine-grained scope configuration.
    pub fn fine_grained(config: FineGrainedScopes) -> Result<Self, crate::ValidationError> {
        Self::try_from_parts(
            TokenScopeType::FineGrained,
            Vec::new(),
            Some(config),
            None,
            None,
        )
    }

    /// Attach and validate an org binding on the token.
    pub fn with_org(self, org_id: String) -> Result<Self, crate::ValidationError> {
        Self::try_from_parts(
            self.scope_type,
            self.scope_strings,
            self.fine_grained,
            Some(org_id),
            self.resolved_permissions,
        )
    }

    /// Attach and validate the immutable permission ceiling resolved from the
    /// requested scope strings at credential creation.
    pub fn with_resolved_permissions(
        self,
        permissions: Vec<String>,
    ) -> Result<Self, crate::ValidationError> {
        Self::try_from_parts(
            self.scope_type,
            self.scope_strings,
            self.fine_grained,
            self.org_id,
            Some(permissions),
        )
    }

    #[must_use]
    pub const fn scope_type(&self) -> TokenScopeType {
        self.scope_type
    }

    #[must_use]
    pub fn scope_strings(&self) -> &[String] {
        &self.scope_strings
    }

    #[must_use]
    pub fn fine_grained_scopes(&self) -> Option<&FineGrainedScopes> {
        self.fine_grained.as_ref()
    }

    #[must_use]
    pub fn org_id(&self) -> Option<&str> {
        self.org_id.as_deref()
    }

    #[must_use]
    pub fn resolved_permissions(&self) -> Option<&[String]> {
        self.resolved_permissions.as_deref()
    }

    fn try_from_parts(
        scope_type: TokenScopeType,
        scope_strings: Vec<String>,
        fine_grained: Option<FineGrainedScopes>,
        org_id: Option<String>,
        resolved_permissions: Option<Vec<String>>,
    ) -> Result<Self, crate::ValidationError> {
        validate_parts(
            scope_type,
            &scope_strings,
            fine_grained.as_ref(),
            org_id.as_ref(),
            resolved_permissions.as_ref(),
        )?;
        Ok(Self {
            scope_type,
            scope_strings,
            fine_grained,
            org_id,
            resolved_permissions,
        })
    }
}

fn validate_parts(
    scope_type: TokenScopeType,
    scope_strings: &[String],
    fine_grained: Option<&FineGrainedScopes>,
    org_id: Option<&String>,
    resolved_permissions: Option<&Vec<String>>,
) -> Result<(), crate::ValidationError> {
    validate_scope_strings(scope_strings)?;
    validate_optional_identifier(org_id)?;
    if let Some(permissions) = resolved_permissions {
        if permissions.is_empty() {
            return Err(invalid_scope(
                "resolved_permissions must contain at least one permission",
            ));
        }
        validate_permission_values(permissions)?;
        if permissions.iter().collect::<HashSet<_>>().len() != permissions.len() {
            return Err(invalid_scope(
                "resolved_permissions must not contain duplicates",
            ));
        }
    }

    let has_scope_strings = !scope_strings.is_empty();
    let has_fine_grained = fine_grained.is_some();
    let has_resolved_permissions = resolved_permissions.is_some();
    match scope_type {
        TokenScopeType::FullAccess
            if has_scope_strings || has_fine_grained || has_resolved_permissions =>
        {
            return Err(invalid_scope(
                "full_access token scope cannot include restricted scope fields",
            ));
        }
        TokenScopeType::ScopeStrings if has_fine_grained => {
            return Err(invalid_scope(
                "scope_strings token scope cannot include fine_grained fields",
            ));
        }
        TokenScopeType::ScopeStrings if has_resolved_permissions && !has_scope_strings => {
            return Err(invalid_scope(
                "resolved_permissions requires non-empty scope_strings",
            ));
        }
        TokenScopeType::FineGrained if has_scope_strings => {
            return Err(invalid_scope(
                "fine_grained token scope cannot include scope_strings fields",
            ));
        }
        TokenScopeType::FineGrained if has_resolved_permissions => {
            return Err(invalid_scope(
                "fine_grained token scope cannot include resolved_permissions",
            ));
        }
        TokenScopeType::FineGrained if fine_grained.is_none() => {
            return Err(invalid_scope(
                "fine_grained token scope requires a fine_grained payload",
            ));
        }
        _ => {}
    }

    if let Some(fine_grained) = fine_grained {
        validate_fine_grained(fine_grained)?;
    }

    Ok(())
}

fn invalid_scope(message: &str) -> crate::ValidationError {
    crate::ValidationError::InvalidFormat {
        field: "token_scope",
        message: message.to_string(),
    }
}

fn validate_scope_strings(values: &[String]) -> Result<(), crate::ValidationError> {
    validate_string_vec(
        values,
        MAX_SCOPE_STRINGS,
        MAX_SCOPE_TEXT_BYTES,
        "scope_strings",
    )
}

fn validate_permission_values(values: &[String]) -> Result<(), crate::ValidationError> {
    validate_string_vec(
        values,
        MAX_SCOPE_VALUES,
        MAX_SCOPE_TEXT_BYTES,
        "resolved_permissions",
    )
}

fn validate_selected_resources(values: &[String]) -> Result<(), crate::ValidationError> {
    validate_string_vec(
        values,
        MAX_SELECTED_RESOURCES,
        MAX_SCOPE_KEY_BYTES,
        "selected_resources",
    )
}

fn validate_string_vec(
    values: &[String],
    max_items: usize,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), crate::ValidationError> {
    if values.len() > max_items {
        return Err(crate::ValidationError::LimitExceeded {
            resource: field,
            limit: max_items,
            actual: values.len(),
        });
    }
    if values
        .iter()
        .any(|value| value.is_empty() || value.len() > max_bytes)
    {
        return Err(crate::ValidationError::InvalidFormat {
            field,
            message: format!("string entries must be 1..={max_bytes} bytes"),
        });
    }
    Ok(())
}

fn validate_optional_identifier(value: Option<&String>) -> Result<(), crate::ValidationError> {
    if value.is_some_and(|value| value.is_empty() || value.len() > MAX_SCOPE_KEY_BYTES) {
        return Err(crate::ValidationError::InvalidFormat {
            field: "org_id",
            message: format!("identifiers must be 1..={MAX_SCOPE_KEY_BYTES} bytes"),
        });
    }
    Ok(())
}

fn validate_fine_grained(fine_grained: &FineGrainedScopes) -> Result<(), crate::ValidationError> {
    match fine_grained.resource_selection {
        ResourceSelection::All if !fine_grained.selected_resources.is_empty() => {
            return Err(invalid_scope(
                "resource_selection=all cannot include selected_resources",
            ));
        }
        ResourceSelection::Selected if fine_grained.selected_resources.is_empty() => {
            return Err(invalid_scope(
                "resource_selection=selected requires selected_resources",
            ));
        }
        _ => {}
    }
    validate_selected_resources(&fine_grained.selected_resources)?;
    validate_permission_map(&fine_grained.resource_permissions)?;
    validate_permission_map(&fine_grained.org_permissions)?;
    Ok(())
}

fn validate_permission_map(
    values: &HashMap<String, Vec<String>>,
) -> Result<(), crate::ValidationError> {
    if values.len() > MAX_SCOPE_MAP_ENTRIES {
        return Err(crate::ValidationError::LimitExceeded {
            resource: "permission_map",
            limit: MAX_SCOPE_MAP_ENTRIES,
            actual: values.len(),
        });
    }
    for (key, permissions) in values {
        if key.is_empty() || key.len() > MAX_SCOPE_KEY_BYTES {
            return Err(crate::ValidationError::InvalidFormat {
                field: "permission_map.key",
                message: format!("map keys must be 1..={MAX_SCOPE_KEY_BYTES} bytes"),
            });
        }
        validate_permission_values(permissions)?;
    }
    Ok(())
}

/// Scoping model used by a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum TokenScopeType {
    /// No additional restriction; token inherits all user permissions.
    #[default]
    FullAccess,

    /// Coarse-grained OAuth-style scope strings.
    ScopeStrings,

    /// Fine-grained per-resource permission allow-lists.
    FineGrained,
}

/// Fine-grained permission allow-lists per resource type.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, ToSchema)]
#[schema(example = json!({
    "resource_selection": "selected",
    "selected_resources": ["doc_1", "doc_2"],
    "resource_permissions": { "document": ["doc:read"] },
    "org_permissions": { "org_123": ["org:manage"] }
}))]
pub struct FineGrainedScopes {
    /// Which resources the token can access.
    #[serde(default)]
    #[schema(value_type = String, default = "all", example = "selected")]
    pub resource_selection: ResourceSelection,

    /// Explicit resource identifiers when `resource_selection` is `Selected`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(max_items = 1000, example = json!(["doc_1", "doc_2"]))]
    pub selected_resources: Vec<String>,

    /// Allowed permission ids per resource type identifier.
    ///
    /// A permission is admitted only when its id is present under every
    /// resource type referenced by that permission's allowed actions. This
    /// keeps composite permissions from inheriting a bucket from their id
    /// prefix or from an unrelated action resource.
    ///
    /// Example:
    /// `{"repo": ["repo:read", "repo:write"]}`
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    #[schema(example = json!({ "document": ["doc:read", "doc:write"] }))]
    pub resource_permissions: HashMap<String, Vec<String>>,

    /// Optional org-level allowed permission ids keyed by target organization.
    ///
    /// This is an additional ceiling for permissions whose action targets the
    /// `organization` resource type. A missing target entry is restrictive;
    /// it must not be interpreted as an unrestricted token.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    #[schema(example = json!({ "org_123": ["org:manage"] }))]
    pub org_permissions: HashMap<String, Vec<String>>,
}

impl<'de> Deserialize<'de> for FineGrainedScopes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireFineGrainedScopes {
            #[serde(default)]
            resource_selection: ResourceSelection,
            #[serde(default, deserialize_with = "deserialize_selected_resources")]
            selected_resources: Vec<String>,
            #[serde(default, deserialize_with = "deserialize_resource_permissions")]
            resource_permissions: HashMap<String, Vec<String>>,
            #[serde(default, deserialize_with = "deserialize_org_permissions")]
            org_permissions: HashMap<String, Vec<String>>,
        }

        let wire = WireFineGrainedScopes::deserialize(deserializer)?;
        match wire.resource_selection {
            ResourceSelection::All if !wire.selected_resources.is_empty() => {
                return Err(D::Error::custom(
                    "resource_selection=all cannot include selected_resources",
                ));
            }
            ResourceSelection::Selected if wire.selected_resources.is_empty() => {
                return Err(D::Error::custom(
                    "resource_selection=selected requires selected_resources",
                ));
            }
            _ => {}
        }
        Ok(Self {
            resource_selection: wire.resource_selection,
            selected_resources: wire.selected_resources,
            resource_permissions: wire.resource_permissions,
            org_permissions: wire.org_permissions,
        })
    }
}

struct BoundedStringVec<const MAX_ITEMS: usize, const MAX_BYTES: usize>(Vec<String>);

impl<'de, const MAX_ITEMS: usize, const MAX_BYTES: usize> Deserialize<'de>
    for BoundedStringVec<MAX_ITEMS, MAX_BYTES>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        struct Visitor<const MAX_ITEMS: usize, const MAX_BYTES: usize>;

        impl<'de, const MAX_ITEMS: usize, const MAX_BYTES: usize> serde::de::Visitor<'de>
            for Visitor<MAX_ITEMS, MAX_BYTES>
        {
            type Value = BoundedStringVec<MAX_ITEMS, MAX_BYTES>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded string sequence")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where A: serde::de::SeqAccess<'de> {
                let mut values = Vec::new();
                while values.len() < MAX_ITEMS {
                    let Some(value) = sequence.next_element::<String>()? else {
                        return Ok(BoundedStringVec(values));
                    };
                    if value.is_empty() || value.len() > MAX_BYTES {
                        return Err(serde::de::Error::custom(format!(
                            "string entries must be 1..={MAX_BYTES} bytes"
                        )));
                    }
                    values.push(value);
                }

                if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "sequence exceeds maximum of {MAX_ITEMS} entries"
                    )));
                }
                Ok(BoundedStringVec(values))
            }
        }

        deserializer.deserialize_seq(Visitor::<MAX_ITEMS, MAX_BYTES>)
    }
}

struct BoundedStringMap<
    const MAX_ENTRIES: usize,
    const MAX_VALUES: usize,
    const MAX_KEY_BYTES: usize,
    const MAX_VALUE_BYTES: usize,
>(HashMap<String, Vec<String>>);

impl<
    'de,
    const MAX_ENTRIES: usize,
    const MAX_VALUES: usize,
    const MAX_KEY_BYTES: usize,
    const MAX_VALUE_BYTES: usize,
> Deserialize<'de> for BoundedStringMap<MAX_ENTRIES, MAX_VALUES, MAX_KEY_BYTES, MAX_VALUE_BYTES>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        struct Visitor<
            const MAX_ENTRIES: usize,
            const MAX_VALUES: usize,
            const MAX_KEY_BYTES: usize,
            const MAX_VALUE_BYTES: usize,
        >;

        impl<
            'de,
            const MAX_ENTRIES: usize,
            const MAX_VALUES: usize,
            const MAX_KEY_BYTES: usize,
            const MAX_VALUE_BYTES: usize,
        > serde::de::Visitor<'de>
            for Visitor<MAX_ENTRIES, MAX_VALUES, MAX_KEY_BYTES, MAX_VALUE_BYTES>
        {
            type Value = BoundedStringMap<MAX_ENTRIES, MAX_VALUES, MAX_KEY_BYTES, MAX_VALUE_BYTES>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded string map")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where A: serde::de::MapAccess<'de> {
                let mut values = HashMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.len() >= MAX_ENTRIES {
                        return Err(serde::de::Error::custom(format!(
                            "map exceeds maximum of {MAX_ENTRIES} entries"
                        )));
                    }
                    if key.is_empty() || key.len() > MAX_KEY_BYTES {
                        return Err(serde::de::Error::custom(format!(
                            "map keys must be 1..={MAX_KEY_BYTES} bytes"
                        )));
                    }
                    let BoundedStringVec(entry_values) =
                        map.next_value::<BoundedStringVec<MAX_VALUES, MAX_VALUE_BYTES>>()?;
                    if values.insert(key, entry_values).is_some() {
                        return Err(serde::de::Error::custom(
                            "permission maps must not contain duplicate keys",
                        ));
                    }
                }
                Ok(BoundedStringMap(values))
            }
        }

        deserializer
            .deserialize_map(Visitor::<MAX_ENTRIES, MAX_VALUES, MAX_KEY_BYTES, MAX_VALUE_BYTES>)
    }
}

fn deserialize_scope_strings<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where D: Deserializer<'de> {
    Ok(BoundedStringVec::<MAX_SCOPE_STRINGS, MAX_SCOPE_TEXT_BYTES>::deserialize(deserializer)?.0)
}

fn deserialize_resolved_permissions<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error>
where D: Deserializer<'de> {
    let value = Option::<BoundedStringVec<MAX_SCOPE_VALUES, MAX_SCOPE_TEXT_BYTES>>::deserialize(
        deserializer,
    )?;
    Ok(value.map(|permissions| permissions.0))
}

fn deserialize_selected_resources<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where D: Deserializer<'de> {
    Ok(
        BoundedStringVec::<MAX_SELECTED_RESOURCES, MAX_SCOPE_KEY_BYTES>::deserialize(deserializer)?
            .0,
    )
}

fn deserialize_resource_permissions<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, Vec<String>>, D::Error>
where D: Deserializer<'de> {
    Ok(BoundedStringMap::<
        MAX_SCOPE_MAP_ENTRIES,
        MAX_SCOPE_VALUES,
        MAX_SCOPE_KEY_BYTES,
        MAX_SCOPE_TEXT_BYTES,
    >::deserialize(deserializer)?
    .0)
}

fn deserialize_org_permissions<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, Vec<String>>, D::Error>
where D: Deserializer<'de> {
    deserialize_resource_permissions(deserializer)
}

fn deserialize_bounded_optional_identifier<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where D: Deserializer<'de> {
    let value = Option::<String>::deserialize(deserializer)?;
    if let Some(value) = &value
        && (value.is_empty() || value.len() > MAX_SCOPE_KEY_BYTES)
    {
        return Err(D::Error::custom(format!(
            "identifiers must be 1..={MAX_SCOPE_KEY_BYTES} bytes"
        )));
    }
    Ok(value)
}

/// Resource selection strategy for fine-grained tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResourceSelection {
    /// All resources the user can access.
    #[default]
    All,

    /// Only explicitly selected resources.
    Selected,
}
