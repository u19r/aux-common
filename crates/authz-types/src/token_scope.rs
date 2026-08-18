//! Token scoping types for API key permission ceilings.
//!
//! Effective permissions are always the intersection of user claims and
//! token scopes. Tokens can only restrict, never expand, what the user can do.

use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use utoipa::ToSchema;

const MAX_SCOPE_STRINGS: usize = 200;
const MAX_SELECTED_RESOURCES: usize = 1_000;
const MAX_SCOPE_MAP_ENTRIES: usize = 1_000;
const MAX_SCOPE_VALUES: usize = 500;
const MAX_SCOPE_TEXT_BYTES: usize = 128;
const MAX_SCOPE_KEY_BYTES: usize = 58;

/// Defines how an API token restricts the user's permissions.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[schema(example = json!({
    "scope_type": "scope_strings",
    "scope_strings": ["doc:read", "doc:write"],
    "fine_grained": null,
    "org_id": null
}))]
pub struct TokenScopeConfig {
    /// Scoping model used by the token.
    #[serde(default)]
    #[schema(
        value_type = String,
        default = "full_access",
        example = "scope_strings"
    )]
    pub scope_type: TokenScopeType,

    /// OAuth-style scope strings (coarse-grained scopes).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(max_items = 200, example = json!(["doc:read", "doc:write"]))]
    pub scope_strings: Vec<String>,

    /// Fine-grained per-resource permissions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true)]
    pub fine_grained: Option<FineGrainedScopes>,

    /// Optional organization binding for the token (org-scoped tokens).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, min_length = 1, max_length = 58, example = "org_123")]
    pub org_id: Option<String>,
}

impl<'de> Deserialize<'de> for TokenScopeConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        #[derive(Deserialize)]
        struct WireTokenScopeConfig {
            #[serde(default)]
            scope_type: Option<TokenScopeType>,
            #[serde(default, deserialize_with = "deserialize_scope_strings")]
            scope_strings: Vec<String>,
            #[serde(default)]
            fine_grained: Option<FineGrainedScopes>,
            #[serde(default, deserialize_with = "deserialize_bounded_optional_identifier")]
            org_id: Option<String>,
        }

        let wire = WireTokenScopeConfig::deserialize(deserializer)?;
        let has_scope_strings = !wire.scope_strings.is_empty();
        let has_fine_grained = wire.fine_grained.is_some();
        let scope_type = match wire.scope_type {
            Some(TokenScopeType::FullAccess) if has_scope_strings || has_fine_grained => {
                return Err(D::Error::custom(
                    "full_access token scope cannot include restricted scope fields",
                ));
            }
            Some(TokenScopeType::ScopeStrings) if has_fine_grained => {
                return Err(D::Error::custom(
                    "scope_strings token scope cannot include fine_grained fields",
                ));
            }
            Some(TokenScopeType::FineGrained) if has_scope_strings => {
                return Err(D::Error::custom(
                    "fine_grained token scope cannot include scope_strings fields",
                ));
            }
            Some(scope_type) => scope_type,
            None if has_scope_strings || has_fine_grained => {
                return Err(D::Error::custom(
                    "scope_type is required when restricted scope fields are present",
                ));
            }
            None => TokenScopeType::FullAccess,
        };

        Ok(Self {
            scope_type,
            scope_strings: wire.scope_strings,
            fine_grained: wire.fine_grained,
            org_id: wire.org_id,
        })
    }
}

impl Default for TokenScopeConfig {
    fn default() -> Self {
        Self {
            scope_type: TokenScopeType::FullAccess,
            scope_strings: Vec::new(),
            fine_grained: None,
            org_id: None,
        }
    }
}

impl TokenScopeConfig {
    /// Create an unrestricted token scope (default behavior).
    pub fn full_access() -> Self {
        Self::default()
    }

    /// Create a coarse-grained scope configuration.
    pub fn with_scopes(scopes: Vec<String>) -> Self {
        Self {
            scope_type: TokenScopeType::ScopeStrings,
            scope_strings: scopes,
            fine_grained: None,
            org_id: None,
        }
    }

    /// Create a fine-grained scope configuration.
    pub fn fine_grained(config: FineGrainedScopes) -> Self {
        Self {
            scope_type: TokenScopeType::FineGrained,
            scope_strings: Vec::new(),
            fine_grained: Some(config),
            org_id: None,
        }
    }

    /// Attach an org binding to the token.
    pub fn with_org(mut self, org_id: String) -> Self {
        self.org_id = Some(org_id);
        self
    }
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
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
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
                    values.insert(key, entry_values);
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
