use std::collections::BTreeSet;

use crate::ResourceType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionPatternParseError {
    Empty {
        field: &'static str,
    },
    TooLong {
        field: &'static str,
        max_len: usize,
    },
    InvalidCharacter {
        field: &'static str,
        character: char,
    },
    InvalidWildcardShape {
        field: &'static str,
    },
}

impl std::fmt::Display for ActionPatternParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty { field } => write!(f, "{field} cannot be empty"),
            Self::TooLong { field, max_len } => {
                write!(f, "{field} exceeds max length {max_len}")
            }
            Self::InvalidCharacter { field, .. } => write!(
                f,
                "{field} must use lowercase letters, digits, '-', '_' or '.'"
            ),
            Self::InvalidWildcardShape { field } => write!(
                f,
                "{field} wildcard must be one of exact, '*', 'prefix*', or '*suffix'"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionPatternExpandError {
    InvalidPattern(ActionPatternParseError),
    NoMatches {
        resource_type_pattern: String,
        action_name_pattern: String,
        used_wildcard: bool,
    },
}

impl std::fmt::Display for ActionPatternExpandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPattern(error) => write!(f, "{error}"),
            Self::NoMatches {
                resource_type_pattern,
                action_name_pattern,
                used_wildcard,
            } => {
                if *used_wildcard {
                    write!(
                        f,
                        "wildcard pattern matched zero resource_type_action entries: \
                         {resource_type_pattern}:{action_name_pattern}"
                    )
                } else {
                    write!(
                        f,
                        "reference not found: {resource_type_pattern}:{action_name_pattern}"
                    )
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedActionRef {
    pub resource_type: String,
    pub action_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WildcardPattern {
    Any,
    Exact(String),
    Prefix(String),
    Suffix(String),
}

impl WildcardPattern {
    fn parse(
        raw: &str,
        field: &'static str,
        max_len: usize,
    ) -> Result<Self, ActionPatternParseError> {
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return Err(ActionPatternParseError::Empty { field });
        }
        if normalized.len() > max_len {
            return Err(ActionPatternParseError::TooLong { field, max_len });
        }
        if normalized == "*" {
            return Ok(Self::Any);
        }

        let wildcard_count = normalized.chars().filter(|ch| *ch == '*').count();
        if wildcard_count == 0 {
            validate_segment_chars(field, normalized.as_str())?;
            return Ok(Self::Exact(normalized));
        }
        if wildcard_count > 1 {
            return Err(ActionPatternParseError::InvalidWildcardShape { field });
        }

        if normalized.starts_with('*') {
            let suffix = normalized.get(1..).unwrap_or_default();
            if suffix.is_empty() {
                return Err(ActionPatternParseError::InvalidWildcardShape { field });
            }
            validate_segment_chars(field, suffix)?;
            return Ok(Self::Suffix(suffix.to_string()));
        }
        if normalized.ends_with('*') {
            let prefix = normalized
                .get(..normalized.len().saturating_sub(1))
                .unwrap_or_default();
            if prefix.is_empty() {
                return Err(ActionPatternParseError::InvalidWildcardShape { field });
            }
            validate_segment_chars(field, prefix)?;
            return Ok(Self::Prefix(prefix.to_string()));
        }

        Err(ActionPatternParseError::InvalidWildcardShape { field })
    }

    /// Match a catalog identifier, ignoring surrounding whitespace and ASCII
    /// case, without allocating. Pattern values are lowercase ASCII.
    fn matches(&self, candidate: &str) -> bool {
        let candidate = candidate.trim().as_bytes();
        match self {
            Self::Any => true,
            Self::Exact(value) => candidate.eq_ignore_ascii_case(value.as_bytes()),
            Self::Prefix(value) => candidate
                .get(..value.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(value.as_bytes())),
            Self::Suffix(value) => candidate
                .len()
                .checked_sub(value.len())
                .and_then(|start| candidate.get(start..))
                .is_some_and(|suffix| suffix.eq_ignore_ascii_case(value.as_bytes())),
        }
    }

    fn uses_wildcard(&self) -> bool {
        !matches!(self, Self::Exact(_))
    }
}

fn validate_segment_chars(
    field: &'static str,
    segment: &str,
) -> Result<(), ActionPatternParseError> {
    match segment
        .chars()
        .find(|character| character.is_ascii_uppercase() || !is_action_name_char(*character))
    {
        Some(character) => Err(ActionPatternParseError::InvalidCharacter { field, character }),
        None => Ok(()),
    }
}

/// Characters allowed in a catalog action name and in an action reference
/// (references compare case-insensitively). Excluding `:` and `#` keeps the
/// `resource_type:action` Cedar action ID and the `#` bundle manifest keys
/// unambiguous.
pub(crate) fn is_action_name_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
}

/// A parsed `resource_type:action` reference that may use wildcards.
pub(crate) struct ActionPattern {
    resource: WildcardPattern,
    action: WildcardPattern,
}

impl ActionPattern {
    pub(crate) fn parse(
        resource_type_pattern: &str,
        action_name_pattern: &str,
        resource_type_max_len: usize,
        action_name_max_len: usize,
    ) -> Result<Self, ActionPatternExpandError> {
        let resource = WildcardPattern::parse(
            resource_type_pattern,
            "resource_type",
            resource_type_max_len,
        )
        .map_err(ActionPatternExpandError::InvalidPattern)?;
        let action =
            WildcardPattern::parse(action_name_pattern, "action_name", action_name_max_len)
                .map_err(ActionPatternExpandError::InvalidPattern)?;
        Ok(Self { resource, action })
    }

    /// Catalog entries matched by this pattern, in catalog order.
    pub(crate) fn matches<'catalog>(
        &self,
        resource_types: &'catalog [ResourceType],
    ) -> impl Iterator<Item = (&'catalog str, &'catalog str)> {
        resource_types
            .iter()
            .filter(|resource_type| self.resource.matches(resource_type.id.as_str()))
            .flat_map(|resource_type| {
                resource_type
                    .actions
                    .iter()
                    .filter(|action| self.action.matches(action.name.as_str()))
                    .map(|action| (resource_type.id.as_str(), action.name.as_str()))
            })
    }

    /// Count matches without materializing them, so a caller can bound an
    /// expansion before allocating it. Duplicate catalog entries are counted
    /// twice, which keeps the count an upper bound on the expansion.
    pub(crate) fn count_matches(
        &self,
        resource_types: &[ResourceType],
        resource_type_pattern: &str,
        action_name_pattern: &str,
    ) -> Result<usize, ActionPatternExpandError> {
        match self.matches(resource_types).count() {
            0 => Err(self.no_matches(resource_type_pattern, action_name_pattern)),
            count => Ok(count),
        }
    }

    fn no_matches(
        &self,
        resource_type_pattern: &str,
        action_name_pattern: &str,
    ) -> ActionPatternExpandError {
        ActionPatternExpandError::NoMatches {
            resource_type_pattern: resource_type_pattern.trim().to_ascii_lowercase(),
            action_name_pattern: action_name_pattern.trim().to_ascii_lowercase(),
            used_wildcard: self.resource.uses_wildcard() || self.action.uses_wildcard(),
        }
    }
}

/// Expands resource_type/action patterns against the configured action catalog.
///
/// Patterns support exact, `*`, prefix (`prefix*`) and suffix (`*suffix`)
/// forms.
pub fn expand_action_patterns(
    resource_types: &[ResourceType],
    resource_type_pattern: &str,
    action_name_pattern: &str,
    resource_type_max_len: usize,
    action_name_max_len: usize,
) -> Result<Vec<ExpandedActionRef>, ActionPatternExpandError> {
    let pattern = ActionPattern::parse(
        resource_type_pattern,
        action_name_pattern,
        resource_type_max_len,
        action_name_max_len,
    )?;
    let deduped = pattern.matches(resource_types).collect::<BTreeSet<_>>();
    if deduped.is_empty() {
        return Err(pattern.no_matches(resource_type_pattern, action_name_pattern));
    }
    Ok(deduped
        .into_iter()
        .map(|(resource_type, action_name)| ExpandedActionRef {
            resource_type: resource_type.to_string(),
            action_name: action_name.to_string(),
        })
        .collect())
}
