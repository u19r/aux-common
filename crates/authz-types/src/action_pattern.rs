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

    fn matches(&self, candidate: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(value) => candidate == value,
            Self::Prefix(value) => candidate.starts_with(value),
            Self::Suffix(value) => candidate.ends_with(value),
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
    for character in segment.chars() {
        if character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || character == '_'
            || character == '-'
            || character == '.'
        {
            continue;
        }
        return Err(ActionPatternParseError::InvalidCharacter { field, character });
    }
    Ok(())
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
    let resource_pattern = WildcardPattern::parse(
        resource_type_pattern,
        "resource_type",
        resource_type_max_len,
    )
    .map_err(ActionPatternExpandError::InvalidPattern)?;
    let action_pattern =
        WildcardPattern::parse(action_name_pattern, "action_name", action_name_max_len)
            .map_err(ActionPatternExpandError::InvalidPattern)?;

    let mut deduped = BTreeSet::new();
    for resource_type in resource_types {
        let resource_type_key = resource_type.id.trim().to_ascii_lowercase();
        if !resource_pattern.matches(resource_type_key.as_str()) {
            continue;
        }
        for action in &resource_type.actions {
            let action_name_key = action.name.trim().to_ascii_lowercase();
            if action_pattern.matches(action_name_key.as_str()) {
                deduped.insert((resource_type.id.clone(), action.name.clone()));
            }
        }
    }

    if deduped.is_empty() {
        return Err(ActionPatternExpandError::NoMatches {
            resource_type_pattern: resource_type_pattern.trim().to_ascii_lowercase(),
            action_name_pattern: action_name_pattern.trim().to_ascii_lowercase(),
            used_wildcard: resource_pattern.uses_wildcard() || action_pattern.uses_wildcard(),
        });
    }

    let expanded = deduped
        .into_iter()
        .map(|(resource_type, action_name)| ExpandedActionRef {
            resource_type,
            action_name,
        })
        .collect();
    Ok(expanded)
}
