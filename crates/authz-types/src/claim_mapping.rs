//! Startup-compiled claim mapping contracts.
//!
//! A mapping is configuration, not request-time scripting.  The serialized
//! specification stores only bounded paths, templates, and regex source.  A
//! [`ClaimMappingRegistry`] compiles and validates that specification once at
//! configuration write/load time, then renders against a verified claim tree
//! without parsing or compiling anything on the request path.

use std::collections::{BTreeMap, BTreeSet};

use regex::{Captures, Regex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use utoipa::ToSchema;

use crate::{ClaimBoundsError, VerifiedClaimTree, is_structural_claim};

pub const MAX_CLAIM_MAPPINGS: usize = 64;
pub const MAX_CLAIM_MAPPING_PATH_BYTES: usize = 1_024;
pub const MAX_CLAIM_MAPPING_PATTERN_BYTES: usize = 1_024;
pub const MAX_CLAIM_MAPPING_TEMPLATE_NODES: usize = 128;

const MAX_CLAIM_MAPPING_REGEX_GROUP_DEPTH: usize = 32;
const MAX_CLAIM_MAPPING_REGEX_QUANTIFIERS: usize = 64;
const MAX_CLAIM_MAPPING_REGEX_REPEAT: u64 = 128;

fn is_claim_mapping_forbidden_character(character: char) -> bool {
    character.is_control()
        || character.is_whitespace()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
        )
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Serialize,
    Deserialize,
    JsonSchema,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ClaimMappingOutput {
    #[default]
    AccessToken,
    IdToken,
    UserInfo,
    SamlAssertion,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct ClaimMappingSpec {
    /// Source claim path.  Paths use a bounded JSONPath subset rooted at `$`.
    #[schema(value_type = serde_json::Value)]
    pub source: ClaimPath,
    /// Top-level output claim name.  Nested output is represented by the
    /// template value rather than arbitrary output-path mutation.
    pub target: String,
    /// Output artifact that owns this mapping. Duplicate writers are rejected
    /// per output rather than silently prioritized.
    #[serde(default)]
    pub output: ClaimMappingOutput,
    #[serde(default)]
    pub matcher: ClaimMappingMatcher,
    /// Regex source is persisted and recompiled when the registry is loaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// Optional regex over object-entry keys below `source`. When present,
    /// `source` must resolve to an object and every matching entry is rendered
    /// in deterministic key order. Named captures from this regex are merged
    /// with captures from `pattern`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_pattern: Option<String>,
    #[schema(value_type = serde_json::Value)]
    pub template: ClaimTemplate,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ClaimMappingMatcher {
    #[default]
    Exact,
    Regex,
}

/// A bounded JSONPath subset: root (`$`), object keys (`.key`), and array
/// indexes (`[0]`).  Wildcards and expressions are deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClaimPath(Vec<ClaimPathSegment>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum ClaimPathSegment {
    Key(String),
    Index(usize),
}

impl ClaimPath {
    pub fn parse(source: &str) -> Result<Self, ClaimMappingError> {
        if source.is_empty() || source.len() > MAX_CLAIM_MAPPING_PATH_BYTES {
            return Err(ClaimMappingError::InvalidPath);
        }
        if source == "$" {
            return Ok(Self(Vec::new()));
        }
        let bytes = source.as_bytes();
        if bytes.first() != Some(&b'$') {
            return Err(ClaimMappingError::InvalidPath);
        }
        let mut index = 1;
        let mut segments = Vec::new();
        while index < bytes.len() {
            match bytes[index] {
                b'.' => {
                    index += 1;
                    let start = index;
                    while index < bytes.len() && bytes[index] != b'.' && bytes[index] != b'[' {
                        index += 1;
                    }
                    if start == index {
                        return Err(ClaimMappingError::InvalidPath);
                    }
                    let key = source
                        .get(start..index)
                        .ok_or(ClaimMappingError::InvalidPath)?;
                    if key.chars().any(is_claim_mapping_forbidden_character) {
                        return Err(ClaimMappingError::InvalidPath);
                    }
                    segments.push(ClaimPathSegment::Key(key.to_owned()));
                }
                b'[' => {
                    index += 1;
                    let start = index;
                    while index < bytes.len() && bytes[index].is_ascii_digit() {
                        index += 1;
                    }
                    if start == index || bytes.get(index) != Some(&b']') {
                        return Err(ClaimMappingError::InvalidPath);
                    }
                    let position = source
                        .get(start..index)
                        .ok_or(ClaimMappingError::InvalidPath)?
                        .parse::<usize>()
                        .map_err(|_| ClaimMappingError::InvalidPath)?;
                    index += 1;
                    segments.push(ClaimPathSegment::Index(position));
                }
                _ => return Err(ClaimMappingError::InvalidPath),
            }
        }
        Ok(Self(segments))
    }

    fn value<'a>(&self, root: &'a Value) -> Option<&'a Value> {
        self.0
            .iter()
            .try_fold(root, |value, segment| match segment {
                ClaimPathSegment::Key(key) => value.get(key),
                ClaimPathSegment::Index(index) => value.get(*index),
            })
    }

    fn validate(&self) -> Result<(), ClaimMappingError> {
        let mut bytes: usize = 1;
        for segment in &self.0 {
            match segment {
                ClaimPathSegment::Key(key) => {
                    if key.is_empty() || key.chars().any(is_claim_mapping_forbidden_character) {
                        return Err(ClaimMappingError::InvalidPath);
                    }
                    bytes = bytes.saturating_add(key.len() + 1);
                }
                ClaimPathSegment::Index(_) => bytes = bytes.saturating_add(3),
            }
        }
        if bytes > MAX_CLAIM_MAPPING_PATH_BYTES {
            return Err(ClaimMappingError::InvalidPath);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClaimTemplate {
    Literal {
        value: Value,
    },
    Source,
    Capture {
        name: String,
    },
    Object {
        fields: BTreeMap<String, ClaimTemplate>,
    },
    Array {
        items: Vec<ClaimTemplate>,
    },
}

impl ClaimTemplate {
    fn node_count(&self) -> usize {
        match self {
            Self::Literal { .. } | Self::Source | Self::Capture { .. } => 1,
            Self::Object { fields } => 1 + fields.values().map(Self::node_count).sum::<usize>(),
            Self::Array { items } => 1 + items.iter().map(Self::node_count).sum::<usize>(),
        }
    }

    fn render(
        &self,
        source: &Value,
        captures: Option<&BTreeMap<String, String>>,
    ) -> Result<Value, ClaimMappingError> {
        match self {
            Self::Literal { value } => Ok(value.clone()),
            Self::Source => Ok(source.clone()),
            Self::Capture { name } => captures
                .and_then(|captures| captures.get(name))
                .map(|capture| Value::String(capture.clone()))
                .ok_or_else(|| ClaimMappingError::MissingCapture(name.clone())),
            Self::Object { fields } => fields
                .iter()
                .map(|(name, value)| Ok((name.clone(), value.render(source, captures)?)))
                .collect::<Result<Map<_, _>, ClaimMappingError>>()
                .map(Value::Object),
            Self::Array { items } => items
                .iter()
                .map(|item| item.render(source, captures))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array),
        }
    }

    fn validate(&self, names: &mut BTreeSet<String>) -> Result<(), ClaimMappingError> {
        if self.node_count() > MAX_CLAIM_MAPPING_TEMPLATE_NODES {
            return Err(ClaimMappingError::TemplateTooLarge);
        }
        match self {
            Self::Literal { value } => {
                VerifiedClaimTree::try_new(value.clone()).map_err(ClaimMappingError::Bounds)?;
            }
            Self::Source => {}
            Self::Capture { name } => {
                if name.is_empty()
                    || name.len() > MAX_CLAIM_MAPPING_PATH_BYTES
                    || name.chars().any(is_claim_mapping_forbidden_character)
                {
                    return Err(ClaimMappingError::InvalidCapture);
                }
                names.insert(name.clone());
            }
            Self::Object { fields } => {
                if fields.len() > crate::MAX_CLAIM_MEMBERS {
                    return Err(ClaimMappingError::TemplateTooLarge);
                }
                for (name, value) in fields {
                    if name.is_empty()
                        || name.len() > crate::MAX_CLAIM_STRING_BYTES
                        || name.chars().any(is_claim_mapping_forbidden_character)
                    {
                        return Err(ClaimMappingError::InvalidCapture);
                    }
                    value.validate(names)?;
                }
            }
            Self::Array { items } => {
                if items.len() > crate::MAX_CLAIM_MEMBERS {
                    return Err(ClaimMappingError::TemplateTooLarge);
                }
                for item in items {
                    item.validate(names)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ClaimMappingError {
    #[error("claim mapping path is invalid or exceeds its bound")]
    InvalidPath,
    #[error("claim mapping target is invalid")]
    InvalidTarget,
    #[error("claim mapping regex is invalid or exceeds its bound")]
    InvalidPattern,
    #[error("claim mapping regex capture is invalid")]
    InvalidCapture,
    #[error("claim mapping regexes declare the same capture name: {0}")]
    DuplicateCapture(String),
    #[error("claim mapping template exceeds its bound")]
    TemplateTooLarge,
    #[error("claim mapping template references a capture that the regex does not provide: {0}")]
    MissingCapture(String),
    #[error("claim mapping target collides with another mapping: {0}")]
    DuplicateTarget(String),
    #[error("claim mapping target is protected: {0}")]
    ProtectedTarget(String),
    #[error("claim mapping source value is not a string")]
    SourceNotString,
    #[error("claim mapping source path is not an object")]
    SourceNotObject,
    #[error("claim mapping source path was not found")]
    SourceNotFound,
    #[error("claim mapping value is outside the canonical claim bounds: {0}")]
    Bounds(ClaimBoundsError),
    #[error("claim mapping template cannot be rendered: {0}")]
    Render(String),
}

#[derive(Debug, Clone)]
struct CompiledClaimMapping {
    spec: ClaimMappingSpec,
    key_regex: Option<Regex>,
    regex: Option<Regex>,
}

/// Immutable, startup-validated mapping registry.
#[derive(Debug, Clone, Default)]
pub struct ClaimMappingRegistry {
    mappings: Vec<CompiledClaimMapping>,
}

impl ClaimMappingRegistry {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }

    pub fn compile(specs: Vec<ClaimMappingSpec>) -> Result<Self, ClaimMappingError> {
        if specs.len() > MAX_CLAIM_MAPPINGS {
            return Err(ClaimMappingError::TemplateTooLarge);
        }
        let mut targets = BTreeSet::new();
        let mappings = specs
            .into_iter()
            .map(|spec| {
                spec.source.validate()?;
                if spec.target.is_empty()
                    || spec.target.len() > crate::MAX_CLAIM_STRING_BYTES
                    || spec
                        .target
                        .chars()
                        .any(is_claim_mapping_forbidden_character)
                    || is_structural_claim(&spec.target)
                {
                    return Err(if is_structural_claim(&spec.target) {
                        ClaimMappingError::ProtectedTarget(spec.target)
                    } else {
                        ClaimMappingError::InvalidTarget
                    });
                }
                if !targets.insert((spec.output, spec.target.clone())) {
                    return Err(ClaimMappingError::DuplicateTarget(spec.target));
                }
                let mut template_captures = BTreeSet::new();
                spec.template.validate(&mut template_captures)?;
                let key_regex = spec
                    .key_pattern
                    .as_deref()
                    .map(compile_claim_mapping_regex)
                    .transpose()?;
                let regex = match spec.matcher {
                    ClaimMappingMatcher::Exact => {
                        if spec.pattern.is_some() {
                            return Err(ClaimMappingError::InvalidCapture);
                        }
                        None
                    }
                    ClaimMappingMatcher::Regex => {
                        let pattern = spec
                            .pattern
                            .as_deref()
                            .ok_or(ClaimMappingError::InvalidPattern)?;
                        let regex = compile_claim_mapping_regex(pattern)?;
                        Some(regex)
                    }
                };
                let mut capture_names = BTreeSet::new();
                for name in key_regex
                    .iter()
                    .chain(regex.iter())
                    .flat_map(|regex| regex.capture_names().flatten())
                {
                    if !capture_names.insert(name.to_owned()) {
                        return Err(ClaimMappingError::DuplicateCapture(name.to_owned()));
                    }
                }
                if !template_captures.is_subset(&capture_names) {
                    return Err(ClaimMappingError::InvalidCapture);
                }
                Ok(CompiledClaimMapping {
                    spec,
                    key_regex,
                    regex,
                })
            })
            .collect::<Result<Vec<_>, ClaimMappingError>>()?;
        Ok(Self { mappings })
    }

    /// Render all mappings against the exact verified JSON tree.
    pub fn render(
        &self,
        claims: &VerifiedClaimTree,
    ) -> Result<BTreeMap<String, Value>, ClaimMappingError> {
        self.render_for(ClaimMappingOutput::AccessToken, claims)
    }

    /// Render only mappings owned by one output artifact.
    pub fn render_for(
        &self,
        output: ClaimMappingOutput,
        claims: &VerifiedClaimTree,
    ) -> Result<BTreeMap<String, Value>, ClaimMappingError> {
        self.mappings
            .iter()
            .filter(|mapping| mapping.spec.output == output)
            .map(|mapping| {
                let source = mapping
                    .spec
                    .source
                    .value(&claims.value)
                    .ok_or(ClaimMappingError::SourceNotFound)?;
                let rendered = if let Some(key_regex) = &mapping.key_regex {
                    let object = source
                        .as_object()
                        .ok_or(ClaimMappingError::SourceNotObject)?;
                    let mut entries = Vec::new();
                    let mut keys = object.keys().collect::<Vec<_>>();
                    keys.sort_unstable();
                    for key in keys {
                        let value = object.get(key).expect("key collected from the same object");
                        let Some(key_captures) = key_regex.captures(key) else {
                            continue;
                        };
                        let mut captures = capture_values(key_regex, &key_captures);
                        let value = match (&mapping.spec.matcher, &mapping.regex) {
                            (ClaimMappingMatcher::Exact, None) => value,
                            (ClaimMappingMatcher::Regex, Some(regex)) => {
                                let input =
                                    value.as_str().ok_or(ClaimMappingError::SourceNotString)?;
                                let value_captures = regex.captures(input).ok_or_else(|| {
                                    ClaimMappingError::Render(
                                        "regex did not match an object entry value".into(),
                                    )
                                })?;
                                merge_capture_values(&mut captures, regex, &value_captures)?;
                                value
                            }
                            _ => return Err(ClaimMappingError::InvalidPattern),
                        };
                        entries.push(mapping.spec.template.render(value, Some(&captures))?);
                    }
                    if entries.is_empty() {
                        return Err(ClaimMappingError::Render(
                            "key regex did not match an object entry".into(),
                        ));
                    }
                    Value::Array(entries)
                } else {
                    match (&mapping.spec.matcher, &mapping.regex) {
                        (ClaimMappingMatcher::Exact, None) => {
                            mapping.spec.template.render(source, None)?
                        }
                        (ClaimMappingMatcher::Regex, Some(regex)) => {
                            let input =
                                source.as_str().ok_or(ClaimMappingError::SourceNotString)?;
                            let captures = regex.captures(input).ok_or_else(|| {
                                ClaimMappingError::Render("regex did not match".into())
                            })?;
                            let captures = capture_values(regex, &captures);
                            mapping.spec.template.render(source, Some(&captures))?
                        }
                        _ => return Err(ClaimMappingError::InvalidPattern),
                    }
                };
                VerifiedClaimTree::try_new(rendered.clone()).map_err(ClaimMappingError::Bounds)?;
                Ok((mapping.spec.target.clone(), rendered))
            })
            .collect()
    }
}

impl ClaimMappingSpec {
    /// Regex source is kept in the spec so it can be recompiled after a
    /// restart.  The compiled registry never stores request-local regexes.
    pub fn regex(
        source: ClaimPath,
        target: String,
        pattern: String,
        template: ClaimTemplate,
    ) -> Self {
        Self {
            source,
            target,
            output: ClaimMappingOutput::AccessToken,
            matcher: ClaimMappingMatcher::Regex,
            pattern: Some(pattern),
            key_pattern: None,
            template,
        }
    }

    /// Build a mapping that selects object entries by key and optionally
    /// captures from each selected value. The rendered target is always an
    /// array, preserving all matches without an order-dependent overwrite.
    pub fn entry_regex(
        source: ClaimPath,
        target: String,
        key_pattern: String,
        value_pattern: Option<String>,
        template: ClaimTemplate,
    ) -> Self {
        Self {
            source,
            target,
            output: ClaimMappingOutput::AccessToken,
            matcher: value_pattern
                .as_ref()
                .map_or(ClaimMappingMatcher::Exact, |_| ClaimMappingMatcher::Regex),
            pattern: value_pattern,
            key_pattern: Some(key_pattern),
            template,
        }
    }
}

fn capture_values(regex: &Regex, captures: &Captures<'_>) -> BTreeMap<String, String> {
    regex
        .capture_names()
        .flatten()
        .filter_map(|name| {
            captures
                .name(name)
                .map(|value| (name.to_owned(), value.as_str().to_owned()))
        })
        .collect()
}

fn merge_capture_values(
    target: &mut BTreeMap<String, String>,
    regex: &Regex,
    captures: &Captures<'_>,
) -> Result<(), ClaimMappingError> {
    for name in regex.capture_names().flatten() {
        let value = captures
            .name(name)
            .map(|value| value.as_str().to_owned())
            .unwrap_or_default();
        if target.insert(name.to_owned(), value).is_some() {
            return Err(ClaimMappingError::DuplicateCapture(name.to_owned()));
        }
    }
    Ok(())
}

fn compile_claim_mapping_regex(pattern: &str) -> Result<Regex, ClaimMappingError> {
    if pattern.is_empty() || pattern.len() > MAX_CLAIM_MAPPING_PATTERN_BYTES {
        return Err(ClaimMappingError::InvalidPattern);
    }
    validate_claim_mapping_regex_subset(pattern)?;
    Regex::new(pattern).map_err(|_| ClaimMappingError::InvalidPattern)
}

/// Restrict persisted claim-mapping patterns to a small, auditable regex
/// language. The `regex` crate is linear-time, but accepting its entire syntax
/// still makes configuration review and future engine changes unnecessarily
/// risky. We allow literals, classes, anchors, alternation, non-capturing
/// groups, named captures, and bounded/simple repetition. Lookarounds,
/// backreferences, inline flags, nested repetition, and oversized repeats are
/// rejected before the pattern reaches the regex compiler.
fn validate_claim_mapping_regex_subset(pattern: &str) -> Result<(), ClaimMappingError> {
    #[derive(Default)]
    struct GroupFrame {
        contains_quantifier: bool,
    }

    let characters = pattern.chars().collect::<Vec<_>>();
    let mut groups = Vec::new();
    let mut in_class = false;
    let mut previous_quantifiable = false;
    let mut previous_was_quantified = false;
    let mut quantifier_count = 0;
    let mut index = 0;

    while index < characters.len() {
        let character = characters[index];
        if is_claim_mapping_forbidden_character(character) {
            return Err(ClaimMappingError::InvalidPattern);
        }
        if in_class {
            match character {
                '\\' => {
                    index = index.saturating_add(1);
                    if index >= characters.len() {
                        return Err(ClaimMappingError::InvalidPattern);
                    }
                    if !is_allowed_claim_mapping_regex_class_escape(characters[index]) {
                        return Err(ClaimMappingError::InvalidPattern);
                    }
                }
                ']' => in_class = false,
                _ => {}
            }
            index += 1;
            continue;
        }

        match character {
            '\\' => {
                index = index.saturating_add(1);
                let escaped = characters
                    .get(index)
                    .copied()
                    .ok_or(ClaimMappingError::InvalidPattern)?;
                if !is_allowed_claim_mapping_regex_escape(escaped) {
                    return Err(ClaimMappingError::InvalidPattern);
                }
                previous_quantifiable = !matches!(escaped, 'A' | 'B' | 'b' | 'G' | 'Z' | 'z');
                previous_was_quantified = false;
            }
            '[' => {
                in_class = true;
                previous_quantifiable = true;
                previous_was_quantified = false;
            }
            '(' => {
                if characters.get(index + 1) != Some(&'?') {
                    return Err(ClaimMappingError::InvalidPattern);
                }
                match characters.get(index + 2) {
                    Some(':') => index += 2,
                    Some('P') if characters.get(index + 3) == Some(&'<') => {
                        let name_start = index + 4;
                        if name_start > characters.len() {
                            return Err(ClaimMappingError::InvalidPattern);
                        }
                        let Some(name_end_offset) = characters[name_start..]
                            .iter()
                            .position(|character| *character == '>')
                        else {
                            return Err(ClaimMappingError::InvalidPattern);
                        };
                        let name_end = name_start + name_end_offset;
                        let name = &characters[name_start..name_end];
                        if name.is_empty()
                            || !name[0].is_ascii_alphabetic() && name[0] != '_'
                            || name.iter().any(|character| {
                                !character.is_ascii_alphanumeric() && *character != '_'
                            })
                        {
                            return Err(ClaimMappingError::InvalidPattern);
                        }
                        index = name_end;
                    }
                    _ => return Err(ClaimMappingError::InvalidPattern),
                }
                if groups.len() >= MAX_CLAIM_MAPPING_REGEX_GROUP_DEPTH {
                    return Err(ClaimMappingError::InvalidPattern);
                }
                groups.push(GroupFrame::default());
                previous_quantifiable = false;
                previous_was_quantified = false;
            }
            ')' => {
                let group = groups.pop().ok_or(ClaimMappingError::InvalidPattern)?;
                if group.contains_quantifier
                    && let Some(parent) = groups.last_mut()
                {
                    parent.contains_quantifier = true;
                }
                previous_quantifiable = true;
                previous_was_quantified = group.contains_quantifier;
            }
            '|' => {
                previous_quantifiable = false;
                previous_was_quantified = false;
            }
            '*' | '+' => {
                if !previous_quantifiable || previous_was_quantified {
                    return Err(ClaimMappingError::InvalidPattern);
                }
                quantifier_count += 1;
                if quantifier_count > MAX_CLAIM_MAPPING_REGEX_QUANTIFIERS {
                    return Err(ClaimMappingError::InvalidPattern);
                }
                if let Some(group) = groups.last_mut() {
                    group.contains_quantifier = true;
                }
                previous_was_quantified = true;
            }
            '?' => {
                if !previous_quantifiable || previous_was_quantified {
                    return Err(ClaimMappingError::InvalidPattern);
                }
                quantifier_count += 1;
                if quantifier_count > MAX_CLAIM_MAPPING_REGEX_QUANTIFIERS {
                    return Err(ClaimMappingError::InvalidPattern);
                }
                if let Some(group) = groups.last_mut() {
                    group.contains_quantifier = true;
                }
                previous_was_quantified = true;
            }
            '{' => {
                if !previous_quantifiable {
                    return Err(ClaimMappingError::InvalidPattern);
                }
                let mut end = index + 1;
                while end < characters.len() && characters[end] != '}' {
                    end += 1;
                }
                let Some(&'}') = characters.get(end) else {
                    return Err(ClaimMappingError::InvalidPattern);
                };
                let range = characters[index + 1..end].iter().collect::<String>();
                let mut bounds = range.split(',');
                let lower = bounds
                    .next()
                    .filter(|bound| !bound.is_empty())
                    .and_then(|bound| bound.parse::<u64>().ok())
                    .ok_or(ClaimMappingError::InvalidPattern)?;
                let upper = match bounds.next() {
                    None => lower,
                    Some("") => {
                        return Err(ClaimMappingError::InvalidPattern);
                    }
                    Some(bound) => bound
                        .parse::<u64>()
                        .map_err(|_| ClaimMappingError::InvalidPattern)?,
                };
                if bounds.next().is_some() {
                    return Err(ClaimMappingError::InvalidPattern);
                }
                if upper < lower
                    || lower > MAX_CLAIM_MAPPING_REGEX_REPEAT
                    || upper > MAX_CLAIM_MAPPING_REGEX_REPEAT
                    || previous_was_quantified
                {
                    return Err(ClaimMappingError::InvalidPattern);
                }
                quantifier_count += 1;
                if quantifier_count > MAX_CLAIM_MAPPING_REGEX_QUANTIFIERS {
                    return Err(ClaimMappingError::InvalidPattern);
                }
                if let Some(group) = groups.last_mut() {
                    group.contains_quantifier = true;
                }
                previous_was_quantified = true;
                index = end;
            }
            '}' => return Err(ClaimMappingError::InvalidPattern),
            '^' | '$' => {
                previous_quantifiable = false;
                previous_was_quantified = false;
            }
            _ => {
                previous_quantifiable = true;
                previous_was_quantified = false;
            }
        }
        index += 1;
    }

    if in_class || !groups.is_empty() {
        return Err(ClaimMappingError::InvalidPattern);
    }
    Ok(())
}

fn is_allowed_claim_mapping_regex_escape(character: char) -> bool {
    matches!(
        character,
        'A' | 'B'
            | 'b'
            | 'd'
            | 'D'
            | 'G'
            | 's'
            | 'S'
            | 'w'
            | 'W'
            | 'z'
            | 'Z'
            | '\\'
            | '.'
            | '+'
            | '*'
            | '?'
            | '('
            | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | '|'
            | '^'
            | '$'
            | '-'
            | '#'
    )
}

fn is_allowed_claim_mapping_regex_class_escape(character: char) -> bool {
    matches!(
        character,
        'd' | 'D'
            | 's'
            | 'S'
            | 'w'
            | 'W'
            | '\\'
            | '.'
            | '+'
            | '*'
            | '?'
            | '('
            | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | '|'
            | '^'
            | '$'
            | '-'
            | '#'
    )
}
