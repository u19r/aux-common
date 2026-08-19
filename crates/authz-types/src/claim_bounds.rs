use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::Value;
use thiserror::Error;

/// Maximum nesting depth accepted in a verified claim tree.
pub const MAX_CLAIM_DEPTH: usize = 8;
/// Maximum members allowed in any claim object or array.
pub const MAX_CLAIM_MEMBERS: usize = 128;
/// Maximum custom top-level claims in one access token.
pub const MAX_CUSTOM_CLAIMS: usize = 64;
/// Maximum UTF-8 bytes in a custom property name or string value.
pub const MAX_CLAIM_STRING_BYTES: usize = 1_024;
/// Maximum canonical JSON bytes occupied by one custom claim.
pub const MAX_CUSTOM_CLAIM_JSON_BYTES: usize = 4 * 1_024;
/// Maximum aggregate canonical JSON bytes occupied by custom claims.
pub const MAX_CUSTOM_CLAIMS_JSON_BYTES: usize = 8 * 1_024;
/// Maximum bytes in the final compact JWT.
pub const MAX_COMPACT_JWT_BYTES: usize = 16 * 1_024;

/// Claim names owned by the signed access-token protocol rather than tenant
/// configuration or runtime hook output.
pub const STRUCTURAL_CLAIM_NAMES: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "client_id",
    "scope",
    "tenant",
    "token_type",
    "principal_type",
    "auth_time",
    "acr",
    "amr",
    "nonce",
    "azp",
    "at_hash",
    "c_hash",
    "permission_set_id",
    "permission_set_revision",
];

/// The serialization context is a fixed internal value so error messages can
/// describe the failed operation without exposing a serializer's raw output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimSerializationContext {
    CompactJwtPayload,
    JsonObject,
}

impl std::fmt::Display for ClaimSerializationContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::CompactJwtPayload => "compact JWT payload",
            Self::JsonObject => "JSON object",
        })
    }
}

/// Errors returned when a claim value cannot satisfy the public token bounds.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ClaimBoundsError {
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds {limit} bytes (actual: {actual})")]
    StringTooLong {
        field: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("claim tree exceeds maximum depth of {limit}")]
    DepthExceeded { limit: usize },
    #[error("claim {kind} exceeds maximum members of {limit} (actual: {actual})")]
    MembersExceeded {
        kind: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("custom claims exceed maximum entries of {limit} (actual: {actual})")]
    CustomClaimsExceeded { limit: usize, actual: usize },
    #[error("custom claim {name:?} exceeds {limit} canonical JSON bytes (actual: {actual})")]
    CustomClaimTooLarge {
        name: String,
        limit: usize,
        actual: usize,
    },
    #[error("custom claims exceed {limit} canonical JSON bytes (actual: {actual})")]
    CustomClaimsTooLarge { limit: usize, actual: usize },
    #[error("custom claim {0:?} conflicts with a structural claim")]
    ProtectedClaim(String),
    #[error("audience must contain at least one non-empty value")]
    InvalidAudience,
    #[error("scope entries must be non-empty and contain no ASCII whitespace")]
    InvalidScope,
    #[error("principal does not match the signed subject or principal type")]
    PrincipalMismatch,
    #[error("verified claims do not match the canonical signed access-token claims")]
    VerifiedClaimsMismatch,
    #[error("compact JWT exceeds {limit} bytes (actual: {actual})")]
    CompactJwtTooLarge { limit: usize, actual: usize },
    #[error("claims could not be serialized for {context}")]
    Serialization { context: ClaimSerializationContext },
    #[error("OAuth temporal claims are inconsistent")]
    InvalidTemporalOrder,
    #[error("Permission Set id and revision must be provided together with a positive revision")]
    InvalidPermissionSetReference,
}

pub(crate) fn validate_claim_value(value: &Value, depth: usize) -> Result<(), ClaimBoundsError> {
    if depth > MAX_CLAIM_DEPTH {
        return Err(ClaimBoundsError::DepthExceeded {
            limit: MAX_CLAIM_DEPTH,
        });
    }
    match value {
        Value::String(value) => validate_string("claim string", value),
        Value::Array(values) => {
            validate_members("array", values.len())?;
            for value in values {
                validate_claim_value(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            validate_members("object", values.len())?;
            for (name, value) in values {
                validate_string("claim property name", name)?;
                validate_claim_value(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

pub(crate) fn validate_members(kind: &'static str, actual: usize) -> Result<(), ClaimBoundsError> {
    if actual > MAX_CLAIM_MEMBERS {
        return Err(ClaimBoundsError::MembersExceeded {
            kind,
            limit: MAX_CLAIM_MEMBERS,
            actual,
        });
    }
    Ok(())
}

pub(crate) fn validate_string(field: &'static str, value: &str) -> Result<(), ClaimBoundsError> {
    if value.len() > MAX_CLAIM_STRING_BYTES {
        return Err(ClaimBoundsError::StringTooLong {
            field,
            limit: MAX_CLAIM_STRING_BYTES,
            actual: value.len(),
        });
    }
    Ok(())
}

pub(crate) fn validate_scope_values(scope: &[String]) -> Result<(), ClaimBoundsError> {
    validate_members("array", scope.len())?;
    for value in scope {
        if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(ClaimBoundsError::InvalidScope);
        }
        validate_string("scope", value)?;
    }
    Ok(())
}

pub(crate) fn serialize_scope<S>(scope: &[String], serializer: S) -> Result<S::Ok, S::Error>
where S: Serializer {
    scope.join(" ").serialize(serializer)
}

pub(crate) fn deserialize_scope<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where D: Deserializer<'de> {
    let scope = String::deserialize(deserializer)?;
    let values: Vec<String> = scope
        .split_ascii_whitespace()
        .map(ToString::to_string)
        .collect();
    validate_scope_values(&values).map_err(D::Error::custom)?;
    Ok(values)
}

pub(crate) fn base64url_len(bytes: usize) -> usize {
    bytes.saturating_mul(4).saturating_add(2) / 3
}

pub fn is_structural_claim(name: &str) -> bool {
    STRUCTURAL_CLAIM_NAMES.contains(&name)
}

pub(crate) fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => json_string(value),
        Value::Array(values) => {
            let values = values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{values}]")
        }
        Value::Object(values) => {
            let sorted = values.iter().collect::<BTreeMap<_, _>>();
            let values = sorted
                .into_iter()
                .map(|(name, value)| format!("{}:{}", json_string(name), canonical_json(value)))
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{values}}}")
        }
    }
}

fn json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0C}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", u32::from(character));
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}
