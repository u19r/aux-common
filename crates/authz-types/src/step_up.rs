//! Step-up authentication rule types and ACR vocabulary.
//!
//! These types intentionally mirror OIDC ACR / AMR semantics so tenants can
//! configure standards-aligned step-up behaviors without bespoke headers.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Authentication Context Class Reference values.
///
/// Higher numeric values indicate stronger assurance, except `RecentAuth`
/// which represents a temporal freshness requirement.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
#[schema(example = "multi_factor")]
pub enum AcrLevel {
    /// No authentication (anonymous access).
    #[default]
    None = 0,
    /// Single-factor authentication (e.g., password).
    SingleFactor = 1,
    /// Multi-factor authentication (e.g., password + TOTP).
    MultiFactor = 2,
    /// Hardware-backed authentication (e.g., FIDO2/WebAuthn).
    HardwareToken = 3,
    /// Recent re-authentication required within a configured max age.
    RecentAuth = 4,
}

impl AcrLevel {
    /// Convert to standard URN representation.
    pub fn to_urn(self) -> &'static str {
        match self {
            AcrLevel::None => "urn:acr:0",
            AcrLevel::SingleFactor => "urn:acr:1",
            AcrLevel::MultiFactor => "urn:acr:2",
            AcrLevel::HardwareToken => "urn:acr:3",
            AcrLevel::RecentAuth => "urn:acr:4",
        }
    }

    /// Parse an ACR URN into an [`AcrLevel`].
    pub fn from_urn(urn: &str) -> Option<Self> {
        match urn {
            "urn:acr:0" | "acr:0" | "urn:acr:none" | "none" => Some(AcrLevel::None),
            "urn:acr:1" | "acr:1" | "urn:acr:password" | "password" | "single_factor" => {
                Some(AcrLevel::SingleFactor)
            }
            "urn:acr:2" | "acr:2" | "urn:acr:mfa" | "mfa" | "multi_factor" => {
                Some(AcrLevel::MultiFactor)
            }
            "urn:acr:3"
            | "acr:3"
            | "urn:acr:phishing-resistant"
            | "urn:acr:hardware"
            | "phishing-resistant"
            | "hardware_token" => Some(AcrLevel::HardwareToken),
            "urn:acr:4" | "acr:4" | "urn:acr:recent" | "recent_auth" => Some(AcrLevel::RecentAuth),
            _ => None,
        }
    }

    /// Check if the current level satisfies a required level.
    ///
    /// `RecentAuth` is treated as a separate freshness requirement, not a
    /// strictly higher assurance than hardware.
    pub fn satisfies(self, required: AcrLevel) -> bool {
        if required == AcrLevel::RecentAuth {
            return self == AcrLevel::RecentAuth;
        }
        self >= required
    }
}

fn default_true() -> bool {
    true
}

/// A step-up rule describing additional authentication requirements.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "rule_id": "rule_mfa_sensitive",
    "name": "MFA for sensitive actions",
    "description": "Requires MFA for delete operations",
    "required_acr": "multi_factor",
    "max_auth_age_seconds": 3600,
    "max_mfa_age_seconds": 600,
    "required_amr": ["otp", "webauthn"],
    "applies_to_api_keys": false
}))]
pub struct StepUpRule {
    /// Unique identifier for the rule.
    #[schema(min_length = 1, max_length = 58, example = "rule_mfa_sensitive")]
    pub rule_id: String,
    /// Human-friendly name.
    #[schema(
        min_length = 1,
        max_length = 128,
        example = "MFA for sensitive actions"
    )]
    pub name: String,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(
        nullable = true,
        min_length = 1,
        max_length = 250,
        example = "Requires MFA for delete operations"
    )]
    pub description: Option<String>,
    /// Minimum required ACR level.
    #[schema(value_type = String, example = "multi_factor")]
    pub required_acr: AcrLevel,
    /// Maximum seconds since last authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, minimum = 1, example = 3600)]
    pub max_auth_age_seconds: Option<u64>,
    /// Maximum seconds since last MFA completion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, minimum = 1, example = 600)]
    pub max_mfa_age_seconds: Option<u64>,
    /// Required AMR methods; at least one must be present to satisfy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(max_items = 10, example = json!(["otp", "webauthn"]))]
    pub required_amr: Vec<String>,
    /// Whether API keys must satisfy this rule.
    #[serde(default = "default_true")]
    #[schema(default = true, example = true)]
    pub applies_to_api_keys: bool,
}

impl StepUpRule {
    /// Convenience helper to require a minimum ACR.
    pub fn require_acr(rule_id: &str, name: &str, acr: AcrLevel) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            name: name.to_string(),
            description: None,
            required_acr: acr,
            max_auth_age_seconds: None,
            max_mfa_age_seconds: None,
            required_amr: Vec::new(),
            applies_to_api_keys: true,
        }
    }

    /// Require re-authentication within the supplied max age.
    pub fn require_recent_auth(rule_id: &str, name: &str, max_age_seconds: u64) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            name: name.to_string(),
            description: Some(format!(
                "Re-authentication required within {max_age_seconds} seconds"
            )),
            required_acr: AcrLevel::SingleFactor,
            max_auth_age_seconds: Some(max_age_seconds),
            max_mfa_age_seconds: None,
            required_amr: Vec::new(),
            applies_to_api_keys: false,
        }
    }

    /// Require one of the provided AMR methods (implicitly MFA).
    pub fn require_amr(rule_id: &str, name: &str, amr: Vec<String>) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            name: name.to_string(),
            description: None,
            required_acr: AcrLevel::MultiFactor,
            max_auth_age_seconds: None,
            max_mfa_age_seconds: None,
            required_amr: amr,
            applies_to_api_keys: true,
        }
    }
}

/// Step-up configuration at the resource/action level.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "default_rule": "rule_mfa_sensitive",
    "action_rules": { "delete": "rule_mfa_delete" }
}))]
pub struct StepUpConfig {
    /// Default rule for the resource type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(
        nullable = true,
        min_length = 1,
        max_length = 58,
        example = "rule_mfa_sensitive"
    )]
    pub default_rule: Option<String>,
    /// Action-specific overrides.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    #[schema(
        value_type = std::collections::HashMap<String, String>,
        example = json!({ "delete": "rule_mfa_delete" })
    )]
    pub action_rules: std::collections::HashMap<String, String>,
}
