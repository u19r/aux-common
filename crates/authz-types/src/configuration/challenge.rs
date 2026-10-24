//! Challenge metadata returned when step-up authentication is required.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AcrLevel;

/// Specific challenge a client must complete to satisfy step-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    Mfa,
    Totp,
    Fido2,
    SmsOtp,
    EmailOtp,
    ReAuthenticate,
    HardwareKey,
    Biometric,
    SsoRequired,
    Custom,
}

impl ChallengeType {
    pub fn description(&self) -> &'static str {
        match self {
            ChallengeType::Mfa => "Multi-factor authentication required",
            ChallengeType::Totp => "TOTP verification required",
            ChallengeType::Fido2 => "FIDO2/WebAuthn authentication required",
            ChallengeType::SmsOtp => "SMS verification required",
            ChallengeType::EmailOtp => "Email verification required",
            ChallengeType::ReAuthenticate => "Re-authentication required",
            ChallengeType::HardwareKey => "Hardware security key required",
            ChallengeType::Biometric => "Biometric verification required",
            ChallengeType::SsoRequired => "SSO authentication required",
            ChallengeType::Custom => "Additional authentication required",
        }
    }

    /// Canonical snake_case label for metrics/reasons.
    pub fn as_str(&self) -> &'static str {
        match self {
            ChallengeType::Mfa => "mfa",
            ChallengeType::Totp => "totp",
            ChallengeType::Fido2 => "fido2",
            ChallengeType::SmsOtp => "sms_otp",
            ChallengeType::EmailOtp => "email_otp",
            ChallengeType::ReAuthenticate => "re_authenticate",
            ChallengeType::HardwareKey => "hardware_key",
            ChallengeType::Biometric => "biometric",
            ChallengeType::SsoRequired => "sso_required",
            ChallengeType::Custom => "custom",
        }
    }

    pub fn from_acr_level(level: AcrLevel) -> Vec<Self> {
        match level {
            AcrLevel::None => vec![],
            AcrLevel::SingleFactor => vec![ChallengeType::ReAuthenticate],
            AcrLevel::MultiFactor => vec![
                ChallengeType::Mfa,
                ChallengeType::Totp,
                ChallengeType::Fido2,
                ChallengeType::SmsOtp,
            ],
            AcrLevel::HardwareToken => vec![ChallengeType::Fido2, ChallengeType::HardwareKey],
            AcrLevel::RecentAuth => vec![ChallengeType::ReAuthenticate],
        }
    }
}

/// Challenge details carried in authorization responses.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "challenge_type": "mfa",
    "triggered_by_rule": "rule_mfa_sensitive",
    "required_acr": "multi_factor",
    "message": "Multi-factor authentication required",
    "alternatives": ["fido2", "totp"],
    "challenge_url": "https://app.example.com/step-up",
    "expires_in_seconds": 300,
    "www_authenticate": "Bearer error=\"insufficient_authentication\""
}))]
pub struct AuthzChallenge {
    /// Primary challenge type requested.
    #[schema(value_type = String, example = "mfa")]
    pub challenge_type: ChallengeType,
    /// ID of the rule that triggered the challenge.
    #[schema(min_length = 1, max_length = 58, example = "rule_mfa_sensitive")]
    pub triggered_by_rule: String,
    /// Required ACR to satisfy.
    #[schema(value_type = String, example = "multi_factor")]
    pub required_acr: AcrLevel,
    /// Human-readable message for clients.
    #[schema(
        min_length = 1,
        max_length = 500,
        example = "Multi-factor authentication required"
    )]
    pub message: String,
    /// Alternative challenge types that would also satisfy the rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(max_items = 10)]
    pub alternatives: Vec<ChallengeType>,
    /// Optional URL to complete the challenge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(
        nullable = true,
        min_length = 8,
        max_length = 2048,
        example = "https://app.example.com/step-up"
    )]
    pub challenge_url: Option<String>,
    /// Optional expiration window (seconds) for the challenge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, minimum = 1, example = 300)]
    pub expires_in_seconds: Option<u64>,
    /// RFC 9470 compatible `WWW-Authenticate` value suggested for resource
    /// servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(
        nullable = true,
        min_length = 1,
        max_length = 1024,
        example = "Bearer error=\"insufficient_authentication\""
    )]
    pub www_authenticate: Option<String>,
}

impl AuthzChallenge {
    pub fn for_step_up(rule_id: &str, required_acr: AcrLevel, primary: ChallengeType) -> Self {
        let alternatives: Vec<ChallengeType> = ChallengeType::from_acr_level(required_acr)
            .into_iter()
            .filter(|c| *c != primary)
            .collect();

        Self {
            challenge_type: primary,
            triggered_by_rule: rule_id.to_string(),
            required_acr,
            message: primary.description().to_string(),
            alternatives,
            challenge_url: None,
            expires_in_seconds: None,
            www_authenticate: None,
        }
    }

    pub fn re_authenticate(rule_id: &str, max_age: u64) -> Self {
        Self {
            challenge_type: ChallengeType::ReAuthenticate,
            triggered_by_rule: rule_id.to_string(),
            required_acr: AcrLevel::RecentAuth,
            message: format!(
                "Please re-authenticate; last authentication exceeded {max_age} seconds."
            ),
            alternatives: Vec::new(),
            challenge_url: None,
            expires_in_seconds: Some(300),
            www_authenticate: None,
        }
    }

    pub fn with_url(mut self, url: String) -> Self {
        self.challenge_url = Some(url);
        self
    }

    pub fn with_www_authenticate(mut self, header_value: String) -> Self {
        self.www_authenticate = Some(header_value);
        self
    }
}
