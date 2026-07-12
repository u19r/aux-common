//! Session context carrying authentication state for step-up evaluation.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AcrLevel;

/// Authentication state captured at evaluation time.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "acr": "multi_factor",
    "amr": ["pwd", "otp"],
    "auth_time": 1739611200,
    "mfa_time": 1739611300,
    "sso_session": false,
    "sso_provider": null,
    "saml_authenticated": false,
    "saml_expires_at": null
}))]
pub struct SessionContext {
    /// Current Authentication Context Class Reference.
    #[schema(default = "none", example = "multi_factor")]
    pub acr: AcrLevel,
    /// Authentication Methods References used to establish the session.
    #[serde(default)]
    #[schema(max_items = 10, example = json!(["pwd", "otp"]))]
    pub amr: Vec<String>,
    /// Initial authentication time (seconds since epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, minimum = 0, example = 1739611200)]
    pub auth_time: Option<i64>,
    /// Time of last MFA (seconds since epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, minimum = 0, example = 1739611300)]
    pub mfa_time: Option<i64>,
    /// Whether session came from SSO.
    #[serde(default)]
    #[schema(default = false, example = false)]
    pub sso_session: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Upstream SSO provider name or identifier when `sso_session=true`.
    #[schema(nullable = true, min_length = 1, max_length = 250, example = "okta")]
    pub sso_provider: Option<String>,
    #[serde(default)]
    #[schema(default = false, example = false)]
    pub saml_authenticated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, minimum = 0, example = 1739614900)]
    pub saml_expires_at: Option<i64>,
}

impl SessionContext {
    pub fn password_only(auth_time: i64) -> Self {
        Self {
            acr: AcrLevel::SingleFactor,
            amr: vec!["pwd".into()],
            auth_time: Some(auth_time),
            mfa_time: None,
            sso_session: false,
            sso_provider: None,
            saml_authenticated: false,
            saml_expires_at: None,
        }
    }

    pub fn with_mfa(auth_time: i64, mfa_time: i64, mfa_method: &str) -> Self {
        Self {
            acr: AcrLevel::MultiFactor,
            amr: vec!["pwd".into(), mfa_method.to_string()],
            auth_time: Some(auth_time),
            mfa_time: Some(mfa_time),
            sso_session: false,
            sso_provider: None,
            saml_authenticated: false,
            saml_expires_at: None,
        }
    }

    pub fn is_auth_recent(&self, max_age_seconds: u64) -> bool {
        self.is_auth_recent_at(Utc::now().timestamp(), max_age_seconds)
    }

    pub fn is_auth_recent_at(&self, now_seconds: i64, max_age_seconds: u64) -> bool {
        self.auth_time
            .and_then(|auth_time| elapsed_seconds(now_seconds, auth_time))
            .is_some_and(|age| age <= max_age_seconds)
    }

    pub fn is_mfa_recent(&self, max_age_seconds: u64) -> bool {
        self.is_mfa_recent_at(Utc::now().timestamp(), max_age_seconds)
    }

    pub fn is_mfa_recent_at(&self, now_seconds: i64, max_age_seconds: u64) -> bool {
        self.mfa_time
            .and_then(|mfa_time| elapsed_seconds(now_seconds, mfa_time))
            .is_some_and(|age| age <= max_age_seconds)
    }

    pub fn has_amr(&self, method: &str) -> bool {
        self.amr.iter().any(|m| m == method)
    }

    /// Build a session context from JWT/OIDC claims when present.
    pub fn from_claims(claims: &serde_json::Value) -> Option<Self> {
        let acr = claims
            .get("acr")
            .and_then(|v| v.as_str())
            .and_then(AcrLevel::from_urn)
            .or_else(|| {
                claims
                    .get("acr")
                    .and_then(|v| v.as_str())
                    .map(|_| AcrLevel::None)
            })?;

        let amr = claims
            .get("amr")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToString::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let auth_time = claims
            .get("auth_time")
            .and_then(|v| v.as_i64())
            .or_else(|| {
                claims
                    .get("auth_time")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as i64)
            });

        let mfa_time = claims.get("mfa_time").and_then(|v| v.as_i64()).or_else(|| {
            claims
                .get("mfa_time")
                .and_then(|v| v.as_u64())
                .map(|n| n as i64)
        });

        Some(SessionContext {
            acr,
            amr,
            auth_time,
            mfa_time,
            sso_session: false,
            sso_provider: None,
            saml_authenticated: false,
            saml_expires_at: None,
        })
    }
}

fn elapsed_seconds(now_seconds: i64, event_seconds: i64) -> Option<u64> {
    now_seconds
        .checked_sub(event_seconds)
        .and_then(|age| u64::try_from(age).ok())
}
