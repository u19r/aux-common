use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::{
    ClaimErrorKind, JwtDecodeError, JwtDecodeErrorKind, PolicyErrorKind, RegisteredClaims, Result,
    TokenKind, VerificationPolicy,
};

pub(crate) struct ClaimsPolicy<'a> {
    policy: &'a VerificationPolicy,
    now: SystemTime,
}

impl<'a> ClaimsPolicy<'a> {
    pub(crate) fn new(policy: &'a VerificationPolicy, now: SystemTime) -> Self {
        Self { policy, now }
    }

    pub(crate) fn registered_claims(value: &Value) -> Result<RegisteredClaims> {
        serde_json::from_value(value.clone()).map_err(|_| {
            JwtDecodeError::new(JwtDecodeErrorKind::ClaimsInvalid(
                ClaimErrorKind::Deserialize,
            ))
        })
    }

    pub(crate) fn validate_registered(&self, claims: &RegisteredClaims) -> Result<()> {
        self.validate_issuer_and_audience(claims)?;
        self.validate_time(claims)
    }

    pub(crate) fn validate_token_type_and_client(
        &self,
        value: &Value,
        audience_count: usize,
    ) -> Result<()> {
        self.validate_token_type(value)?;
        self.validate_client(value, audience_count)?;
        self.validate_nonce(value)
    }

    fn validate_issuer_and_audience(&self, claims: &RegisteredClaims) -> Result<()> {
        if claims.iss.is_empty() {
            return Err(Self::invalid_claim("iss"));
        }
        if claims.iss != self.policy.issuer {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::IssuerMismatch));
        }
        if !claims.aud.is_valid() {
            return Err(Self::invalid_claim("aud"));
        }
        if claims.aud.contains(&self.policy.audience) {
            return Ok(());
        }
        Err(JwtDecodeError::new(JwtDecodeErrorKind::AudienceMismatch))
    }

    fn validate_time(&self, claims: &RegisteredClaims) -> Result<()> {
        let now = Self::unix_seconds(self.now)?;
        let leeway = Self::duration_seconds(self.policy.leeway, "leeway")?;
        if claims.exp.checked_add(leeway).is_none_or(|exp| exp < now) {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::Expired));
        }
        if claims
            .nbf
            .is_some_and(|nbf| nbf.checked_sub(leeway).is_none_or(|nbf| nbf > now))
        {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::NotYetValid));
        }
        if claims.iat.checked_sub(leeway).is_none_or(|iat| iat > now) {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::IssuedAtInvalid));
        }
        self.validate_max_age(claims.iat, now, leeway)
    }

    fn validate_max_age(&self, iat: i64, now: i64, leeway: i64) -> Result<()> {
        let Some(max_age) = self.policy.max_issued_age else {
            return Ok(());
        };
        let max_age = Self::duration_seconds(max_age, "max_issued_age")?;
        if iat
            .checked_add(max_age)
            .and_then(|fresh_until| fresh_until.checked_add(leeway))
            .is_some_and(|fresh_until| fresh_until >= now)
        {
            return Ok(());
        }
        Err(JwtDecodeError::new(JwtDecodeErrorKind::IssuedAtInvalid))
    }

    fn validate_token_type(&self, value: &Value) -> Result<()> {
        if !self.policy.require_token_type {
            return Ok(());
        }
        let Some(token_type) = Self::string_claim(value, &self.policy.token_type_claim) else {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::TokenTypeMismatch));
        };
        if token_type == self.policy.token_type_value {
            return Ok(());
        }
        Err(JwtDecodeError::new(JwtDecodeErrorKind::TokenTypeMismatch))
    }

    fn validate_client(&self, value: &Value, audience_count: usize) -> Result<()> {
        let Some(expected_client_id) = &self.policy.client_id else {
            return Ok(());
        };
        let claim_name = self.client_claim_name(audience_count);
        let Some(client_id) = Self::string_claim(value, claim_name) else {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::ClientMismatch));
        };
        if client_id == expected_client_id {
            return Ok(());
        }
        Err(JwtDecodeError::new(JwtDecodeErrorKind::ClientMismatch))
    }

    fn validate_nonce(&self, value: &Value) -> Result<()> {
        let Some(expected_nonce) = &self.policy.nonce else {
            return Ok(());
        };
        let Some(nonce) = Self::string_claim(value, "nonce") else {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::NonceMismatch));
        };
        if nonce == expected_nonce {
            return Ok(());
        }
        Err(JwtDecodeError::new(JwtDecodeErrorKind::NonceMismatch))
    }

    fn client_claim_name(&self, audience_count: usize) -> &'static str {
        if self.policy.token_kind == TokenKind::Id && audience_count > 1 {
            return "azp";
        }
        "client_id"
    }

    fn string_claim<'b>(value: &'b Value, name: &str) -> Option<&'b str> {
        value
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
    }

    fn unix_seconds(now: SystemTime) -> Result<i64> {
        let duration = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::IssuedAtInvalid))?;
        i64::try_from(duration.as_secs())
            .map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::IssuedAtInvalid))
    }

    fn duration_seconds(duration: std::time::Duration, name: &'static str) -> Result<i64> {
        i64::try_from(duration.as_secs()).map_err(|_| {
            JwtDecodeError::new(JwtDecodeErrorKind::PolicyInvalid(
                PolicyErrorKind::EmptyValue(name),
            ))
        })
    }

    fn invalid_claim(name: &'static str) -> JwtDecodeError {
        JwtDecodeError::new(JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Invalid(
            name,
        )))
    }
}
