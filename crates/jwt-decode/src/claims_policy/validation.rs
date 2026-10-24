use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::Value;

use crate::{
    ClaimErrorKind, JwtDecodeError, JwtDecodeErrorKind, PolicyErrorKind, RegisteredClaims,
    TokenKind, VerificationPolicy, error::Result,
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
        RegisteredClaims::deserialize(value).map_err(|_| {
            JwtDecodeError::new(JwtDecodeErrorKind::ClaimsInvalid(
                ClaimErrorKind::Deserialize,
            ))
        })
    }

    pub(crate) fn validate_registered(&self, claims: &RegisteredClaims) -> Result<()> {
        self.validate_issuer_and_audience(claims)?;
        self.validate_time(claims)
    }

    pub(crate) fn registered_claim_refs(value: &Value) -> Result<RegisteredClaimRefs<'_>> {
        let iss = Self::string_claim(value, "iss").ok_or_else(|| Self::invalid_claim("iss"))?;
        let exp = Self::i64_claim(value, "exp")?.ok_or_else(|| Self::invalid_claim("exp"))?;
        Ok(RegisteredClaimRefs {
            iss,
            aud: Self::audience_claim(value)?,
            exp,
            nbf: Self::i64_claim(value, "nbf")?,
            iat: Self::i64_claim(value, "iat")?,
        })
    }

    pub(crate) fn validate_registered_refs(&self, claims: &RegisteredClaimRefs<'_>) -> Result<()> {
        self.validate_issuer_and_audience_refs(claims)?;
        self.validate_time_refs(claims)
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
        let Some(expected_audiences) = &self.policy.audiences else {
            if claims
                .aud
                .as_ref()
                .is_some_and(|audience| !audience.is_valid())
            {
                return Err(Self::invalid_claim("aud"));
            }
            return Ok(());
        };
        let Some(audience) = &claims.aud else {
            return Err(Self::invalid_claim("aud"));
        };
        if !audience.is_valid() {
            return Err(Self::invalid_claim("aud"));
        }
        if expected_audiences
            .iter()
            .any(|expected| audience.contains(expected))
        {
            return Ok(());
        }
        Err(JwtDecodeError::new(JwtDecodeErrorKind::AudienceMismatch))
    }

    fn validate_issuer_and_audience_refs(&self, claims: &RegisteredClaimRefs<'_>) -> Result<()> {
        if claims.iss.is_empty() {
            return Err(Self::invalid_claim("iss"));
        }
        if claims.iss != self.policy.issuer {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::IssuerMismatch));
        }
        let Some(expected_audiences) = &self.policy.audiences else {
            if claims
                .aud
                .as_ref()
                .is_some_and(|audience| !audience.is_valid())
            {
                return Err(Self::invalid_claim("aud"));
            }
            return Ok(());
        };
        let Some(audience) = &claims.aud else {
            return Err(Self::invalid_claim("aud"));
        };
        if !audience.is_valid() {
            return Err(Self::invalid_claim("aud"));
        }
        if expected_audiences
            .iter()
            .any(|expected| audience.contains(expected))
        {
            return Ok(());
        }
        Err(JwtDecodeError::new(JwtDecodeErrorKind::AudienceMismatch))
    }

    fn validate_time(&self, claims: &RegisteredClaims) -> Result<()> {
        let now = Self::unix_seconds(self.now)?;
        let leeway = Self::duration_seconds(self.policy.leeway, "leeway")?;
        if claims.exp.checked_add(leeway).is_none_or(|exp| exp <= now) {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::Expired));
        }
        if claims
            .nbf
            .is_some_and(|nbf| nbf.checked_sub(leeway).is_none_or(|nbf| nbf > now))
        {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::NotYetValid));
        }
        let Some(iat) = claims.iat else {
            if self.policy.require_issued_at || self.policy.max_issued_age.is_some() {
                return Err(JwtDecodeError::new(JwtDecodeErrorKind::IssuedAtInvalid));
            }
            return Ok(());
        };
        if iat.checked_sub(leeway).is_none_or(|iat| iat > now) {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::IssuedAtInvalid));
        }
        self.validate_max_age(iat, now, leeway)
    }

    fn validate_time_refs(&self, claims: &RegisteredClaimRefs<'_>) -> Result<()> {
        let now = Self::unix_seconds(self.now)?;
        let leeway = Self::duration_seconds(self.policy.leeway, "leeway")?;
        if claims.exp.checked_add(leeway).is_none_or(|exp| exp <= now) {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::Expired));
        }
        if claims
            .nbf
            .is_some_and(|nbf| nbf.checked_sub(leeway).is_none_or(|nbf| nbf > now))
        {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::NotYetValid));
        }
        let Some(iat) = claims.iat else {
            if self.policy.require_issued_at || self.policy.max_issued_age.is_some() {
                return Err(JwtDecodeError::new(JwtDecodeErrorKind::IssuedAtInvalid));
            }
            return Ok(());
        };
        if iat.checked_sub(leeway).is_none_or(|iat| iat > now) {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::IssuedAtInvalid));
        }
        self.validate_max_age(iat, now, leeway)
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

    #[cfg(test)]
    pub(super) fn test_validate_max_age(&self, iat: i64, now: i64, leeway: i64) -> Result<()> {
        self.validate_max_age(iat, now, leeway)
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
        let Some(expected) = &self.policy.client_id else {
            return Ok(());
        };
        match self.policy.token_kind {
            TokenKind::Id => Self::validate_id_client(value, audience_count, expected),
            TokenKind::Access | TokenKind::Refresh => {
                Self::validate_access_client(value, audience_count, expected)
            }
        }
    }

    fn validate_id_client(value: &Value, audience_count: usize, expected: &str) -> Result<()> {
        if audience_count > 1 {
            Self::require_claim_equals(value, "azp", expected)?;
        } else {
            Self::require_claim_equals(value, "client_id", expected)?;
        }
        Self::require_present_claim_equals_when_present(value, "azp", expected)?;
        Self::require_present_claim_equals_when_present(value, "client_id", expected)?;
        Ok(())
    }

    fn validate_access_client(value: &Value, audience_count: usize, expected: &str) -> Result<()> {
        if audience_count > 1 {
            Self::require_claim_equals(value, "azp", expected)?;
            Self::require_present_claim_equals_when_present(value, "client_id", expected)?;
            return Ok(());
        }
        let azp = Self::string_claim(value, "azp");
        let client_id = Self::string_claim(value, "client_id");
        if azp.is_none() && client_id.is_none() {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::ClientMismatch));
        }
        Self::require_present_claim_equals_when_present(value, "azp", expected)?;
        Self::require_present_claim_equals_when_present(value, "client_id", expected)?;
        Ok(())
    }

    fn require_claim_equals(value: &Value, name: &str, expected: &str) -> Result<()> {
        match Self::string_claim(value, name) {
            Some(actual) if actual == expected => Ok(()),
            _ => Err(JwtDecodeError::new(JwtDecodeErrorKind::ClientMismatch)),
        }
    }

    fn require_present_claim_equals_when_present(
        value: &Value,
        name: &str,
        expected: &str,
    ) -> Result<()> {
        match Self::string_claim(value, name) {
            None => Ok(()),
            Some(actual) if actual == expected => Ok(()),
            Some(_) => Err(JwtDecodeError::new(JwtDecodeErrorKind::ClientMismatch)),
        }
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

    fn string_claim<'b>(value: &'b Value, name: &str) -> Option<&'b str> {
        value
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
    }

    fn i64_claim(value: &Value, name: &'static str) -> Result<Option<i64>> {
        let Some(value) = value.get(name) else {
            return Ok(None);
        };
        if value.is_null() {
            return Ok(None);
        }
        value
            .as_i64()
            .map(Some)
            .ok_or_else(|| Self::invalid_claim(name))
    }

    fn audience_claim(value: &Value) -> Result<Option<AudienceRef<'_>>> {
        let Some(value) = value.get("aud") else {
            return Ok(None);
        };
        if let Some(audience) = value.as_str() {
            return Ok(Some(AudienceRef::Single(audience)));
        }
        let Some(values) = value.as_array() else {
            return Err(Self::invalid_claim("aud"));
        };
        values
            .iter()
            .map(|value| value.as_str().ok_or_else(|| Self::invalid_claim("aud")))
            .collect::<Result<Vec<_>>>()
            .map(AudienceRef::Multiple)
            .map(Some)
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
                PolicyErrorKind::OutOfRange(name),
            ))
        })
    }

    fn invalid_claim(name: &'static str) -> JwtDecodeError {
        JwtDecodeError::new(JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Invalid(
            name,
        )))
    }
}

pub(crate) struct RegisteredClaimRefs<'a> {
    iss: &'a str,
    aud: Option<AudienceRef<'a>>,
    exp: i64,
    nbf: Option<i64>,
    iat: Option<i64>,
}

impl RegisteredClaimRefs<'_> {
    pub(crate) fn audience_count(&self) -> usize {
        self.aud.as_ref().map_or(0, AudienceRef::count)
    }

    #[cfg(test)]
    pub(super) fn from_test_parts<'a>(
        iss: &'a str,
        aud: Option<AudienceRef<'a>>,
        exp: i64,
        nbf: Option<i64>,
        iat: Option<i64>,
    ) -> RegisteredClaimRefs<'a> {
        RegisteredClaimRefs {
            iss,
            aud,
            exp,
            nbf,
            iat,
        }
    }
}

pub(crate) enum AudienceRef<'a> {
    Single(&'a str),
    Multiple(Vec<&'a str>),
}

impl AudienceRef<'_> {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::Single(value) => *value == expected,
            Self::Multiple(values) => values.contains(&expected),
        }
    }

    pub(crate) fn count(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::Multiple(values) => values.len(),
        }
    }

    fn is_valid(&self) -> bool {
        match self {
            Self::Single(value) => !value.is_empty(),
            Self::Multiple(values) => {
                !values.is_empty() && values.iter().all(|value| !value.is_empty())
            }
        }
    }
}
