use std::time::Duration;

use crate::{
    JwtDecodeError, JwtDecodeErrorKind, PolicyErrorKind, TokenKind, constants::DEFAULT_LEEWAY,
    error::Result,
};

#[derive(Debug, Clone)]
pub struct VerificationPolicy {
    pub(crate) token_kind: TokenKind,
    pub(crate) issuer: String,
    pub(crate) audiences: Option<Vec<String>>,
    pub(crate) require_token_type: bool,
    pub(crate) validate_access_typ: bool,
    pub(crate) token_type_claim: String,
    pub(crate) token_type_value: String,
    pub(crate) client_id: Option<String>,
    pub(crate) nonce: Option<String>,
    pub(crate) max_issued_age: Option<Duration>,
    pub(crate) leeway: Duration,
    pub(crate) allowed_header_types: Vec<String>,
    pub(crate) require_issued_at: bool,
}

impl VerificationPolicy {
    #[must_use]
    pub fn generic_jwt() -> VerificationPolicyBuilder {
        VerificationPolicyBuilder::new(TokenKind::Access)
            .without_token_type()
            .without_access_typ()
    }

    #[must_use]
    pub fn access_token() -> VerificationPolicyBuilder {
        VerificationPolicyBuilder::new(TokenKind::Access)
            .token_type_claim("token_type")
            .token_type_value(TokenKind::Access.default_claim_value())
    }

    #[must_use]
    pub fn id_token() -> VerificationPolicyBuilder {
        VerificationPolicyBuilder::new(TokenKind::Id)
            .token_type_claim("token_type")
            .token_type_value(TokenKind::Id.default_claim_value())
    }

    #[must_use]
    pub fn refresh_token() -> VerificationPolicyBuilder {
        VerificationPolicyBuilder::new(TokenKind::Refresh)
            .token_type_claim("token_type")
            .token_type_value(TokenKind::Refresh.default_claim_value())
    }
}

#[derive(Debug, Clone)]
enum AudienceRequirement {
    Unconfigured,
    Unchecked,
    AnyOf(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct VerificationPolicyBuilder {
    token_kind: TokenKind,
    issuer: Option<String>,
    audience_requirement: AudienceRequirement,
    require_token_type: bool,
    validate_access_typ: bool,
    token_type_claim: String,
    token_type_value: String,
    client_id: Option<String>,
    nonce: Option<String>,
    max_issued_age: Option<Duration>,
    leeway: Duration,
    allowed_header_types: Vec<String>,
    require_issued_at: bool,
}

impl VerificationPolicyBuilder {
    fn new(token_kind: TokenKind) -> Self {
        Self {
            token_kind,
            issuer: None,
            audience_requirement: AudienceRequirement::Unconfigured,
            require_token_type: true,
            validate_access_typ: token_kind == TokenKind::Access,
            token_type_claim: String::new(),
            token_type_value: String::new(),
            client_id: None,
            nonce: None,
            max_issued_age: None,
            leeway: DEFAULT_LEEWAY,
            allowed_header_types: default_header_types(token_kind),
            require_issued_at: true,
        }
    }

    pub fn issuer(mut self, issuer: impl Into<String>) -> Result<Self> {
        self.issuer = Some(Self::non_empty(issuer.into(), "issuer")?);
        Ok(self)
    }

    pub fn audience(self, audience: impl Into<String>) -> Result<Self> {
        let audience: String = audience.into();
        self.audiences([audience])
    }

    /// Accept a token addressed to any configured audience. The caller owns
    /// application-specific configuration limits; empty lists or values fail.
    pub fn audiences<I, S>(mut self, audiences: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let audiences = audiences
            .into_iter()
            .map(|value| Self::non_empty(value.into(), "audience"))
            .collect::<Result<Vec<_>>>()?;
        if audiences.is_empty() {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::PolicyInvalid(
                PolicyErrorKind::MissingAudience,
            )));
        }
        self.audience_requirement = AudienceRequirement::AnyOf(audiences);
        Ok(self)
    }

    #[must_use]
    pub fn without_audience(mut self) -> Self {
        self.audience_requirement = AudienceRequirement::Unchecked;
        self
    }

    pub fn client_id(mut self, client_id: impl Into<String>) -> Result<Self> {
        self.client_id = Some(Self::non_empty(client_id.into(), "client_id")?);
        Ok(self)
    }

    pub fn nonce(mut self, nonce: impl Into<String>) -> Result<Self> {
        self.nonce = Some(Self::non_empty(nonce.into(), "nonce")?);
        Ok(self)
    }

    #[must_use]
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    #[must_use]
    pub fn max_issued_age(mut self, max_issued_age: Duration) -> Self {
        self.max_issued_age = Some(max_issued_age);
        self
    }

    #[must_use]
    pub fn allow_missing_issued_at(mut self) -> Self {
        self.require_issued_at = false;
        self
    }

    #[must_use]
    pub fn token_type_claim(mut self, token_type_claim: impl Into<String>) -> Self {
        self.token_type_claim = token_type_claim.into();
        self
    }

    #[must_use]
    pub fn token_type_value(mut self, token_type_value: impl Into<String>) -> Self {
        self.token_type_value = token_type_value.into();
        self
    }

    #[must_use]
    pub fn allow_application_access_token_typ(mut self) -> Self {
        if self.token_kind == TokenKind::Access {
            self.allowed_header_types
                .push("application/at+jwt".to_owned());
        }
        self
    }

    #[must_use]
    pub fn allow_missing_access_token_typ(mut self) -> Self {
        if self.token_kind == TokenKind::Access {
            self.allowed_header_types.push(String::new());
        }
        self
    }

    pub fn build(self) -> Result<VerificationPolicy> {
        self.validate_duration_ranges()?;
        let (token_type_claim, token_type_value) = self.token_type_policy()?;
        Ok(VerificationPolicy {
            token_kind: self.token_kind,
            issuer: self.required_issuer()?,
            audiences: self.required_audiences()?,
            require_token_type: self.require_token_type,
            validate_access_typ: self.validate_access_typ,
            token_type_claim,
            token_type_value,
            client_id: self.client_id,
            nonce: self.nonce,
            max_issued_age: self.max_issued_age,
            leeway: self.leeway,
            allowed_header_types: self.allowed_header_types,
            require_issued_at: self.require_issued_at,
        })
    }

    fn validate_duration_ranges(&self) -> Result<()> {
        if self.require_token_type
            && self.token_type_claim == "token_type"
            && self.token_type_value == "access_token"
            && self.leeway > Duration::from_secs(oauth_dpop::MAX_ACCESS_TOKEN_EXPIRY_LEEWAY_SECONDS)
        {
            return Err(Self::out_of_range("leeway"));
        }
        if i64::try_from(self.leeway.as_secs()).is_err() {
            return Err(Self::out_of_range("leeway"));
        }
        if self
            .max_issued_age
            .is_some_and(|duration| i64::try_from(duration.as_secs()).is_err())
        {
            return Err(Self::out_of_range("max_issued_age"));
        }
        Ok(())
    }

    fn without_token_type(mut self) -> Self {
        self.require_token_type = false;
        self.token_type_claim.clear();
        self.token_type_value.clear();
        self
    }

    fn without_access_typ(mut self) -> Self {
        self.validate_access_typ = false;
        self.allowed_header_types.clear();
        self
    }

    fn token_type_policy(&self) -> Result<(String, String)> {
        if !self.require_token_type {
            return Ok((String::new(), String::new()));
        }
        Ok((
            Self::non_empty(self.token_type_claim.clone(), "token_type_claim")?,
            Self::non_empty(self.token_type_value.clone(), "token_type_value")?,
        ))
    }

    fn required_issuer(&self) -> Result<String> {
        self.issuer.clone().ok_or_else(|| {
            JwtDecodeError::new(JwtDecodeErrorKind::PolicyInvalid(
                PolicyErrorKind::MissingIssuer,
            ))
        })
    }

    fn required_audiences(&self) -> Result<Option<Vec<String>>> {
        match &self.audience_requirement {
            AudienceRequirement::Unchecked => Ok(None),
            AudienceRequirement::AnyOf(audiences) => Ok(Some(audiences.clone())),
            AudienceRequirement::Unconfigured => Err(JwtDecodeError::new(
                JwtDecodeErrorKind::PolicyInvalid(PolicyErrorKind::MissingAudience),
            )),
        }
    }

    fn non_empty(value: String, name: &'static str) -> Result<String> {
        if !value.is_empty() {
            return Ok(value);
        }
        Err(JwtDecodeError::new(JwtDecodeErrorKind::PolicyInvalid(
            PolicyErrorKind::EmptyValue(name),
        )))
    }

    fn out_of_range(name: &'static str) -> JwtDecodeError {
        JwtDecodeError::new(JwtDecodeErrorKind::PolicyInvalid(
            PolicyErrorKind::OutOfRange(name),
        ))
    }
}

fn default_header_types(token_kind: TokenKind) -> Vec<String> {
    match token_kind {
        TokenKind::Access => vec!["at+jwt".to_owned()],
        TokenKind::Id | TokenKind::Refresh => Vec::new(),
    }
}
