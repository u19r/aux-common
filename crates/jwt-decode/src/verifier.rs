use std::{collections::HashMap, sync::Arc};

use jsonwebtoken::{DecodingKey, Header, Validation, decode, decode_header};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{
    AllowedAlgorithms, ClaimErrorKind, Clock, JwksSource, JwtDecodeError, JwtDecodeErrorKind,
    Result, SignatureAlgorithm, SystemClock, TokenKind, VerificationPolicy, VerifiedJwt,
    claims_policy::ClaimsPolicy, json::CompactToken,
};

#[derive(Clone)]
pub struct JwtVerifier {
    jwks_source: JwksSource,
    allowed_algorithms: AllowedAlgorithms,
    signature_validations: HashMap<SignatureAlgorithm, Validation>,
    clock: Arc<dyn Clock>,
}

impl JwtVerifier {
    #[must_use]
    pub fn builder() -> JwtVerifierBuilder {
        JwtVerifierBuilder::default()
    }

    pub async fn verify<T>(
        &self,
        token: &str,
        policy: &VerificationPolicy,
    ) -> Result<VerifiedJwt<T>>
    where
        T: DeserializeOwned,
    {
        let compact = CompactToken::try_from(token)?;
        compact.reject_duplicate_json_members()?;

        let header = decode_header(token).map_err(Self::map_backend_error)?;
        let algorithm = SignatureAlgorithm::from(header.alg);
        self.reject_disallowed_algorithm(algorithm)?;
        Self::reject_header(&header, policy)?;

        let kid = Self::required_kid(&header)?;
        let key = self
            .decoding_key_for(kid, algorithm, &policy.issuer)
            .await?;
        let validation = self.signature_validation(algorithm)?;
        let data = decode::<Value>(token, &key, validation).map_err(Self::map_backend_error)?;

        let registered = ClaimsPolicy::registered_claims(&data.claims)?;
        let audience_count = registered.aud.as_ref().map_or(0, crate::Audience::count);
        let claims_policy = ClaimsPolicy::new(policy, self.clock.now());
        claims_policy.validate_registered(&registered)?;
        claims_policy.validate_token_type_and_client(&data.claims, audience_count)?;

        let claims = serde_json::from_value::<T>(data.claims).map_err(|_| {
            JwtDecodeError::new(JwtDecodeErrorKind::ClaimsInvalid(
                ClaimErrorKind::Deserialize,
            ))
        })?;
        Ok(VerifiedJwt {
            algorithm,
            key_id: kid.to_owned(),
            registered,
            claims,
        })
    }

    pub async fn verify_json_claims(
        &self,
        token: &str,
        policy: &VerificationPolicy,
    ) -> Result<VerifiedJwt<Value>> {
        self.verify::<Value>(token, policy).await
    }

    pub async fn verify_json_claims_only(
        &self,
        token: &str,
        policy: &VerificationPolicy,
    ) -> Result<Value> {
        let compact = CompactToken::try_from(token)?;
        compact.reject_duplicate_header_members()?;

        let header = decode_header(token).map_err(Self::map_backend_error)?;
        let algorithm = SignatureAlgorithm::from(header.alg);
        self.reject_disallowed_algorithm(algorithm)?;
        Self::reject_header(&header, policy)?;

        let kid = Self::required_kid(&header)?;
        let key = self
            .decoding_key_for(kid, algorithm, &policy.issuer)
            .await?;
        self.verify_signature(&compact, &key, algorithm)?;
        let claims = compact.payload_value_rejecting_duplicates()?;

        let registered = ClaimsPolicy::registered_claim_refs(&claims)?;
        let audience_count = registered.audience_count();
        let claims_policy = ClaimsPolicy::new(policy, self.clock.now());
        claims_policy.validate_registered_refs(&registered)?;
        claims_policy.validate_token_type_and_client(&claims, audience_count)?;

        Ok(claims)
    }

    pub fn verify_static<T>(
        &self,
        token: &str,
        policy: &VerificationPolicy,
    ) -> Result<VerifiedJwt<T>>
    where
        T: DeserializeOwned,
    {
        let compact = CompactToken::try_from(token)?;
        compact.reject_duplicate_json_members()?;

        let header = decode_header(token).map_err(Self::map_backend_error)?;
        let algorithm = SignatureAlgorithm::from(header.alg);
        self.reject_disallowed_algorithm(algorithm)?;
        Self::reject_header(&header, policy)?;

        let kid = Self::required_kid(&header)?;
        let key = self.decoding_key_for_static(kid, algorithm, &policy.issuer)?;
        let validation = self.signature_validation(algorithm)?;
        let data = decode::<Value>(token, &key, validation).map_err(Self::map_backend_error)?;

        let registered = ClaimsPolicy::registered_claims(&data.claims)?;
        let audience_count = registered.aud.as_ref().map_or(0, crate::Audience::count);
        let claims_policy = ClaimsPolicy::new(policy, self.clock.now());
        claims_policy.validate_registered(&registered)?;
        claims_policy.validate_token_type_and_client(&data.claims, audience_count)?;

        let claims = serde_json::from_value::<T>(data.claims).map_err(|_| {
            JwtDecodeError::new(JwtDecodeErrorKind::ClaimsInvalid(
                ClaimErrorKind::Deserialize,
            ))
        })?;
        Ok(VerifiedJwt {
            algorithm,
            key_id: kid.to_owned(),
            registered,
            claims,
        })
    }

    pub fn verify_static_json_claims(
        &self,
        token: &str,
        policy: &VerificationPolicy,
    ) -> Result<VerifiedJwt<Value>> {
        self.verify_static::<Value>(token, policy)
    }

    pub fn verify_static_json_claims_only(
        &self,
        token: &str,
        policy: &VerificationPolicy,
    ) -> Result<Value> {
        let compact = CompactToken::try_from(token)?;
        compact.reject_duplicate_header_members()?;

        let header = decode_header(token).map_err(Self::map_backend_error)?;
        let algorithm = SignatureAlgorithm::from(header.alg);
        self.reject_disallowed_algorithm(algorithm)?;
        Self::reject_header(&header, policy)?;

        let kid = Self::required_kid(&header)?;
        let key = self.decoding_key_for_static(kid, algorithm, &policy.issuer)?;
        self.verify_signature(&compact, &key, algorithm)?;
        let claims = compact.payload_value_rejecting_duplicates()?;

        let registered = ClaimsPolicy::registered_claim_refs(&claims)?;
        let audience_count = registered.audience_count();
        let claims_policy = ClaimsPolicy::new(policy, self.clock.now());
        claims_policy.validate_registered_refs(&registered)?;
        claims_policy.validate_token_type_and_client(&claims, audience_count)?;

        Ok(claims)
    }

    fn reject_disallowed_algorithm(&self, algorithm: SignatureAlgorithm) -> Result<()> {
        if self.allowed_algorithms.contains(algorithm) {
            return Ok(());
        }
        Err(JwtDecodeError::new(
            JwtDecodeErrorKind::UnsupportedAlgorithm(algorithm),
        ))
    }

    async fn decoding_key_for(
        &self,
        kid: &str,
        algorithm: SignatureAlgorithm,
        issuer: &str,
    ) -> Result<DecodingKey> {
        if algorithm.is_symmetric() && matches!(self.jwks_source, JwksSource::LocalSymmetric(_)) {
            return self.local_symmetric_decoding_key(kid, algorithm);
        }
        self.jwks_decoding_key(kid, algorithm, issuer).await
    }

    fn decoding_key_for_static(
        &self,
        kid: &str,
        algorithm: SignatureAlgorithm,
        issuer: &str,
    ) -> Result<DecodingKey> {
        if algorithm.is_symmetric() && matches!(self.jwks_source, JwksSource::LocalSymmetric(_)) {
            return self.local_symmetric_decoding_key(kid, algorithm);
        }
        self.static_jwks_decoding_key(kid, algorithm, issuer)
    }

    fn local_symmetric_decoding_key(
        &self,
        kid: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<DecodingKey> {
        if !self.allowed_algorithms.allow_symmetric() {
            return Err(JwtDecodeError::new(
                JwtDecodeErrorKind::UnsupportedAlgorithm(algorithm),
            ));
        }
        let key = self.jwks_source.local_symmetric_key_for(kid)?;
        Ok(key.decoding_key())
    }

    async fn jwks_decoding_key(
        &self,
        kid: &str,
        algorithm: SignatureAlgorithm,
        issuer: &str,
    ) -> Result<DecodingKey> {
        let mut document = self.jwks_source.document_for_issuer(issuer).await?;
        if document
            .find_unique_key(kid)
            .is_err_and(|error| matches!(error.kind(), JwtDecodeErrorKind::KeyNotFound))
        {
            document = self.jwks_source.refresh_document_for_issuer(issuer).await?;
        }
        document.decoding_key_for(kid, algorithm, self.allowed_algorithms.allow_symmetric())
    }

    fn static_jwks_decoding_key(
        &self,
        kid: &str,
        algorithm: SignatureAlgorithm,
        issuer: &str,
    ) -> Result<DecodingKey> {
        let document = self.jwks_source.static_document_for_issuer(issuer)?;
        document.decoding_key_for(kid, algorithm, self.allowed_algorithms.allow_symmetric())
    }

    fn reject_header(header: &Header, policy: &VerificationPolicy) -> Result<()> {
        if Self::has_unsupported_key_material(header) {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::UnsupportedHeader));
        }
        if policy.validate_access_typ && !Self::access_typ_allowed(header, policy) {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::TokenTypeMismatch));
        }
        if policy.token_kind == TokenKind::Id && header.typ.as_deref() == Some("at+jwt") {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::TokenTypeMismatch));
        }
        Ok(())
    }

    fn access_typ_allowed(header: &Header, policy: &VerificationPolicy) -> bool {
        let typ = header.typ.as_deref().unwrap_or_default();
        policy
            .allowed_header_types
            .iter()
            .any(|allowed| allowed == typ)
    }

    fn has_unsupported_key_material(header: &Header) -> bool {
        header.jku.is_some()
            || header.jwk.is_some()
            || header.x5u.is_some()
            || header.x5c.is_some()
            || header.x5t.is_some()
            || header.x5t_s256.is_some()
            || header.crit.as_ref().is_some_and(|crit| !crit.is_empty())
    }

    fn required_kid(header: &Header) -> Result<&str> {
        header
            .kid
            .as_deref()
            .ok_or_else(|| JwtDecodeError::new(JwtDecodeErrorKind::MissingKeyId))
    }

    fn signature_validation(&self, algorithm: SignatureAlgorithm) -> Result<&Validation> {
        self.signature_validations
            .get(&algorithm)
            .ok_or_else(|| JwtDecodeError::new(JwtDecodeErrorKind::UnsupportedAlgorithm(algorithm)))
    }

    fn verify_signature(
        &self,
        compact: &CompactToken<'_>,
        key: &DecodingKey,
        algorithm: SignatureAlgorithm,
    ) -> Result<()> {
        self.signature_validation(algorithm)?;
        match jsonwebtoken::crypto::verify(
            compact.signature,
            compact.message.as_bytes(),
            key,
            algorithm.to_backend(),
        ) {
            Ok(true) => Ok(()),
            Ok(false) => Err(JwtDecodeError::new(JwtDecodeErrorKind::SignatureInvalid)),
            Err(error) => Err(Self::map_backend_error(error)),
        }
    }

    fn signature_only_validation(algorithm: SignatureAlgorithm) -> Validation {
        let mut validation = Validation::new(algorithm.to_backend());
        validation.algorithms = vec![algorithm.to_backend()];
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.leeway = 0;
        validation
    }

    fn map_backend_error(error: jsonwebtoken::errors::Error) -> JwtDecodeError {
        use jsonwebtoken::errors::ErrorKind;
        let kind = match error.kind() {
            ErrorKind::InvalidToken | ErrorKind::InvalidRsaKey(_) => {
                JwtDecodeErrorKind::MalformedToken
            }
            ErrorKind::InvalidSignature | ErrorKind::Provider(_) => {
                JwtDecodeErrorKind::SignatureInvalid
            }
            ErrorKind::InvalidAlgorithm => JwtDecodeErrorKind::UnsupportedHeader,
            ErrorKind::InvalidKeyFormat
            | ErrorKind::InvalidEcdsaKey
            | ErrorKind::InvalidAlgorithmName => JwtDecodeErrorKind::InvalidKey,
            _ => JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Deserialize),
        };
        JwtDecodeError::new(kind)
    }
}

#[derive(Default)]
pub struct JwtVerifierBuilder {
    jwks_source: Option<JwksSource>,
    allowed_algorithms: AllowedAlgorithms,
    clock: Option<Arc<dyn Clock>>,
}

impl JwtVerifierBuilder {
    #[must_use]
    pub fn jwks_source(mut self, source: JwksSource) -> Self {
        self.jwks_source = Some(source);
        self
    }

    #[must_use]
    pub fn allowed_algorithms(mut self, algorithms: AllowedAlgorithms) -> Self {
        self.allowed_algorithms = algorithms;
        self
    }

    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    pub fn build(self) -> Result<JwtVerifier> {
        let Some(jwks_source) = self.jwks_source else {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::JwksParse));
        };
        Ok(JwtVerifier {
            jwks_source,
            signature_validations: self
                .allowed_algorithms
                .iter()
                .map(|algorithm| (algorithm, JwtVerifier::signature_only_validation(algorithm)))
                .collect(),
            allowed_algorithms: self.allowed_algorithms,
            clock: self.clock.unwrap_or_else(|| Arc::new(SystemClock)),
        })
    }
}
