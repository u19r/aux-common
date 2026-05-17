use std::sync::Arc;

use jsonwebtoken::{DecodingKey, Header, Validation, decode, decode_header};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{
    AllowedAlgorithms, ClaimErrorKind, Clock, JwksSource, JwtDecodeError, JwtDecodeErrorKind,
    Result, SignatureAlgorithm, SystemClock, TokenKind, VerificationPolicy, VerifiedJwt,
    claims_policy::ClaimsPolicy, json::CompactToken, key_policy::KeyPolicy,
};

#[derive(Clone)]
pub struct JwtVerifier {
    jwks_source: JwksSource,
    allowed_algorithms: AllowedAlgorithms,
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
        let data = decode::<Value>(token, &key, &self.signature_only_validation(algorithm))
            .map_err(Self::map_backend_error)?;

        let registered = ClaimsPolicy::registered_claims(&data.claims)?;
        ClaimsPolicy::new(policy, self.clock.now()).validate_registered(&registered)?;
        ClaimsPolicy::new(policy, self.clock.now())
            .validate_token_type_and_client(&data.claims, registered.aud.count())?;

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
        if algorithm.is_symmetric() {
            return self.local_symmetric_decoding_key(kid, algorithm);
        }
        self.jwks_decoding_key(kid, algorithm, issuer).await
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
        Ok(DecodingKey::from_secret(key.secret()))
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
        let jwk = document.find_unique_key(kid)?;
        KeyPolicy::new(jwk, algorithm, self.allowed_algorithms.allow_symmetric()).validate()?;
        DecodingKey::from_jwk(jwk).map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey))
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

    fn signature_only_validation(&self, algorithm: SignatureAlgorithm) -> Validation {
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
            allowed_algorithms: self.allowed_algorithms,
            clock: self.clock.unwrap_or_else(|| Arc::new(SystemClock)),
        })
    }
}
