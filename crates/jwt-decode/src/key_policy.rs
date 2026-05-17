use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, KeyOperations, PublicKeyUse};

use crate::{JwtDecodeError, JwtDecodeErrorKind, Result, SignatureAlgorithm};

pub(crate) struct KeyPolicy<'a> {
    jwk: &'a Jwk,
    algorithm: SignatureAlgorithm,
    allow_symmetric: bool,
}

impl<'a> KeyPolicy<'a> {
    pub(crate) fn new(jwk: &'a Jwk, algorithm: SignatureAlgorithm, allow_symmetric: bool) -> Self {
        Self {
            jwk,
            algorithm,
            allow_symmetric,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.validate_key_use()?;
        self.validate_key_algorithm()?;
        self.validate_key_family()
    }

    fn validate_key_use(&self) -> Result<()> {
        if matches!(
            &self.jwk.common.public_key_use,
            Some(PublicKeyUse::Encryption | PublicKeyUse::Other(_))
        ) {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
        }
        if self
            .jwk
            .common
            .key_operations
            .as_ref()
            .is_some_and(|operations| {
                !operations
                    .iter()
                    .any(|operation| matches!(operation, KeyOperations::Verify))
            })
        {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
        }
        Ok(())
    }

    fn validate_key_algorithm(&self) -> Result<()> {
        let Some(key_algorithm) = self.jwk.common.key_algorithm else {
            return Ok(());
        };
        let key_algorithm = SignatureAlgorithm::try_from(key_algorithm)?;
        if key_algorithm == self.algorithm {
            return Ok(());
        }
        Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey))
    }

    fn validate_key_family(&self) -> Result<()> {
        if matches!(self.jwk.algorithm, AlgorithmParameters::OctetKey(_)) && !self.allow_symmetric {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
        }
        if self.algorithm_matches_key_family() {
            return Ok(());
        }
        Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey))
    }

    fn algorithm_matches_key_family(&self) -> bool {
        matches!(
            (&self.jwk.algorithm, self.algorithm),
            (
                AlgorithmParameters::RSA(_),
                SignatureAlgorithm::RS256
                    | SignatureAlgorithm::RS384
                    | SignatureAlgorithm::RS512
                    | SignatureAlgorithm::PS256
                    | SignatureAlgorithm::PS384
                    | SignatureAlgorithm::PS512
            ) | (
                AlgorithmParameters::EllipticCurve(_),
                SignatureAlgorithm::ES256 | SignatureAlgorithm::ES384
            ) | (
                AlgorithmParameters::OctetKeyPair(_),
                SignatureAlgorithm::EdDSA
            ) | (
                AlgorithmParameters::OctetKey(_),
                SignatureAlgorithm::HS256 | SignatureAlgorithm::HS384 | SignatureAlgorithm::HS512
            )
        )
    }
}
