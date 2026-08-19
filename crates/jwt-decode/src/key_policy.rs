use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use curve25519_dalek::edwards::CompressedEdwardsY;
use jsonwebtoken::jwk::{
    AlgorithmParameters, EllipticCurve, EllipticCurveKeyParameters, Jwk, KeyOperations,
    OctetKeyPairParameters, PublicKeyUse,
};

use crate::{JwtDecodeError, JwtDecodeErrorKind, Result, SignatureAlgorithm};

pub(crate) const MIN_RSA_MODULUS_BITS: usize = 2048;
pub(crate) const MAX_RSA_MODULUS_BYTES: usize = 1024;
pub(crate) const MIN_HMAC_KEY_BYTES: usize = 32;
pub(crate) const MAX_HMAC_KEY_BYTES: usize = 64;
const MAX_ED25519_PUBLIC_KEY_BYTES: usize = 32;

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
        if !self.algorithm_matches_key_family() {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
        }
        match &self.jwk.algorithm {
            AlgorithmParameters::RSA(_) => self.validate_rsa_modulus(),
            AlgorithmParameters::OctetKey(parameters) => {
                if !self.allow_symmetric {
                    return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
                }
                self.validate_hmac_key(parameters.value.as_bytes())
            }
            AlgorithmParameters::EllipticCurve(parameters) => self.validate_ec_key(parameters),
            AlgorithmParameters::OctetKeyPair(parameters) => self.validate_okp_key(parameters),
            _ => Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey)),
        }
    }

    fn validate_rsa_modulus(&self) -> Result<()> {
        let AlgorithmParameters::RSA(parameters) = &self.jwk.algorithm else {
            return Ok(());
        };
        let modulus = decode_bounded(parameters.n.as_bytes(), MAX_RSA_MODULUS_BYTES)?;
        let Some(first_nonzero) = modulus.iter().position(|byte| *byte != 0) else {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
        };
        let first = modulus[first_nonzero];
        let significant_bits =
            (modulus.len() - first_nonzero - 1) * 8 + (u8::BITS - first.leading_zeros()) as usize;
        if !(MIN_RSA_MODULUS_BITS..=MAX_RSA_MODULUS_BYTES * 8).contains(&significant_bits) {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
        }
        Ok(())
    }

    fn validate_hmac_key(&self, encoded: &[u8]) -> Result<()> {
        let key = decode_bounded(encoded, MAX_HMAC_KEY_BYTES)?;
        let minimum = match self.algorithm {
            SignatureAlgorithm::HS256 => MIN_HMAC_KEY_BYTES,
            SignatureAlgorithm::HS384 => 48,
            SignatureAlgorithm::HS512 => 64,
            _ => return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey)),
        };
        if key.len() < minimum {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
        }
        Ok(())
    }

    fn validate_ec_key(&self, parameters: &EllipticCurveKeyParameters) -> Result<()> {
        let coordinate_bytes = match self.algorithm {
            SignatureAlgorithm::ES256 => 32,
            SignatureAlgorithm::ES384 => 48,
            _ => return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey)),
        };
        let x = decode_bounded(parameters.x.as_bytes(), coordinate_bytes)?;
        let y = decode_bounded(parameters.y.as_bytes(), coordinate_bytes)?;
        if x.len() != coordinate_bytes || y.len() != coordinate_bytes {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
        }
        Ok(())
    }

    fn validate_okp_key(&self, parameters: &OctetKeyPairParameters) -> Result<()> {
        if !matches!(self.algorithm, SignatureAlgorithm::EdDSA) {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
        }
        let public_key = decode_bounded(parameters.x.as_bytes(), MAX_ED25519_PUBLIC_KEY_BYTES)?;
        if public_key.len() != MAX_ED25519_PUBLIC_KEY_BYTES || !valid_ed25519_point(&public_key) {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
        }
        Ok(())
    }

    fn algorithm_matches_key_family(&self) -> bool {
        match (&self.jwk.algorithm, self.algorithm) {
            (
                AlgorithmParameters::RSA(_),
                SignatureAlgorithm::RS256
                | SignatureAlgorithm::RS384
                | SignatureAlgorithm::RS512
                | SignatureAlgorithm::PS256
                | SignatureAlgorithm::PS384
                | SignatureAlgorithm::PS512,
            ) => true,
            (AlgorithmParameters::EllipticCurve(parameters), SignatureAlgorithm::ES256)
                if parameters.curve == EllipticCurve::P256 =>
            {
                true
            }
            (AlgorithmParameters::EllipticCurve(parameters), SignatureAlgorithm::ES384)
                if parameters.curve == EllipticCurve::P384 =>
            {
                true
            }
            (AlgorithmParameters::OctetKeyPair(parameters), SignatureAlgorithm::EdDSA)
                if parameters.curve == EllipticCurve::Ed25519 =>
            {
                true
            }
            (
                AlgorithmParameters::OctetKey(_),
                SignatureAlgorithm::HS256 | SignatureAlgorithm::HS384 | SignatureAlgorithm::HS512,
            ) if self.allow_symmetric => true,
            _ => false,
        }
    }
}

fn decode_bounded(encoded: &[u8], max_bytes: usize) -> Result<Vec<u8>> {
    let max_encoded_len = max_bytes.div_ceil(3) * 4;
    if encoded.len() > max_encoded_len {
        return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey))?;
    if decoded.len() > max_bytes {
        return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
    }
    Ok(decoded)
}

fn valid_ed25519_point(bytes: &[u8]) -> bool {
    // Keep weak points out of jsonwebtoken's verifier, which otherwise accepts
    // low-order Ed25519 JWKs before signature verification.
    let Ok(compressed) = CompressedEdwardsY::from_slice(bytes) else {
        return false;
    };
    let Some(point) = compressed.decompress() else {
        return false;
    };
    !point.is_small_order() && point.compress().to_bytes() == compressed.to_bytes()
}

#[cfg(test)]
#[path = "key_policy_tests.rs"]
mod key_policy_tests;
