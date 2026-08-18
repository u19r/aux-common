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
mod tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::jwk::{
        AlgorithmParameters, EllipticCurve, EllipticCurveKeyParameters, EllipticCurveKeyType, Jwk,
        OctetKeyPairParameters, OctetKeyPairType, OctetKeyParameters, OctetKeyType,
        RSAKeyParameters, RSAKeyType,
    };

    use super::KeyPolicy;
    use crate::{JwtDecodeErrorKind, SignatureAlgorithm};

    fn rsa_jwk(modulus_bytes: usize) -> Jwk {
        Jwk {
            common: Default::default(),
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: RSAKeyType::RSA,
                n: URL_SAFE_NO_PAD.encode(vec![0xff; modulus_bytes]),
                e: "AQAB".to_string(),
            }),
        }
    }

    fn ec_jwk(curve: EllipticCurve) -> Jwk {
        let coordinate_bytes = match curve {
            EllipticCurve::P256 => 32,
            EllipticCurve::P384 => 48,
            _ => 1,
        };
        Jwk {
            common: Default::default(),
            algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve,
                x: URL_SAFE_NO_PAD.encode(vec![0x01; coordinate_bytes]),
                y: URL_SAFE_NO_PAD.encode(vec![0x01; coordinate_bytes]),
            }),
        }
    }

    fn okp_jwk(curve: EllipticCurve) -> Jwk {
        okp_jwk_with_coordinate_len(curve, 32)
    }

    fn hmac_jwk(bytes: usize) -> Jwk {
        Jwk {
            common: Default::default(),
            algorithm: AlgorithmParameters::OctetKey(OctetKeyParameters {
                key_type: OctetKeyType::Octet,
                value: URL_SAFE_NO_PAD.encode(vec![0x42; bytes]),
            }),
        }
    }

    #[test]
    fn undersized_rsa_modulus_is_rejected_before_backend_selection() {
        let error = KeyPolicy::new(&rsa_jwk(128), SignatureAlgorithm::RS256, false)
            .validate()
            .expect_err("RSA keys below 2048 bits must be rejected");

        assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
    }

    #[test]
    fn two_thousand_forty_eight_bit_rsa_modulus_passes_size_policy() {
        KeyPolicy::new(&rsa_jwk(256), SignatureAlgorithm::RS256, false)
            .validate()
            .expect("2048-bit RSA keys should pass the size policy");
    }

    #[test]
    fn given_2040_bit_rsa_modulus_when_validating_key_policy_then_rejects() {
        let error = KeyPolicy::new(&rsa_jwk(255), SignatureAlgorithm::RS256, false)
            .validate()
            .expect_err("2040-bit RSA keys must be rejected");

        assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
    }

    #[test]
    fn given_ec_curve_mismatch_when_validating_key_policy_then_rejects() {
        let error = KeyPolicy::new(
            &ec_jwk(EllipticCurve::P384),
            SignatureAlgorithm::ES256,
            false,
        )
        .validate()
        .expect_err("ES256 must not consume a P-384 key");

        assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
        KeyPolicy::new(
            &ec_jwk(EllipticCurve::P256),
            SignatureAlgorithm::ES256,
            false,
        )
        .validate()
        .expect("the matching P-256 curve remains supported");
    }

    #[test]
    fn given_okp_curve_mismatch_when_validating_key_policy_then_rejects() {
        let error = KeyPolicy::new(
            &okp_jwk(EllipticCurve::P256),
            SignatureAlgorithm::EdDSA,
            false,
        )
        .validate()
        .expect_err("EdDSA must only consume Ed25519 keys");

        assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
        KeyPolicy::new(
            &okp_jwk(EllipticCurve::Ed25519),
            SignatureAlgorithm::EdDSA,
            false,
        )
        .validate()
        .expect("the matching Ed25519 curve remains supported");
    }

    #[test]
    fn given_short_hmac_jwk_when_validating_key_policy_then_rejects() {
        let error = KeyPolicy::new(&hmac_jwk(31), SignatureAlgorithm::HS256, true)
            .validate()
            .expect_err("HS256 JWKs must contain at least 256 bits");

        assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
        KeyPolicy::new(&hmac_jwk(32), SignatureAlgorithm::HS256, true)
            .validate()
            .expect("a 256-bit HMAC JWK remains supported");
    }

    #[test]
    fn given_oversized_rsa_modulus_when_validating_key_policy_then_rejects() {
        let error = KeyPolicy::new(&rsa_jwk(1025), SignatureAlgorithm::RS256, false)
            .validate()
            .expect_err("RSA modulus material above the supported profile must be rejected");

        assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
    }

    #[test]
    fn given_oversized_ec_coordinate_when_validating_key_policy_then_rejects() {
        let mut jwk = ec_jwk(EllipticCurve::P256);
        if let AlgorithmParameters::EllipticCurve(parameters) = &mut jwk.algorithm {
            parameters.x = URL_SAFE_NO_PAD.encode(vec![0x42; 49]);
        }
        let error = KeyPolicy::new(&jwk, SignatureAlgorithm::ES256, false)
            .validate()
            .expect_err("EC coordinates above the selected curve width must be rejected");

        assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
    }

    #[test]
    fn given_oversized_okp_coordinate_when_validating_key_policy_then_rejects() {
        let error = KeyPolicy::new(
            &okp_jwk_with_coordinate_len(EllipticCurve::Ed25519, 33),
            SignatureAlgorithm::EdDSA,
            false,
        )
        .validate()
        .expect_err("Ed25519 public keys must have exactly 32 bytes");

        assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
    }

    #[test]
    fn given_low_order_okp_key_when_validating_key_policy_then_rejects() {
        let mut point = [0_u8; 32];
        point[0] = 1;
        let jwk = okp_jwk_with_coordinate(URL_SAFE_NO_PAD.encode(point));
        let error = KeyPolicy::new(&jwk, SignatureAlgorithm::EdDSA, false)
            .validate()
            .expect_err("Ed25519 low-order public points must be rejected");

        assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
    }

    #[test]
    fn given_oversized_hmac_jwk_when_validating_key_policy_then_rejects() {
        let error = KeyPolicy::new(&hmac_jwk(65), SignatureAlgorithm::HS512, true)
            .validate()
            .expect_err("HMAC material above the supported profile must be rejected");

        assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
    }

    fn okp_jwk_with_coordinate_len(curve: EllipticCurve, bytes: usize) -> Jwk {
        okp_jwk_with_coordinate_for_curve(curve, URL_SAFE_NO_PAD.encode(vec![0x01; bytes]))
    }

    fn okp_jwk_with_coordinate(coordinate: String) -> Jwk {
        okp_jwk_with_coordinate_for_curve(EllipticCurve::Ed25519, coordinate)
    }

    fn okp_jwk_with_coordinate_for_curve(curve: EllipticCurve, coordinate: String) -> Jwk {
        Jwk {
            common: Default::default(),
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: OctetKeyPairType::OctetKeyPair,
                curve,
                x: coordinate,
            }),
        }
    }
}
