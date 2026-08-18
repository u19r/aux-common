use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED, ED25519, ParsedPublicKey,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, VerificationAlgorithm,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use curve25519_dalek::edwards::CompressedEdwardsY;
use serde::Serialize;
use x509_parser::{
    prelude::{FromDer, SubjectPublicKeyInfo},
    public_key::PublicKey,
};

use crate::{JoseError, JwsAlgorithm};

const MAX_PUBLIC_KEY_BYTES: usize = 8 * 1024;

pub struct PreparedVerifier {
    algorithm: JwsAlgorithm,
    key: ParsedPublicKey,
}

impl std::fmt::Debug for PreparedVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedVerifier")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl PreparedVerifier {
    pub fn try_new(algorithm: JwsAlgorithm, public_key: &[u8]) -> Result<Self, JoseError> {
        validate_spki(algorithm, public_key)?;
        let verification_algorithm: &'static dyn VerificationAlgorithm = match algorithm {
            JwsAlgorithm::Rs256 => &RSA_PKCS1_2048_8192_SHA256,
            JwsAlgorithm::Rs384 => &RSA_PKCS1_2048_8192_SHA384,
            JwsAlgorithm::Es256 => &ECDSA_P256_SHA256_FIXED,
            JwsAlgorithm::Es384 => &ECDSA_P384_SHA384_FIXED,
            JwsAlgorithm::EdDsa => &ED25519,
        };
        let key = ParsedPublicKey::new(verification_algorithm, public_key)
            .map_err(|_| JoseError::InvalidPublicKey)?;
        Ok(Self { algorithm, key })
    }

    #[must_use]
    pub const fn algorithm(&self) -> JwsAlgorithm {
        self.algorithm
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        if self.algorithm == JwsAlgorithm::EdDsa
            && signature.len() == 64
            && !valid_ed25519_point(&signature[..32])
        {
            return Err(JoseError::InvalidSignature);
        }
        self.key
            .verify_sig(message, signature)
            .map_err(|_| JoseError::InvalidSignature)
    }
}

/// Caller-supplied public components used to construct a neutral JWK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKeyComponents {
    Rsa {
        modulus: Vec<u8>,
        exponent: Vec<u8>,
    },
    Ec {
        curve: &'static str,
        x: Vec<u8>,
        y: Vec<u8>,
    },
    Ed25519 {
        x: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PublicJwk {
    kty: String,
    kid: String,
    #[serde(rename = "use")]
    use_: String,
    alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    y: Option<String>,
}

impl PublicJwk {
    /// Build a JWK from a complete DER SubjectPublicKeyInfo.
    pub fn from_spki(
        algorithm: JwsAlgorithm,
        kid: impl Into<String>,
        public_key: &[u8],
    ) -> Result<Self, JoseError> {
        let components = components_from_spki(algorithm, public_key)?;
        Self::from_components(algorithm, kid, components)
    }

    pub fn from_components(
        algorithm: JwsAlgorithm,
        kid: impl Into<String>,
        components: PublicKeyComponents,
    ) -> Result<Self, JoseError> {
        let kid = kid.into();
        if kid.is_empty() {
            return Err(JoseError::EmptyKeyId);
        }
        let common = (kid, "sig".to_string(), algorithm.as_str().to_string());
        match (algorithm, components) {
            (
                JwsAlgorithm::Rs256 | JwsAlgorithm::Rs384,
                PublicKeyComponents::Rsa { modulus, exponent },
            ) if valid_rsa_components(algorithm, &modulus, &exponent) => {
                let (kid, use_, alg) = common;
                Ok(Self {
                    kty: "RSA".to_string(),
                    kid,
                    use_,
                    alg,
                    n: Some(URL_SAFE_NO_PAD.encode(strip_leading_zeroes(&modulus))),
                    e: Some(URL_SAFE_NO_PAD.encode(strip_leading_zeroes(&exponent))),
                    crv: None,
                    x: None,
                    y: None,
                })
            }
            (JwsAlgorithm::Es256, PublicKeyComponents::Ec { curve, x, y })
                if curve == "P-256" && x.len() == 32 && y.len() == 32 =>
            {
                p256::PublicKey::from_sec1_bytes(&[vec![0x04], x.clone(), y.clone()].concat())
                    .map_err(|_| JoseError::InvalidJwk)?;
                let (kid, use_, alg) = common;
                Ok(Self {
                    kty: "EC".to_string(),
                    kid,
                    use_,
                    alg,
                    n: None,
                    e: None,
                    crv: Some(curve.to_string()),
                    x: Some(URL_SAFE_NO_PAD.encode(x)),
                    y: Some(URL_SAFE_NO_PAD.encode(y)),
                })
            }
            (JwsAlgorithm::Es384, PublicKeyComponents::Ec { curve, x, y })
                if curve == "P-384" && x.len() == 48 && y.len() == 48 =>
            {
                p384::PublicKey::from_sec1_bytes(&[vec![0x04], x.clone(), y.clone()].concat())
                    .map_err(|_| JoseError::InvalidJwk)?;
                let (kid, use_, alg) = common;
                Ok(Self {
                    kty: "EC".to_string(),
                    kid,
                    use_,
                    alg,
                    n: None,
                    e: None,
                    crv: Some(curve.to_string()),
                    x: Some(URL_SAFE_NO_PAD.encode(x)),
                    y: Some(URL_SAFE_NO_PAD.encode(y)),
                })
            }
            (JwsAlgorithm::EdDsa, PublicKeyComponents::Ed25519 { x })
                if x.len() == 32 && valid_ed25519_point(&x) =>
            {
                let (kid, use_, alg) = common;
                Ok(Self {
                    kty: "OKP".to_string(),
                    kid,
                    use_,
                    alg,
                    n: None,
                    e: None,
                    crv: Some("Ed25519".to_string()),
                    x: Some(URL_SAFE_NO_PAD.encode(x)),
                    y: None,
                })
            }
            _ => Err(JoseError::InvalidJwk),
        }
    }

    #[must_use]
    pub fn kty(&self) -> &str {
        &self.kty
    }
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }
    #[must_use]
    pub fn use_(&self) -> &str {
        &self.use_
    }
    #[must_use]
    pub fn alg(&self) -> &str {
        &self.alg
    }
    #[must_use]
    pub fn n(&self) -> Option<&str> {
        self.n.as_deref()
    }
    #[must_use]
    pub fn e(&self) -> Option<&str> {
        self.e.as_deref()
    }
    #[must_use]
    pub fn crv(&self) -> Option<&str> {
        self.crv.as_deref()
    }
    #[must_use]
    pub fn x(&self) -> Option<&str> {
        self.x.as_deref()
    }
    #[must_use]
    pub fn y(&self) -> Option<&str> {
        self.y.as_deref()
    }
}

fn valid_rsa_components(algorithm: JwsAlgorithm, modulus: &[u8], exponent: &[u8]) -> bool {
    let expected_len = match algorithm {
        JwsAlgorithm::Rs256 => 256,
        JwsAlgorithm::Rs384 => 384,
        _ => return false,
    };
    canonical_rsa_components(modulus, exponent, expected_len).is_some()
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PublicJwks {
    keys: Vec<PublicJwk>,
}

impl PublicJwks {
    pub fn try_new(mut keys: Vec<PublicJwk>) -> Result<Self, JoseError> {
        keys.sort_by(|left, right| left.kid.cmp(&right.kid));
        if keys.windows(2).any(|pair| pair[0].kid == pair[1].kid) {
            return Err(JoseError::InvalidJwk);
        }
        Ok(Self { keys })
    }

    #[must_use]
    pub fn keys(&self) -> &[PublicJwk] {
        &self.keys
    }
}

fn strip_leading_zeroes(value: &[u8]) -> &[u8] {
    let first_nonzero = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    &value[first_nonzero..]
}

fn validate_spki(algorithm: JwsAlgorithm, public_key: &[u8]) -> Result<(), JoseError> {
    components_from_spki(algorithm, public_key).map(|_| ())
}

fn components_from_spki(
    algorithm: JwsAlgorithm,
    public_key: &[u8],
) -> Result<PublicKeyComponents, JoseError> {
    if public_key.is_empty() || public_key.len() > MAX_PUBLIC_KEY_BYTES {
        return Err(JoseError::InvalidPublicKey);
    }
    let (remainder, spki) =
        SubjectPublicKeyInfo::from_der(public_key).map_err(|_| JoseError::InvalidPublicKey)?;
    if !remainder.is_empty() || spki.raw.len() != public_key.len() {
        return Err(JoseError::InvalidPublicKey);
    }
    let algorithm_oid = spki.algorithm.algorithm.to_id_string();
    let curve_oid = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.as_oid().ok())
        .map(|oid| oid.to_id_string());
    let parsed = spki.parsed().map_err(|_| JoseError::InvalidPublicKey)?;
    match (algorithm, algorithm_oid.as_str(), parsed) {
        (JwsAlgorithm::Rs256, "1.2.840.113549.1.1.1", PublicKey::RSA(key)) => {
            let (modulus, exponent) = canonical_rsa_components(key.modulus, key.exponent, 256)
                .ok_or(JoseError::InvalidPublicKey)?;
            Ok(PublicKeyComponents::Rsa { modulus, exponent })
        }
        (JwsAlgorithm::Rs384, "1.2.840.113549.1.1.1", PublicKey::RSA(key)) => {
            let (modulus, exponent) = canonical_rsa_components(key.modulus, key.exponent, 384)
                .ok_or(JoseError::InvalidPublicKey)?;
            Ok(PublicKeyComponents::Rsa { modulus, exponent })
        }
        (JwsAlgorithm::Es256, "1.2.840.10045.2.1", PublicKey::EC(point))
            if curve_oid.as_deref() == Some("1.2.840.10045.3.1.7")
                && point.data().len() == 65
                && point.data()[0] == 0x04 =>
        {
            let point = point.data();
            p256::PublicKey::from_sec1_bytes(point).map_err(|_| JoseError::InvalidPublicKey)?;
            Ok(PublicKeyComponents::Ec {
                curve: "P-256",
                x: point[1..33].to_vec(),
                y: point[33..].to_vec(),
            })
        }
        (JwsAlgorithm::Es384, "1.2.840.10045.2.1", PublicKey::EC(point))
            if curve_oid.as_deref() == Some("1.3.132.0.34")
                && point.data().len() == 97
                && point.data()[0] == 0x04 =>
        {
            let point = point.data();
            p384::PublicKey::from_sec1_bytes(point).map_err(|_| JoseError::InvalidPublicKey)?;
            Ok(PublicKeyComponents::Ec {
                curve: "P-384",
                x: point[1..49].to_vec(),
                y: point[49..].to_vec(),
            })
        }
        (JwsAlgorithm::EdDsa, "1.3.101.112", PublicKey::Unknown(key))
            if spki.algorithm.parameters.is_none()
                && key.len() == 32
                && valid_ed25519_point(key) =>
        {
            Ok(PublicKeyComponents::Ed25519 { x: key.to_vec() })
        }
        _ => Err(JoseError::InvalidPublicKey),
    }
}

fn valid_ed25519_point(bytes: &[u8]) -> bool {
    // AWS-LC's generic Ed25519 verifier accepts weak points, so enforce the
    // RFC 8032 strict import/verification rule at this boundary instead.
    let Ok(compressed) = CompressedEdwardsY::from_slice(bytes) else {
        return false;
    };
    let Some(point) = compressed.decompress() else {
        return false;
    };
    !point.is_small_order() && point.compress().to_bytes() == compressed.to_bytes()
}

fn canonical_rsa_components(
    modulus: &[u8],
    exponent: &[u8],
    expected_len: usize,
) -> Option<(Vec<u8>, Vec<u8>)> {
    if modulus.len() > expected_len + 1 || exponent.len() > 5 {
        return None;
    }
    let modulus = strip_leading_zeroes(modulus);
    let exponent = strip_leading_zeroes(exponent);
    if modulus.len() != expected_len
        || modulus.first().is_none_or(|byte| byte & 0x80 == 0)
        || modulus.last().is_none_or(|byte| byte & 1 == 0)
        || exponent.is_empty()
        || exponent.len() > 4
    {
        return None;
    }
    let value = exponent
        .iter()
        .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte));
    if value < 3 || value % 2 == 0 {
        return None;
    }
    Some((modulus.to_vec(), exponent.to_vec()))
}
