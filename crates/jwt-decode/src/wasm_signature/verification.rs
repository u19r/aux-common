use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{
    Signature as Ed25519Signature, Verifier as _, VerifyingKey as Ed25519VerifyingKey,
};
use jsonwebtoken::DecodingKey;
use purecrypto::{
    bignum::BoxedUint,
    hash::{
        Digest as PureDigest, Hmac as PureHmac, Sha256 as PureSha256, Sha384 as PureSha384,
        Sha512 as PureSha512,
    },
    rsa::{BoxedRsaPublicKey, Pkcs1Digest},
};

use crate::{JwtDecodeError, JwtDecodeErrorKind, SignatureAlgorithm, error::Result};

pub(crate) fn verify(
    encoded_signature: &str,
    message: &[u8],
    key: &DecodingKey,
    algorithm: SignatureAlgorithm,
) -> Result<()> {
    let signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| invalid_signature())?;
    let verified = match algorithm {
        SignatureAlgorithm::HS256 => verify_hmac::<PureSha256>(key, message, &signature),
        SignatureAlgorithm::HS384 => verify_hmac::<PureSha384>(key, message, &signature),
        SignatureAlgorithm::HS512 => verify_hmac::<PureSha512>(key, message, &signature),
        SignatureAlgorithm::RS256 => verify_rsa_pkcs1::<PureSha256>(key, message, &signature),
        SignatureAlgorithm::RS384 => verify_rsa_pkcs1::<PureSha384>(key, message, &signature),
        SignatureAlgorithm::RS512 => verify_rsa_pkcs1::<PureSha512>(key, message, &signature),
        SignatureAlgorithm::PS256 => verify_rsa_pss::<PureSha256>(key, message, &signature),
        SignatureAlgorithm::PS384 => verify_rsa_pss::<PureSha384>(key, message, &signature),
        SignatureAlgorithm::PS512 => verify_rsa_pss::<PureSha512>(key, message, &signature),
        SignatureAlgorithm::ES256 => verify_es256(key, message, &signature),
        SignatureAlgorithm::ES384 => verify_es384(key, message, &signature),
        SignatureAlgorithm::EdDSA => verify_ed25519(key, message, &signature),
    };
    verified.map_err(|_| invalid_signature())
}

fn verify_hmac<D>(
    key: &DecodingKey,
    message: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()>
where
    D: PureDigest,
{
    let key = key.try_get_as_bytes().map_err(|_| ())?;
    bool::from(PureHmac::<D>::new(key).chain(message).verify(signature))
        .then_some(())
        .ok_or(())
}

fn rsa_key(key: &DecodingKey) -> std::result::Result<BoxedRsaPublicKey, ()> {
    let jsonwebtoken::DecodingKeyKind::RsaModulusExponent { n, e } = key.kind() else {
        return Err(());
    };
    BoxedRsaPublicKey::try_new(BoxedUint::from_be_bytes(n), BoxedUint::from_be_bytes(e))
        .map_err(|_| ())
}

fn verify_rsa_pkcs1<D>(
    key: &DecodingKey,
    message: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()>
where
    D: Pkcs1Digest,
{
    rsa_key(key)?
        .verify_pkcs1v15::<D>(message, signature)
        .map_err(|_| ())
}

fn verify_rsa_pss<D>(
    key: &DecodingKey,
    message: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()>
where
    D: PureDigest,
{
    rsa_key(key)?
        .verify_pss::<D>(message, signature)
        .map_err(|_| ())
}

fn verify_es256(
    key: &DecodingKey,
    message: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    let normalized = crate::constants::normalize_low_s_raw(signature.try_into().map_err(|_| ())?);
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key.try_get_as_bytes().map_err(|_| ())?)
        .map_err(|_| ())?;
    let signature = p256::ecdsa::Signature::from_slice(&normalized).map_err(|_| ())?;
    key.verify(message, &signature).map_err(|_| ())
}

fn verify_es384(
    key: &DecodingKey,
    message: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(key.try_get_as_bytes().map_err(|_| ())?)
        .map_err(|_| ())?;
    let signature = p384::ecdsa::Signature::from_slice(signature).map_err(|_| ())?;
    key.verify(message, &signature).map_err(|_| ())
}

fn verify_ed25519(
    key: &DecodingKey,
    message: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    let key_bytes: &[u8; 32] = key
        .try_get_as_bytes()
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())?;
    let key = Ed25519VerifyingKey::from_bytes(key_bytes).map_err(|_| ())?;
    let signature = Ed25519Signature::from_slice(signature).map_err(|_| ())?;
    key.verify(message, &signature).map_err(|_| ())
}

fn invalid_signature() -> JwtDecodeError {
    JwtDecodeError::new(JwtDecodeErrorKind::SignatureInvalid)
}
