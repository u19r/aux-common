use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jose_core::JwkThumbprint;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    DpopAlgorithm, DpopError, DpopTargetUri, DpopValidationInput, ValidatedDpopProof,
    constants::MAX_ACCESS_TOKEN_BYTES,
};

/// A present but unsupported confirmation never becomes unbound Bearer
/// authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessTokenConfirmation {
    Absent,
    Dpop { jkt: JwkThumbprint },
    Unsupported,
}

impl AccessTokenConfirmation {
    /// Call after duplicate-safe token parsing and signature/claim
    /// verification.
    pub fn parse(claim: Option<&Value>) -> Result<Self, DpopError> {
        let Some(claim) = claim else {
            return Ok(Self::Absent);
        };
        let object = claim.as_object().ok_or(DpopError::InvalidConfirmation)?;
        if object.len() > 16 {
            return Err(DpopError::InvalidConfirmation);
        }
        let Some(jkt) = object.get("jkt") else {
            return Ok(Self::Unsupported);
        };
        if ["jwk", "jwe", "jku", "kid", "x5t#S256"]
            .iter()
            .any(|name| object.contains_key(*name))
        {
            return Err(DpopError::InvalidConfirmation);
        }
        let jkt = jkt.as_str().ok_or(DpopError::InvalidConfirmation)?;
        let jkt =
            JwkThumbprint::try_from(jkt.to_owned()).map_err(|_| DpopError::InvalidConfirmation)?;
        Ok(Self::Dpop { jkt })
    }
}

pub struct ResourceProofValidationInput<'a> {
    pub access_token: &'a str,
    pub proof: &'a str,
    pub method: &'a str,
    pub target_uri: &'a DpopTargetUri,
    pub expected_jkt: &'a JwkThumbprint,
    pub now_seconds: i64,
}

impl ResourceProofValidationInput<'_> {
    pub fn validate(&self) -> Result<ValidatedDpopProof, DpopError> {
        if self.access_token.is_empty()
            || !self.access_token.is_ascii()
            || self.access_token.len() > MAX_ACCESS_TOKEN_BYTES
        {
            return Err(DpopError::InvalidProof);
        }
        let proof = DpopValidationInput {
            proof: self.proof,
            method: self.method,
            target_uri: self.target_uri,
            now_seconds: self.now_seconds,
            nonce_controls_freshness: false,
            algorithms: DpopAlgorithm::supported(),
        }
        .validate()?;
        let ath = URL_SAFE_NO_PAD.encode(Sha256::digest(self.access_token.as_bytes()));
        if proof.thumbprint() != self.expected_jkt || !proof.matches_access_token_hash(&ath) {
            return Err(DpopError::InvalidProof);
        }
        Ok(proof)
    }
}

/// Transport-authenticated request context and already-verified token
/// authority.
pub struct PresenterValidationInput<'a> {
    pub scheme: &'a str,
    pub access_token: &'a str,
    pub proof: Option<&'a str>,
    pub method: &'a str,
    pub target_uri: &'a DpopTargetUri,
    pub confirmation: &'a AccessTokenConfirmation,
    pub now_seconds: i64,
}

impl PresenterValidationInput<'_> {
    pub fn validate(&self) -> Result<(), DpopError> {
        match self.confirmation {
            AccessTokenConfirmation::Absent
                if self.scheme.eq_ignore_ascii_case("Bearer") && self.proof.is_none() =>
            {
                Ok(())
            }
            AccessTokenConfirmation::Dpop { jkt } if self.scheme.eq_ignore_ascii_case("DPoP") => {
                ResourceProofValidationInput {
                    access_token: self.access_token,
                    proof: self.proof.ok_or(DpopError::InvalidProof)?,
                    method: self.method,
                    target_uri: self.target_uri,
                    expected_jkt: jkt,
                    now_seconds: self.now_seconds,
                }
                .validate()
                .map(|_| ())
            }
            _ => Err(DpopError::InvalidPresenter),
        }
    }
}
