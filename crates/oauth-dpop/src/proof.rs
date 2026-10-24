use jose_core::{JwkThumbprint, LosslessJws};
use serde_json::Value;

use crate::{
    DpopAlgorithm, DpopError, DpopTargetUri,
    constants::{MAX_FUTURE_SKEW_SECONDS, MAX_JTI_BYTES, MAX_METHOD_BYTES, MAX_PROOF_AGE_SECONDS},
    numeric_date::NumericDate,
};

/// Trusted operation inputs. An authenticated AS nonce may replace iat
/// freshness. The issuer must authenticate its nonce before accepting a proof
/// returned with nonce-controlled freshness.
pub struct DpopValidationInput<'a> {
    pub proof: &'a str,
    pub method: &'a str,
    pub target_uri: &'a DpopTargetUri,
    pub now_seconds: i64,
    pub nonce_controls_freshness: bool,
    pub algorithms: &'a [DpopAlgorithm],
}

/// Cryptographically valid proof; nonce authenticity remains the issuer's
/// responsibility.
pub struct ValidatedDpopProof {
    thumbprint: JwkThumbprint,
    nonce: Option<String>,
    access_token_hash: Option<Value>,
}

impl DpopValidationInput<'_> {
    pub fn validate(&self) -> Result<ValidatedDpopProof, DpopError> {
        let jws = LosslessJws::parse(self.proof)?;
        validate_header(jws.header(), self.algorithms)?;
        let key = jws.embedded_es256_key()?;
        key.verify(jws.signing_input(), jws.signature())?;
        self.validate_claims(&jws)?;
        let nonce = match jws.payload().get("nonce") {
            None => None,
            Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
            _ => return Err(DpopError::InvalidProof),
        };
        Ok(ValidatedDpopProof {
            thumbprint: key.thumbprint().clone(),
            nonce,
            access_token_hash: jws.payload().get("ath").cloned(),
        })
    }

    fn validate_claims(&self, jws: &LosslessJws<'_>) -> Result<(), DpopError> {
        let claims = jws.payload();
        let jti = claims["jti"].as_str().ok_or(DpopError::InvalidProof)?;
        let method = claims["htm"].as_str().ok_or(DpopError::InvalidProof)?;
        if self.method.parse::<http::Method>().is_err()
            || jti.is_empty()
            || jti.len() > MAX_JTI_BYTES
            || method.is_empty()
            || method.len() > MAX_METHOD_BYTES
            || method != self.method
        {
            return Err(DpopError::InvalidProof);
        }
        let target =
            DpopTargetUri::try_from(claims["htu"].as_str().ok_or(DpopError::InvalidProof)?)?;
        if target != *self.target_uri {
            return Err(DpopError::InvalidProof);
        }
        let iat = NumericDate::parse_payload(jws.payload_bytes())?;
        if !self.nonce_controls_freshness
            && !iat.is_between(
                self.now_seconds.saturating_sub(MAX_PROOF_AGE_SECONDS),
                self.now_seconds.saturating_add(MAX_FUTURE_SKEW_SECONDS),
            )
        {
            return Err(DpopError::InvalidProof);
        }
        Ok(())
    }
}

impl ValidatedDpopProof {
    pub fn thumbprint(&self) -> &JwkThumbprint {
        &self.thumbprint
    }
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    pub(crate) fn matches_access_token_hash(&self, expected: &str) -> bool {
        self.access_token_hash.as_ref().and_then(Value::as_str) == Some(expected)
    }
}

fn validate_header(header: &Value, algorithms: &[DpopAlgorithm]) -> Result<(), DpopError> {
    let typ = header["typ"].as_str().ok_or(DpopError::InvalidProof)?;
    if !(typ.eq_ignore_ascii_case("dpop+jwt") || typ.eq_ignore_ascii_case("application/dpop+jwt")) {
        return Err(DpopError::InvalidProof);
    }
    if header["alg"] != "ES256"
        || !algorithms.contains(&DpopAlgorithm::Es256)
        || !header["jwk"].is_object()
    {
        return Err(DpopError::InvalidProof);
    }
    match (header.get("b64"), header.get("crit")) {
        (None, None) => Ok(()),
        (Some(Value::Bool(true)), Some(Value::Array(critical)))
            if critical.len() == 1 && critical[0] == "b64" =>
        {
            Ok(())
        }
        _ => Err(DpopError::InvalidProof),
    }
}
