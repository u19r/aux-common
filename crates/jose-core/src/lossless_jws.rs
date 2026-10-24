use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

use crate::{
    BoundedJson, JoseError,
    constants::{
        MAX_ENCODED_PROOF_PART_BYTES, MAX_PROOF_BYTES, MAX_PROOF_JSON_BYTES,
        MAX_PROOF_SIGNATURE_BYTES,
    },
};

/// Original protected and payload bytes remain authoritative for verification.
/// Debug deliberately excludes the complete proof and its components.
pub struct LosslessJws<'a> {
    signing_input: &'a [u8],
    header: Value,
    header_bytes: Vec<u8>,
    payload: Value,
    payload_bytes: Vec<u8>,
    signature: Vec<u8>,
}

impl<'a> LosslessJws<'a> {
    pub fn parse(compact: &'a str) -> Result<Self, JoseError> {
        if compact.len() > MAX_PROOF_BYTES || !compact.is_ascii() {
            return Err(JoseError::InvalidCompactShape);
        }
        let parts: Vec<_> = compact.splitn(4, '.').collect();
        let [header, payload, signature] = parts.as_slice() else {
            return Err(JoseError::InvalidCompactShape);
        };
        let header_bytes = decode_part(header, MAX_PROOF_JSON_BYTES)?;
        let payload_bytes = decode_part(payload, MAX_PROOF_JSON_BYTES)?;
        let signature = decode_part(signature, MAX_PROOF_SIGNATURE_BYTES)?;
        let signing_input = &compact.as_bytes()[..header.len() + 1 + payload.len()];
        Ok(Self {
            signing_input,
            header: BoundedJson::parse(&header_bytes)?.into_value(),
            header_bytes,
            payload: BoundedJson::parse(&payload_bytes)?.into_value(),
            payload_bytes,
            signature,
        })
    }

    pub fn embedded_es256_key(&self) -> Result<crate::EmbeddedEs256Key, JoseError> {
        #[derive(serde::Deserialize)]
        struct Header<'a> {
            #[serde(borrow)]
            jwk: &'a serde_json::value::RawValue,
        }
        let header: Header<'_> =
            serde_json::from_slice(&self.header_bytes).map_err(|_| JoseError::InvalidJwk)?;
        crate::EmbeddedEs256Key::parse_json(header.jwk.get().as_bytes())
    }

    pub fn header(&self) -> &Value {
        &self.header
    }
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload_bytes
    }
    pub fn payload(&self) -> &Value {
        &self.payload
    }
    pub fn signing_input(&self) -> &[u8] {
        self.signing_input
    }
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

pub(crate) fn decode_part(encoded: &str, max_bytes: usize) -> Result<Vec<u8>, JoseError> {
    if encoded.is_empty()
        || encoded.len() > MAX_ENCODED_PROOF_PART_BYTES
        || encoded.len() > max_bytes.div_ceil(3) * 4
    {
        return Err(JoseError::InvalidCompactShape);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| JoseError::InvalidBase64)?;
    if decoded.len() > max_bytes || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(JoseError::InvalidBase64);
    }
    Ok(decoded)
}
