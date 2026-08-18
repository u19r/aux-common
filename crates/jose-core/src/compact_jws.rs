use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::{JoseError, ProtectedHeader, key_material::PreparedVerifier};

const MAX_COMPACT_JWS_BYTES: usize = 1024 * 1024;
const MAX_SIGNATURE_B64_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedJwsInput {
    encoded: String,
}

impl PreparedJwsInput {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    #[must_use]
    pub fn finish(&self, signature: &[u8]) -> String {
        format!("{}.{}", self.encoded, URL_SAFE_NO_PAD.encode(signature))
    }
}

#[must_use]
pub fn finish_compact_jws(signing_input: &str, signature: &[u8]) -> String {
    format!("{}.{}", signing_input, URL_SAFE_NO_PAD.encode(signature))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactJws {
    pub header: ProtectedHeader,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl CompactJws {
    pub fn prepare(
        header: &ProtectedHeader,
        payload: &[u8],
    ) -> Result<PreparedJwsInput, JoseError> {
        Ok(PreparedJwsInput {
            encoded: format!("{}.{}", header.encode()?, URL_SAFE_NO_PAD.encode(payload)),
        })
    }

    pub fn decode(compact: &str) -> Result<Self, JoseError> {
        if compact.len() > MAX_COMPACT_JWS_BYTES {
            return Err(JoseError::InvalidCompactShape);
        }
        let mut parts = compact.split('.');
        let Some(header_segment) = parts.next() else {
            return Err(JoseError::InvalidCompactShape);
        };
        let Some(payload_segment) = parts.next() else {
            return Err(JoseError::InvalidCompactShape);
        };
        let Some(signature_segment) = parts.next() else {
            return Err(JoseError::InvalidCompactShape);
        };
        if parts.next().is_some()
            || header_segment.is_empty()
            || signature_segment.is_empty()
            || signature_segment.len() > MAX_SIGNATURE_B64_BYTES
        {
            return Err(JoseError::InvalidCompactShape);
        }
        let header = ProtectedHeader::decode(header_segment)?;
        let payload = decode_canonical(payload_segment)?;
        let signature = decode_canonical(signature_segment)?;
        Ok(Self {
            header,
            payload,
            signature,
        })
    }

    pub fn verify(&self, verifier: &PreparedVerifier) -> Result<(), JoseError> {
        if verifier.algorithm() != self.header.algorithm() {
            return Err(JoseError::InvalidSignature);
        }
        let signing_input = Self::prepare(&self.header, &self.payload)?;
        verifier.verify(signing_input.as_str().as_bytes(), &self.signature)
    }
}

fn decode_canonical(encoded: &str) -> Result<Vec<u8>, JoseError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| JoseError::InvalidBase64)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(JoseError::InvalidBase64);
    }
    Ok(decoded)
}
