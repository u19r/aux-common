use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;

use crate::JoseError;

#[derive(Serialize)]
struct EncryptionHeader<'a> {
    alg: &'static str,
    enc: &'static str,
    cty: &'static str,
    kid: &'a str,
}

pub(super) fn encode_protected_header(key_id: &str) -> Result<String, JoseError> {
    let header = EncryptionHeader {
        alg: "RSA-OAEP-256",
        enc: "A256GCM",
        cty: "JWT",
        kid: key_id,
    };
    let encoded = serde_json::to_vec(&header).map_err(|_| JoseError::InvalidProtectedHeader)?;
    Ok(URL_SAFE_NO_PAD.encode(encoded))
}
