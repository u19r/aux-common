use ciborium::value::Value;

use crate::{
    WebAuthnError,
    assertion::parse_authenticator_data,
    cbor::{decode_bounded_cbor, ensure_canonical_cbor, validate_canonical_map_order},
    client_data::parse_client_data,
    types::{AttestationInput, RegistrationResult},
};

const MAX_ATTESTATION_OBJECT_BYTES: usize = 32 * 1024;

pub fn verify_none_attestation(
    input: AttestationInput<'_>,
) -> Result<RegistrationResult, WebAuthnError> {
    let value = decode_bounded_cbor(input.attestation_object, MAX_ATTESTATION_OBJECT_BYTES)?;
    parse_client_data(input.client_data_json, "webauthn.create", input.policy)?;
    ensure_canonical_cbor(&value, input.attestation_object)?;
    let Value::Map(entries) = value else {
        return Err(WebAuthnError::Malformed);
    };
    validate_canonical_map_order(&entries)?;
    let mut fmt = None;
    let mut auth_data = None;
    let mut att_stmt = None;
    let mut seen = std::collections::HashSet::new();
    for (key, value) in entries {
        let Value::Text(key) = key else {
            return Err(WebAuthnError::Malformed);
        };
        if !seen.insert(key.clone()) {
            return Err(WebAuthnError::Malformed);
        }
        match key.as_str() {
            "fmt" => {
                fmt = match value {
                    Value::Text(value) => Some(value),
                    _ => return Err(WebAuthnError::Malformed),
                }
            }
            "authData" => {
                auth_data = match value {
                    Value::Bytes(value) => Some(value),
                    _ => return Err(WebAuthnError::Malformed),
                }
            }
            "attStmt" => att_stmt = Some(value),
            _ => return Err(WebAuthnError::Malformed),
        }
    }
    if fmt.as_deref() != Some("none") {
        return Err(WebAuthnError::UnsupportedAttestation);
    }
    if !matches!(att_stmt, Some(Value::Map(ref values)) if values.is_empty()) {
        return Err(WebAuthnError::Malformed);
    }
    let parsed = parse_authenticator_data(
        &auth_data.ok_or(WebAuthnError::Malformed)?,
        input.policy.expected_rp_id_hash(),
        true,
        input.policy.user_verification(),
    )?;
    let Some(attested) = parsed.attested else {
        return Err(WebAuthnError::Malformed);
    };
    let public_key = crate::parse_cose_key(&attested.cose_key)?;
    Ok(RegistrationResult {
        credential_id: attested.credential_id,
        public_key_cose: attested.cose_key,
        public_key,
        aaguid: attested.aaguid,
        sign_count: parsed.sign_count,
        user_verified: parsed.flags & 0x04 != 0,
    })
}
