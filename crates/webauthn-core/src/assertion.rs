use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use sha2::{Digest as _, Sha256};

use crate::{
    WebAuthnError,
    cbor::{MAX_COSE_KEY_BYTES, parse_cose_key},
    client_data::parse_client_data,
    types::{AssertionInput, AssertionResult, SignCountStatus, UserVerification},
};

const MAX_AUTHENTICATOR_DATA_BYTES: usize = 16 * 1024;
const MAX_SIGNATURE_BYTES: usize = 256;
pub(crate) const MAX_CREDENTIAL_ID_BYTES: usize = 1023;

pub(crate) struct ParsedAuthenticatorData {
    pub(crate) rp_id_hash: [u8; 32],
    pub(crate) flags: u8,
    pub(crate) sign_count: u32,
    pub(crate) attested: Option<AttestedCredentialData>,
}

pub(crate) struct AttestedCredentialData {
    pub(crate) aaguid: [u8; 16],
    pub(crate) credential_id: Vec<u8>,
    pub(crate) cose_key: Vec<u8>,
}

pub fn verify_assertion(input: AssertionInput<'_>) -> Result<AssertionResult, WebAuthnError> {
    if input.credential_id.is_empty() || input.credential_id.len() > MAX_CREDENTIAL_ID_BYTES {
        return Err(WebAuthnError::Malformed);
    }
    if input.authenticator_data.len() > MAX_AUTHENTICATOR_DATA_BYTES
        || input.signature.len() > MAX_SIGNATURE_BYTES
        || input.credential_public_key_cose.len() > MAX_COSE_KEY_BYTES
    {
        return Err(WebAuthnError::Malformed);
    }
    parse_client_data(input.client_data_json, "webauthn.get", input.policy)?;
    let parsed = parse_authenticator_data(
        input.authenticator_data,
        input.policy.expected_rp_id_hash(),
        false,
        input.policy.user_verification(),
    )?;
    if parsed.rp_id_hash != *input.policy.expected_rp_id_hash() {
        return Err(WebAuthnError::RpIdHashMismatch);
    }
    let key = parse_cose_key(input.credential_public_key_cose)?;
    let mut encoded_key = Vec::with_capacity(65);
    encoded_key.push(0x04);
    encoded_key.extend_from_slice(&key.x);
    encoded_key.extend_from_slice(&key.y);
    let verifying_key = VerifyingKey::from_sec1_bytes(&encoded_key)
        .map_err(|_| WebAuthnError::UnsupportedCoseKey)?;
    let signature =
        Signature::from_der(input.signature).map_err(|_| WebAuthnError::InvalidSignature)?;
    let client_hash = Sha256::digest(input.client_data_json);
    let mut signed = Vec::with_capacity(input.authenticator_data.len() + client_hash.len());
    signed.extend_from_slice(input.authenticator_data);
    signed.extend_from_slice(&client_hash);
    verifying_key
        .verify(&signed, &signature)
        .map_err(|_| WebAuthnError::InvalidSignature)?;
    Ok(AssertionResult {
        credential_id: input.credential_id.to_vec(),
        user_handle: None,
        user_verified: parsed.flags & 0x04 != 0,
        sign_count: parsed.sign_count,
        sign_count_status: classify_counter(input.previous_sign_count, parsed.sign_count),
    })
}

pub(crate) fn parse_authenticator_data(
    bytes: &[u8],
    expected_rp_id_hash: &[u8; 32],
    require_attested_data: bool,
    user_verification: UserVerification,
) -> Result<ParsedAuthenticatorData, WebAuthnError> {
    if bytes.len() < 37 || bytes.len() > MAX_AUTHENTICATOR_DATA_BYTES {
        return Err(WebAuthnError::Malformed);
    }
    let rp_id_hash: [u8; 32] = bytes[..32]
        .try_into()
        .map_err(|_| WebAuthnError::Malformed)?;
    if &rp_id_hash != expected_rp_id_hash {
        return Err(WebAuthnError::RpIdHashMismatch);
    }
    let flags = bytes[32];
    if flags & 0x02 != 0 || flags & 0x20 != 0 || flags & 0x10 != 0 && flags & 0x08 == 0 {
        return Err(WebAuthnError::Malformed);
    }
    if flags & 0x01 == 0 {
        return Err(WebAuthnError::UserPresenceMissing);
    }
    if matches!(user_verification, UserVerification::Required) && flags & 0x04 == 0 {
        return Err(WebAuthnError::UserVerificationRequired);
    }
    if flags & 0x80 != 0 {
        return Err(WebAuthnError::UnsupportedExtensions);
    }
    let sign_count = u32::from_be_bytes(
        bytes[33..37]
            .try_into()
            .map_err(|_| WebAuthnError::Malformed)?,
    );
    let has_attested_data = flags & 0x40 != 0;
    if has_attested_data && !require_attested_data {
        return Err(WebAuthnError::Malformed);
    }
    if require_attested_data && !has_attested_data {
        return Err(WebAuthnError::Malformed);
    }
    if !has_attested_data {
        if bytes.len() != 37 {
            return Err(WebAuthnError::Malformed);
        }
        return Ok(ParsedAuthenticatorData {
            rp_id_hash,
            flags,
            sign_count,
            attested: None,
        });
    }
    if bytes.len() < 55 {
        return Err(WebAuthnError::Malformed);
    }
    let mut aaguid = [0_u8; 16];
    aaguid.copy_from_slice(&bytes[37..53]);
    let credential_id_len = u16::from_be_bytes(
        bytes[53..55]
            .try_into()
            .map_err(|_| WebAuthnError::Malformed)?,
    ) as usize;
    if credential_id_len == 0
        || credential_id_len > MAX_CREDENTIAL_ID_BYTES
        || bytes.len() < 55 + credential_id_len
    {
        return Err(WebAuthnError::Malformed);
    }
    let credential_id = bytes[55..55 + credential_id_len].to_vec();
    let cose = bytes[55 + credential_id_len..].to_vec();
    let _ = parse_cose_key(&cose)?;
    Ok(ParsedAuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        attested: Some(AttestedCredentialData {
            aaguid,
            credential_id,
            cose_key: cose,
        }),
    })
}

pub(crate) fn classify_counter(previous: u32, current: u32) -> SignCountStatus {
    match (previous, current) {
        (0, value) => SignCountStatus::Initial { value },
        (previous, current) if current > previous => {
            SignCountStatus::Increased { previous, current }
        }
        (previous, current) if current == previous => SignCountStatus::Unchanged { value: current },
        (previous, current) => SignCountStatus::Regression { previous, current },
    }
}
