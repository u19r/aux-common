#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserVerification {
    Required,
    Preferred,
    Discouraged,
}

/// Policy for `crossOrigin` client-data entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossOriginPolicy {
    /// Reject cross-origin ceremonies and require no `topOrigin` member.
    Disallowed,
    /// Allow only the normalized related origins supplied by the caller.
    AllowedOrigins(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpPolicy {
    expected_challenge_b64: String,
    expected_origin: String,
    expected_rp_id_hash: [u8; 32],
    user_verification: UserVerification,
    cross_origin_policy: CrossOriginPolicy,
}

impl RpPolicy {
    /// Construct a policy after validating the challenge and origin syntax.
    pub fn try_new(
        expected_challenge_b64: impl Into<String>,
        expected_origin: impl Into<String>,
        expected_rp_id_hash: [u8; 32],
        user_verification: UserVerification,
        cross_origin_policy: CrossOriginPolicy,
    ) -> Result<Self, crate::WebAuthnError> {
        let expected_challenge_b64 = expected_challenge_b64.into();
        const MAX_CHALLENGE_B64_BYTES: usize = (MAX_CHALLENGE_BYTES * 8).div_ceil(6);
        if expected_challenge_b64.len() > MAX_CHALLENGE_B64_BYTES {
            return Err(crate::WebAuthnError::InvalidPolicy);
        }
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(expected_challenge_b64.as_bytes())
            .map_err(|_| crate::WebAuthnError::InvalidPolicy)?;
        if challenge.len() < MIN_CHALLENGE_BYTES
            || challenge.len() > MAX_CHALLENGE_BYTES
            || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge)
                != expected_challenge_b64
        {
            return Err(crate::WebAuthnError::InvalidPolicy);
        }
        let expected_origin = expected_origin.into();
        if !crate::client_data::is_valid_origin(&expected_origin) {
            return Err(crate::WebAuthnError::InvalidPolicy);
        }
        let cross_origin_policy = match cross_origin_policy {
            CrossOriginPolicy::Disallowed => CrossOriginPolicy::Disallowed,
            CrossOriginPolicy::AllowedOrigins(origins) if origins.is_empty() => {
                return Err(crate::WebAuthnError::InvalidPolicy);
            }
            CrossOriginPolicy::AllowedOrigins(origins) => {
                let mut normalized = origins
                    .into_iter()
                    .map(|origin| {
                        crate::client_data::normalize_origin(&origin)
                            .ok_or(crate::WebAuthnError::InvalidPolicy)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                normalized.sort();
                normalized.dedup();
                CrossOriginPolicy::AllowedOrigins(normalized)
            }
        };
        Ok(Self {
            expected_challenge_b64,
            expected_origin,
            expected_rp_id_hash,
            user_verification,
            cross_origin_policy,
        })
    }

    #[must_use]
    pub fn expected_challenge_b64(&self) -> &str {
        &self.expected_challenge_b64
    }

    #[must_use]
    pub fn expected_origin(&self) -> &str {
        &self.expected_origin
    }

    #[must_use]
    pub const fn expected_rp_id_hash(&self) -> &[u8; 32] {
        &self.expected_rp_id_hash
    }

    #[must_use]
    pub const fn user_verification(&self) -> UserVerification {
        self.user_verification
    }

    #[must_use]
    pub fn cross_origin_policy(&self) -> &CrossOriginPolicy {
        &self.cross_origin_policy
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssertionInput<'a> {
    pub client_data_json: &'a [u8],
    pub authenticator_data: &'a [u8],
    pub signature: &'a [u8],
    pub credential_public_key_cose: &'a [u8],
    pub credential_id: &'a [u8],
    pub previous_sign_count: u32,
    pub policy: &'a RpPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignCountStatus {
    Initial { value: u32 },
    Increased { previous: u32, current: u32 },
    Unchanged { value: u32 },
    Regression { previous: u32, current: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionResult {
    pub credential_id: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
    pub user_verified: bool,
    pub sign_count: u32,
    pub sign_count_status: SignCountStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationInput<'a> {
    pub client_data_json: &'a [u8],
    pub attestation_object: &'a [u8],
    pub policy: &'a RpPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationResult {
    pub credential_id: Vec<u8>,
    pub public_key_cose: Vec<u8>,
    pub public_key: CosePublicKey,
    pub aaguid: [u8; 16],
    pub sign_count: u32,
    pub user_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosePublicKey {
    pub algorithm: i64,
    pub curve: i64,
    pub x: [u8; 32],
    pub y: [u8; 32],
}
use base64::Engine as _;

const MIN_CHALLENGE_BYTES: usize = 16;
const MAX_CHALLENGE_BYTES: usize = 128;
