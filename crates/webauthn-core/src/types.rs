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
    expected_user_handle: Option<Vec<u8>>,
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
            expected_user_handle: None,
        })
    }

    /// Bind this ceremony to the expected user handle.
    ///
    /// WebAuthn L3 section 7.2 requires the relying party to verify that the
    /// authenticator's `userHandle` identifies the account being
    /// authenticated. Callers that bind credentials by `credential_id` alone
    /// leave this as `None`; callers that require the check provide the
    /// stored user id here and supply the authenticator's `userHandle` in
    /// [`AssertionInput::user_handle`].
    pub fn with_expected_user_handle(
        mut self,
        user_handle: &[u8],
    ) -> Result<Self, crate::WebAuthnError> {
        if user_handle.is_empty() || user_handle.len() > crate::constants::MAX_USER_HANDLE_BYTES {
            return Err(crate::WebAuthnError::InvalidPolicy);
        }
        self.expected_user_handle = Some(user_handle.to_vec());
        Ok(self)
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

    #[must_use]
    pub fn expected_user_handle(&self) -> Option<&[u8]> {
        self.expected_user_handle.as_deref()
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
    /// Authenticator-provided `userHandle` from
    /// `AuthenticatorAssertionResponse`, not from `clientDataJSON`.
    ///
    /// `None` means the authenticator reported no user handle. When the
    /// policy carries an expected handle, `None` or a mismatch fails closed;
    /// otherwise the provided value (if any) is returned in
    /// [`AssertionResult::user_handle`] for caller-side binding.
    pub user_handle: Option<&'a [u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignCountStatus {
    Initial {
        value: u32,
    },
    Increased {
        previous: u32,
        current: u32,
    },
    Unchanged {
        value: u32,
    },
    Regression {
        previous: u32,
        current: u32,
    },
    /// Authenticator reports a zero counter with no history to compare.
    ///
    /// WebAuthn Level 3 notes authenticators may not implement a counter and
    /// always return zero. A `ZeroCounter` result carries no replay signal:
    /// first use and unlimited zero-counter replays are indistinguishable,
    /// so callers must not use it for replay-detection-sensitive decisions.
    ZeroCounter,
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

use crate::constants::{MAX_CHALLENGE_BYTES, MIN_CHALLENGE_BYTES};
