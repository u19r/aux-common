use std::fmt;

use sha2::{Digest as _, Sha256};

use crate::SigningError;

/// Payload input for header signing and presigning. Payload bytes never appear
/// in Debug output.
#[derive(Clone)]
#[non_exhaustive]
pub enum SignableBody<'a> {
    Bytes(&'a [u8]),
    UnsignedPayload,
    Precomputed(String),
    StreamingUnsignedPayloadTrailer,
    StreamingSignedPayloadTrailer,
}

impl SignableBody<'_> {
    #[must_use]
    pub const fn empty() -> SignableBody<'static> {
        SignableBody::Bytes(&[])
    }

    pub(crate) fn payload_hash(&self) -> Result<String, SigningError> {
        match self {
            Self::Bytes(bytes) => Ok(data_encoding::HEXLOWER.encode(&Sha256::digest(bytes))),
            Self::UnsignedPayload => Ok("UNSIGNED-PAYLOAD".to_owned()),
            Self::StreamingUnsignedPayloadTrailer => {
                Ok("STREAMING-UNSIGNED-PAYLOAD-TRAILER".to_owned())
            }
            Self::StreamingSignedPayloadTrailer => {
                Ok("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER".to_owned())
            }
            Self::Precomputed(hash) => {
                if hash.len() != 64
                    || !hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(SigningError::PrepareRequest);
                }
                Ok(hash.clone())
            }
        }
    }
}

impl fmt::Debug for SignableBody<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Bytes(_) => "Bytes([REDACTED])",
            Self::UnsignedPayload => "UnsignedPayload",
            Self::Precomputed(_) => "Precomputed([REDACTED])",
            Self::StreamingUnsignedPayloadTrailer => "StreamingUnsignedPayloadTrailer",
            Self::StreamingSignedPayloadTrailer => "StreamingSignedPayloadTrailer",
        };
        formatter.write_str(name)
    }
}
