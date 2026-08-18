use std::{collections::HashSet, fmt};

use serde::{Deserialize, Serialize};

use crate::{JwtDecodeError, JwtDecodeErrorKind, PolicyErrorKind, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    ES256,
    ES384,
    EdDSA,
}

impl SignatureAlgorithm {
    #[must_use]
    pub fn is_symmetric(self) -> bool {
        matches!(self, Self::HS256 | Self::HS384 | Self::HS512)
    }

    pub(crate) fn to_backend(self) -> jsonwebtoken::Algorithm {
        match self {
            Self::HS256 => jsonwebtoken::Algorithm::HS256,
            Self::HS384 => jsonwebtoken::Algorithm::HS384,
            Self::HS512 => jsonwebtoken::Algorithm::HS512,
            Self::RS256 => jsonwebtoken::Algorithm::RS256,
            Self::RS384 => jsonwebtoken::Algorithm::RS384,
            Self::RS512 => jsonwebtoken::Algorithm::RS512,
            Self::PS256 => jsonwebtoken::Algorithm::PS256,
            Self::PS384 => jsonwebtoken::Algorithm::PS384,
            Self::PS512 => jsonwebtoken::Algorithm::PS512,
            Self::ES256 => jsonwebtoken::Algorithm::ES256,
            Self::ES384 => jsonwebtoken::Algorithm::ES384,
            Self::EdDSA => jsonwebtoken::Algorithm::EdDSA,
        }
    }
}

impl TryFrom<jsonwebtoken::Algorithm> for SignatureAlgorithm {
    type Error = JwtDecodeError;

    fn try_from(algorithm: jsonwebtoken::Algorithm) -> Result<Self> {
        match algorithm {
            jsonwebtoken::Algorithm::HS256 => Ok(Self::HS256),
            jsonwebtoken::Algorithm::HS384 => Ok(Self::HS384),
            jsonwebtoken::Algorithm::HS512 => Ok(Self::HS512),
            jsonwebtoken::Algorithm::RS256 => Ok(Self::RS256),
            jsonwebtoken::Algorithm::RS384 => Ok(Self::RS384),
            jsonwebtoken::Algorithm::RS512 => Ok(Self::RS512),
            jsonwebtoken::Algorithm::PS256 => Ok(Self::PS256),
            jsonwebtoken::Algorithm::PS384 => Ok(Self::PS384),
            jsonwebtoken::Algorithm::PS512 => Ok(Self::PS512),
            jsonwebtoken::Algorithm::ES256 => Ok(Self::ES256),
            jsonwebtoken::Algorithm::ES384 => Ok(Self::ES384),
            jsonwebtoken::Algorithm::EdDSA => Ok(Self::EdDSA),
            _ => Err(JwtDecodeError::new(JwtDecodeErrorKind::UnsupportedHeader)),
        }
    }
}

impl TryFrom<jsonwebtoken::jwk::KeyAlgorithm> for SignatureAlgorithm {
    type Error = JwtDecodeError;

    fn try_from(algorithm: jsonwebtoken::jwk::KeyAlgorithm) -> Result<Self> {
        use jsonwebtoken::jwk::KeyAlgorithm;
        match algorithm {
            KeyAlgorithm::HS256 => Ok(Self::HS256),
            KeyAlgorithm::HS384 => Ok(Self::HS384),
            KeyAlgorithm::HS512 => Ok(Self::HS512),
            KeyAlgorithm::ES256 => Ok(Self::ES256),
            KeyAlgorithm::ES384 => Ok(Self::ES384),
            KeyAlgorithm::RS256 => Ok(Self::RS256),
            KeyAlgorithm::RS384 => Ok(Self::RS384),
            KeyAlgorithm::RS512 => Ok(Self::RS512),
            KeyAlgorithm::PS256 => Ok(Self::PS256),
            KeyAlgorithm::PS384 => Ok(Self::PS384),
            KeyAlgorithm::PS512 => Ok(Self::PS512),
            KeyAlgorithm::EdDSA => Ok(Self::EdDSA),
            _ => Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey)),
        }
    }
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone)]
pub struct AllowedAlgorithms {
    algorithms: HashSet<SignatureAlgorithm>,
    allow_symmetric: bool,
}

impl AllowedAlgorithms {
    #[must_use]
    pub fn asymmetric_2026() -> Self {
        Self::unchecked([
            SignatureAlgorithm::RS256,
            SignatureAlgorithm::PS256,
            SignatureAlgorithm::ES256,
            SignatureAlgorithm::EdDSA,
        ])
    }

    pub fn asymmetric<const N: usize>(algorithms: [SignatureAlgorithm; N]) -> Result<Self> {
        Self::new(algorithms, false)
    }

    pub fn symmetric<const N: usize>(algorithms: [SignatureAlgorithm; N]) -> Result<Self> {
        Self::new(algorithms, true)
    }

    pub(crate) fn contains(&self, algorithm: SignatureAlgorithm) -> bool {
        self.algorithms.contains(&algorithm)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = SignatureAlgorithm> + '_ {
        self.algorithms.iter().copied()
    }

    pub(crate) fn allow_symmetric(&self) -> bool {
        self.allow_symmetric
    }

    fn new<const N: usize>(
        algorithms: [SignatureAlgorithm; N],
        allow_symmetric: bool,
    ) -> Result<Self> {
        let algorithms = algorithms.into_iter().collect::<HashSet<_>>();
        if algorithms.is_empty() {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::PolicyInvalid(
                PolicyErrorKind::EmptyAlgorithmAllowlist,
            )));
        }
        Self::validate_families(&algorithms, allow_symmetric)?;
        Ok(Self {
            algorithms,
            allow_symmetric,
        })
    }

    fn unchecked<const N: usize>(algorithms: [SignatureAlgorithm; N]) -> Self {
        Self {
            algorithms: algorithms.into_iter().collect(),
            allow_symmetric: false,
        }
    }

    fn validate_families(
        algorithms: &HashSet<SignatureAlgorithm>,
        allow_symmetric: bool,
    ) -> Result<()> {
        let has_symmetric = algorithms.iter().any(|algorithm| algorithm.is_symmetric());
        let has_asymmetric = algorithms.iter().any(|algorithm| !algorithm.is_symmetric());
        if has_symmetric == allow_symmetric && !(has_symmetric && has_asymmetric) {
            return Ok(());
        }
        Err(JwtDecodeError::new(JwtDecodeErrorKind::PolicyInvalid(
            PolicyErrorKind::MixedAlgorithmFamilies,
        )))
    }
}

impl Default for AllowedAlgorithms {
    fn default() -> Self {
        Self::asymmetric_2026()
    }
}
