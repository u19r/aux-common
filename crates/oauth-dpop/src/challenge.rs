use crate::DpopAlgorithm;

/// Safe challenge classes shared by resource transports. No arbitrary customer
/// text is rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceChallenge {
    MissingCredentials,
    InvalidToken,
    InvalidDpopProof,
    InsufficientScope,
}

impl ResourceChallenge {
    pub fn render(self) -> String {
        let algorithms = DpopAlgorithm::supported()
            .iter()
            .map(|algorithm| algorithm.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        match self {
            Self::MissingCredentials => format!("DPoP algs=\"{algorithms}\", Bearer"),
            Self::InvalidToken => format!(
                "DPoP algs=\"{algorithms}\", error=\"invalid_token\", Bearer \
                 error=\"invalid_token\""
            ),
            Self::InsufficientScope => format!(
                "DPoP algs=\"{algorithms}\", error=\"insufficient_scope\", Bearer \
                 error=\"insufficient_scope\""
            ),
            Self::InvalidDpopProof => {
                format!("DPoP algs=\"{algorithms}\", error=\"invalid_dpop_proof\", Bearer")
            }
        }
    }
}
