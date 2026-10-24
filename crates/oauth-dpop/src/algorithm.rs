use serde::{Deserialize, Serialize};

/// Algorithms supported by the shared native and WASM validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "docs", derive(utoipa::ToSchema))]
pub enum DpopAlgorithm {
    #[serde(rename = "ES256")]
    Es256,
}

impl DpopAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
        }
    }

    pub fn supported() -> &'static [Self] {
        &[Self::Es256]
    }
}
