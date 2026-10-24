use crate::error::ValidationError;

/// An arbitrary non-empty ordered key owned by a store operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct StoreKey(Vec<u8>);

impl StoreKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl TryFrom<Vec<u8>> for StoreKey {
    type Error = ValidationError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.is_empty() {
            return Err(ValidationError::Empty { field: "store key" });
        }
        Ok(Self(bytes))
    }
}

impl TryFrom<&[u8]> for StoreKey {
    type Error = ValidationError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(bytes.to_vec())
    }
}
