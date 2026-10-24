use std::{fmt, marker::PhantomData};

use bytes::Bytes;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::encoding::encode_json;
use crate::{
    configuration::{TenantScope, validate_version},
    constants::{DEFAULT_CODEC_VERSION, RAW_BYTES_CODEC_VERSION},
    error::{ConfigurationError, EncodeError},
};

/// Pre-encoded byte item for callers that already own serialized bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteItem {
    bytes: Bytes,
}

impl WriteItem {
    #[must_use]
    pub fn bytes(bytes: impl Into<Bytes>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &Bytes {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }
}

impl fmt::Debug for WriteItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WriteItem")
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Scoped record wrapper for multi-tenant writers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedWrite<T> {
    scope: TenantScope,
    item: T,
}

impl<T> ScopedWrite<T> {
    #[must_use]
    pub const fn new(scope: TenantScope, item: T) -> Self {
        Self { scope, item }
    }

    #[must_use]
    pub const fn scope(&self) -> &TenantScope {
        &self.scope
    }

    #[must_use]
    pub const fn item(&self) -> &T {
        &self.item
    }

    #[must_use]
    pub fn into_parts(self) -> (TenantScope, T) {
        (self.scope, self.item)
    }
}

/// Versioned record codec contract.
pub trait RecordCodec<T>: Send + Sync + 'static {
    fn version(&self) -> &str;
    /// Encode without producing more than `max_bytes` of output. Stop encoding
    /// when the budget is exhausted and return `PayloadTooLarge`. Custom codecs
    /// can delegate to `SerdeJsonCodec::encode` for bounded JSON output.
    fn encode(&self, item: &T, max_bytes: usize) -> Result<Bytes, EncodeError>;

    fn decode(&self, bytes: &[u8]) -> Result<T, EncodeError>;
}

/// Default JSON record codec.
pub struct SerdeJsonCodec<T> {
    version: String,
    _marker: PhantomData<fn() -> T>,
}

impl<T> Default for SerdeJsonCodec<T> {
    fn default() -> Self {
        Self {
            version: DEFAULT_CODEC_VERSION.to_owned(),
            _marker: PhantomData,
        }
    }
}

impl<T> SerdeJsonCodec<T> {
    pub fn with_version(version: impl Into<String>) -> Result<Self, ConfigurationError> {
        let version = version.into();
        validate_version(&version)?;
        Ok(Self {
            version,
            _marker: PhantomData,
        })
    }
}

impl<T> RecordCodec<T> for SerdeJsonCodec<T>
where T: Serialize + DeserializeOwned + Send + Sync + 'static
{
    fn version(&self) -> &str {
        &self.version
    }

    fn encode(&self, item: &T, max_bytes: usize) -> Result<Bytes, EncodeError> {
        encode_json(item, max_bytes)
    }

    fn decode(&self, bytes: &[u8]) -> Result<T, EncodeError> {
        serde_json::from_slice(bytes).map_err(|_| EncodeError::DeserializationFailed)
    }
}

/// Pass-through codec for [`WriteItem`].
#[derive(Clone, Copy, Debug, Default)]
pub struct RawBytesCodec;

impl RecordCodec<WriteItem> for RawBytesCodec {
    fn version(&self) -> &str {
        RAW_BYTES_CODEC_VERSION
    }

    fn encode(&self, item: &WriteItem, max_bytes: usize) -> Result<Bytes, EncodeError> {
        if item.as_bytes().len() > max_bytes {
            return Err(EncodeError::PayloadTooLarge {
                size: item.as_bytes().len(),
                limit: max_bytes,
            });
        }
        Ok(item.as_bytes().clone())
    }

    fn decode(&self, bytes: &[u8]) -> Result<WriteItem, EncodeError> {
        Ok(WriteItem::bytes(Bytes::copy_from_slice(bytes)))
    }
}
