//! Versioned producer/host contract. This module supplies no execution
//! authority.
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::{
    JsError, JsSourceOrder,
    constants::PROTOCOL_VERSION,
    invocation::{validate_arguments, validate_names, validate_source},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestBinding {
    pub name: String,
    pub argument_index: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestJob {
    pub version: u16,
    pub source: String,
    pub function: String,
    pub arguments: Vec<Box<RawValue>>,
    pub bindings: Vec<GuestBinding>,
    pub source_order: JsSourceOrder,
}
impl GuestJob {
    /// Revalidate a deserialized document at the private guest boundary.
    pub fn validate(&self) -> Result<(), JsError> {
        if self.version != PROTOCOL_VERSION {
            return Err(JsError::InvalidInvocation);
        }
        validate_source(&self.source)?;
        validate_names(
            &self.function,
            self.bindings.iter().map(|b| b.name.as_str()),
        )?;
        validate_arguments(&self.arguments)?;
        self.validate_binding_indices()?;
        Ok(())
    }
    pub(crate) fn validate_binding_indices(&self) -> Result<(), JsError> {
        if self
            .bindings
            .iter()
            .any(|b| b.argument_index >= self.arguments.len())
        {
            return Err(JsError::InvalidInvocation);
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestReply {
    pub version: u16,
    pub result: GuestResult,
}
impl GuestReply {
    /// Encode one reply without growing the producer's wire buffer beyond its
    /// ceiling.
    pub fn encode(&self) -> Result<Vec<u8>, JsError> {
        super::bounded_writer::BoundedWriter::serialize(
            self,
            super::constants::MAX_REPLY_BYTES,
            JsError::OutputTooLarge,
        )
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestResult {
    Success { value: Box<RawValue> },
    Failure { code: GuestFailure },
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestFailure {
    InvalidJob,
    ScriptFailed,
    InvalidOutput,
    OutputTooLarge,
}

// Deserialize directly from the document: Serde's internally tagged enum
// buffering cannot preserve RawValue. Keep the exact same wire schema and
// reject mixed fields.
impl<'de> Deserialize<'de> for GuestResult {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ReplyFields {
            #[serde(rename = "type")]
            kind: ReplyKind,
            #[serde(default, deserialize_with = "present_value")]
            value: Option<Box<RawValue>>,
            #[serde(default, deserialize_with = "present_code")]
            code: Option<GuestFailure>,
        }
        let fields = ReplyFields::deserialize(deserializer)?;
        match (fields.kind, fields.value, fields.code) {
            (ReplyKind::Success, Some(value), None) => Ok(Self::Success { value }),
            (ReplyKind::Failure, None, Some(code)) => Ok(Self::Failure { code }),
            _ => Err(serde::de::Error::custom("invalid_reply")),
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReplyKind {
    Success,
    Failure,
}
fn present_value<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Box<RawValue>>, D::Error> {
    Box::<RawValue>::deserialize(deserializer).map(Some)
}

fn present_code<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<GuestFailure>, D::Error> {
    GuestFailure::deserialize(deserializer).map(Some)
}
