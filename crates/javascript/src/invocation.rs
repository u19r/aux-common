use serde::{Deserialize, Serialize};

use super::{JsError, constants::*};
#[cfg(feature = "runtime")]
use super::{
    bounded_writer::BoundedWriter,
    protocol::{GuestBinding, GuestJob},
};

/// A global alias to an argument, without duplicating its JSON value on the
/// wire.
pub struct JsBinding<'a> {
    pub name: &'a str,
    pub argument_index: usize,
}
/// Source loading order; aliases preserve the identities of the called
/// arguments.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsSourceOrder {
    BeforeBindings,
    AfterBindings,
}
/// Explicit data authority supplied by the caller. Arguments serialize to a
/// JSON array.
pub struct JsInvocationInput<'a, A> {
    pub source: &'a str,
    pub function: &'a str,
    pub arguments: A,
    pub bindings: &'a [JsBinding<'a>],
    pub source_order: JsSourceOrder,
}
/// Invocation whose source and names satisfy generic limits.
#[cfg(feature = "runtime")]
pub struct JsInvocation<'a, A> {
    input: JsInvocationInput<'a, A>,
}
/// Owned, bounded job prepared before execution. Its wire data is intentionally
/// private.
#[cfg(feature = "runtime")]
pub struct JsJob {
    pub(crate) wire: Vec<u8>,
}

#[cfg(feature = "runtime")]
impl<'a, A> JsInvocation<'a, A> {
    pub fn try_new(input: JsInvocationInput<'a, A>) -> Result<Self, JsError> {
        validate_source(input.source)?;
        validate_names(input.function, input.bindings.iter().map(|b| b.name))?;
        Ok(Self { input })
    }
}
#[cfg(feature = "runtime")]
impl<A: Serialize> JsInvocation<'_, A> {
    pub(crate) fn prepare(self) -> Result<JsJob, JsError> {
        let input = self.input;
        let bytes = BoundedWriter::serialize(
            &input.arguments,
            MAX_ARGUMENT_BYTES + MAX_ARGUMENTS + 1,
            JsError::InputTooLarge,
        )?;
        let arguments: Vec<Box<serde_json::value::RawValue>> =
            serde_json::from_slice(&bytes).map_err(|_| JsError::InvalidInvocation)?;
        validate_arguments(&arguments)?;
        let job = GuestJob {
            version: PROTOCOL_VERSION,
            source: input.source.to_owned(),
            function: input.function.to_owned(),
            arguments,
            bindings: input
                .bindings
                .iter()
                .map(|b| GuestBinding {
                    name: b.name.to_owned(),
                    argument_index: b.argument_index,
                })
                .collect(),
            source_order: input.source_order,
        };
        job.validate_binding_indices()?;
        Ok(JsJob {
            wire: BoundedWriter::serialize(&job, MAX_JOB_BYTES, JsError::InputTooLarge)?,
        })
    }
}
pub(crate) fn validate_source(source: &str) -> Result<(), JsError> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(JsError::SourceTooLarge);
    }
    Ok(())
}
pub(crate) fn validate_names<'a>(
    function: &str,
    bindings: impl Iterator<Item = &'a str>,
) -> Result<(), JsError> {
    if !is_identifier(function) {
        return Err(JsError::InvalidInvocation);
    }
    let mut names = Vec::new();
    for name in bindings {
        if names.len() == MAX_BINDINGS || !is_identifier(name) || names.contains(&name) {
            return Err(JsError::InvalidInvocation);
        }
        names.push(name);
    }
    Ok(())
}
fn is_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    !RESERVED_IDENTIFIERS.contains(&name)
        && name.len() <= MAX_IDENTIFIER_BYTES
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_' || b == b'$')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
}
pub(crate) fn validate_arguments(
    arguments: &[Box<serde_json::value::RawValue>],
) -> Result<(), JsError> {
    if arguments.len() > MAX_ARGUMENTS {
        return Err(JsError::InvalidInvocation);
    }
    if arguments.iter().map(|v| v.get().len()).sum::<usize>() > MAX_ARGUMENT_BYTES {
        return Err(JsError::InputTooLarge);
    }
    Ok(())
}
