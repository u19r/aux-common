use std::fmt;

/// Fixed failure categories. Never contains source, customer data or engine
/// diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsError {
    InvalidInvocation,
    SourceTooLarge,
    InputTooLarge,
    OutputTooLarge,
    ScriptFailed,
    InvalidOutput,
    ResourceLimit,
    Timeout,
    Cancelled,
    Unavailable,
}
impl fmt::Display for JsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for JsError {}
