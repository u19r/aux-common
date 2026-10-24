use javascript::{constants::MAX_RESULT_BYTES, protocol::GuestFailure};
use rquickjs::{Ctx, Value};
use serde_json::value::RawValue;

pub(super) fn encode_result<'js>(
    ctx: &Ctx<'js>,
    value: Value<'js>,
) -> Result<Box<RawValue>, GuestFailure> {
    let rendered = ctx
        .json_stringify(value)
        .map_err(|_| GuestFailure::InvalidOutput)?
        .ok_or(GuestFailure::InvalidOutput)?;
    let rendered = rendered
        .to_cstring()
        .map_err(|_| GuestFailure::InvalidOutput)?;
    if rendered.len() > MAX_RESULT_BYTES {
        return Err(GuestFailure::OutputTooLarge);
    }
    RawValue::from_string(rendered.as_str().to_owned()).map_err(|_| GuestFailure::InvalidOutput)
}
