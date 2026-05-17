use std::borrow::Cow;

use crate::{SafeTelemetryValue, TelemetryDisplay};

struct OperationName(&'static str);

impl TelemetryDisplay for OperationName {
    fn telemetry_display(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.0)
    }
}

#[test]
fn safe_telemetry_value_given_service_newtype_then_uses_trait_output() {
    let value = SafeTelemetryValue::from_display(&OperationName("users.lookup"));

    assert_eq!(value.as_str(), "users.lookup");
    assert_eq!(value.to_string(), "users.lookup");
}

#[test]
fn safe_telemetry_value_given_static_value_then_can_be_reused_as_display_value() {
    let value = SafeTelemetryValue::from_static("http.request");
    let round_trip = SafeTelemetryValue::from_display(&value);

    assert_eq!(round_trip.into_string(), "http.request");
}
