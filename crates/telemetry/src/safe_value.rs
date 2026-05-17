use std::{borrow::Cow, fmt};

use serde::Serialize;

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct SafeTelemetryValue(String);

impl SafeTelemetryValue {
    pub fn from_display(value: &impl TelemetryDisplay) -> Self {
        Self(value.telemetry_display().into_owned())
    }

    pub fn from_static(value: &'static str) -> Self {
        Self(value.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for SafeTelemetryValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub trait TelemetryDisplay {
    fn telemetry_display(&self) -> Cow<'_, str>;
}

impl TelemetryDisplay for SafeTelemetryValue {
    fn telemetry_display(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.as_str())
    }
}
