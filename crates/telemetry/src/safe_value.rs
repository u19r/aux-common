use std::{borrow::Cow, cell::RefCell, fmt};

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

    /// Records this explicitly safe string on an existing tracing span.
    ///
    /// `TypedOnly` policies drop ordinary string fields. This method gives
    /// callers a typed path for low-cardinality enum/newtype values without
    /// weakening that policy for arbitrary strings, errors, or debug output.
    pub fn record_on(&self, span: &tracing::Span, field: &'static str) {
        let recording = SafeRecording {
            field,
            value: self.0.clone(),
        };
        SAFE_RECORDINGS.with(|recordings| recordings.borrow_mut().push(recording));
        let _guard = SafeRecordingGuard;
        span.record(field, self.as_str());
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

struct SafeRecording {
    field: &'static str,
    value: String,
}

thread_local! {
    static SAFE_RECORDINGS: RefCell<Vec<SafeRecording>> = const { RefCell::new(Vec::new()) };
}

struct SafeRecordingGuard;

impl Drop for SafeRecordingGuard {
    fn drop(&mut self) {
        SAFE_RECORDINGS.with(|recordings| {
            recordings.borrow_mut().pop();
        });
    }
}

pub(crate) fn is_safe_recording(field: &str, value: &str) -> bool {
    SAFE_RECORDINGS.with(|recordings| {
        recordings
            .borrow()
            .last()
            .is_some_and(|recording| recording.field == field && recording.value == value)
    })
}
