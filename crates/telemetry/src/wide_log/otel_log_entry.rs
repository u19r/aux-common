use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{Value, json};
use tracing::Level;

use super::{
    field_security::SpanFields,
    span_state::{RootLogEntry, SpanEvent, SpanSnapshotChild},
};
use crate::constants::{FIELD_SPAN_ID, FIELD_TRACE_FLAGS, FIELD_TRACE_ID};

#[derive(Clone, Debug, Serialize)]
struct OtelLogEntry<'a> {
    time_unix_nano: u64,
    observed_time_unix_nano: u64,
    severity_text: &'static str,
    severity_number: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    span_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_flags: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<&'a serde_json::Map<String, Value>>,
    #[serde(skip_serializing_if = "SpanFields::is_empty")]
    attributes: SpanFields,
    body: LogBody,
}

#[derive(Clone, Debug, Serialize)]
struct LogBody {
    message: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    events: Vec<SpanEvent>,
    #[serde(skip_serializing_if = "SpanSnapshotChild::is_empty")]
    spans: SpanSnapshotChild,
}

pub(crate) fn build_resource_attributes(
    service_name: Option<&str>,
    namespace: Option<&str>,
) -> Option<serde_json::Map<String, Value>> {
    let mut attributes = serde_json::Map::new();
    if let Some(service_name) = service_name {
        attributes.insert("service.name".to_string(), json!(service_name));
    }
    if let Some(namespace) = namespace {
        attributes.insert("service.namespace".to_string(), json!(namespace));
    }
    if attributes.is_empty() {
        None
    } else {
        Some(attributes)
    }
}

pub(crate) fn encode_otel_log_entry(
    entry: RootLogEntry,
    resource_attributes: Option<&serde_json::Map<String, Value>>,
) -> Result<String, serde_json::Error> {
    let errors = collect_event_errors(&entry.events);
    let attributes = attributes_from_root(&entry, errors);
    let severity_text = entry.level.as_str();
    let severity_number = severity_number(entry.level);
    let trace_id = attributes.value_as_string(FIELD_TRACE_ID);
    let span_id = attributes.value_as_string(FIELD_SPAN_ID);
    let trace_flags = attributes.value_as_string(FIELD_TRACE_FLAGS);
    let message = entry.name.to_string();
    let RootLogEntry { events, spans, .. } = entry;
    let body = LogBody {
        message,
        events,
        spans,
    };
    let log_entry = OtelLogEntry {
        time_unix_nano: now_timestamp_nanos(),
        observed_time_unix_nano: now_timestamp_nanos(),
        severity_text,
        severity_number,
        trace_id,
        span_id,
        trace_flags,
        resource: resource_attributes,
        attributes,
        body,
    };

    serde_json::to_string(&log_entry)
}

fn now_timestamp_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
}

fn collect_event_errors(events: &[SpanEvent]) -> Vec<Value> {
    let mut errors = Vec::new();
    for event in events {
        if let Some(error_value) = event.fields.get("error") {
            errors.push(error_value.clone());
        }
    }
    errors
}

fn attributes_from_root(root: &RootLogEntry, errors: Vec<Value>) -> SpanFields {
    let mut attributes = SpanFields::default();
    for (key, value) in root.fields.iter() {
        if key == "errors" {
            continue;
        }
        attributes.insert_value(key.clone(), value.clone());
    }

    if !root.fields.contains_key("target") {
        attributes.insert_str("target", root.target);
    }
    if !root.fields.contains_key("name") {
        attributes.insert_str("name", root.name);
    }
    if !root.fields.contains_key("level") {
        attributes.insert_str("level", root.level.as_str());
    }
    if !root.fields.contains_key("duration_ms") {
        attributes.insert_value("duration_ms", Value::from(root.duration_ms));
    }

    if !errors.is_empty() {
        attributes.insert_value("errors", Value::Array(errors));
    }
    attributes
}

fn severity_number(level: Level) -> u8 {
    match level {
        Level::ERROR => 17,
        Level::WARN => 13,
        Level::INFO => 9,
        Level::DEBUG => 5,
        Level::TRACE => 1,
    }
}
