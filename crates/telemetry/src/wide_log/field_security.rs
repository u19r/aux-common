use std::{fmt, sync::Arc};

use serde::{
    Serialize,
    ser::{SerializeMap, Serializer},
};
use serde_json::Value;
use tracing::field::{Field, Visit};

use crate::{config::FieldEmissionMode, safe_value::is_safe_recording};

const DEFAULT_FIELD_CAPACITY: usize = 12;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SpanFields {
    mode: FieldEmissionMode,
    field_allowlist: Arc<[String]>,
    sensitive_field_blocklist: Arc<[String]>,
    values: Vec<(String, Value)>,
}

impl SpanFields {
    pub(crate) fn new(
        mode: FieldEmissionMode,
        field_allowlist: impl Into<Arc<[String]>>,
        sensitive_field_blocklist: impl Into<Arc<[String]>>,
    ) -> Self {
        Self {
            mode,
            field_allowlist: field_allowlist.into(),
            sensitive_field_blocklist: sensitive_field_blocklist.into(),
            values: Vec::with_capacity(DEFAULT_FIELD_CAPACITY),
        }
    }

    fn normalize_value_for_key(
        &self,
        key: &str,
        value: Value,
        safety: FieldValueSafety,
    ) -> Option<Value> {
        if !self.should_emit_key(key) {
            return None;
        }
        if self.mode == FieldEmissionMode::TypedOnly && safety == FieldValueSafety::FreeText {
            return None;
        }
        if self.is_sensitive_key(key) {
            return Some(Value::String("[REDACTED]".to_string()));
        }
        Some(value)
    }

    fn should_emit_key(&self, key: &str) -> bool {
        match self.mode {
            FieldEmissionMode::RedactSensitive => true,
            FieldEmissionMode::StrictAllowlist | FieldEmissionMode::TypedOnly => {
                self.field_allowlist.iter().any(|allowed| allowed == key)
            }
        }
    }

    fn is_sensitive_key(&self, key: &str) -> bool {
        self.sensitive_field_blocklist
            .iter()
            .any(|suffix| has_sensitive_suffix(key, suffix))
    }

    pub(crate) fn insert_str(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let Some(new_value) = self.normalize_value_for_key(
            &key,
            Value::String(value.into()),
            FieldValueSafety::FreeText,
        ) else {
            return;
        };

        self.insert_normalized_value(key, new_value);
    }

    fn insert_safe_str(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let Some(new_value) = self.normalize_value_for_key(
            &key,
            Value::String(value.into()),
            FieldValueSafety::Structured,
        ) else {
            return;
        };

        self.insert_normalized_value(key, new_value);
    }

    pub(crate) fn insert_value(&mut self, key: impl Into<String>, value: Value) {
        let key = key.into();
        let Some(value) = self.normalize_value_for_key(&key, value, FieldValueSafety::Structured)
        else {
            return;
        };

        self.insert_normalized_value(key, value);
    }

    pub(crate) fn extend_allowlist(&mut self, other: &SpanFields, allowlist: &[String]) {
        if allowlist.is_empty() {
            return;
        }

        let filtered = other.select_keys(allowlist);
        if filtered.is_empty() {
            return;
        }

        self.extend(&filtered);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub(crate) fn contains_key(&self, key: &str) -> bool {
        self.values
            .iter()
            .any(|(existing_key, _)| existing_key == key)
    }

    pub(crate) fn get(&self, key: &str) -> Option<&Value> {
        self.values
            .iter()
            .find_map(|(existing_key, value)| (existing_key == key).then_some(value))
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&String, &Value)> {
        self.values.iter().map(|(key, value)| (key, value))
    }

    pub(crate) fn value_as_string(&self, key: &str) -> Option<String> {
        self.get(key).and_then(value_to_string)
    }

    fn insert_normalized_value(&mut self, key: String, value: Value) {
        if let Some((_, existing)) = self
            .values
            .iter_mut()
            .find(|(existing_key, _)| existing_key == &key)
        {
            if existing == &value {
                return;
            }

            match existing {
                Value::Array(arr) => {
                    if arr.contains(&value) {
                        return;
                    }
                    arr.push(value);
                }
                other => {
                    *other = Value::Array(vec![other.clone(), value]);
                }
            }
            return;
        }
        self.values.push((key, value));
    }

    fn extend_array_unique(arr: &mut Vec<Value>, incoming: &Value) {
        match incoming {
            Value::Array(incoming_arr) => {
                for item in incoming_arr {
                    if !arr.contains(item) {
                        arr.push(item.clone());
                    }
                }
            }
            item if !arr.contains(item) => arr.push(item.clone()),
            _ => {}
        }
    }

    fn extend(&mut self, other: &SpanFields) {
        for (key, value) in &other.values {
            match self
                .values
                .iter_mut()
                .find(|(existing_key, _)| existing_key == key)
                .map(|(_, value)| value)
            {
                Some(Value::Array(existing)) => {
                    Self::extend_array_unique(existing, value);
                }
                Some(existing) if existing != value => {
                    let mut new_arr = match existing.clone() {
                        Value::Array(arr) => arr,
                        other => vec![other],
                    };
                    Self::extend_array_unique(&mut new_arr, value);
                    *existing = Value::Array(new_arr);
                }
                None => {
                    self.values.push((key.clone(), value.clone()));
                }
                _ => {}
            }
        }
    }

    fn select_keys(&self, keys: &[String]) -> SpanFields {
        let mut selected = SpanFields::new(
            self.mode,
            self.field_allowlist.clone(),
            self.sensitive_field_blocklist.clone(),
        );
        for key in keys {
            if let Some(value) = self.get(key) {
                selected.insert_value(key.clone(), value.clone());
            }
        }
        selected
    }
}

impl Serialize for SpanFields {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let mut map = serializer.serialize_map(Some(self.values.len()))?;
        for (key, value) in &self.values {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

pub(crate) fn has_sensitive_suffix(key: &str, suffix: &str) -> bool {
    let key = key.as_bytes();
    let suffix = suffix.as_bytes();
    if key.len() < suffix.len() {
        return false;
    }

    let suffix_start = key.len() - suffix.len();
    let suffix_matches = key[suffix_start..]
        .iter()
        .zip(suffix.iter())
        .all(|(left, right)| left.eq_ignore_ascii_case(right));
    if !suffix_matches {
        return false;
    }

    suffix_start == 0 || matches!(key[suffix_start - 1], b'.' | b'_' | b'-')
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FieldValueSafety {
    Structured,
    FreeText,
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Array(values) => values.first().and_then(value_to_string),
        _ => None,
    }
}

impl Visit for SpanFields {
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert_value(field.name().to_string(), Value::Bool(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert_value(field.name().to_string(), Value::Number(value.into()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        match serde_json::Number::from_u128(u128::from(value)) {
            Some(number) => self.insert_value(field.name().to_string(), Value::Number(number)),
            None => self.insert_str(field.name(), value.to_string()),
        }
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        match serde_json::Number::from_f64(value) {
            Some(number) => self.insert_value(field.name().to_string(), Value::Number(number)),
            None => self.insert_str(field.name(), value.to_string()),
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if is_safe_recording(field.name(), value) {
            self.insert_safe_str(field.name(), value);
            return;
        }
        self.insert_str(field.name(), value);
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.insert_str(field.name(), value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.insert_str(field.name(), format!("{value:?}"));
    }
}
