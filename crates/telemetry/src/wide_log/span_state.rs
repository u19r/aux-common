use std::time::Instant;

use serde::Serialize;
use tracing::Level;

use super::{field_security::SpanFields, trace_rule::TraceRule};
use crate::constants::FIELD_FEATURE;

#[derive(Debug)]
pub(crate) struct SpanState {
    target: &'static str,
    name: &'static str,
    level: Level,
    started_at: Instant,
    pub(crate) fields: SpanFields,
    events: Vec<SpanEvent>,
    pub(crate) children: Vec<SpanSnapshot>,
}

impl SpanState {
    pub(crate) fn new(
        target: &'static str,
        name: &'static str,
        level: Level,
        fields: SpanFields,
    ) -> Self {
        Self {
            target,
            name,
            level,
            started_at: Instant::now(),
            fields,
            events: Vec::new(),
            children: Vec::new(),
        }
    }

    pub(crate) fn record_event(
        &mut self,
        name: &'static str,
        target: &'static str,
        level: Level,
        mut fields: SpanFields,
    ) {
        fields.insert_str("type", "log");
        self.level = self.level.min(level);
        self.events.push(SpanEvent {
            level,
            name,
            target: target.to_string(),
            fields,
        });
    }

    pub(crate) fn merge_child(&mut self, child: SpanSnapshot, allowlist: &[String]) {
        self.level = self.level.min(child.level);
        self.fields.extend_allowlist(&child.fields, allowlist);
        self.events.extend(child.events.iter().cloned());
        self.children.push(child);
    }

    pub(crate) fn into_snapshot(self) -> SpanSnapshot {
        let elapsed_ms: f64 = self.started_at.elapsed().as_micros() as f64 / 1000.0;

        SpanSnapshot {
            target: self.target,
            name: self.name,
            level: self.level,
            duration_ms: elapsed_ms,
            fields: self.fields,
            events: self.events,
            children: self.children,
            parent_target: None,
            depth: 0,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RootLogEntry {
    pub(crate) target: &'static str,
    pub(crate) name: &'static str,
    #[serde(serialize_with = "serialize_level")]
    pub(crate) level: Level,
    pub(crate) duration_ms: f64,
    #[serde(flatten, skip_serializing_if = "SpanFields::is_empty")]
    pub(crate) fields: SpanFields,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) events: Vec<SpanEvent>,
    #[serde(skip_serializing_if = "SpanSnapshotChild::is_empty")]
    pub(crate) spans: SpanSnapshotChild,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum SpanSnapshotChild {
    Full(Vec<SpanSnapshot>),
    Minimal(Vec<SpanSnapshotMinimal>),
}

impl SpanSnapshotChild {
    pub(crate) fn is_empty(&self) -> bool {
        match self {
            SpanSnapshotChild::Full(items) => items.is_empty(),
            SpanSnapshotChild::Minimal(items) => items.is_empty(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SpanSnapshot {
    pub(crate) target: &'static str,
    pub(crate) name: &'static str,
    #[serde(serialize_with = "serialize_level")]
    pub(crate) level: Level,
    pub(crate) duration_ms: f64,
    #[serde(flatten, skip_serializing_if = "SpanFields::is_empty")]
    pub(crate) fields: SpanFields,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) events: Vec<SpanEvent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) children: Vec<SpanSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) parent_target: Option<&'static str>,
    #[serde(default)]
    pub(crate) depth: usize,
}

impl SpanSnapshot {
    pub(crate) fn flatten_minimal(&self) -> Vec<SpanSnapshotMinimal> {
        let mut result = Vec::new();
        result.push(self.clone().into());
        for child in self.children.iter() {
            result.extend(child.flatten_minimal());
        }
        result
    }

    pub(crate) fn flatten(&mut self) -> Vec<SpanSnapshot> {
        let mut result = Vec::new();
        let mut snapshot = self.clone();
        snapshot.children.clear();
        result.push(snapshot);
        for child in &mut self.children {
            child.parent_target = Some(self.target);
            child.depth = self.depth + 1;
            result.extend(child.flatten());
        }
        self.children.clear();
        result
    }

    pub(crate) fn matches_trace_rule(&self, rule: &TraceRule) -> bool {
        if self.level > rule.level {
            return false;
        }
        if self.name.starts_with(rule.feature.as_str()) {
            return true;
        }
        if self
            .fields
            .value_as_string(FIELD_FEATURE)
            .is_some_and(|value| value.starts_with(rule.feature.as_str()))
        {
            return true;
        }
        if self
            .events
            .iter()
            .any(|event| rule.matches_event(event.name, event.level, &event.fields))
        {
            return true;
        }
        self.children
            .iter()
            .any(|child| child.matches_trace_rule(rule))
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SpanSnapshotMinimal {
    #[serde(serialize_with = "serialize_level")]
    level: Level,
    duration_ms: f64,
    #[serde(flatten, skip_serializing_if = "SpanFields::is_empty")]
    fields: SpanFields,
    name: &'static str,
}

impl From<SpanSnapshot> for SpanSnapshotMinimal {
    fn from(snapshot: SpanSnapshot) -> Self {
        Self {
            level: snapshot.level,
            duration_ms: snapshot.duration_ms,
            fields: snapshot.fields,
            name: snapshot.name,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SpanEvent {
    #[serde(serialize_with = "serialize_level")]
    pub(crate) level: Level,
    #[serde(skip_serializing)]
    pub(crate) name: &'static str,
    pub(crate) target: String,
    #[serde(flatten, skip_serializing_if = "SpanFields::is_empty")]
    pub(crate) fields: SpanFields,
}

fn serialize_level<S>(level: &Level, serializer: S) -> Result<S::Ok, S::Error>
where S: serde::Serializer {
    serializer.serialize_str(level.as_str())
}
