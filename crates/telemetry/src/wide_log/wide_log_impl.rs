use std::sync::Arc;

use serde_json::Value;
use tracing::{
    Event, Level, Subscriber,
    span::{Attributes, Id, Record},
};
use tracing_subscriber::{
    layer::{Context, Layer},
    registry::LookupSpan,
};

use super::{
    field_security::SpanFields,
    otel_log_entry::{build_resource_attributes, encode_otel_log_entry},
    sink::{WideLogInitError, WideLogSink, build_log_sink},
    span_state::{
        RootLogEntry, SpanEvent, SpanSnapshot, SpanSnapshotChild, SpanSnapshotMinimal, SpanState,
    },
    trace_rule::TraceRule,
};
use crate::{
    config::{FieldEmissionMode, TracingConfig},
    constants::FIELD_FEATURE,
};

#[derive(Clone)]
pub struct WideLogLayer {
    sink: WideLogSink,
    resource_attributes: Option<serde_json::Map<String, Value>>,
    trace_rules: Vec<TraceRule>,
    top_level_field_allowlist: Arc<[String]>,
    sensitive_field_blocklist: Arc<[String]>,
    field_emission_mode: FieldEmissionMode,
    root_span_names: Vec<String>,
    root_feature_prefixes: Vec<String>,
}

impl WideLogLayer {
    pub fn new(tracing_cfg: &TracingConfig) -> Result<Self, WideLogInitError> {
        Self::new_with_sink(
            tracing_cfg,
            build_log_sink(tracing_cfg.log_destination.as_str())?,
        )
    }

    pub fn new_with_sink(
        tracing_cfg: &TracingConfig,
        sink: WideLogSink,
    ) -> Result<Self, WideLogInitError> {
        let service_name = tracing_cfg
            .service_name
            .clone()
            .or_else(|| read_env_trimmed("AUX_SERVICE_NAME"));
        let namespace = tracing_cfg
            .namespace
            .clone()
            .or_else(|| read_env_trimmed("POD_NAMESPACE"));
        let resource_attributes =
            build_resource_attributes(service_name.as_deref(), namespace.as_deref());
        let trace_rules = TraceRule::from_config(tracing_cfg);

        Ok(Self {
            sink,
            resource_attributes,
            trace_rules,
            top_level_field_allowlist: Arc::from(
                tracing_cfg.field_security.top_level_allowlist().to_vec(),
            ),
            sensitive_field_blocklist: Arc::from(
                tracing_cfg.field_security.sensitive_blocklist().to_vec(),
            ),
            field_emission_mode: tracing_cfg.field_security.mode(),
            root_span_names: tracing_cfg.root_spans.always_emit_span_names().to_vec(),
            root_feature_prefixes: tracing_cfg
                .root_spans
                .always_emit_feature_prefixes()
                .to_vec(),
        })
    }
}

impl<S> Layer<S> for WideLogLayer
where S: Subscriber + for<'span> LookupSpan<'span>
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let mut fields = self.new_span_fields();
            attrs.record(&mut fields);

            let metadata = span.metadata();
            let state = SpanState::new(
                metadata.target(),
                metadata.name(),
                *metadata.level(),
                fields,
            );
            span.extensions_mut().insert(state);
        }
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            if let Some(state) = span.extensions_mut().get_mut::<SpanState>() {
                values.record(&mut state.fields);
            } else {
                let mut fields = self.new_span_fields();
                values.record(&mut fields);
                let metadata = span.metadata();
                let state = SpanState::new(
                    metadata.target(),
                    metadata.name(),
                    *metadata.level(),
                    fields,
                );
                span.extensions_mut().insert(state);
            }
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let span = event
            .parent()
            .and_then(|id| ctx.span(id))
            .or_else(|| ctx.current_span().id().and_then(|id| ctx.span(id)));

        if let Some(span) = span {
            if let Some(state) = span.extensions_mut().get_mut::<SpanState>() {
                let metadata = event.metadata();
                let mut fields = self.new_span_fields();
                event.record(&mut fields);
                state.record_event(
                    metadata.name(),
                    metadata.target(),
                    *metadata.level(),
                    fields,
                );
            }
            return;
        }

        self.emit_spanless_event(event);
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };

        let mut extensions = span.extensions_mut();
        let Some(state) = extensions.remove::<SpanState>() else {
            return;
        };

        let snapshot = state.into_snapshot();
        if let Some(parent) = span.parent() {
            if let Some(parent_state) = parent.extensions_mut().get_mut::<SpanState>() {
                parent_state.merge_child(snapshot, self.top_level_field_allowlist.as_ref());
            }
            return;
        }

        self.emit_root(snapshot);
    }
}

impl WideLogLayer {
    fn emit_root(&self, mut root: SpanSnapshot) {
        let is_allowed_root = self
            .root_span_names
            .iter()
            .any(|name| root.name == name.as_str());
        let root_feature = root.fields.value_as_string(FIELD_FEATURE);
        let is_allowed_feature_root = root_feature.as_deref().is_some_and(|feature| {
            self.root_feature_prefixes
                .iter()
                .any(|prefix| feature.starts_with(prefix))
        });
        if !(is_allowed_root || is_allowed_feature_root) && root.level > Level::WARN {
            return;
        }

        let include_details = root.level <= Level::WARN || self.matches_trace_rules(&root);
        let spans = if !include_details {
            root.events.clear();
            SpanSnapshotChild::Minimal(Self::flatten_children_minimal(&root))
        } else {
            SpanSnapshotChild::Full(Self::flatten_children_full(&mut root))
        };

        let entry = RootLogEntry {
            target: root.target,
            name: root.name,
            level: root.level,
            duration_ms: root.duration_ms,
            fields: root.fields.clone(),
            events: root.events,
            spans,
        };

        self.emit_entry(entry);
    }

    fn emit_entry(&self, entry: RootLogEntry) {
        match encode_otel_log_entry(entry, self.resource_attributes.as_ref()) {
            Ok(line) => (self.sink)(line),
            Err(error) => {
                tracing::error!(target = "wide_log", %error, "failed to encode wide log line")
            }
        }
    }

    fn emit_spanless_event(&self, event: &Event<'_>) {
        let metadata = event.metadata();
        let mut fields = self.new_span_fields();
        event.record(&mut fields);
        fields.insert_str("type", "log");
        if *metadata.level() > Level::WARN
            && !self.matches_trace_rule_for_event(metadata.name(), *metadata.level(), &fields)
        {
            return;
        }

        let span_event = SpanEvent {
            level: *metadata.level(),
            name: metadata.name(),
            target: metadata.target().to_string(),
            fields,
        };
        let entry = RootLogEntry {
            target: metadata.target(),
            name: metadata.name(),
            level: *metadata.level(),
            duration_ms: 0.0,
            fields: self.new_span_fields(),
            events: vec![span_event],
            spans: SpanSnapshotChild::Minimal(Vec::new()),
        };

        self.emit_entry(entry);
    }

    fn flatten_children_minimal(root: &SpanSnapshot) -> Vec<SpanSnapshotMinimal> {
        let mut result = Vec::new();
        for child in root.children.iter() {
            result.extend(child.flatten_minimal());
        }
        result
    }

    fn flatten_children_full(root: &mut SpanSnapshot) -> Vec<SpanSnapshot> {
        let mut result = Vec::new();
        for child in &mut root.children {
            child.parent_target = Some(root.target);
            child.depth = 1;
            result.extend(child.flatten());
        }
        root.children.clear();
        result
    }

    fn matches_trace_rules(&self, root: &SpanSnapshot) -> bool {
        if self.trace_rules.is_empty() {
            return false;
        }
        self.trace_rules
            .iter()
            .any(|rule| root.matches_trace_rule(rule))
    }

    fn matches_trace_rule_for_event(
        &self,
        name: &'static str,
        level: Level,
        fields: &SpanFields,
    ) -> bool {
        if self.trace_rules.is_empty() {
            return false;
        }
        self.trace_rules
            .iter()
            .any(|rule| rule.matches_event(name, level, fields))
    }

    fn new_span_fields(&self) -> SpanFields {
        SpanFields::new(
            self.field_emission_mode,
            self.top_level_field_allowlist.clone(),
            self.sensitive_field_blocklist.clone(),
        )
    }
}

fn read_env_trimmed(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}
