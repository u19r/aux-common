use std::collections::BTreeMap;

const DEFAULT_LOG_DESTINATION: &str = "stdout";
const DEFAULT_LOG_FILTER: &str = "warn";
const DEFAULT_SLOW_OPERATION_THRESHOLD_MS: u64 = 500;
const DEFAULT_METRICS_PATH: &str = "/internal/metrics";

const DEFAULT_TOP_LEVEL_FIELD_ALLOWLIST: &[&str] = &[
    crate::constants::FIELD_FEATURE,
    crate::constants::FIELD_OPERATION_NAME,
    crate::constants::FIELD_REQUEST_ID,
    crate::constants::FIELD_TRACE_ID,
    crate::constants::FIELD_SOURCE_IP,
    crate::constants::FIELD_TENANT_ID,
    crate::constants::FIELD_ORG_ID,
    crate::constants::FIELD_USER_ID,
    "method",
    "path",
    "host",
    "status_code",
    "duration_ms",
    "request_bytes",
    "response_bytes",
    crate::constants::FIELD_SPAN_ID,
    crate::constants::FIELD_TRACE_FLAGS,
];

const DEFAULT_SENSITIVE_FIELD_BLOCKLIST: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "set_cookie",
    "x-api-key",
    "api-key",
    "api_key",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "password",
    "secret",
    "token",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TracingConfig {
    pub log_level: Option<String>,
    pub log_destination: String,
    pub service_name: Option<String>,
    pub namespace: Option<String>,
    pub traces: Vec<TraceRuleConfig>,
    pub field_security: FieldSecurityPolicy,
    pub root_spans: RootSpanPolicy,
}

impl TracingConfig {
    #[must_use]
    pub fn new(
        log_destination: impl Into<String>,
        field_security: FieldSecurityPolicy,
        root_spans: RootSpanPolicy,
    ) -> Self {
        Self {
            log_level: Some(DEFAULT_LOG_FILTER.to_string()),
            log_destination: log_destination.into(),
            service_name: None,
            namespace: None,
            traces: Vec::new(),
            field_security,
            root_spans,
        }
    }

    #[must_use]
    pub fn with_default_security() -> Self {
        Self::new(
            DEFAULT_LOG_DESTINATION,
            FieldSecurityPolicy::default_allowlist_and_blocklist(),
            RootSpanPolicy::for_http_services(),
        )
    }

    #[must_use]
    pub fn with_log_level(mut self, log_level: Option<String>) -> Self {
        self.log_level = log_level;
        self
    }

    #[must_use]
    pub fn with_log_destination(mut self, log_destination: impl Into<String>) -> Self {
        self.log_destination = log_destination.into();
        self
    }

    #[must_use]
    pub fn with_service_name(mut self, service_name: Option<String>) -> Self {
        self.service_name = service_name;
        self
    }

    #[must_use]
    pub fn with_namespace(mut self, namespace: Option<String>) -> Self {
        self.namespace = namespace;
        self
    }

    #[must_use]
    pub fn with_trace_rules(mut self, traces: Vec<TraceRuleConfig>) -> Self {
        self.traces = traces;
        self
    }

    #[must_use]
    pub fn with_root_spans(mut self, root_spans: RootSpanPolicy) -> Self {
        self.root_spans = root_spans;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceRuleConfig {
    pub feature: String,
    pub log_level: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldSecurityPolicy {
    mode: FieldEmissionMode,
    top_level_allowlist: Vec<String>,
    sensitive_blocklist: Vec<String>,
}

impl FieldSecurityPolicy {
    #[must_use]
    pub fn new(top_level_allowlist: Vec<String>, sensitive_blocklist: Vec<String>) -> Self {
        Self {
            mode: FieldEmissionMode::RedactSensitive,
            top_level_allowlist,
            sensitive_blocklist,
        }
    }

    #[must_use]
    pub fn strict_allowlist(
        top_level_allowlist: Vec<String>,
        sensitive_blocklist: Vec<String>,
    ) -> Self {
        Self {
            mode: FieldEmissionMode::StrictAllowlist,
            top_level_allowlist,
            sensitive_blocklist,
        }
    }

    #[must_use]
    pub fn typed_only(top_level_allowlist: Vec<String>, sensitive_blocklist: Vec<String>) -> Self {
        Self {
            mode: FieldEmissionMode::TypedOnly,
            top_level_allowlist,
            sensitive_blocklist,
        }
    }

    #[must_use]
    pub fn default_allowlist_and_blocklist() -> Self {
        Self::strict_allowlist(
            DEFAULT_TOP_LEVEL_FIELD_ALLOWLIST
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
            DEFAULT_SENSITIVE_FIELD_BLOCKLIST
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
        )
    }

    #[must_use]
    pub fn with_extra_top_level_fields(mut self, fields: impl IntoIterator<Item = String>) -> Self {
        self.top_level_allowlist.extend(fields);
        self
    }

    #[must_use]
    pub fn top_level_allowlist(&self) -> &[String] {
        &self.top_level_allowlist
    }

    #[must_use]
    pub fn sensitive_blocklist(&self) -> &[String] {
        &self.sensitive_blocklist
    }

    #[must_use]
    pub fn mode(&self) -> FieldEmissionMode {
        self.mode
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FieldEmissionMode {
    #[default]
    RedactSensitive,
    StrictAllowlist,
    TypedOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootSpanPolicy {
    always_emit_span_names: Vec<String>,
    always_emit_feature_prefixes: Vec<String>,
}

impl RootSpanPolicy {
    #[must_use]
    pub fn new(
        always_emit_span_names: Vec<String>,
        always_emit_feature_prefixes: Vec<String>,
    ) -> Self {
        Self {
            always_emit_span_names,
            always_emit_feature_prefixes,
        }
    }

    #[must_use]
    pub fn for_http_services() -> Self {
        Self::new(vec!["http.request".to_string()], Vec::new())
    }

    #[must_use]
    pub fn always_emit_span_names(&self) -> &[String] {
        &self.always_emit_span_names
    }

    #[must_use]
    pub fn always_emit_feature_prefixes(&self) -> &[String] {
        &self.always_emit_feature_prefixes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlowOperationThresholds {
    pub default: u64,
    pub overrides: BTreeMap<String, u64>,
}

impl SlowOperationThresholds {
    #[must_use]
    pub fn new(default: u64, overrides: BTreeMap<String, u64>) -> Self {
        Self { default, overrides }
    }

    #[must_use]
    pub fn threshold_ms_for(&self, operation_name: &str) -> u64 {
        self.overrides
            .get(operation_name)
            .copied()
            .unwrap_or(self.default)
    }
}

impl Default for SlowOperationThresholds {
    fn default() -> Self {
        Self::new(DEFAULT_SLOW_OPERATION_THRESHOLD_MS, BTreeMap::new())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub bearer_token: Option<String>,
    pub metrics_path: String,
}

impl MetricsConfig {
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            bearer_token: None,
            metrics_path: DEFAULT_METRICS_PATH.to_string(),
        }
    }

    #[must_use]
    pub fn enabled(bearer_token: impl Into<String>) -> Self {
        Self {
            enabled: true,
            bearer_token: Some(bearer_token.into()),
            metrics_path: DEFAULT_METRICS_PATH.to_string(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ForwardedHeaderConfig {
    pub trust_forwarded_headers: bool,
}
