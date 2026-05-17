use std::collections::BTreeMap;

use crate::{
    FieldEmissionMode, FieldSecurityPolicy, RootSpanPolicy, SlowOperationThresholds, TracingConfig,
};

#[test]
fn tracing_config_given_default_security_opt_in_then_contains_redaction_blocklist() {
    let config = TracingConfig::with_default_security();

    assert!(
        config
            .field_security
            .sensitive_blocklist()
            .iter()
            .any(|field| field == "authorization")
    );
    assert!(
        config
            .field_security
            .top_level_allowlist()
            .iter()
            .any(|field| field == crate::FIELD_TRACE_ID)
    );
}

#[test]
fn tracing_config_given_custom_policy_then_does_not_inject_defaults() {
    let policy =
        FieldSecurityPolicy::new(vec!["safe_field".to_string()], vec!["secret".to_string()]);
    let config = TracingConfig::new("stdout", policy, RootSpanPolicy::for_http_services());

    assert_eq!(
        config.field_security.top_level_allowlist(),
        &["safe_field".to_string()]
    );
    assert_eq!(
        config.field_security.sensitive_blocklist(),
        &["secret".to_string()]
    );
    assert_eq!(
        config.field_security.mode(),
        FieldEmissionMode::RedactSensitive
    );
}

#[test]
fn field_security_policy_when_strict_allowlist_then_records_mode() {
    let policy = FieldSecurityPolicy::strict_allowlist(
        vec!["safe_field".to_string()],
        vec!["secret".to_string()],
    );

    assert_eq!(policy.mode(), FieldEmissionMode::StrictAllowlist);
}

#[test]
fn slow_thresholds_given_operation_override_then_uses_override() {
    let thresholds =
        SlowOperationThresholds::new(500, BTreeMap::from([("GET /health".to_string(), 20)]));

    assert_eq!(thresholds.threshold_ms_for("GET /health"), 20);
    assert_eq!(thresholds.threshold_ms_for("GET /other"), 500);
}
