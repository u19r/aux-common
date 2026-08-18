use super::{
    MAX_PUBLIC_SAFE_INTEGER, RoleActionLimit, RoleLimitCountScope, RoleLimitCountSource,
    RoleLimitEnforcementMode, RoleLimitThresholds,
};

fn valid_limit() -> RoleActionLimit {
    RoleActionLimit::try_new(
        "projects",
        5,
        "projects",
        RoleLimitCountScope::Organization,
        RoleLimitCountSource::Capacity,
        RoleLimitEnforcementMode::Hard,
        120,
        RoleLimitThresholds::try_new(Some(80), Some(90)).expect("valid thresholds"),
    )
    .expect("valid role-action limit")
}

#[test]
fn given_arbitrary_product_key_and_unit_when_constructed_then_typed_limit_is_retained() {
    let limit = RoleActionLimit::try_new(
        "widgets-v2",
        0,
        "widget-hours",
        RoleLimitCountScope::ResourceParent,
        RoleLimitCountSource::CustomerSupplied,
        RoleLimitEnforcementMode::Advisory,
        900,
        RoleLimitThresholds::default(),
    )
    .expect("arbitrary product key and unit are valid");

    assert_eq!(limit.key.as_str(), "widgets-v2");
    assert_eq!(limit.unit.as_str(), "widget-hours");
    assert_eq!(limit.amount.get(), 0);
    assert_eq!(limit.reservation_ttl_seconds.get(), 900);
}

#[test]
fn given_amount_above_public_safe_integer_when_constructed_then_limit_is_rejected() {
    let error = RoleActionLimit::try_new(
        "projects",
        MAX_PUBLIC_SAFE_INTEGER + 1,
        "projects",
        RoleLimitCountScope::Tenant,
        RoleLimitCountSource::Capacity,
        RoleLimitEnforcementMode::Hard,
        120,
        RoleLimitThresholds::default(),
    )
    .expect_err("unsafe public integer must be rejected");

    assert!(error.to_string().contains("amount"));
}

#[test]
fn given_customer_supplied_hard_limit_when_constructed_then_limit_is_rejected() {
    let error = RoleActionLimit::try_new(
        "projects",
        5,
        "projects",
        RoleLimitCountScope::Tenant,
        RoleLimitCountSource::CustomerSupplied,
        RoleLimitEnforcementMode::Hard,
        120,
        RoleLimitThresholds::default(),
    )
    .expect_err("customer-supplied counts cannot be hard enforced by AuxFn");

    assert!(error.to_string().contains("enforcement_mode"));
}

#[test]
fn given_capacity_advisory_limit_when_constructed_then_limit_is_rejected() {
    let error = RoleActionLimit::try_new(
        "projects",
        5,
        "projects",
        RoleLimitCountScope::Tenant,
        RoleLimitCountSource::Capacity,
        RoleLimitEnforcementMode::Advisory,
        120,
        RoleLimitThresholds::default(),
    )
    .expect_err("capacity limits are strict in V1");

    assert!(error.to_string().contains("enforcement_mode"));
}

#[test]
fn given_thresholds_out_of_order_when_constructed_then_thresholds_are_rejected() {
    let error = RoleLimitThresholds::try_new(Some(90), Some(80))
        .expect_err("critical threshold must not be below low threshold");

    assert!(error.to_string().contains("threshold"));
    assert!(RoleLimitThresholds::try_new(Some(80), Some(80)).is_err());
}

#[test]
fn given_unknown_count_source_when_deserialized_then_limit_is_rejected() {
    let payload = serde_json::json!({
        "key": "projects",
        "amount": 5,
        "unit": "projects",
        "count_scope": "tenant",
        "count_source": "billing_metric",
        "enforcement_mode": "advisory",
        "reservation_ttl_seconds": 120,
        "thresholds": {}
    });

    let error = serde_json::from_value::<RoleActionLimit>(payload)
        .expect_err("unsupported count source must not enter the role contract");

    assert!(error.to_string().contains("billing_metric"));
}

#[test]
fn given_valid_limit_when_serialized_and_deserialized_then_contract_round_trips() {
    let original = valid_limit();
    let encoded = serde_json::to_value(&original).expect("serialize role-action limit");
    let decoded = serde_json::from_value::<RoleActionLimit>(encoded).expect("deserialize limit");

    assert_eq!(decoded, original);
}
