use crate::{EvaluationProperties, Scope};

#[test]
fn evaluation_properties_identify_scope_fields() {
    let properties = EvaluationProperties {
        owner_org_id: Some("org_123".to_string()),
        owner_group_id: Some("group_123".to_string()),
        owner_user_id: Some("user_123".to_string()),
        ..EvaluationProperties::default()
    };

    assert!(properties.satisfies_scope(&Scope::Org));
    assert!(properties.satisfies_scope(&Scope::Group));
    assert!(properties.satisfies_scope(&Scope::Own));
    assert!(properties.satisfies_scope(&Scope::Tenant));
}

#[test]
fn evaluation_properties_report_missing_scoped_field_codes() {
    let properties = EvaluationProperties::default();

    assert!(!properties.satisfies_scope(&Scope::Org));
    assert_eq!(
        EvaluationProperties::missing_scope_field_code(&Scope::Org),
        Some("authz_owner_org_id_missing")
    );
    assert_eq!(
        EvaluationProperties::missing_scope_field_code(&Scope::Group),
        Some("authz_owner_group_id_missing")
    );
    assert_eq!(
        EvaluationProperties::missing_scope_field_code(&Scope::Own),
        Some("authz_owner_user_id_missing")
    );
}

#[test]
fn evaluation_properties_serialize_known_fields_without_extra_shape() {
    let properties = EvaluationProperties {
        resource_org_id: Some("org_123".to_string()),
        resource_owner_id: Some("user_123".to_string()),
        ..EvaluationProperties::default()
    };

    let value = serde_json::to_value(properties).expect("serialize evaluation properties");

    assert_eq!(value["resource_org_id"], "org_123");
    assert_eq!(value["resource_owner_id"], "user_123");
    assert!(value.get("owner_group_id").is_none());
}
