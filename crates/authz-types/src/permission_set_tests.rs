use std::collections::BTreeMap;

use serde_json::Value;

use super::*;

#[test]
fn permission_set_validation_is_bounded_and_protocol_explicit() {
    let mut set = PermissionSet {
        id: "reports".to_string(),
        revision: 1,
        enabled: true,
        protocols: [PermissionSetProtocol::OAuth, PermissionSetProtocol::Saml]
            .into_iter()
            .collect(),
        permissions: vec!["reports.read".to_string()],
        claims: BTreeMap::from([("tier".to_string(), Value::String("pro".to_string()))]),
    };
    assert!(set.validate().is_ok());
    set.protocols.clear();
    assert_eq!(
        set.validate(),
        Err(ValidationError::RequiredFieldMissing("protocols"))
    );
}

#[test]
fn assignment_requires_positive_revision_and_scoped_ids() {
    let assignment = PermissionSetAssignment {
        application_id: "app".to_string(),
        principal_id: "sp_1".to_string(),
        principal_type: PrincipalType::ServicePrincipal,
        permission_set_id: "reports".to_string(),
        revision: 1,
        active: true,
    };
    assert!(assignment.validate().is_ok());
}

fn service_set(revision: u64) -> PermissionSet {
    PermissionSet {
        id: "service".to_string(),
        revision,
        enabled: true,
        protocols: [PermissionSetProtocol::OAuth].into_iter().collect(),
        permissions: vec!["reports.read".to_string()],
        claims: BTreeMap::new(),
    }
}

#[test]
fn interactive_selection_is_zero_one_many_and_explicit() {
    let sets = vec![service_set(1)];
    assert_eq!(
        select_interactive_permission_set(&sets, PermissionSetProtocol::OAuth, None)
            .expect("single set")
            .map(|set| set.id.as_str()),
        Some("service")
    );
    assert_eq!(
        select_interactive_permission_set(&[], PermissionSetProtocol::OAuth, None),
        Err(PermissionSetSelectionError::NoEligibleSet)
    );
    let mut second = service_set(1);
    second.id = "second".to_string();
    let many = vec![service_set(1), second];
    assert_eq!(
        select_interactive_permission_set(&many, PermissionSetProtocol::OAuth, None),
        Err(PermissionSetSelectionError::SelectionRequired)
    );
    assert_eq!(
        select_interactive_permission_set(&many, PermissionSetProtocol::OAuth, Some("second"))
            .expect("explicit set")
            .map(|set| set.id.as_str()),
        Some("second")
    );
}

#[test]
fn service_assignment_requires_current_active_revision() {
    let sets = vec![service_set(2)];
    let stale = PermissionSetAssignment {
        application_id: "app".to_string(),
        principal_id: "sp_1".to_string(),
        principal_type: PrincipalType::ServicePrincipal,
        permission_set_id: "service".to_string(),
        revision: 1,
        active: true,
    };
    assert_eq!(
        select_service_permission_set(&sets, Some(&stale), PermissionSetProtocol::OAuth, "sp_1"),
        Err(PermissionSetSelectionError::StaleAssignment)
    );
    let current = PermissionSetAssignment {
        revision: 2,
        ..stale
    };
    assert_eq!(
        select_service_permission_set(&sets, Some(&current), PermissionSetProtocol::OAuth, "sp_1")
            .expect("current assignment")
            .id,
        "service"
    );
}

#[test]
fn render_claims_adds_permissions_and_rejects_protocol_collisions() {
    let set = PermissionSet {
        id: "reports".to_string(),
        revision: 1,
        enabled: true,
        protocols: [
            PermissionSetProtocol::OAuth,
            PermissionSetProtocol::Oidc,
            PermissionSetProtocol::Saml,
            PermissionSetProtocol::Native,
        ]
        .into_iter()
        .collect(),
        permissions: vec!["reports.read".to_string()],
        claims: BTreeMap::from([("tier".to_string(), Value::String("pro".to_string()))]),
    };
    for protocol in [
        PermissionSetProtocol::OAuth,
        PermissionSetProtocol::Oidc,
        PermissionSetProtocol::Native,
        PermissionSetProtocol::Saml,
    ] {
        let claims = set.render_claims(protocol).expect("rendered claims");
        assert_eq!(claims["permissions"], serde_json::json!(["reports.read"]));
        assert_eq!(claims["tier"], "pro");
    }

    let protected = PermissionSet {
        claims: BTreeMap::from([("sub".to_string(), Value::String("other".to_string()))]),
        ..set.clone()
    };
    assert!(
        protected
            .render_claims(PermissionSetProtocol::OAuth)
            .is_err()
    );

    let saml = PermissionSet {
        protocols: [PermissionSetProtocol::Saml].into_iter().collect(),
        claims: BTreeMap::from([("nested".to_string(), serde_json::json!({"x": 1}))]),
        ..set
    };
    assert!(saml.render_claims(PermissionSetProtocol::Saml).is_err());
}
