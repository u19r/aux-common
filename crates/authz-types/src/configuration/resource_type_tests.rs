#[test]
fn validated_identifier_deserialization_rejects_values_bypassing_constructors() {
    let invalid_role = serde_json::from_str::<crate::RoleId>("\"\"").unwrap_err();
    assert!(invalid_role.to_string().contains("cannot be empty"));

    let invalid_resource = serde_json::from_str::<crate::ResourceTypeId>(r#""A-B""#).unwrap_err();
    assert!(
        invalid_resource
            .to_string()
            .contains("lowercase alphanumeric")
    );
}
