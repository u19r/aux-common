use crate::evaluation_runtime::permission_resource_type;

#[test]
fn permission_resource_type_preserves_dotted_namespace() {
    assert_eq!(permission_resource_type("repo.v2:read"), "repo.v2");
}
