pub trait RoleAssignmentScopeView {
    fn scope_type(&self) -> Option<&str>;
    fn scope_id(&self) -> Option<&str>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind<'a> {
    Tenant,
    Org,
    Group,
    Resource { resource_type: Option<&'a str> },
    Other,
}

pub fn classify_scope(scope_type: &str) -> ScopeKind<'_> {
    let scope = scope_type.trim();
    if scope.eq_ignore_ascii_case("tenant") {
        return ScopeKind::Tenant;
    }
    if scope.eq_ignore_ascii_case("org") {
        return ScopeKind::Org;
    }
    if scope.eq_ignore_ascii_case("group") {
        return ScopeKind::Group;
    }
    if scope.eq_ignore_ascii_case("resource") {
        return ScopeKind::Resource {
            resource_type: None,
        };
    }

    const RESOURCE_PREFIX: &str = "resource:";
    if let Some(prefix) = scope.get(..RESOURCE_PREFIX.len())
        && prefix.eq_ignore_ascii_case(RESOURCE_PREFIX)
    {
        return ScopeKind::Resource {
            resource_type: scope
                .get(RESOURCE_PREFIX.len()..)
                .filter(|&resource_type| !resource_type.is_empty()),
        };
    }

    ScopeKind::Other
}

pub fn role_assignment_covers_resource(
    assignment: &impl RoleAssignmentScopeView,
    resource_type: &str,
    resource_id: &str,
    resource_org: Option<&str>,
) -> bool {
    match assignment.scope_type() {
        // The public assignment API intentionally defaults an omitted scope to
        // tenant-wide. Preserve that documented contract for legacy records;
        // malformed non-tenant scope values still fail closed below.
        None => true,
        Some(scope_type) => match classify_scope(scope_type) {
            ScopeKind::Tenant => true,
            ScopeKind::Resource {
                resource_type: Some(scope_resource_type),
            } => {
                scope_resource_type.eq_ignore_ascii_case(resource_type)
                    && assignment.scope_id() == Some(resource_id)
            }
            ScopeKind::Org => resource_org.is_some_and(|org| assignment.scope_id() == Some(org)),
            ScopeKind::Group
            | ScopeKind::Resource {
                resource_type: None,
            }
            | ScopeKind::Other => false,
        },
    }
}

impl RoleAssignmentScopeView for crate::EffectiveRoleAssignment {
    fn scope_type(&self) -> Option<&str> {
        self.scope_type.as_deref()
    }

    fn scope_id(&self) -> Option<&str> {
        self.scope_id.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        EffectiveRoleAssignment, ScopeKind, classify_scope, role_assignment_covers_resource,
    };

    #[test]
    fn classify_scope_supports_known_values_case_insensitively() {
        assert_eq!(classify_scope("tenant"), ScopeKind::Tenant);
        assert_eq!(classify_scope("ORG"), ScopeKind::Org);
        assert_eq!(classify_scope(" Group "), ScopeKind::Group);
        assert_eq!(
            classify_scope("RESOURCE:Document"),
            ScopeKind::Resource {
                resource_type: Some("Document"),
            }
        );
        assert_eq!(
            classify_scope("resource"),
            ScopeKind::Resource {
                resource_type: None,
            }
        );
    }

    #[test]
    fn resource_scope_only_covers_matching_resource() {
        let assignment = EffectiveRoleAssignment {
            principal_id: None,
            role_id: "role_reader".to_string(),
            scope_type: Some("resource:document".to_string()),
            scope_id: Some("doc_1".to_string()),
            expires_at: None,
        };

        assert!(role_assignment_covers_resource(
            &assignment,
            "document",
            "doc_1",
            None
        ));
        assert!(!role_assignment_covers_resource(
            &assignment,
            "document",
            "doc_2",
            None
        ));
    }
}
