use authz_types::{AccessAssignmentMode, AccessAssignmentPolicySpec};

pub(crate) fn permanent_assignment_policy() -> AccessAssignmentPolicySpec {
    AccessAssignmentPolicySpec {
        assignment_mode: AccessAssignmentMode::PermanentOrTemporary,
        maximum_duration_seconds: None,
    }
}
