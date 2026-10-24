//! Authorization types for the authz subsystem.
//!
//! This crate contains shared types used across authz crates:
//! - Configuration model types (ResourceType, Permission, Role)
//! - API evaluation types (Subject, Resource, Action, Context)
//! - Evaluation request/response types
//! - Validation errors

mod claims;
mod configuration;
mod constants;
mod control_plane;
mod error;
mod evaluation;
mod identity;

pub use claims::{
    AccessTokenType, ClaimBoundsError, ClaimMappingError, ClaimMappingMatcher, ClaimMappingOutput,
    ClaimMappingRegistry, ClaimMappingSpec, ClaimPath, ClaimSerializationContext, ClaimTemplate,
    ConfirmationClaim, CustomClaims, MAX_CLAIM_DEPTH, MAX_CLAIM_MAPPING_PATH_BYTES,
    MAX_CLAIM_MAPPING_PATTERN_BYTES, MAX_CLAIM_MAPPING_TEMPLATE_NODES, MAX_CLAIM_MAPPINGS,
    MAX_CLAIM_MEMBERS, MAX_CLAIM_STRING_BYTES, MAX_COMPACT_JWT_BYTES, MAX_CUSTOM_CLAIM_JSON_BYTES,
    MAX_CUSTOM_CLAIMS, MAX_CUSTOM_CLAIMS_JSON_BYTES, NormalizedAudience, OAuthAccessTokenClaims,
    OAuthAccessTokenClaimsInput, Principal, PrincipalType, STRUCTURAL_CLAIM_NAMES,
    ValidatedPrincipal, VerifiedClaimTree, is_structural_claim,
};
pub use configuration::{
    AcrLevel, Action, ActionDefinition, ActionPatternExpandError, ActionPatternParseError,
    AuthnProviderConfig, AuthzChallenge, ChallengeType, ConfigurationModel, DefaultScopingConfig,
    ExpandedActionRef, MAX_PERMISSION_SET_CLAIM_BYTES, MAX_PERMISSION_SET_CLAIMS,
    MAX_PERMISSION_SET_ID_BYTES, MAX_PERMISSION_SET_PERMISSIONS, Permission, PermissionActionRef,
    PermissionId, PermissionSet, PermissionSetAssignment, PermissionSetProtocol,
    PermissionSetSelectionError, ResourceScopingConfig, ResourceType, ResourceTypeId, Role,
    RoleActionLimit, RoleActionRef, RoleId, RoleLimitAmount, RoleLimitCountScope,
    RoleLimitCountSource, RoleLimitEnforcementMode, RoleLimitKey, RoleLimitReservationTtlSeconds,
    RoleLimitThresholds, RoleLimitUnit, RolePermission, Scope, ScopeMappingEntry, ScopingPattern,
    ScopingPatternConfig, StepUpConfig, StepUpRule, ValidatedConfigurationModel,
    eligible_permission_sets, expand_action_patterns, select_interactive_permission_set,
    select_service_permission_set,
};
pub use constants::{
    CONTEXT_INTERNAL_KEY, CONTEXT_RESOURCE_PARENTS_KEY, CONTEXT_SUBJECT_PARENTS_KEY,
    DEFAULT_RESERVATION_TTL_SECONDS, MAX_ACTIONS_PER_RESOURCE_TYPE, MAX_AUTHN_PROVIDERS,
    MAX_BATCH_EVALUATIONS, MAX_DESCRIPTION_LEN, MAX_IDENTIFIER_LEN, MAX_PERMISSION_ACTION_REFS,
    MAX_PERMISSION_ID_LEN, MAX_PERMISSIONS, MAX_PUBLIC_SAFE_INTEGER, MAX_RESERVATION_TTL_SECONDS,
    MAX_RESOURCE_TYPES, MAX_ROLE_ACTION_REFS, MAX_ROLE_ENTRY_SCOPES, MAX_ROLE_PERMISSION_REFS,
    MAX_ROLES, MAX_SCOPE_MAPPING_INCLUDES, MAX_SCOPE_MAPPING_PERMISSIONS, MAX_SCOPE_MAPPINGS,
    MAX_STEP_UP_RULES,
};
pub use control_plane::{
    CreatePermissionRequest, CreateResourceTypeRequest, CreateRoleRequest,
    PermissionActionByNameInput, PermissionByNameInput, ResourceTypeActionByNameInput,
    ResourceTypeByNameInput, RoleActionByNameInput, RoleByNameInput, RolePermissionByNameInput,
    UpdateRoleRequest,
};
pub use error::ValidationError;
pub use evaluation::{
    ApiAction, ApiBatchEvaluationRequest, ApiBatchEvaluationResponse, ApiContext,
    ApiEvaluationRequest, ApiEvaluationResponse, ApiResource, ApiResponseContext, ApiSubject,
    BatchEvaluationRequest, BatchEvaluationResponse, Context, DecisionContext,
    EvaluationProperties, EvaluationRequest, EvaluationResponse, Resource, Subject, SubjectType,
};
pub use identity::{
    AccessAssignmentDurationSeconds, AccessAssignmentExplanation, AccessAssignmentMode,
    AccessAssignmentPolicy, AccessAssignmentPolicySpec, AccessAssignmentRemovalCause,
    AccessAssignmentRemovalSource, AccessAssignmentStatus, AccessAssignmentTarget,
    AccessProfileSessionReference, AccessProfileSessionReferenceError, FineGrainedScopes,
    GroupMembership, JwtContext, MAX_ACCESS_ASSIGNMENT_DURATION_SECONDS,
    MAX_ACCESS_ASSIGNMENT_EXPLANATION_BYTES, MIN_ACCESS_ASSIGNMENT_DURATION_SECONDS, OrgMembership,
    ResourceSelection, RoleAssignment, RoleScope, SessionContext, TokenContext, TokenScopeConfig,
    TokenScopeType, TokenSubjectBinding,
};
