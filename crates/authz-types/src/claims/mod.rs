mod access_token_claims;
mod access_token_type;
mod claim_bounds;
mod claim_mapping;
mod constants;
mod custom_claims;
mod normalized_audience;
mod principal;
mod validated_principal;
mod verified_claim_tree;

pub use access_token_claims::{OAuthAccessTokenClaims, OAuthAccessTokenClaimsInput};
pub use access_token_type::AccessTokenType;
pub use claim_bounds::{ClaimBoundsError, ClaimSerializationContext, is_structural_claim};
pub use claim_mapping::{
    ClaimMappingError, ClaimMappingMatcher, ClaimMappingOutput, ClaimMappingRegistry,
    ClaimMappingSpec, ClaimPath, ClaimTemplate,
};
pub use constants::{
    MAX_CLAIM_DEPTH, MAX_CLAIM_MAPPING_PATH_BYTES, MAX_CLAIM_MAPPING_PATTERN_BYTES,
    MAX_CLAIM_MAPPING_TEMPLATE_NODES, MAX_CLAIM_MAPPINGS, MAX_CLAIM_MEMBERS,
    MAX_CLAIM_STRING_BYTES, MAX_COMPACT_JWT_BYTES, MAX_CUSTOM_CLAIM_JSON_BYTES, MAX_CUSTOM_CLAIMS,
    MAX_CUSTOM_CLAIMS_JSON_BYTES, STRUCTURAL_CLAIM_NAMES,
};
pub use custom_claims::CustomClaims;
pub use normalized_audience::NormalizedAudience;
pub use principal::{Principal, PrincipalType};
pub use validated_principal::ValidatedPrincipal;
pub use verified_claim_tree::VerifiedClaimTree;

#[cfg(test)]
mod access_token_claims_tests;
#[cfg(test)]
mod claim_mapping_tests;

mod confirmation;
pub use confirmation::ConfirmationClaim;

#[cfg(test)]
mod confirmation_tests;
