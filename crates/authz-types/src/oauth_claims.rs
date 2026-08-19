//! Public OAuth claim type exports.
//!
//! The implementation is split by ownership so each production Rust file stays
//! small enough to review in isolation.

pub use crate::{
    access_token_claims::{OAuthAccessTokenClaims, OAuthAccessTokenClaimsInput},
    access_token_type::AccessTokenType,
    claim_bounds::{
        ClaimBoundsError, ClaimSerializationContext, MAX_CLAIM_DEPTH, MAX_CLAIM_MEMBERS,
        MAX_CLAIM_STRING_BYTES, MAX_COMPACT_JWT_BYTES, MAX_CUSTOM_CLAIM_JSON_BYTES,
        MAX_CUSTOM_CLAIMS, MAX_CUSTOM_CLAIMS_JSON_BYTES, STRUCTURAL_CLAIM_NAMES,
        is_structural_claim,
    },
    custom_claims::CustomClaims,
    normalized_audience::NormalizedAudience,
    principal::{Principal, PrincipalType},
    validated_principal::ValidatedPrincipal,
    verified_claim_tree::VerifiedClaimTree,
};
