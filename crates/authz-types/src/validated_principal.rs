use serde_json::from_value;

use crate::{
    AccessTokenType, ClaimBoundsError, OAuthAccessTokenClaims, Principal, PrincipalType,
    VerifiedClaimTree,
};

/// Verified identity handed from a resource server to an authorization adapter.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedPrincipal {
    pub principal: Principal,
    pub issuer: String,
    pub subject: String,
    pub tenant: String,
    pub client_id: String,
    pub token_type: AccessTokenType,
    pub audience: crate::NormalizedAudience,
    pub scopes: Vec<String>,
    pub token_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub not_before: Option<i64>,
    pub auth_time: Option<i64>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
    pub nonce: Option<String>,
    pub authorized_party: Option<String>,
    pub access_token_hash: Option<String>,
    pub code_hash: Option<String>,
    pub permission_set_id: Option<String>,
    pub permission_set_revision: Option<u64>,
    pub verified_claims: VerifiedClaimTree,
}

impl ValidatedPrincipal {
    pub fn try_from_access_token(
        claims: &OAuthAccessTokenClaims,
        principal: Principal,
        verified_claims: VerifiedClaimTree,
    ) -> Result<Self, ClaimBoundsError> {
        claims.validate()?;
        let (principal_id, principal_type) = match &principal {
            Principal::User { id } => (id, PrincipalType::User),
            Principal::ServicePrincipal { id } => (id, PrincipalType::ServicePrincipal),
        };
        if principal_id != &claims.subject || principal_type != claims.principal_type {
            return Err(ClaimBoundsError::PrincipalMismatch);
        }
        let verified_typed = from_value::<OAuthAccessTokenClaims>(verified_claims.value.clone())
            .map_err(|_| ClaimBoundsError::VerifiedClaimsMismatch)?;
        if verified_typed != *claims {
            return Err(ClaimBoundsError::VerifiedClaimsMismatch);
        }
        Ok(Self {
            principal,
            issuer: claims.issuer.clone(),
            subject: claims.subject.clone(),
            tenant: claims.tenant.clone(),
            client_id: claims.client_id.clone(),
            token_type: claims.token_type,
            audience: claims.audience.clone(),
            scopes: claims.scope.clone(),
            token_id: claims.token_id.clone(),
            issued_at: claims.issued_at,
            expires_at: claims.expires_at,
            not_before: claims.not_before,
            auth_time: claims.auth_time,
            acr: claims.acr.clone(),
            amr: claims.amr.clone(),
            nonce: claims.nonce.clone(),
            authorized_party: claims.authorized_party.clone(),
            access_token_hash: claims.access_token_hash.clone(),
            code_hash: claims.code_hash.clone(),
            permission_set_id: claims.permission_set_id.clone(),
            permission_set_revision: claims.permission_set_revision,
            verified_claims,
        })
    }
}
