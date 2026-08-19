use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;
use typed_builder::TypedBuilder;

use crate::{
    AccessTokenType, ClaimBoundsError, ClaimSerializationContext, CustomClaims, MAX_CLAIM_MEMBERS,
    NormalizedAudience, PrincipalType,
    claim_bounds::{
        base64url_len, deserialize_scope, serialize_scope, validate_scope_values, validate_string,
    },
};

/// Canonical signed OAuth access-token claims.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OAuthAccessTokenClaims {
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "sub")]
    pub subject: String,
    #[serde(rename = "aud")]
    pub audience: NormalizedAudience,
    #[serde(rename = "exp")]
    pub expires_at: i64,
    #[serde(rename = "iat")]
    pub issued_at: i64,
    #[serde(rename = "nbf", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<i64>,
    #[serde(rename = "jti")]
    pub token_id: String,
    pub client_id: String,
    #[serde(
        serialize_with = "serialize_scope",
        deserialize_with = "deserialize_scope"
    )]
    pub scope: Vec<String>,
    pub tenant: String,
    pub token_type: AccessTokenType,
    pub principal_type: PrincipalType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub amr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(rename = "azp", default, skip_serializing_if = "Option::is_none")]
    pub authorized_party: Option<String>,
    #[serde(rename = "at_hash", default, skip_serializing_if = "Option::is_none")]
    pub access_token_hash: Option<String>,
    #[serde(rename = "c_hash", default, skip_serializing_if = "Option::is_none")]
    pub code_hash: Option<String>,
    /// The selected application Permission Set, when the issuer enabled the
    /// feature for this flow. The identifier and revision are structural so
    /// consumers can reject stale authority without interpreting custom JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_set_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_set_revision: Option<u64>,
    #[serde(flatten)]
    pub custom_claims: CustomClaims,
}

/// Input required to build a bounded canonical OAuth access-token claim set.
#[derive(Debug, Clone, PartialEq, TypedBuilder)]
pub struct OAuthAccessTokenClaimsInput {
    pub issuer: String,
    pub subject: String,
    pub audience: NormalizedAudience,
    pub expires_at: i64,
    pub issued_at: i64,
    pub not_before: Option<i64>,
    pub token_id: String,
    pub client_id: String,
    pub scope: Vec<String>,
    pub tenant: String,
    pub principal_type: PrincipalType,
    pub auth_time: Option<i64>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
    pub nonce: Option<String>,
    pub authorized_party: Option<String>,
    pub access_token_hash: Option<String>,
    pub code_hash: Option<String>,
    pub permission_set_id: Option<String>,
    pub permission_set_revision: Option<u64>,
    pub custom_claims: CustomClaims,
}

#[derive(Deserialize)]
struct OAuthAccessTokenClaimsWire {
    #[serde(rename = "iss")]
    issuer: String,
    #[serde(rename = "sub")]
    subject: String,
    #[serde(rename = "aud")]
    audience: NormalizedAudience,
    #[serde(rename = "exp")]
    expires_at: i64,
    #[serde(rename = "iat")]
    issued_at: i64,
    #[serde(rename = "nbf", default)]
    not_before: Option<i64>,
    #[serde(rename = "jti")]
    token_id: String,
    client_id: String,
    #[serde(deserialize_with = "deserialize_scope")]
    scope: Vec<String>,
    tenant: String,
    token_type: AccessTokenType,
    principal_type: PrincipalType,
    #[serde(default)]
    auth_time: Option<i64>,
    #[serde(default)]
    acr: Option<String>,
    #[serde(default)]
    amr: Vec<String>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(rename = "azp", default)]
    authorized_party: Option<String>,
    #[serde(rename = "at_hash", default)]
    access_token_hash: Option<String>,
    #[serde(rename = "c_hash", default)]
    code_hash: Option<String>,
    #[serde(default)]
    permission_set_id: Option<String>,
    #[serde(default)]
    permission_set_revision: Option<u64>,
    #[serde(flatten)]
    custom_claims: CustomClaims,
}

impl OAuthAccessTokenClaims {
    pub fn try_new(input: OAuthAccessTokenClaimsInput) -> Result<Self, ClaimBoundsError> {
        let claims = Self {
            issuer: input.issuer,
            subject: input.subject,
            audience: input.audience,
            expires_at: input.expires_at,
            issued_at: input.issued_at,
            not_before: input.not_before,
            token_id: input.token_id,
            client_id: input.client_id,
            scope: input.scope,
            tenant: input.tenant,
            token_type: AccessTokenType::AccessToken,
            principal_type: input.principal_type,
            auth_time: input.auth_time,
            acr: input.acr,
            amr: input.amr,
            nonce: input.nonce,
            authorized_party: input.authorized_party,
            access_token_hash: input.access_token_hash,
            code_hash: input.code_hash,
            permission_set_id: input.permission_set_id,
            permission_set_revision: input.permission_set_revision,
            custom_claims: input.custom_claims,
        };
        claims.validate()?;
        Ok(claims)
    }

    pub fn validate(&self) -> Result<(), ClaimBoundsError> {
        for (field, value) in [
            ("iss", &self.issuer),
            ("sub", &self.subject),
            ("jti", &self.token_id),
            ("client_id", &self.client_id),
            ("tenant", &self.tenant),
        ] {
            if value.is_empty() {
                return Err(ClaimBoundsError::Empty { field });
            }
            validate_string(field, value)?;
        }
        validate_scope_values(&self.scope)?;
        if self.expires_at <= self.issued_at
            || self
                .not_before
                .is_some_and(|not_before| not_before > self.expires_at)
            || self
                .auth_time
                .is_some_and(|auth_time| auth_time > self.issued_at)
        {
            return Err(ClaimBoundsError::InvalidTemporalOrder);
        }
        for value in self
            .amr
            .iter()
            .chain(self.acr.iter())
            .chain(self.nonce.iter())
            .chain(self.authorized_party.iter())
            .chain(self.access_token_hash.iter())
            .chain(self.code_hash.iter())
        {
            validate_string("OAuth claim", value)?;
        }
        if self.permission_set_id.is_some() != self.permission_set_revision.is_some()
            || self.permission_set_revision == Some(0)
        {
            return Err(ClaimBoundsError::InvalidPermissionSetReference);
        }
        if self.amr.len() > MAX_CLAIM_MEMBERS {
            return Err(ClaimBoundsError::MembersExceeded {
                kind: "array",
                limit: MAX_CLAIM_MEMBERS,
                actual: self.amr.len(),
            });
        }
        Ok(())
    }

    pub fn validate_compact_jwt_size(
        &self,
        protected_header: &[u8],
        signature_bytes: usize,
    ) -> Result<(), ClaimBoundsError> {
        self.validate()?;
        let payload_bytes =
            serde_json::to_vec(self).map_err(|_| ClaimBoundsError::Serialization {
                context: ClaimSerializationContext::CompactJwtPayload,
            })?;
        let actual = base64url_len(protected_header.len())
            .saturating_add(1)
            .saturating_add(base64url_len(payload_bytes.len()))
            .saturating_add(1)
            .saturating_add(base64url_len(signature_bytes));
        if actual > crate::MAX_COMPACT_JWT_BYTES {
            return Err(ClaimBoundsError::CompactJwtTooLarge {
                limit: crate::MAX_COMPACT_JWT_BYTES,
                actual,
            });
        }
        Ok(())
    }

    /// Return the exact JSON object that is intended to be signed.
    pub fn to_json_value(&self) -> Result<Value, ClaimBoundsError> {
        serde_json::to_value(self).map_err(|_| ClaimBoundsError::Serialization {
            context: ClaimSerializationContext::JsonObject,
        })
    }
}

impl TryFrom<OAuthAccessTokenClaimsWire> for OAuthAccessTokenClaims {
    type Error = ClaimBoundsError;

    fn try_from(wire: OAuthAccessTokenClaimsWire) -> Result<Self, Self::Error> {
        let claims = Self {
            issuer: wire.issuer,
            subject: wire.subject,
            audience: wire.audience,
            expires_at: wire.expires_at,
            issued_at: wire.issued_at,
            not_before: wire.not_before,
            token_id: wire.token_id,
            client_id: wire.client_id,
            scope: wire.scope,
            tenant: wire.tenant,
            token_type: wire.token_type,
            principal_type: wire.principal_type,
            auth_time: wire.auth_time,
            acr: wire.acr,
            amr: wire.amr,
            nonce: wire.nonce,
            authorized_party: wire.authorized_party,
            access_token_hash: wire.access_token_hash,
            code_hash: wire.code_hash,
            permission_set_id: wire.permission_set_id,
            permission_set_revision: wire.permission_set_revision,
            custom_claims: wire.custom_claims,
        };
        claims.validate()?;
        Ok(claims)
    }
}

impl<'de> Deserialize<'de> for OAuthAccessTokenClaims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        OAuthAccessTokenClaimsWire::deserialize(deserializer)?
            .try_into()
            .map_err(D::Error::custom)
    }
}
