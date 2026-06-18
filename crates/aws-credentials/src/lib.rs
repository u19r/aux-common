#![doc(hidden)]

mod constants;
mod provider;

#[cfg(test)]
mod provider_tests;

pub use aws_credential_types::provider::error::CredentialsError;
pub use provider::{
    AwsResolvedCredentials, AwsStaticCredentials, CredentialSource,
    DefaultChainCredentialsProvider, half_life_refresh_after, resolve_default_chain_credentials,
    resolve_default_chain_credentials_with_expiry, resolve_ecs_authorization_token,
    resolve_ecs_task_credentials_uri, static_credentials, validate_ecs_full_uri,
};
