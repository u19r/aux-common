#![doc(hidden)]

mod constants;
mod credential_provider;
mod credentials;
mod error;
mod provider;

#[cfg(test)]
mod provider_tests;

pub use credential_provider::{ProvideCredentials, SharedCredentialsProvider};
pub use credentials::{
    AwsResolvedCredentials, AwsStaticCredentials, CredentialSource, Credentials,
};
pub use error::CredentialsError;
pub use provider::{
    DefaultChainCredentialsProvider, half_life_refresh_after, resolve_default_chain_credentials,
    resolve_default_chain_credentials_with_expiry, resolve_ecs_authorization_token,
    resolve_ecs_task_credentials_uri, static_credentials, validate_ecs_full_uri,
};
