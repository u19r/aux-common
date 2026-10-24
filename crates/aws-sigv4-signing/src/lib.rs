#![doc(hidden)]

mod constants;
mod error;
mod http_client;
mod signable_body;
mod signer;
mod signing;

#[cfg(test)]
mod http_client_tests;
#[cfg(test)]
mod signable_body_tests;
#[cfg(test)]
mod signer_tests;

pub use aws_credentials::{
    AwsResolvedCredentials, AwsStaticCredentials, CredentialSource, SharedCredentialsProvider,
    resolve_default_chain_credentials, resolve_default_chain_credentials_with_expiry,
};
pub use signable_body::SignableBody;

pub use crate::{
    error::SigningError,
    http_client::{AwsSigv4HttpClient, AwsSigv4TextResponse},
    signer::AwsRequestSigner,
};
