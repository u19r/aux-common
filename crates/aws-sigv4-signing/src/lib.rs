#![doc(hidden)]

mod error;
mod http_client;
mod signer;

#[cfg(test)]
mod http_client_tests;
#[cfg(test)]
mod signer_tests;

pub use aws_credentials::{
    AwsResolvedCredentials, AwsStaticCredentials, CredentialSource,
    resolve_default_chain_credentials, resolve_default_chain_credentials_with_expiry,
};
pub use aws_sigv4::http_request::SignableBody;

pub use crate::{
    error::SigningError,
    http_client::{AwsSigv4HttpClient, AwsSigv4TextResponse},
    signer::AwsRequestSigner,
};
