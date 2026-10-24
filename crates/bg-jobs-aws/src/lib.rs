//! AWS SigV4 authorisation and immutable S3 publication for durable jobs.
#![deny(unsafe_code)]

mod authorizer;
mod constants;
mod s3_publication;
#[cfg(test)]
mod s3_publication_tests;

pub use authorizer::{SigV4Authorizer, SigV4AuthorizerError};
pub use aws_credentials::CredentialSource;
pub use constants::S3_SOURCE_IDENTITY_HEADER;
pub use s3_publication::{
    S3ObjectInput, S3ObjectPublication, S3ObjectPublisher, S3PublicationError,
};

#[cfg(test)]
mod authorizer_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod quint;
