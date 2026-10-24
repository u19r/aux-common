use std::{fmt, sync::Arc};

use futures_util::future::BoxFuture;

use crate::{Credentials, CredentialsError};

/// Credential resolution supplied by the caller. Failure does not select
/// another provider.
pub trait ProvideCredentials: Send + Sync + fmt::Debug {
    fn provide_credentials(&self) -> BoxFuture<'_, Result<Credentials, CredentialsError>>;
}

/// Cloneable, type-erased provider used by shared request signers.
#[derive(Clone)]
pub struct SharedCredentialsProvider(Arc<dyn ProvideCredentials>);

impl SharedCredentialsProvider {
    #[must_use]
    pub fn new(provider: impl ProvideCredentials + 'static) -> Self {
        Self(Arc::new(provider))
    }
}

impl ProvideCredentials for SharedCredentialsProvider {
    fn provide_credentials(&self) -> BoxFuture<'_, Result<Credentials, CredentialsError>> {
        self.0.provide_credentials()
    }
}

impl fmt::Debug for SharedCredentialsProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SharedCredentialsProvider([REDACTED])")
    }
}

impl ProvideCredentials for Credentials {
    fn provide_credentials(&self) -> BoxFuture<'_, Result<Credentials, CredentialsError>> {
        Box::pin(std::future::ready(Ok(self.clone())))
    }
}
