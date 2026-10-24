use std::{error::Error, fmt};

#[derive(Debug, thiserror::Error)]
pub(crate) enum CredentialProviderErrorKind {
    #[error("no credentials found in environment variables, ECS task metadata, or IMDS")]
    NoDefaultCredentials,
    #[error("credential providers failed: {}", format_provider_failures(.0))]
    DefaultChainFailures(Vec<CredentialProviderSource>),
    #[error("failed to resolve credentials from default chain: {}", format_provider_failures(.0))]
    BlockingDefaultChainFailures(Vec<CredentialProviderSource>),
    #[error("{endpoint} endpoint returned status {status}")]
    MetadataEndpointStatus {
        endpoint: MetadataEndpoint,
        status: reqwest::StatusCode,
    },
    #[error("token endpoint returned an empty token")]
    EmptyImdsToken,
    #[error("role listing endpoint returned no role name")]
    MissingImdsRoleName,
    #[error("AWS credential environment variables are partially configured")]
    PartialEnvironmentCredentials,
    #[error("failed to run aws cli credential provider")]
    AwsCliRunFailed,
    #[error("aws cli credential provider rejected the requested profile")]
    AwsCliProfileExportFailed,
    #[error("aws cli credential output exceeds configured limit")]
    AwsCliOutputTooLarge,
    #[error("aws cli credential command timed out")]
    AwsCliTimedOut,
    #[error("authorization token file exceeds configured limit")]
    AuthorizationTokenFileTooLarge,
    #[error("aws cli credential provider returned invalid JSON")]
    InvalidAwsCliCredentialJson,
    #[error("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI must be a path")]
    EcsRelativeUriMustBePath,
    #[error("AWS_CONTAINER_CREDENTIALS_FULL_URI is missing a host")]
    EcsFullUriMissingHost,
    #[error("AWS_CONTAINER_CREDENTIALS_FULL_URI must not embed userinfo credentials")]
    EcsFullUriRejectsUserinfo,
    #[error("AWS_CONTAINER_CREDENTIALS_FULL_URI must use HTTPS or a loopback/local ECS host")]
    EcsFullUriRequiresHttpsOrLocal,
    #[error("AWS_CONTAINER_CREDENTIALS_FULL_URI must use HTTP or HTTPS")]
    EcsFullUriRequiresHttpOrHttps,
    #[error("authorization token file was empty")]
    EmptyAuthorizationTokenFile,
    #[error("credential response did not include access key id and secret access key")]
    IncompleteCredentialResponse,
    #[error("metadata request failed")]
    MetadataRequestFailed,
    #[error("credential provider client initialization failed")]
    ProviderClientInitFailed,
    #[error("credential metadata response was invalid")]
    MetadataResponseInvalid,
    #[error("credential metadata response was not valid JSON")]
    MetadataCredentialsJsonInvalid,
    #[error("credential metadata response was not valid UTF-8")]
    MetadataCredentialsTextInvalid,
    #[error("authorization token file could not be read")]
    AuthorizationTokenFileReadFailed,
    #[error("authorization token file was not valid UTF-8")]
    AuthorizationTokenFileInvalidUtf8,
    #[error("ECS credentials URI was invalid")]
    InvalidEcsCredentialsUri,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum CredentialProviderSource {
    AwsCliProfile,
    EcsTaskMetadata,
    Imds,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum MetadataEndpoint {
    Credential,
    Credentials,
    Token,
    RoleListing,
    RoleCredentials,
}

impl fmt::Display for CredentialProviderSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AwsCliProfile => f.write_str("aws cli profile"),
            Self::EcsTaskMetadata => f.write_str("ecs task metadata"),
            Self::Imds => f.write_str("imds"),
        }
    }
}

impl fmt::Display for MetadataEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Credential => f.write_str("credential"),
            Self::Credentials => f.write_str("credentials"),
            Self::Token => f.write_str("token"),
            Self::RoleListing => f.write_str("role listing"),
            Self::RoleCredentials => f.write_str("role credentials"),
        }
    }
}

fn format_provider_failures(failures: &[CredentialProviderSource]) -> String {
    failures
        .iter()
        .map(|source| format!("{source}: provider request failed"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// A safe credential failure category. Error sources retain provider-owned
/// diagnostics.
pub struct CredentialsError {
    category: CredentialFailureCategory,
    source: Option<Box<dyn Error + Send + Sync>>,
}

#[derive(Debug)]
enum CredentialFailureCategory {
    InvalidConfiguration,
    Provider,
    NotLoaded,
}

impl CredentialsError {
    pub(crate) fn invalid_configuration(source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            category: CredentialFailureCategory::InvalidConfiguration,
            source: Some(Box::new(source)),
        }
    }

    pub(crate) fn provider_error(source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            category: CredentialFailureCategory::Provider,
            source: Some(Box::new(source)),
        }
    }

    pub(crate) fn not_loaded(source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            category: CredentialFailureCategory::NotLoaded,
            source: Some(Box::new(source)),
        }
    }

    #[must_use]
    pub fn not_loaded_no_source() -> Self {
        Self {
            category: CredentialFailureCategory::NotLoaded,
            source: None,
        }
    }
}

impl fmt::Display for CredentialsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.category {
            CredentialFailureCategory::InvalidConfiguration => "invalid credential configuration",
            CredentialFailureCategory::Provider => "credential provider failed",
            CredentialFailureCategory::NotLoaded => "the credentials provider was not enabled",
        })
    }
}

impl fmt::Debug for CredentialsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialsError")
            .field("category", &self.category)
            .finish_non_exhaustive()
    }
}

impl Error for CredentialsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}
