use std::{
    env, fmt, io,
    path::Path,
    process::Command,
    time::{Duration, SystemTime},
};

use aws_credential_types::{
    Credentials,
    provider::{self, ProvideCredentials, SharedCredentialsProvider},
};
use aws_sigv4::{
    http_request::{
        PayloadChecksumKind, SignableRequest, SignatureLocation, SigningParams, SigningSettings,
        sign,
    },
    sign::v4,
};
use aws_smithy_runtime_api::client::identity::Identity;
use aws_smithy_types::date_time::{DateTime, Format};
use http::{HeaderMap, HeaderName, HeaderValue, Uri, header::AUTHORIZATION};
use lru_ttl_cache::{CacheConfig, LruTtlCache};
use reqwest::header::AUTHORIZATION as REQWEST_AUTHORIZATION;
use serde::Deserialize;
use url::Url;

use crate::{
    SignableBody, SigningError,
    constants::{
        AWS_ACCESS_KEY, AWS_ACCESS_KEY_ID, AWS_CLI_CREDENTIAL_PROVIDER_NAME,
        AWS_CLI_PROFILE_DEFAULT, AWS_CONFIG_FILE, AWS_CONFIG_RELATIVE_PATH,
        AWS_CONTAINER_AUTHORIZATION_TOKEN, AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE,
        AWS_CONTAINER_CREDENTIALS_FULL_URI, AWS_CONTAINER_CREDENTIALS_RELATIVE_URI,
        AWS_CREDENTIALS_RELATIVE_PATH, AWS_DEFAULT_PROFILE, AWS_EC2_METADATA_DISABLED, AWS_PROFILE,
        AWS_SECRET_ACCESS_KEY, AWS_SECRET_KEY, AWS_SESSION_TOKEN, AWS_SHARED_CREDENTIALS_FILE,
        CREDENTIAL_CACHE_CAPACITY, CREDENTIAL_CACHE_STATIC_TTL, CREDENTIAL_REFRESH_FALLBACK,
        CREDENTIAL_REFRESH_SKEW, DEFAULT_CREDENTIAL_CACHE_KEY, ECS_LOCAL_IPV4_HOST,
        ECS_RELATIVE_CREDENTIALS_BASE, ECS_TASK_METADATA_PROVIDER_NAME, ENVIRONMENT_PROVIDER_NAME,
        HOME, IMDS_PROVIDER_NAME, IMDS_ROLE_LIST_URL, IMDS_TOKEN_HEADER, IMDS_TOKEN_TTL_HEADER,
        IMDS_TOKEN_TTL_SECONDS, IMDS_TOKEN_URL, LOCALHOST, LOOPBACK_IPV4, LOOPBACK_IPV6,
        METADATA_CONNECT_TIMEOUT, METADATA_REQUEST_TIMEOUT, STATIC_PROVIDER_NAME,
    },
    error::CredentialErrorKind,
};
type CredentialProviderError = provider::error::CredentialsError;
type CredentialProviderResult<T> = Result<T, CredentialProviderError>;

#[derive(Debug, Clone)]
pub struct AwsStaticCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AwsResolvedCredentials {
    pub credentials: AwsStaticCredentials,
    pub expires_after: Option<SystemTime>,
    pub refresh_after: Option<SystemTime>,
}

#[derive(Debug, Clone)]
pub enum CredentialSource {
    DefaultChain,
    Static(AwsStaticCredentials),
}

pub fn resolve_default_chain_credentials() -> Result<AwsStaticCredentials, SigningError> {
    Ok(resolve_default_chain_credentials_with_expiry()?.credentials)
}

pub fn resolve_default_chain_credentials_with_expiry()
-> Result<AwsResolvedCredentials, SigningError> {
    let resolved = resolve_default_chain_blocking()?;
    let expires_after = resolved.credentials.expiry();
    Ok(AwsResolvedCredentials {
        credentials: AwsStaticCredentials {
            access_key_id: resolved.credentials.access_key_id().to_string(),
            secret_access_key: resolved.credentials.secret_access_key().to_string(),
            session_token: resolved.credentials.session_token().map(ToOwned::to_owned),
        },
        expires_after,
        refresh_after: half_life_refresh_after(SystemTime::now(), expires_after),
    })
}

#[derive(Debug, Clone)]
pub struct AwsRequestSigner {
    region: String,
    credentials: SharedCredentialsProvider,
    service_name: String,
}

impl AwsRequestSigner {
    pub fn new(
        region: &str,
        credentials: CredentialSource,
        service_name: &str,
    ) -> Result<Self, SigningError> {
        let provider = match credentials {
            CredentialSource::DefaultChain => {
                let provider = DefaultChainCredentialsProvider::new()?;
                SharedCredentialsProvider::new(provider)
            }
            CredentialSource::Static(creds) => {
                SharedCredentialsProvider::new(static_credentials(&creds))
            }
        };

        Ok(Self {
            region: region.to_owned(),
            credentials: provider,
            service_name: service_name.to_string(),
        })
    }

    pub async fn sign(
        &self,
        uri: &Uri,
        base_headers: &HeaderMap,
        body: &[u8],
    ) -> Result<HeaderMap, SigningError> {
        self.sign_request("POST", uri, base_headers, SignableBody::Bytes(body))
            .await
    }

    pub async fn sign_request(
        &self,
        method: &str,
        uri: &Uri,
        base_headers: &HeaderMap,
        body: SignableBody<'_>,
    ) -> Result<HeaderMap, SigningError> {
        let credentials = self
            .credentials
            .provide_credentials()
            .await
            .map_err(SigningError::from)?;

        let mut headers = base_headers.clone();
        if !headers.contains_key(http::header::HOST)
            && let Some(authority) = uri.authority()
        {
            let host_value = HeaderValue::from_str(authority.as_str())
                .map_err(|_| SigningError::InvalidHeaderValue)?;
            headers.insert(http::header::HOST, host_value);
        }

        let mut header_pairs = Vec::with_capacity(headers.len());
        for (name, value) in &headers {
            let value_str = value
                .to_str()
                .map_err(|_| SigningError::InvalidHeaderValue)?;
            header_pairs.push((name.as_str().to_owned(), value_str.to_owned()));
        }

        let signable = SignableRequest::new(
            method,
            uri.to_string(),
            header_pairs
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
            body,
        )
        .map_err(|err| SigningError::PrepareRequest(err.to_string()))?;

        let mut settings = SigningSettings::default();
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

        let identity = Identity::new(credentials.clone(), credentials.expiry());
        let signing_params: SigningParams = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name(&self.service_name)
            .time(SystemTime::now())
            .settings(settings)
            .build()
            .map_err(|err| SigningError::Signing(err.to_string()))?
            .into();

        let (instructions, _) = sign(signable, &signing_params)
            .map_err(|err| SigningError::Signing(err.to_string()))?
            .into_parts();

        for (name, value) in instructions.headers() {
            let header_name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| SigningError::InvalidHeaderName)?;
            let mut header_value =
                HeaderValue::from_str(value).map_err(|_| SigningError::InvalidHeaderValue)?;
            if header_name == AUTHORIZATION {
                header_value.set_sensitive(true);
            }
            headers.insert(header_name, header_value);
        }

        Ok(headers)
    }

    pub async fn presign_request(
        &self,
        method: &str,
        uri: &Uri,
        base_headers: &HeaderMap,
        body: SignableBody<'_>,
        expires_in: Duration,
    ) -> Result<Uri, SigningError> {
        let credentials = self
            .credentials
            .provide_credentials()
            .await
            .map_err(SigningError::from)?;

        let mut headers = base_headers.clone();
        if !headers.contains_key(http::header::HOST)
            && let Some(authority) = uri.authority()
        {
            let host_value = HeaderValue::from_str(authority.as_str())
                .map_err(|_| SigningError::InvalidHeaderValue)?;
            headers.insert(http::header::HOST, host_value);
        }

        let mut header_pairs = Vec::with_capacity(headers.len());
        for (name, value) in &headers {
            let value_str = value
                .to_str()
                .map_err(|_| SigningError::InvalidHeaderValue)?;
            header_pairs.push((name.as_str().to_owned(), value_str.to_owned()));
        }

        let signable = SignableRequest::new(
            method,
            uri.to_string(),
            header_pairs
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
            body,
        )
        .map_err(|err| SigningError::PrepareRequest(err.to_string()))?;

        let mut settings = SigningSettings::default();
        settings.payload_checksum_kind = PayloadChecksumKind::NoHeader;
        settings.signature_location = SignatureLocation::QueryParams;
        settings.expires_in = Some(expires_in);

        let identity = Identity::new(credentials.clone(), credentials.expiry());
        let signing_params: SigningParams = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name(&self.service_name)
            .time(SystemTime::now())
            .settings(settings)
            .build()
            .map_err(|err| SigningError::Signing(err.to_string()))?
            .into();

        let (instructions, _) = sign(signable, &signing_params)
            .map_err(|err| SigningError::Signing(err.to_string()))?
            .into_parts();

        let mut url = Url::parse(&uri.to_string())
            .map_err(|err| SigningError::InvalidUrl(err.to_string()))?;
        if !instructions.params().is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (name, value) in instructions.params() {
                pairs.append_pair(name, value.as_ref());
            }
        }

        url.as_str()
            .parse::<Uri>()
            .map_err(|err| SigningError::InvalidUri(err.to_string()))
    }
}

struct DefaultChainCredentialsProvider {
    client: reqwest::Client,
    cache: LruTtlCache<&'static str, Credentials>,
}

#[derive(Debug, Clone)]
struct ResolvedCredentials {
    credentials: Credentials,
    refresh_after: Option<SystemTime>,
}

impl fmt::Debug for DefaultChainCredentialsProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DefaultChainCredentialsProvider")
            .field("client", &self.client)
            .field("cache_ttl", &self.cache.ttl())
            .finish()
    }
}

#[derive(Debug)]
enum CredentialProviderErrorKind {
    NoDefaultCredentials,
    DefaultChainFailures(Vec<ProviderFailure>),
    BlockingDefaultChainFailures(Vec<ProviderFailure>),
    MetadataEndpointStatus {
        endpoint: MetadataEndpoint,
        status: reqwest::StatusCode,
    },
    EmptyImdsToken,
    MissingImdsRoleName,
    PartialEnvironmentCredentials,
    AwsCliRunFailed(String),
    AwsCliProfileExportFailed {
        profile: String,
        reason: String,
    },
    InvalidAwsCliCredentialJson(String),
    EcsRelativeUriMustBePath,
    EcsFullUriMissingHost,
    EcsFullUriRequiresHttpsOrLocal,
    EcsFullUriRequiresHttpOrHttps,
    EmptyAuthorizationTokenFile(String),
    IncompleteCredentialResponse,
}

#[derive(Debug)]
struct ProviderFailure {
    source: CredentialProviderSource,
    error: String,
}

impl ProviderFailure {
    fn new(source: CredentialProviderSource, error: &CredentialProviderError) -> Self {
        Self {
            source,
            error: error.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum CredentialProviderSource {
    AwsCliProfile,
    EcsTaskMetadata,
    Imds,
}

#[derive(Debug, Clone, Copy)]
enum MetadataEndpoint {
    Credential,
    Credentials,
    Token,
    RoleListing,
    RoleCredentials,
}

impl fmt::Display for CredentialProviderErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDefaultCredentials => f.write_str(
                "no credentials found in environment variables, ECS task metadata, or IMDS",
            ),
            Self::DefaultChainFailures(failures) => {
                write!(f, "credential providers failed: ")?;
                write_provider_failures(f, failures)
            }
            Self::BlockingDefaultChainFailures(failures) => {
                write!(f, "failed to resolve credentials from default chain: ")?;
                write_provider_failures(f, failures)
            }
            Self::MetadataEndpointStatus { endpoint, status } => {
                write!(f, "{endpoint} endpoint returned status {status}")
            }
            Self::EmptyImdsToken => f.write_str("token endpoint returned an empty token"),
            Self::MissingImdsRoleName => f.write_str("role listing endpoint returned no role name"),
            Self::PartialEnvironmentCredentials => {
                f.write_str("AWS credential environment variables are partially configured")
            }
            Self::AwsCliRunFailed(error) => write!(f, "failed to run aws cli: {error}"),
            Self::AwsCliProfileExportFailed { profile, reason } => {
                write!(
                    f,
                    "failed to export credentials for profile `{profile}`: {reason}"
                )
            }
            Self::InvalidAwsCliCredentialJson(error) => {
                write!(f, "invalid aws cli credential JSON: {error}")
            }
            Self::EcsRelativeUriMustBePath => {
                f.write_str("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI must be a path")
            }
            Self::EcsFullUriMissingHost => {
                f.write_str("AWS_CONTAINER_CREDENTIALS_FULL_URI is missing a host")
            }
            Self::EcsFullUriRequiresHttpsOrLocal => f.write_str(
                "AWS_CONTAINER_CREDENTIALS_FULL_URI must use HTTPS or a loopback/local ECS host",
            ),
            Self::EcsFullUriRequiresHttpOrHttps => {
                f.write_str("AWS_CONTAINER_CREDENTIALS_FULL_URI must use HTTP or HTTPS")
            }
            Self::EmptyAuthorizationTokenFile(path) => {
                write!(f, "authorization token file `{path}` was empty")
            }
            Self::IncompleteCredentialResponse => f.write_str(
                "credential response did not include access key id and secret access key",
            ),
        }
    }
}

impl std::error::Error for CredentialProviderErrorKind {}

impl fmt::Display for ProviderFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.source, self.error)
    }
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

fn write_provider_failures(
    f: &mut fmt::Formatter<'_>,
    failures: &[ProviderFailure],
) -> fmt::Result {
    for (index, failure) in failures.iter().enumerate() {
        if index > 0 {
            f.write_str("; ")?;
        }
        write!(f, "{failure}")?;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MetadataCredentialsResponse {
    access_key_id: String,
    secret_access_key: String,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    expiration: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AwsCliCredentialProcessOutput {
    access_key_id: String,
    secret_access_key: String,
    #[serde(default)]
    session_token: Option<String>,
    #[serde(default)]
    expiration: Option<String>,
}

impl DefaultChainCredentialsProvider {
    fn new() -> Result<Self, SigningError> {
        let client = reqwest::Client::builder()
            .connect_timeout(METADATA_CONNECT_TIMEOUT)
            .timeout(METADATA_REQUEST_TIMEOUT)
            .build()
            .map_err(|err| {
                SigningError::Credentials(CredentialErrorKind::HttpClientInit(err.to_string()))
            })?;

        Ok(Self {
            client,
            cache: LruTtlCache::new(
                CacheConfig::new()
                    .with_capacity(CREDENTIAL_CACHE_CAPACITY)
                    .with_ttl(CREDENTIAL_CACHE_STATIC_TTL),
            ),
        })
    }

    async fn load_credentials(&self) -> provider::Result {
        if let Some(credentials) = self.cached_credentials() {
            return Ok(credentials);
        }

        let resolved = self.resolve_default_chain().await?;
        self.store_cached_credentials(&resolved);
        Ok(resolved.credentials)
    }

    fn cached_credentials(&self) -> Option<Credentials> {
        self.cache.get(&DEFAULT_CREDENTIAL_CACHE_KEY)
    }

    fn store_cached_credentials(&self, resolved: &ResolvedCredentials) {
        self.cache.insert_with_ttl(
            DEFAULT_CREDENTIAL_CACHE_KEY,
            resolved.credentials.clone(),
            credential_cache_ttl(resolved.refresh_after),
        );
    }

    async fn resolve_default_chain(&self) -> CredentialProviderResult<ResolvedCredentials> {
        if let Some(credentials) = resolve_environment_credentials()? {
            return Ok(credentials);
        }

        let mut provider_errors = Vec::new();

        match resolve_profile_credentials() {
            Ok(Some(credentials)) => return Ok(credentials),
            Ok(None) => {}
            Err(err) => provider_errors.push(ProviderFailure::new(
                CredentialProviderSource::AwsCliProfile,
                &err,
            )),
        }

        match self.resolve_ecs_task_credentials().await {
            Ok(Some(credentials)) => return Ok(credentials),
            Ok(None) => {}
            Err(err) => provider_errors.push(ProviderFailure::new(
                CredentialProviderSource::EcsTaskMetadata,
                &err,
            )),
        }

        match self.resolve_imds_credentials().await {
            Ok(Some(credentials)) => return Ok(credentials),
            Ok(None) => {}
            Err(err) => {
                provider_errors.push(ProviderFailure::new(CredentialProviderSource::Imds, &err));
            }
        }

        if provider_errors.is_empty() {
            return Err(not_loaded_error(
                CredentialProviderErrorKind::NoDefaultCredentials,
            ));
        }

        Err(not_loaded_error(
            CredentialProviderErrorKind::DefaultChainFailures(provider_errors),
        ))
    }

    async fn resolve_ecs_task_credentials(
        &self,
    ) -> CredentialProviderResult<Option<ResolvedCredentials>> {
        let Some(uri) = resolve_ecs_task_credentials_uri()? else {
            return Ok(None);
        };

        let mut request = self.client.get(uri);
        if let Some(token) = resolve_ecs_authorization_token()? {
            request = request.header(REQWEST_AUTHORIZATION, token);
        }

        let response = request
            .send()
            .await
            .map_err(provider::error::CredentialsError::provider_error)?;
        if !response.status().is_success() {
            return Err(provider_error_message(
                CredentialProviderErrorKind::MetadataEndpointStatus {
                    endpoint: MetadataEndpoint::Credential,
                    status: response.status(),
                },
            ));
        }

        let payload = response
            .json::<MetadataCredentialsResponse>()
            .await
            .map_err(provider::error::CredentialsError::provider_error)?;

        metadata_to_credentials(payload, ECS_TASK_METADATA_PROVIDER_NAME).map(Some)
    }

    async fn resolve_imds_credentials(
        &self,
    ) -> CredentialProviderResult<Option<ResolvedCredentials>> {
        if ec2_metadata_is_disabled() {
            return Ok(None);
        }

        let token_response = self
            .client
            .put(IMDS_TOKEN_URL)
            .header(IMDS_TOKEN_TTL_HEADER, IMDS_TOKEN_TTL_SECONDS)
            .send()
            .await
            .map_err(provider::error::CredentialsError::provider_error)?;
        if !token_response.status().is_success() {
            return Err(provider_error_message(
                CredentialProviderErrorKind::MetadataEndpointStatus {
                    endpoint: MetadataEndpoint::Token,
                    status: token_response.status(),
                },
            ));
        }

        let token_body = token_response
            .text()
            .await
            .map_err(provider::error::CredentialsError::provider_error)?;
        let token = token_body.trim().to_owned();
        if token.is_empty() {
            return Err(provider_error_message(
                CredentialProviderErrorKind::EmptyImdsToken,
            ));
        }

        let role_response = self
            .client
            .get(IMDS_ROLE_LIST_URL)
            .header(IMDS_TOKEN_HEADER, token.as_str())
            .send()
            .await
            .map_err(provider::error::CredentialsError::provider_error)?;
        if !role_response.status().is_success() {
            return Err(provider_error_message(
                CredentialProviderErrorKind::MetadataEndpointStatus {
                    endpoint: MetadataEndpoint::RoleListing,
                    status: role_response.status(),
                },
            ));
        }

        let role_body = role_response
            .text()
            .await
            .map_err(provider::error::CredentialsError::provider_error)?;
        let role_name = role_body
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .ok_or_else(|| {
                provider_error_message(CredentialProviderErrorKind::MissingImdsRoleName)
            })?
            .to_owned();

        let role_credentials_url = format!("{IMDS_ROLE_LIST_URL}{role_name}");
        let credentials_response = self
            .client
            .get(role_credentials_url)
            .header(IMDS_TOKEN_HEADER, token)
            .send()
            .await
            .map_err(provider::error::CredentialsError::provider_error)?;
        if !credentials_response.status().is_success() {
            return Err(provider_error_message(
                CredentialProviderErrorKind::MetadataEndpointStatus {
                    endpoint: MetadataEndpoint::RoleCredentials,
                    status: credentials_response.status(),
                },
            ));
        }

        let payload = credentials_response
            .json::<MetadataCredentialsResponse>()
            .await
            .map_err(provider::error::CredentialsError::provider_error)?;

        metadata_to_credentials(payload, IMDS_PROVIDER_NAME).map(Some)
    }
}

impl ProvideCredentials for DefaultChainCredentialsProvider {
    fn provide_credentials<'a>(&'a self) -> provider::future::ProvideCredentials<'a>
    where Self: 'a {
        provider::future::ProvideCredentials::new(self.load_credentials())
    }
}

fn resolve_default_chain_blocking() -> CredentialProviderResult<ResolvedCredentials> {
    if let Some(credentials) = resolve_environment_credentials()? {
        return Ok(credentials);
    }

    let mut provider_errors = Vec::new();

    match resolve_profile_credentials() {
        Ok(Some(credentials)) => return Ok(credentials),
        Ok(None) => {}
        Err(err) => provider_errors.push(ProviderFailure::new(
            CredentialProviderSource::AwsCliProfile,
            &err,
        )),
    }

    match resolve_ecs_task_credentials_blocking() {
        Ok(Some(credentials)) => return Ok(credentials),
        Ok(None) => {}
        Err(err) => provider_errors.push(ProviderFailure::new(
            CredentialProviderSource::EcsTaskMetadata,
            &err,
        )),
    }

    match resolve_imds_credentials_blocking() {
        Ok(Some(credentials)) => return Ok(credentials),
        Ok(None) => {}
        Err(err) => {
            provider_errors.push(ProviderFailure::new(CredentialProviderSource::Imds, &err));
        }
    }

    if provider_errors.is_empty() {
        return Err(not_loaded_error(
            CredentialProviderErrorKind::NoDefaultCredentials,
        ));
    }

    Err(provider_error_message(
        CredentialProviderErrorKind::BlockingDefaultChainFailures(provider_errors),
    ))
}

fn resolve_environment_credentials() -> CredentialProviderResult<Option<ResolvedCredentials>> {
    let access_key_id =
        non_empty_env_var(AWS_ACCESS_KEY_ID).or_else(|| non_empty_env_var(AWS_ACCESS_KEY));
    let secret_access_key =
        non_empty_env_var(AWS_SECRET_ACCESS_KEY).or_else(|| non_empty_env_var(AWS_SECRET_KEY));

    match (access_key_id, secret_access_key) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(invalid_configuration_message(
            CredentialProviderErrorKind::PartialEnvironmentCredentials,
        )),
        (Some(access_key_id), Some(secret_access_key)) => {
            let session_token = non_empty_env_var(AWS_SESSION_TOKEN);
            let credentials = Credentials::new(
                access_key_id,
                secret_access_key,
                session_token,
                None,
                ENVIRONMENT_PROVIDER_NAME,
            );
            Ok(Some(ResolvedCredentials {
                credentials,
                refresh_after: None,
            }))
        }
    }
}

fn resolve_profile_credentials() -> CredentialProviderResult<Option<ResolvedCredentials>> {
    let profile = requested_profile_name();
    if !should_try_profile_credentials(profile.as_deref()) {
        return Ok(None);
    }

    let mut command = Command::new("aws");
    command
        .arg("configure")
        .arg("export-credentials")
        .arg("--format")
        .arg("process");
    if let Some(profile_name) = profile.as_deref() {
        command.arg("--profile").arg(profile_name);
    }

    let output = command.output().map_err(|err| {
        provider_error_message(CredentialProviderErrorKind::AwsCliRunFailed(
            err.to_string(),
        ))
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let profile_name = profile.as_deref().unwrap_or(AWS_CLI_PROFILE_DEFAULT);
        let reason = if stderr.is_empty() {
            format!("exit status {}", output.status)
        } else {
            stderr
        };
        return Err(provider_error_message(
            CredentialProviderErrorKind::AwsCliProfileExportFailed {
                profile: profile_name.to_owned(),
                reason,
            },
        ));
    }

    let parsed: AwsCliCredentialProcessOutput =
        serde_json::from_slice(&output.stdout).map_err(|err| {
            provider_error_message(CredentialProviderErrorKind::InvalidAwsCliCredentialJson(
                err.to_string(),
            ))
        })?;
    metadata_to_credentials(
        MetadataCredentialsResponse {
            access_key_id: parsed.access_key_id,
            secret_access_key: parsed.secret_access_key,
            token: parsed.session_token,
            expiration: parsed.expiration,
        },
        AWS_CLI_CREDENTIAL_PROVIDER_NAME,
    )
    .map(Some)
}

fn blocking_metadata_http_client() -> CredentialProviderResult<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .connect_timeout(METADATA_CONNECT_TIMEOUT)
        .timeout(METADATA_REQUEST_TIMEOUT)
        .build()
        .map_err(provider::error::CredentialsError::provider_error)
}

fn resolve_ecs_task_credentials_blocking() -> CredentialProviderResult<Option<ResolvedCredentials>>
{
    let Some(uri) = resolve_ecs_task_credentials_uri()? else {
        return Ok(None);
    };

    let client = blocking_metadata_http_client()?;
    let mut request = client.get(uri);
    if let Some(token) = resolve_ecs_authorization_token()? {
        request = request.header(REQWEST_AUTHORIZATION, token);
    }

    let response = request
        .send()
        .map_err(provider::error::CredentialsError::provider_error)?;
    if !response.status().is_success() {
        return Err(provider_error_message(
            CredentialProviderErrorKind::MetadataEndpointStatus {
                endpoint: MetadataEndpoint::Credentials,
                status: response.status(),
            },
        ));
    }

    let payload = response
        .json::<MetadataCredentialsResponse>()
        .map_err(provider::error::CredentialsError::provider_error)?;

    metadata_to_credentials(payload, ECS_TASK_METADATA_PROVIDER_NAME).map(Some)
}

fn resolve_imds_credentials_blocking() -> CredentialProviderResult<Option<ResolvedCredentials>> {
    if ec2_metadata_is_disabled() {
        return Ok(None);
    }

    let client = blocking_metadata_http_client()?;
    let token_response = client
        .put(IMDS_TOKEN_URL)
        .header(IMDS_TOKEN_TTL_HEADER, IMDS_TOKEN_TTL_SECONDS)
        .send()
        .map_err(provider::error::CredentialsError::provider_error)?;
    if !token_response.status().is_success() {
        return Err(provider_error_message(
            CredentialProviderErrorKind::MetadataEndpointStatus {
                endpoint: MetadataEndpoint::Token,
                status: token_response.status(),
            },
        ));
    }

    let token = token_response
        .text()
        .map_err(provider::error::CredentialsError::provider_error)?;
    if token.trim().is_empty() {
        return Err(provider_error_message(
            CredentialProviderErrorKind::EmptyImdsToken,
        ));
    }

    let role_list_response = client
        .get(IMDS_ROLE_LIST_URL)
        .header(IMDS_TOKEN_HEADER, token.as_str())
        .send()
        .map_err(provider::error::CredentialsError::provider_error)?;
    if !role_list_response.status().is_success() {
        return Err(provider_error_message(
            CredentialProviderErrorKind::MetadataEndpointStatus {
                endpoint: MetadataEndpoint::RoleListing,
                status: role_list_response.status(),
            },
        ));
    }

    let role_body = role_list_response
        .text()
        .map_err(provider::error::CredentialsError::provider_error)?;
    let role_name = role_body
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| provider_error_message(CredentialProviderErrorKind::MissingImdsRoleName))?
        .to_owned();

    let credentials_response = client
        .get(format!("{IMDS_ROLE_LIST_URL}{role_name}"))
        .header(IMDS_TOKEN_HEADER, token)
        .send()
        .map_err(provider::error::CredentialsError::provider_error)?;
    if !credentials_response.status().is_success() {
        return Err(provider_error_message(
            CredentialProviderErrorKind::MetadataEndpointStatus {
                endpoint: MetadataEndpoint::RoleCredentials,
                status: credentials_response.status(),
            },
        ));
    }

    let payload = credentials_response
        .json::<MetadataCredentialsResponse>()
        .map_err(provider::error::CredentialsError::provider_error)?;

    metadata_to_credentials(payload, IMDS_PROVIDER_NAME).map(Some)
}

fn requested_profile_name() -> Option<String> {
    non_empty_env_var(AWS_PROFILE).or_else(|| non_empty_env_var(AWS_DEFAULT_PROFILE))
}

fn should_try_profile_credentials(profile: Option<&str>) -> bool {
    profile.is_some()
        || non_empty_env_var(AWS_CONFIG_FILE).is_some()
        || non_empty_env_var(AWS_SHARED_CREDENTIALS_FILE).is_some()
        || default_aws_profile_files_exist()
}

fn default_aws_profile_files_exist() -> bool {
    let Some(home_dir) = non_empty_env_var(HOME) else {
        return false;
    };
    let home_path = Path::new(&home_dir);
    home_path.join(AWS_CONFIG_RELATIVE_PATH).exists()
        || home_path.join(AWS_CREDENTIALS_RELATIVE_PATH).exists()
}

pub(crate) fn resolve_ecs_task_credentials_uri() -> CredentialProviderResult<Option<Url>> {
    if let Some(full_uri) = non_empty_env_var(AWS_CONTAINER_CREDENTIALS_FULL_URI) {
        let uri = Url::parse(&full_uri)
            .map_err(provider::error::CredentialsError::invalid_configuration)?;
        validate_ecs_full_uri(&uri)?;
        return Ok(Some(uri));
    }

    let Some(relative_uri) = non_empty_env_var(AWS_CONTAINER_CREDENTIALS_RELATIVE_URI) else {
        return Ok(None);
    };

    if relative_uri.starts_with("//") {
        return Err(invalid_configuration_message(
            CredentialProviderErrorKind::EcsRelativeUriMustBePath,
        ));
    }

    let normalized = if relative_uri.starts_with('/') {
        relative_uri
    } else {
        format!("/{relative_uri}")
    };

    let uri = Url::parse(ECS_RELATIVE_CREDENTIALS_BASE)
        .and_then(|base| base.join(&normalized))
        .map_err(provider::error::CredentialsError::invalid_configuration)?;

    Ok(Some(uri))
}

pub(crate) fn validate_ecs_full_uri(uri: &Url) -> CredentialProviderResult<()> {
    match uri.scheme() {
        "https" => Ok(()),
        "http" => {
            let Some(host) = uri.host_str() else {
                return Err(invalid_configuration_message(
                    CredentialProviderErrorKind::EcsFullUriMissingHost,
                ));
            };
            if matches!(
                host,
                ECS_LOCAL_IPV4_HOST | LOCALHOST | LOOPBACK_IPV4 | LOOPBACK_IPV6
            ) {
                Ok(())
            } else {
                Err(invalid_configuration_message(
                    CredentialProviderErrorKind::EcsFullUriRequiresHttpsOrLocal,
                ))
            }
        }
        _ => Err(invalid_configuration_message(
            CredentialProviderErrorKind::EcsFullUriRequiresHttpOrHttps,
        )),
    }
}

pub(crate) fn resolve_ecs_authorization_token() -> CredentialProviderResult<Option<String>> {
    if let Some(token_file) = non_empty_env_var(AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE) {
        let token = std::fs::read_to_string(&token_file)
            .map_err(provider::error::CredentialsError::provider_error)?;
        let trimmed = token.trim().to_owned();
        if trimmed.is_empty() {
            return Err(provider_error_message(
                CredentialProviderErrorKind::EmptyAuthorizationTokenFile(token_file),
            ));
        }
        return Ok(Some(trimmed));
    }

    Ok(non_empty_env_var(AWS_CONTAINER_AUTHORIZATION_TOKEN))
}

fn ec2_metadata_is_disabled() -> bool {
    non_empty_env_var(AWS_EC2_METADATA_DISABLED)
        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

fn metadata_to_credentials(
    response: MetadataCredentialsResponse,
    provider_name: &'static str,
) -> CredentialProviderResult<ResolvedCredentials> {
    if response.access_key_id.trim().is_empty() || response.secret_access_key.trim().is_empty() {
        return Err(provider_error_message(
            CredentialProviderErrorKind::IncompleteCredentialResponse,
        ));
    }

    let expires_after = response
        .expiration
        .as_deref()
        .and_then(parse_expiration_datetime);

    let refresh_after = Some(match expires_after {
        Some(expires_after) => expires_after
            .checked_sub(CREDENTIAL_REFRESH_SKEW)
            .unwrap_or_else(|| SystemTime::now() + CREDENTIAL_REFRESH_FALLBACK),
        None => SystemTime::now() + CREDENTIAL_REFRESH_FALLBACK,
    });

    Ok(ResolvedCredentials {
        credentials: Credentials::new(
            response.access_key_id,
            response.secret_access_key,
            response.token,
            expires_after,
            provider_name,
        ),
        refresh_after,
    })
}

pub(crate) fn half_life_refresh_after(
    now: SystemTime,
    expires_after: Option<SystemTime>,
) -> Option<SystemTime> {
    let expires_after = expires_after?;
    let Ok(remaining) = expires_after.duration_since(now) else {
        return Some(now);
    };
    Some(now + remaining / 2)
}

fn parse_expiration_datetime(value: &str) -> Option<SystemTime> {
    let parsed = DateTime::from_str(value, Format::DateTime).ok()?;
    SystemTime::try_from(parsed).ok()
}

fn credential_cache_ttl(refresh_after: Option<SystemTime>) -> Duration {
    let Some(refresh_after) = refresh_after else {
        return CREDENTIAL_CACHE_STATIC_TTL;
    };
    refresh_after
        .duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO)
}

fn non_empty_env_var(name: &str) -> Option<String> {
    env::var(name).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

fn invalid_configuration_message(kind: CredentialProviderErrorKind) -> CredentialProviderError {
    CredentialProviderError::invalid_configuration(io::Error::other(kind))
}

fn provider_error_message(kind: CredentialProviderErrorKind) -> CredentialProviderError {
    CredentialProviderError::provider_error(io::Error::other(kind))
}

fn not_loaded_error(kind: CredentialProviderErrorKind) -> CredentialProviderError {
    CredentialProviderError::not_loaded(io::Error::other(kind))
}

fn static_credentials(creds: &AwsStaticCredentials) -> Credentials {
    Credentials::new(
        creds.access_key_id.clone(),
        creds.secret_access_key.clone(),
        creds.session_token.clone(),
        None,
        STATIC_PROVIDER_NAME,
    )
}
