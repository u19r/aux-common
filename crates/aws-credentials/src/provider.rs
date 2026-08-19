use std::{
    env, fmt,
    io::{self, Read},
    path::Path,
    process::{Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime},
};

use aws_credential_types::{
    Credentials,
    provider::{self, ProvideCredentials},
};
use aws_smithy_types::date_time::{DateTime, Format};
use futures_util::StreamExt;
use lru_ttl_cache::{CacheConfig, KeyedSingleflight, LruTtlCache};
use reqwest::header::AUTHORIZATION as REQWEST_AUTHORIZATION;
use serde::Deserialize;
use url::Url;

use crate::constants::{
    AWS_ACCESS_KEY, AWS_ACCESS_KEY_ID, AWS_CLI_COMMAND_TIMEOUT, AWS_CLI_CREDENTIAL_PROVIDER_NAME,
    AWS_CONFIG_FILE, AWS_CONFIG_RELATIVE_PATH, AWS_CONTAINER_AUTHORIZATION_TOKEN,
    AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE, AWS_CONTAINER_CREDENTIALS_FULL_URI,
    AWS_CONTAINER_CREDENTIALS_RELATIVE_URI, AWS_CREDENTIALS_RELATIVE_PATH, AWS_DEFAULT_PROFILE,
    AWS_EC2_METADATA_DISABLED, AWS_PROFILE, AWS_SECRET_ACCESS_KEY, AWS_SECRET_KEY,
    AWS_SESSION_TOKEN, AWS_SHARED_CREDENTIALS_FILE, CREDENTIAL_CACHE_CAPACITY,
    CREDENTIAL_CACHE_STATIC_TTL, CREDENTIAL_REFRESH_FALLBACK, CREDENTIAL_REFRESH_SKEW,
    DEFAULT_CREDENTIAL_CACHE_KEY, ECS_RELATIVE_CREDENTIALS_BASE, ECS_TASK_METADATA_PROVIDER_NAME,
    ENVIRONMENT_PROVIDER_NAME, HOME, IMDS_PROVIDER_NAME, IMDS_ROLE_LIST_URL, IMDS_TOKEN_HEADER,
    IMDS_TOKEN_TTL_HEADER, IMDS_TOKEN_TTL_SECONDS, IMDS_TOKEN_URL, LOCALHOST,
    MAX_AUTHORIZATION_TOKEN_BYTES, MAX_AWS_CLI_OUTPUT_BYTES, MAX_METADATA_RESPONSE_BYTES,
    METADATA_CONNECT_TIMEOUT, METADATA_REQUEST_TIMEOUT, STATIC_PROVIDER_NAME,
};

pub(crate) type CredentialProviderError = provider::error::CredentialsError;
pub(crate) type CredentialProviderResult<T> = Result<T, CredentialProviderError>;

#[derive(Clone)]
pub struct AwsStaticCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

#[derive(Clone)]
pub struct AwsResolvedCredentials {
    pub credentials: AwsStaticCredentials,
    pub expires_after: Option<SystemTime>,
    pub refresh_after: Option<SystemTime>,
}

impl AwsResolvedCredentials {
    #[must_use]
    pub fn needs_refresh(&self) -> bool {
        self.needs_refresh_at(SystemTime::now())
    }

    #[must_use]
    pub fn needs_refresh_at(&self, now: SystemTime) -> bool {
        self.refresh_after
            .is_some_and(|refresh_after| now >= refresh_after)
    }
}

#[derive(Clone)]
pub enum CredentialSource {
    DefaultChain,
    Static(AwsStaticCredentials),
}

pub fn resolve_default_chain_credentials() -> CredentialProviderResult<AwsStaticCredentials> {
    Ok(resolve_default_chain_credentials_with_expiry()?.credentials)
}

pub fn resolve_default_chain_credentials_with_expiry()
-> CredentialProviderResult<AwsResolvedCredentials> {
    let resolved = resolve_default_chain_blocking()?;
    Ok(resolved.into_public(SystemTime::now()))
}

#[derive(Clone)]
pub struct DefaultChainCredentialsProvider {
    client: reqwest::Client,
    cache: LruTtlCache<&'static str, Credentials>,
    refresh_flight: KeyedSingleflight<&'static str>,
}

#[derive(Clone)]
struct ResolvedCredentials {
    credentials: Credentials,
    refresh_after: Option<SystemTime>,
}

impl ResolvedCredentials {
    fn into_public(self, now: SystemTime) -> AwsResolvedCredentials {
        let expires_after = self.credentials.expiry();
        AwsResolvedCredentials {
            credentials: AwsStaticCredentials {
                access_key_id: self.credentials.access_key_id().to_string(),
                secret_access_key: self.credentials.secret_access_key().to_string(),
                session_token: self.credentials.session_token().map(ToOwned::to_owned),
            },
            expires_after,
            refresh_after: self
                .refresh_after
                .or_else(|| half_life_refresh_after(now, expires_after)),
        }
    }
}

impl fmt::Debug for AwsStaticCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsStaticCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl fmt::Debug for AwsResolvedCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsResolvedCredentials")
            .field("credentials", &self.credentials)
            .field("expires_after", &self.expires_after)
            .field("refresh_after", &self.refresh_after)
            .finish()
    }
}

impl fmt::Debug for CredentialSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefaultChain => formatter.write_str("DefaultChain"),
            Self::Static(credentials) => {
                formatter.debug_tuple("Static").field(credentials).finish()
            }
        }
    }
}

impl fmt::Debug for ResolvedCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedCredentials")
            .field("credentials", &"[REDACTED]")
            .field("refresh_after", &self.refresh_after)
            .finish()
    }
}

impl fmt::Debug for DefaultChainCredentialsProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DefaultChainCredentialsProvider")
            .field("client", &self.client)
            .field("cache_ttl", &self.cache.ttl())
            .field("refresh_flight", &"[SINGLEFLIGHT]")
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
    AwsCliRunFailed,
    AwsCliProfileExportFailed,
    AwsCliOutputTooLarge,
    AwsCliTimedOut,
    AuthorizationTokenFileTooLarge,
    InvalidAwsCliCredentialJson,
    EcsRelativeUriMustBePath,
    EcsFullUriMissingHost,
    EcsFullUriRequiresHttpsOrLocal,
    EcsFullUriRequiresHttpOrHttps,
    EmptyAuthorizationTokenFile,
    IncompleteCredentialResponse,
    MetadataRequestFailed,
    ProviderClientInitFailed,
    MetadataResponseInvalid,
    MetadataCredentialsJsonInvalid,
    MetadataCredentialsTextInvalid,
    AuthorizationTokenFileReadFailed,
    AuthorizationTokenFileInvalidUtf8,
    InvalidEcsCredentialsUri,
}

#[derive(Debug)]
struct ProviderFailure {
    source: CredentialProviderSource,
    error: &'static str,
}

impl ProviderFailure {
    fn new(source: CredentialProviderSource, _error: &CredentialProviderError) -> Self {
        Self {
            source,
            error: "provider request failed",
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
            Self::AwsCliRunFailed => f.write_str("failed to run aws cli credential provider"),
            Self::AwsCliProfileExportFailed => {
                f.write_str("aws cli credential provider rejected the requested profile")
            }
            Self::AwsCliOutputTooLarge => {
                write!(f, "aws cli credential output exceeds configured limit")
            }
            Self::AwsCliTimedOut => f.write_str("aws cli credential command timed out"),
            Self::AuthorizationTokenFileTooLarge => {
                write!(f, "authorization token file exceeds configured limit")
            }
            Self::InvalidAwsCliCredentialJson => {
                f.write_str("aws cli credential provider returned invalid JSON")
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
            Self::EmptyAuthorizationTokenFile => f.write_str("authorization token file was empty"),
            Self::IncompleteCredentialResponse => f.write_str(
                "credential response did not include access key id and secret access key",
            ),
            Self::MetadataRequestFailed => f.write_str("metadata request failed"),
            Self::ProviderClientInitFailed => {
                f.write_str("credential provider client initialization failed")
            }
            Self::MetadataResponseInvalid => {
                f.write_str("credential metadata response was invalid")
            }
            Self::MetadataCredentialsJsonInvalid => {
                f.write_str("credential metadata response was not valid JSON")
            }
            Self::MetadataCredentialsTextInvalid => {
                f.write_str("credential metadata response was not valid UTF-8")
            }
            Self::AuthorizationTokenFileReadFailed => {
                f.write_str("authorization token file could not be read")
            }
            Self::AuthorizationTokenFileInvalidUtf8 => {
                f.write_str("authorization token file was not valid UTF-8")
            }
            Self::InvalidEcsCredentialsUri => f.write_str("ECS credentials URI was invalid"),
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
    pub fn new() -> CredentialProviderResult<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(METADATA_CONNECT_TIMEOUT)
            .timeout(METADATA_REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| {
                provider_error_message(CredentialProviderErrorKind::ProviderClientInitFailed)
            })?;

        Ok(Self {
            client,
            cache: LruTtlCache::new(
                CacheConfig::new()
                    .with_capacity(CREDENTIAL_CACHE_CAPACITY)
                    .with_ttl(CREDENTIAL_CACHE_STATIC_TTL),
            ),
            refresh_flight: KeyedSingleflight::default(),
        })
    }

    async fn load_credentials(&self) -> provider::Result {
        if let Some(credentials) = self.cached_credentials() {
            return Ok(credentials);
        }

        // Re-check under the singleflight guard.  Without this second cache
        // read every concurrent miss could independently walk the profile,
        // ECS, and IMDS chain before any of them stored the result.
        let _guard = self
            .refresh_flight
            .lock(&DEFAULT_CREDENTIAL_CACHE_KEY)
            .await;
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
            credential_cache_ttl(resolved.refresh_after, SystemTime::now()),
        );
    }

    async fn resolve_default_chain(&self) -> CredentialProviderResult<ResolvedCredentials> {
        if let Some(credentials) = resolve_environment_credentials()? {
            return Ok(credentials);
        }

        let mut provider_errors = Vec::new();

        match resolve_profile_credentials_async().await {
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

        let response = request.send().await.map_err(|_| metadata_request_error())?;
        if !response.status().is_success() {
            return Err(provider_error_message(
                CredentialProviderErrorKind::MetadataEndpointStatus {
                    endpoint: MetadataEndpoint::Credential,
                    status: response.status(),
                },
            ));
        }

        let body = bounded_response_body(response).await.map_err(|_| {
            provider_error_message(CredentialProviderErrorKind::MetadataResponseInvalid)
        })?;
        let payload =
            serde_json::from_slice::<MetadataCredentialsResponse>(&body).map_err(|_| {
                provider_error_message(CredentialProviderErrorKind::MetadataCredentialsJsonInvalid)
            })?;

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
            .map_err(|_| metadata_request_error())?;
        if !token_response.status().is_success() {
            return Err(provider_error_message(
                CredentialProviderErrorKind::MetadataEndpointStatus {
                    endpoint: MetadataEndpoint::Token,
                    status: token_response.status(),
                },
            ));
        }

        let token_body = bounded_response_body(token_response).await.map_err(|_| {
            provider_error_message(CredentialProviderErrorKind::MetadataResponseInvalid)
        })?;
        let token = std::str::from_utf8(&token_body)
            .map_err(|_| {
                provider_error_message(CredentialProviderErrorKind::MetadataCredentialsTextInvalid)
            })?
            .trim()
            .to_owned();
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
            .map_err(|_| metadata_request_error())?;
        if !role_response.status().is_success() {
            return Err(provider_error_message(
                CredentialProviderErrorKind::MetadataEndpointStatus {
                    endpoint: MetadataEndpoint::RoleListing,
                    status: role_response.status(),
                },
            ));
        }

        let role_body = bounded_response_body(role_response).await.map_err(|_| {
            provider_error_message(CredentialProviderErrorKind::MetadataResponseInvalid)
        })?;
        let role_name = std::str::from_utf8(&role_body)
            .map_err(|_| {
                provider_error_message(CredentialProviderErrorKind::MetadataCredentialsTextInvalid)
            })?
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
            .map_err(|_| metadata_request_error())?;
        if !credentials_response.status().is_success() {
            return Err(provider_error_message(
                CredentialProviderErrorKind::MetadataEndpointStatus {
                    endpoint: MetadataEndpoint::RoleCredentials,
                    status: credentials_response.status(),
                },
            ));
        }

        let body = bounded_response_body(credentials_response)
            .await
            .map_err(|_| {
                provider_error_message(CredentialProviderErrorKind::MetadataResponseInvalid)
            })?;
        let payload =
            serde_json::from_slice::<MetadataCredentialsResponse>(&body).map_err(|_| {
                provider_error_message(CredentialProviderErrorKind::MetadataCredentialsJsonInvalid)
            })?;

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

    let client = blocking_metadata_http_client()?;

    match resolve_ecs_task_credentials_with_blocking_client(&client) {
        Ok(Some(credentials)) => return Ok(credentials),
        Ok(None) => {}
        Err(err) => provider_errors.push(ProviderFailure::new(
            CredentialProviderSource::EcsTaskMetadata,
            &err,
        )),
    }

    match resolve_imds_credentials_with_blocking_client(&client) {
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

async fn resolve_profile_credentials_async() -> CredentialProviderResult<Option<ResolvedCredentials>>
{
    tokio::task::spawn_blocking(resolve_profile_credentials)
        .await
        .map_err(|_| provider_error_message(CredentialProviderErrorKind::AwsCliRunFailed))?
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

pub(crate) struct BoundedCommandOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) timed_out: bool,
}

pub(crate) fn run_bounded_command(mut command: Command) -> io::Result<BoundedCommandOutput> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("aws cli stdout pipe was not captured"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("aws cli stderr pipe was not captured"))?;
    let output_too_large = Arc::new(AtomicBool::new(false));
    let stdout_too_large = Arc::clone(&output_too_large);
    let stderr_too_large = Arc::clone(&output_too_large);
    let stdout_reader = thread::spawn(move || {
        read_capped(stdout, MAX_AWS_CLI_OUTPUT_BYTES, stdout_too_large.as_ref())
    });
    let stderr_reader = thread::spawn(move || {
        read_capped(stderr, MAX_AWS_CLI_OUTPUT_BYTES, stderr_too_large.as_ref())
    });

    let deadline = Instant::now() + AWS_CLI_COMMAND_TIMEOUT;
    let (status, timed_out) = loop {
        if output_too_large.load(Ordering::Acquire) {
            let _ = child.kill();
            break (child.wait()?, false);
        }
        if let Some(status) = child.try_wait()? {
            break (status, false);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            break (child.wait()?, true);
        }
        thread::sleep(Duration::from_millis(10));
    };

    let stdout = join_command_reader(stdout_reader)?;
    let stderr = join_command_reader(stderr_reader)?;
    Ok(BoundedCommandOutput {
        status,
        stdout,
        stderr,
        timed_out,
    })
}

fn read_capped<R: Read>(
    mut reader: R,
    limit: usize,
    output_too_large: &AtomicBool,
) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(limit.saturating_add(1));
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(output);
        }
        let remaining = limit.saturating_add(1).saturating_sub(output.len());
        output.extend_from_slice(&buffer[..read.min(remaining)]);
        if output.len() > limit {
            output_too_large.store(true, Ordering::Release);
            return Ok(output);
        }
    }
}

fn join_command_reader(reader: thread::JoinHandle<io::Result<Vec<u8>>>) -> io::Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| io::Error::other("aws cli output reader panicked"))?
}

enum BoundedFileReadError {
    Io,
    TooLarge,
}

fn read_bounded_file(path: &str, limit: usize) -> Result<Vec<u8>, BoundedFileReadError> {
    let file = std::fs::File::open(path).map_err(|_| BoundedFileReadError::Io)?;
    let mut contents = Vec::with_capacity(limit.saturating_add(1));
    file.take(limit.saturating_add(1) as u64)
        .read_to_end(&mut contents)
        .map_err(|_| BoundedFileReadError::Io)?;
    if contents.len() > limit {
        return Err(BoundedFileReadError::TooLarge);
    }
    Ok(contents)
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

    let output = run_bounded_command(command)
        .map_err(|_| provider_error_message(CredentialProviderErrorKind::AwsCliRunFailed))?;
    if output.timed_out {
        return Err(provider_error_message(
            CredentialProviderErrorKind::AwsCliTimedOut,
        ));
    }
    validate_aws_cli_output_size(&output.stdout, &output.stderr)?;
    if !output.status.success() {
        return Err(provider_error_message(
            CredentialProviderErrorKind::AwsCliProfileExportFailed,
        ));
    }

    let parsed: AwsCliCredentialProcessOutput =
        serde_json::from_slice(&output.stdout).map_err(|_| {
            provider_error_message(CredentialProviderErrorKind::InvalidAwsCliCredentialJson)
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

pub(crate) fn validate_aws_cli_output_size(
    stdout: &[u8],
    stderr: &[u8],
) -> CredentialProviderResult<()> {
    if stdout.len().saturating_add(stderr.len()) > MAX_AWS_CLI_OUTPUT_BYTES {
        return Err(provider_error_message(
            CredentialProviderErrorKind::AwsCliOutputTooLarge,
        ));
    }
    Ok(())
}

fn blocking_metadata_http_client() -> CredentialProviderResult<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .connect_timeout(METADATA_CONNECT_TIMEOUT)
        .timeout(METADATA_REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| provider_error_message(CredentialProviderErrorKind::ProviderClientInitFailed))
}

fn resolve_ecs_task_credentials_with_blocking_client(
    client: &reqwest::blocking::Client,
) -> CredentialProviderResult<Option<ResolvedCredentials>> {
    let Some(uri) = resolve_ecs_task_credentials_uri()? else {
        return Ok(None);
    };

    let mut request = client.get(uri);
    if let Some(token) = resolve_ecs_authorization_token()? {
        request = request.header(REQWEST_AUTHORIZATION, token);
    }

    let response = request.send().map_err(|_| metadata_request_error())?;
    if !response.status().is_success() {
        return Err(provider_error_message(
            CredentialProviderErrorKind::MetadataEndpointStatus {
                endpoint: MetadataEndpoint::Credentials,
                status: response.status(),
            },
        ));
    }

    let body = bounded_blocking_response_body(response).map_err(|_| {
        provider_error_message(CredentialProviderErrorKind::MetadataResponseInvalid)
    })?;
    let payload = serde_json::from_slice::<MetadataCredentialsResponse>(&body).map_err(|_| {
        provider_error_message(CredentialProviderErrorKind::MetadataCredentialsJsonInvalid)
    })?;

    metadata_to_credentials(payload, ECS_TASK_METADATA_PROVIDER_NAME).map(Some)
}

fn resolve_imds_credentials_with_blocking_client(
    client: &reqwest::blocking::Client,
) -> CredentialProviderResult<Option<ResolvedCredentials>> {
    if ec2_metadata_is_disabled() {
        return Ok(None);
    }

    let token_response = client
        .put(IMDS_TOKEN_URL)
        .header(IMDS_TOKEN_TTL_HEADER, IMDS_TOKEN_TTL_SECONDS)
        .send()
        .map_err(|_| metadata_request_error())?;
    if !token_response.status().is_success() {
        return Err(provider_error_message(
            CredentialProviderErrorKind::MetadataEndpointStatus {
                endpoint: MetadataEndpoint::Token,
                status: token_response.status(),
            },
        ));
    }

    let token_body = bounded_blocking_response_body(token_response).map_err(|_| {
        provider_error_message(CredentialProviderErrorKind::MetadataResponseInvalid)
    })?;
    let token = std::str::from_utf8(&token_body)
        .map_err(|_| {
            provider_error_message(CredentialProviderErrorKind::MetadataCredentialsTextInvalid)
        })?
        .to_owned();
    if token.trim().is_empty() {
        return Err(provider_error_message(
            CredentialProviderErrorKind::EmptyImdsToken,
        ));
    }

    let role_list_response = client
        .get(IMDS_ROLE_LIST_URL)
        .header(IMDS_TOKEN_HEADER, token.as_str())
        .send()
        .map_err(|_| metadata_request_error())?;
    if !role_list_response.status().is_success() {
        return Err(provider_error_message(
            CredentialProviderErrorKind::MetadataEndpointStatus {
                endpoint: MetadataEndpoint::RoleListing,
                status: role_list_response.status(),
            },
        ));
    }

    let role_body = bounded_blocking_response_body(role_list_response).map_err(|_| {
        provider_error_message(CredentialProviderErrorKind::MetadataResponseInvalid)
    })?;
    let role_name = std::str::from_utf8(&role_body)
        .map_err(|_| {
            provider_error_message(CredentialProviderErrorKind::MetadataCredentialsTextInvalid)
        })?
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| provider_error_message(CredentialProviderErrorKind::MissingImdsRoleName))?
        .to_owned();

    let credentials_response = client
        .get(format!("{IMDS_ROLE_LIST_URL}{role_name}"))
        .header(IMDS_TOKEN_HEADER, token)
        .send()
        .map_err(|_| metadata_request_error())?;
    if !credentials_response.status().is_success() {
        return Err(provider_error_message(
            CredentialProviderErrorKind::MetadataEndpointStatus {
                endpoint: MetadataEndpoint::RoleCredentials,
                status: credentials_response.status(),
            },
        ));
    }

    let body = bounded_blocking_response_body(credentials_response).map_err(|_| {
        provider_error_message(CredentialProviderErrorKind::MetadataResponseInvalid)
    })?;
    let payload = serde_json::from_slice::<MetadataCredentialsResponse>(&body).map_err(|_| {
        provider_error_message(CredentialProviderErrorKind::MetadataCredentialsJsonInvalid)
    })?;

    metadata_to_credentials(payload, IMDS_PROVIDER_NAME).map(Some)
}

fn requested_profile_name() -> Option<String> {
    non_empty_env_var(AWS_PROFILE).or_else(|| non_empty_env_var(AWS_DEFAULT_PROFILE))
}

async fn bounded_response_body(response: reqwest::Response) -> io::Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_METADATA_RESPONSE_BYTES as u64)
    {
        return Err(io::Error::other(
            "metadata response exceeds configured limit",
        ));
    }

    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(io::Error::other)?;
        if body.len().saturating_add(chunk.len()) > MAX_METADATA_RESPONSE_BYTES {
            return Err(io::Error::other(
                "metadata response exceeds configured limit",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub(crate) fn bounded_blocking_response_body(
    response: reqwest::blocking::Response,
) -> io::Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_METADATA_RESPONSE_BYTES as u64)
    {
        return Err(io::Error::other(
            "metadata response exceeds configured limit",
        ));
    }

    let mut body = Vec::with_capacity(response.content_length().map_or(0, |length| {
        usize::try_from(length)
            .unwrap_or(MAX_METADATA_RESPONSE_BYTES)
            .min(MAX_METADATA_RESPONSE_BYTES)
    }));
    response
        .take(MAX_METADATA_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut body)?;
    if body.len() > MAX_METADATA_RESPONSE_BYTES {
        return Err(io::Error::other(
            "metadata response exceeds configured limit",
        ));
    }
    Ok(body)
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

pub fn resolve_ecs_task_credentials_uri() -> CredentialProviderResult<Option<Url>> {
    if let Some(full_uri) = non_empty_env_var(AWS_CONTAINER_CREDENTIALS_FULL_URI) {
        let uri = Url::parse(&full_uri).map_err(|_| {
            invalid_configuration_message(CredentialProviderErrorKind::InvalidEcsCredentialsUri)
        })?;
        validate_ecs_full_uri(&uri)?;
        return Ok(Some(uri));
    }

    let Some(relative_uri) = non_empty_env_var(AWS_CONTAINER_CREDENTIALS_RELATIVE_URI) else {
        return Ok(None);
    };

    if relative_uri.starts_with("//") || relative_uri.contains('\\') {
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
        .map_err(|_| {
            invalid_configuration_message(CredentialProviderErrorKind::InvalidEcsCredentialsUri)
        })?;

    if uri.scheme() != "http" || uri.host_str() != Some("169.254.170.2") {
        return Err(invalid_configuration_message(
            CredentialProviderErrorKind::EcsRelativeUriMustBePath,
        ));
    }

    Ok(Some(uri))
}

pub fn validate_ecs_full_uri(uri: &Url) -> CredentialProviderResult<()> {
    match uri.scheme() {
        "https" => Ok(()),
        "http" => {
            let Some(host) = uri.host() else {
                return Err(invalid_configuration_message(
                    CredentialProviderErrorKind::EcsFullUriMissingHost,
                ));
            };
            if is_allowed_ecs_http_host(&host) {
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

fn is_allowed_ecs_http_host(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Ipv4(address) => {
            *address == std::net::Ipv4Addr::new(169, 254, 170, 2) || address.is_loopback()
        }
        url::Host::Ipv6(address) => address.is_loopback(),
        url::Host::Domain(host) => host.eq_ignore_ascii_case(LOCALHOST),
    }
}

pub fn resolve_ecs_authorization_token() -> CredentialProviderResult<Option<String>> {
    if let Some(token_file) = non_empty_env_var(AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE) {
        let token_bytes =
            read_bounded_file(&token_file, MAX_AUTHORIZATION_TOKEN_BYTES).map_err(|error| {
                match error {
                    BoundedFileReadError::Io => provider_error_message(
                        CredentialProviderErrorKind::AuthorizationTokenFileReadFailed,
                    ),
                    BoundedFileReadError::TooLarge => provider_error_message(
                        CredentialProviderErrorKind::AuthorizationTokenFileTooLarge,
                    ),
                }
            })?;
        let token = std::str::from_utf8(&token_bytes).map_err(|_| {
            provider_error_message(CredentialProviderErrorKind::AuthorizationTokenFileInvalidUtf8)
        })?;
        let trimmed = token.trim().to_owned();
        if trimmed.is_empty() {
            return Err(provider_error_message(
                CredentialProviderErrorKind::EmptyAuthorizationTokenFile,
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
    let refresh_after = Some(metadata_refresh_after(SystemTime::now(), expires_after));

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

#[must_use]
pub fn half_life_refresh_after(
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

pub(crate) fn metadata_refresh_after(
    now: SystemTime,
    expires_after: Option<SystemTime>,
) -> SystemTime {
    match expires_after {
        Some(expires_after) => expires_after
            .checked_sub(CREDENTIAL_REFRESH_SKEW)
            .unwrap_or(now + CREDENTIAL_REFRESH_FALLBACK),
        None => now + CREDENTIAL_REFRESH_FALLBACK,
    }
}

pub(crate) fn credential_cache_ttl(refresh_after: Option<SystemTime>, now: SystemTime) -> Duration {
    let Some(refresh_after) = refresh_after else {
        return CREDENTIAL_CACHE_STATIC_TTL;
    };
    refresh_after.duration_since(now).unwrap_or(Duration::ZERO)
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

fn metadata_request_error() -> CredentialProviderError {
    provider_error_message(CredentialProviderErrorKind::MetadataRequestFailed)
}

fn not_loaded_error(kind: CredentialProviderErrorKind) -> CredentialProviderError {
    CredentialProviderError::not_loaded(io::Error::other(kind))
}

#[must_use]
pub fn static_credentials(creds: &AwsStaticCredentials) -> Credentials {
    Credentials::new(
        creds.access_key_id.clone(),
        creds.secret_access_key.clone(),
        creds.session_token.clone(),
        None,
        STATIC_PROVIDER_NAME,
    )
}
