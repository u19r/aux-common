use std::time::Duration;

pub(crate) const ECS_RELATIVE_CREDENTIALS_BASE: &str = "http://169.254.170.2";
pub(crate) const ECS_LOCAL_IPV4_HOST: &str = "169.254.170.2";
pub(crate) const LOCALHOST: &str = "localhost";
pub(crate) const LOOPBACK_IPV4: &str = "127.0.0.1";
pub(crate) const LOOPBACK_IPV6: &str = "::1";

pub(crate) const IMDS_TOKEN_URL: &str = "http://169.254.169.254/latest/api/token";
pub(crate) const IMDS_ROLE_LIST_URL: &str =
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
pub(crate) const IMDS_TOKEN_TTL_SECONDS: &str = "21600";
pub(crate) const IMDS_TOKEN_TTL_HEADER: &str = "X-aws-ec2-metadata-token-ttl-seconds";
pub(crate) const IMDS_TOKEN_HEADER: &str = "X-aws-ec2-metadata-token";

pub(crate) const METADATA_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
pub(crate) const METADATA_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const CREDENTIAL_REFRESH_SKEW: Duration = Duration::from_mins(5);
pub(crate) const CREDENTIAL_REFRESH_FALLBACK: Duration = Duration::from_mins(10);
pub(crate) const CREDENTIAL_CACHE_STATIC_TTL: Duration = Duration::from_hours(24);
pub(crate) const CREDENTIAL_CACHE_CAPACITY: usize = 1;
pub(crate) const DEFAULT_CREDENTIAL_CACHE_KEY: &str = "default";

pub(crate) const AWS_ACCESS_KEY_ID: &str = "AWS_ACCESS_KEY_ID";
pub(crate) const AWS_ACCESS_KEY: &str = "AWS_ACCESS_KEY";
pub(crate) const AWS_SECRET_ACCESS_KEY: &str = "AWS_SECRET_ACCESS_KEY";
pub(crate) const AWS_SECRET_KEY: &str = "AWS_SECRET_KEY";
pub(crate) const AWS_SESSION_TOKEN: &str = "AWS_SESSION_TOKEN";
pub(crate) const AWS_PROFILE: &str = "AWS_PROFILE";
pub(crate) const AWS_DEFAULT_PROFILE: &str = "AWS_DEFAULT_PROFILE";
pub(crate) const AWS_CONFIG_FILE: &str = "AWS_CONFIG_FILE";
pub(crate) const AWS_SHARED_CREDENTIALS_FILE: &str = "AWS_SHARED_CREDENTIALS_FILE";
pub(crate) const AWS_CONTAINER_CREDENTIALS_FULL_URI: &str = "AWS_CONTAINER_CREDENTIALS_FULL_URI";
pub(crate) const AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: &str =
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
pub(crate) const AWS_CONTAINER_AUTHORIZATION_TOKEN: &str = "AWS_CONTAINER_AUTHORIZATION_TOKEN";
pub(crate) const AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE: &str =
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE";
pub(crate) const AWS_EC2_METADATA_DISABLED: &str = "AWS_EC2_METADATA_DISABLED";

pub(crate) const AWS_CLI_PROFILE_DEFAULT: &str = "default";
pub(crate) const HOME: &str = "HOME";
pub(crate) const AWS_CONFIG_RELATIVE_PATH: &str = ".aws/config";
pub(crate) const AWS_CREDENTIALS_RELATIVE_PATH: &str = ".aws/credentials";
pub(crate) const AWS_CLI_CREDENTIAL_PROVIDER_NAME: &str = "aws-cli-profile";
pub(crate) const ECS_TASK_METADATA_PROVIDER_NAME: &str = "ecs-task-metadata";
pub(crate) const ENVIRONMENT_PROVIDER_NAME: &str = "environment";
pub(crate) const IMDS_PROVIDER_NAME: &str = "imds";
pub(crate) const STATIC_PROVIDER_NAME: &str = "static";
