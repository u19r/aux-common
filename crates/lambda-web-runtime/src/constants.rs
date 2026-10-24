pub(crate) const HTTP_ENDPOINT_ENV: &str = "AWS_LAMBDA_HTTP_ENDPOINT";
pub(crate) const RUNTIME_API_ENV: &str = "AWS_LAMBDA_RUNTIME_API";
pub(crate) const READY_PATH: &str = "/2025-09-01/ready";
pub(crate) const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
pub(crate) const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_millis(100);
