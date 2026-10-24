use std::time::Duration;

pub(crate) const DEFAULT_IPC_ADDRESS: &str = "127.0.0.1:34900";
pub(crate) const API_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const API_MAX_BODY_BYTES: usize = 64 * 1024;
pub(crate) const NEXT_INVOCATION_PATH: &str = "/2018-06-01/runtime/invocation/next";
pub(crate) const REQUEST_ID_HEADER: &str = "lambda-runtime-aws-request-id";
pub(crate) const ATTEMPT_ID_HEADER: &str = "lambda-runtime-invocation-id";
