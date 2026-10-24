#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LambdaWebRuntimeError {
    #[error("Lambda Web Function listen address is missing or invalid")]
    InvalidListenAddress,
    #[error("Lambda Web Function runtime address is missing or invalid")]
    InvalidRuntimeAddress,
    #[error("Lambda Web Function readiness request failed")]
    ReadyUnavailable,
    #[error("Lambda Web Function readiness was rejected with HTTP {0}")]
    ReadyRejected(u16),
}
