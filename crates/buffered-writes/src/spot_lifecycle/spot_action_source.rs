use futures_util::future::BoxFuture;

use super::action::SpotInstanceAction;

/// Source of IMDSv2 Spot interruption notices.
/// Construct the future without blocking. It can be resumed across response
/// events and dropped on shutdown or driver cancellation; do I/O only when
/// polled.
pub trait SpotActionSource: Send + Sync + 'static {
    fn poll_spot_action(
        &self,
    ) -> BoxFuture<'static, Result<Option<SpotInstanceAction>, crate::LifecycleError>>;
}
