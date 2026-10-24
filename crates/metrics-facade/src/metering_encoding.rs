use buffered_writes::{Deadline, OperationId, TenantScope, WriteError};
use serde::{Deserialize, Serialize};

use super::RequestCostSnapshot;

/// Caller-authorized scope, server execution identity, and remaining admission
/// deadline for one measurement. The identity must be unique per execution;
/// client-controlled correlation IDs are not suitable.
#[derive(Clone)]
pub struct RequestMeteringContext {
    scope: TenantScope,
    request_id: OperationId,
    deadline: Deadline,
}

impl RequestMeteringContext {
    pub fn try_new(
        scope: impl Into<String>,
        request_id: impl Into<String>,
        deadline: impl Into<Deadline>,
    ) -> Result<Self, WriteError> {
        Ok(Self {
            scope: TenantScope::try_new(scope)?,
            request_id: OperationId::try_new(request_id)?,
            deadline: deadline.into(),
        })
    }
}

impl std::fmt::Debug for RequestMeteringContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RequestMeteringContext")
    }
}

/// Versioned request measurements; consumers own billing conversion and
/// persistence schemas.
#[derive(Clone, Serialize, Deserialize)]
pub struct RequestMeasurement {
    scope: TenantScope,
    request_id: OperationId,
    snapshot: RequestCostSnapshot,
    #[serde(skip)]
    deadline: Option<Deadline>,
}

impl RequestMeasurement {
    pub fn try_new(
        context: RequestMeteringContext,
        snapshot: RequestCostSnapshot,
    ) -> Result<Self, WriteError> {
        if !snapshot.wall_ms.is_finite()
            || snapshot.wall_ms < 0.0
            || !snapshot.remote_wait_ms.is_finite()
            || snapshot.remote_wait_ms < 0.0
        {
            return Err(WriteError::Rejected {
                reason: "invalid request measurement",
            });
        }
        Ok(Self {
            scope: context.scope,
            request_id: context.request_id,
            snapshot,
            deadline: Some(context.deadline),
        })
    }

    pub fn scope(&self) -> &TenantScope {
        &self.scope
    }
    /// Returns the server execution identity, distinct from snapshot
    /// correlation.
    pub fn request_id(&self) -> &OperationId {
        &self.request_id
    }
    pub fn snapshot(&self) -> &RequestCostSnapshot {
        &self.snapshot
    }
    pub(super) fn deadline(&self) -> Option<Deadline> {
        self.deadline
    }
}

impl std::fmt::Debug for RequestMeasurement {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RequestMeasurement")
    }
}
