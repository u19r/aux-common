use serde::{Deserialize, Serialize};

use super::{admission_deadline::AdmissionDeadline, write_failure::WriteFailure};
use crate::{Admission, FlushReportSummary, Namespace, OperationId, TenantScope};

/// Classic Lambda Extensions API event delivered to an external extension.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "eventType", rename_all = "UPPERCASE")]
pub(super) enum LambdaExtensionEvent {
    Invoke {
        #[serde(rename = "deadlineMs")]
        deadline_ms: u64,
        #[serde(rename = "requestId")]
        request_id: String,
    },
    Shutdown {
        #[serde(rename = "deadlineMs")]
        deadline_ms: u64,
        #[serde(rename = "shutdownReason", default)]
        shutdown_reason: Option<String>,
    },
}

impl std::fmt::Debug for LambdaExtensionEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invoke { .. } => formatter.write_str("LambdaExtensionEvent::Invoke"),
            Self::Shutdown { .. } => formatter.write_str("LambdaExtensionEvent::Shutdown"),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct IpcRequest<T> {
    pub version: u16,
    pub auth_token: String,
    pub command: IpcCommand<T>,
}

#[derive(Serialize, Deserialize)]
pub(super) enum IpcCommand<T> {
    Bind {
        request_id: String,
        attempt_id: String,
    },
    Submit {
        session: uuid::Uuid,
        deadline: AdmissionDeadline,
        operation_id: OperationId,
        scope: Option<TenantScope>,
        item: T,
    },
    InvocationComplete {
        session: uuid::Uuid,
    },
}

#[derive(Serialize, Deserialize)]
pub(super) enum IpcResponse {
    Bound {
        request_id: String,
        attempt_id: String,
        session: uuid::Uuid,
        namespace: Namespace,
    },
    Admitted(Admission),
    Completed(FlushReportSummary),
    WriteFailed(WriteFailure),
    Rejected,
}
