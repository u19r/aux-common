use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum JobId {
    JobA,
    JobB,
    JobC,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum Node {
    NodeA,
    NodeB,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum OperationId {
    OperationA,
    OperationB,
    OperationC,
    OperationD,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum HttpStatus {
    Status2xx,
    Status408,
    Status425,
    Status429,
    Status4xx,
    Status5xx,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum TransportResult {
    TransportOk,
    Timeout,
    ConnectFailure,
    InvalidResponse,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum AuthResult {
    Authorised,
    Denied,
    MissingSecret,
    SignFailure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum RetryOwner {
    EngineOwnsRetry,
    NoRetry,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum BatchResult {
    ItemSuccess,
    ItemRetry,
    ItemDeadLetter,
    ItemMissing,
    ItemDuplicate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum ResultClass {
    AppliedClass,
    RejectedClass,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum HttpOutcome {
    Initialised,
    BatchPrepared,
    InvalidInputRejected,
    AuthorisationRejected,
    HttpSuccess,
    HttpRetry,
    HttpDeadLetter,
    TransportRetry,
    DuplicateDelivered,
    ItemOmitted,
    RetryAfterObserved,
    ProjectionRejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub job: JobId,
    pub member: bool,
    pub node: Node,
    pub revision: i64,
    pub generation: i64,
    pub fence: i64,
    pub token: i64,
    pub lease_until: i64,
    pub operation: OperationId,
    pub execution_id: i64,
    pub attempt_id: i64,
    pub attempts: i64,
    pub attempt_executed: bool,
    pub input_secret: bool,
    pub idempotency_header: i64,
    pub destination_valid: bool,
    pub invalid_input: bool,
    pub body_bytes: i64,
    pub auth: AuthResult,
    pub status: HttpStatus,
    pub transport: TransportResult,
    pub retry_after: i64,
    pub retry_owner: RetryOwner,
    pub result: BatchResult,
    pub duplicate: bool,
    pub omitted: bool,
    pub outcome_present: bool,
    pub outcome_job: JobId,
    pub outcome_attempt_id: i64,
    pub outcome_revision: i64,
    pub outcome_generation: i64,
    pub outcome_fence: i64,
    pub outcome_token: i64,
    pub outcome_lease_until: i64,
    pub outcome_operation: OperationId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RequestDiagnostic {
    pub header_count: i64,
    pub body_bytes: i64,
    pub includes_url: bool,
    pub includes_headers: bool,
    pub includes_body: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub batch_members: BTreeSet<JobId>,
    pub batch_results: BTreeMap<JobId, BatchResult>,
    pub last_item: JobId,
    pub last_outcome: HttpOutcome,
    pub engine_retries: i64,
    pub transport_retries: i64,
    pub last_projection: RequestDiagnostic,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityInput {
    pub job: JobId,
    pub node: Node,
    pub revision: i64,
    pub generation: i64,
    pub fence: i64,
    pub token: i64,
    pub lease_until: i64,
    pub operation: OperationId,
    pub execution_id: i64,
    pub attempt_id: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "tag", content = "value")]
pub enum Command {
    HttpPrepare {
        members: BTreeSet<JobId>,
    },
    HttpInput {
        job: JobId,
        secret: bool,
        #[serde(rename = "bodyBytes")]
        body_bytes: i64,
        #[serde(rename = "destinationValid")]
        destination_valid: bool,
    },
    HttpAuthorize {
        job: JobId,
        auth: AuthResult,
    },
    HttpProject {
        job: JobId,
        #[serde(rename = "includeSecret")]
        include_secret: bool,
    },
    HttpExecute {
        authority: AuthorityInput,
        status: HttpStatus,
        transport: TransportResult,
        #[serde(rename = "retryAfter")]
        retry_after: i64,
    },
    HttpRetryCommand {
        job: JobId,
        owner: RetryOwner,
    },
    HttpDuplicate {
        job: JobId,
    },
    HttpOmit {
        job: JobId,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LastTransition {
    pub command: Command,
    pub class: ResultClass,
    pub outcome: HttpOutcome,
    pub affected: BTreeSet<JobId>,
    pub job: JobId,
    pub operation: OperationId,
    pub result: BatchResult,
    pub owner: RetryOwner,
    pub retry_after: i64,
    pub members: BTreeSet<JobId>,
    pub results: BTreeMap<JobId, BatchResult>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "tag", content = "value")]
pub enum CommandResult {
    HttpApplied {
        transition: LastTransition,
        result: BatchResult,
        owner: RetryOwner,
        #[serde(rename = "retryAfter")]
        retry_after: i64,
    },
    HttpRejected {
        transition: LastTransition,
        result: BatchResult,
    },
    HttpRetryResult {
        transition: LastTransition,
        owner: RetryOwner,
        #[serde(rename = "retryAfter")]
        retry_after: i64,
    },
    HttpBatchResult {
        transition: LastTransition,
        members: BTreeSet<JobId>,
        results: BTreeMap<JobId, BatchResult>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct StateProjection {
    pub items: BTreeMap<JobId, Item>,
    pub meta: Meta,
    #[serde(rename = "lastCommand")]
    pub command: Command,
    #[serde(rename = "lastTransition")]
    pub transition: LastTransition,
    #[serde(rename = "lastCommandResult")]
    pub result: CommandResult,
}
