//! The connector's fixture persistence boundary.
//!
//! The store-protocol model deliberately exposes a few dimensions which are
//! not part of the public `JobRecordV1` value (for example, the independently
//! bounded manifest and digest sizes, and the classification of a malformed
//! value).  The connector persists only those narrow operation, route, and
//! fault dimensions beside the real job value.  The driver never keeps a
//! durable model record: every projection and every transition reads and
//! writes these values through the deliberately fake `FakeStore`.

use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroU64},
    time::Duration,
};

use bg_jobs::{
    EffectMode, ExecutionId, FairnessClass, JobId as ActualJobId, JobKind, JobState, Namespace,
    Priority, QueueName, Timestamp,
    store::{JobStore, StoreKey},
    test_support::{
        FakeStoreError,
        codec::{KeyCodec, KeyTag, ValueCodec, ValueTag, decode_job_record, encode_job_record},
        raw::{
            AttemptHistory, BackoffMultiplier, JobPolicySnapshot, JobRecordV1, Lease, LeaseToken,
            PayloadManifest, RetryPolicy, RetryPolicyInput,
        },
    },
};
use bytes::Bytes;

use super::{
    constants::{
        CLAIM_COMPONENT, FAULT_COMPONENT, FAULT_VERSION, OPERATION_VERSION, ROUTE_COMPONENT,
        ROUTE_VERSION, UNKNOWN_COMPONENT,
    },
    types::{
        JobId as ModelJobId, JobState as ModelJobState, Node, OperationId as ModelOperationId,
        Record, RecordKind, StoreResult as ModelStoreResult,
    },
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RouteState {
    pub due: bool,
    pub fair: bool,
    pub lease: bool,
    pub wake: bool,
    pub permit: bool,
    pub rate: bool,
    pub retry_waiting: bool,
}

impl RouteState {
    pub(super) const fn from_record(record: &Record) -> Self {
        Self {
            due: record.due_route,
            fair: record.fair_route,
            lease: record.lease_route,
            wake: record.wake_route,
            permit: record.permit_held,
            rate: record.rate_held,
            retry_waiting: matches!(record.state, ModelJobState::RetryWaiting),
        }
    }

    pub(super) const fn empty() -> Self {
        Self {
            due: false,
            fair: false,
            lease: false,
            wake: false,
            permit: false,
            rate: false,
            retry_waiting: false,
        }
    }

    pub(super) const fn has_state(self) -> bool {
        self.due
            || self.fair
            || self.lease
            || self.wake
            || self.permit
            || self.rate
            || self.retry_waiting
    }

    pub(super) fn encode(self) -> Bytes {
        let mut body = Vec::with_capacity(8);
        body.extend_from_slice(&[
            ROUTE_VERSION,
            u8::from(self.due),
            u8::from(self.fair),
            u8::from(self.lease),
            u8::from(self.wake),
            u8::from(self.permit),
            u8::from(self.rate),
            u8::from(self.retry_waiting),
        ]);
        Bytes::from(body)
    }

    fn decode(encoded: &[u8]) -> Result<Self, String> {
        if encoded.len() != 8 || encoded[0] != ROUTE_VERSION {
            return Err("malformed connector route state".to_owned());
        }
        let bools = &encoded[1..8];
        if bools.iter().any(|value| *value > 1) {
            return Err("invalid connector route state boolean".to_owned());
        }
        Ok(Self {
            due: bools[0] != 0,
            fair: bools[1] != 0,
            lease: bools[2] != 0,
            wake: bools[3] != 0,
            permit: bools[4] != 0,
            rate: bools[5] != 0,
            retry_waiting: bools[6] != 0,
        })
    }
}

/// Operation metadata is intentionally narrower than the model's `Record`.
/// For a live job the primary value supplies identity, revision, execution,
/// payload, checkpoint, and lifecycle state.  The operation value supplies
/// only idempotency/resource dimensions absent from that primary value.  A
/// terminal variant retains the bounded identity needed after completion has
/// deleted the live job, matching the public operation-receipt contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OperationState {
    pub operation_id: ModelOperationId,
    pub fence_high_water: i64,
    pub enqueue_fingerprint: i64,
    pub payload: bool,
    pub manifest_bytes: i64,
    pub chunk_bytes: i64,
    pub digest_bytes: i64,
    pub attempt_id: i64,
    pub terminal: Option<TerminalState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TerminalState {
    pub revision: i64,
    pub node: Node,
    pub generation: i64,
    pub fence: i64,
    pub token: i64,
    pub lease_until: i64,
    pub expires_at: i64,
    pub execution_id: i64,
    pub attempt_id: i64,
    pub attempts: i64,
    pub checkpoint_bytes: i64,
}

impl OperationState {
    pub(super) const fn live_from_fixture(record: &Record) -> Self {
        Self {
            operation_id: record.operation_id,
            fence_high_water: record.fence,
            enqueue_fingerprint: record.enqueue_fingerprint,
            payload: record.payload,
            manifest_bytes: record.manifest_bytes,
            chunk_bytes: record.chunk_bytes,
            digest_bytes: record.digest_bytes,
            attempt_id: record.attempt_id,
            terminal: None,
        }
    }

    pub(super) fn encode(self) -> Result<Bytes, String> {
        let mut body = Vec::with_capacity(1 + 1 + 1 + 1 + (6 * 8) + (10 * 8));
        body.extend_from_slice(&[
            OPERATION_VERSION,
            u8::from(self.terminal.is_some()),
            operation_tag(self.operation_id),
            u8::from(self.payload),
        ]);
        put_i64(&mut body, self.fence_high_water);
        put_i64(&mut body, self.enqueue_fingerprint);
        put_i64(&mut body, self.manifest_bytes);
        put_i64(&mut body, self.chunk_bytes);
        put_i64(&mut body, self.digest_bytes);
        put_i64(&mut body, self.attempt_id);
        if let Some(terminal) = self.terminal {
            body.push(node_tag(terminal.node));
            put_i64(&mut body, terminal.revision);
            put_i64(&mut body, terminal.generation);
            put_i64(&mut body, terminal.fence);
            put_i64(&mut body, terminal.token);
            put_i64(&mut body, terminal.lease_until);
            put_i64(&mut body, terminal.expires_at);
            put_i64(&mut body, terminal.execution_id);
            put_i64(&mut body, terminal.attempt_id);
            put_i64(&mut body, terminal.attempts);
            put_i64(&mut body, terminal.checkpoint_bytes);
        }
        ValueCodec::encode(ValueTag::Operation, &body).map_err(|error| error.to_string())
    }

    pub(super) fn decode(encoded: &[u8]) -> Result<Self, String> {
        let value = ValueCodec::decode(encoded).map_err(|error| error.to_string())?;
        if value.tag != ValueTag::Operation {
            return Err("connector operation state has wrong value tag".to_owned());
        }
        let mut reader = Reader::new(&value.body);
        if reader.byte()? != OPERATION_VERSION {
            return Err("unsupported connector operation state version".to_owned());
        }
        let terminal = reader.bool()?;
        let operation_id = operation(reader.byte()?)?;
        let payload = reader.bool()?;
        let fence_high_water = reader.i64()?;
        let enqueue_fingerprint = reader.i64()?;
        let manifest_bytes = reader.i64()?;
        let chunk_bytes = reader.i64()?;
        let digest_bytes = reader.i64()?;
        let attempt_id = reader.i64()?;
        let terminal = if terminal {
            Some(TerminalState {
                node: node(reader.byte()?)?,
                revision: reader.i64()?,
                generation: reader.i64()?,
                fence: reader.i64()?,
                token: reader.i64()?,
                lease_until: reader.i64()?,
                expires_at: reader.i64()?,
                execution_id: reader.i64()?,
                attempt_id: reader.i64()?,
                attempts: reader.i64()?,
                checkpoint_bytes: reader.i64()?,
            })
        } else {
            None
        };
        reader.finish()?;
        Ok(Self {
            operation_id,
            fence_high_water,
            enqueue_fingerprint,
            payload,
            manifest_bytes,
            chunk_bytes,
            digest_bytes,
            attempt_id,
            terminal,
        })
    }
}

/// The decoded bytes that a connector transition is allowed to observe and
/// mutate.  This is deliberately composed of the public job value and narrow
/// connector sidecars; it is not a modeled `Record` cache.
#[derive(Clone, Debug)]
pub(super) struct StoredState {
    pub core: Option<JobRecordV1>,
    pub operation: OperationState,
    pub operation_present: bool,
    pub route: RouteState,
    pub route_present: bool,
    pub fault: Option<FaultState>,
    pub fault_present: bool,
}

impl StoredState {
    pub(super) fn read(
        store: &impl JobStore<Error = FakeStoreError>,
        namespace: &Namespace,
        job: &ModelJobId,
    ) -> Result<Self, String> {
        let core_key =
            KeyCodec::job(namespace, &actual_job_id(*job)).map_err(|error| error.to_string())?;
        let operation_key = operation_key(namespace, job)?;
        let route_key = route_key(namespace, job)?;
        let fault_key = fault_key(namespace, job)?;

        let keys = [core_key, operation_key, route_key, fault_key];
        let values = block_on(store.get_many(&keys)).map_err(|error| error.to_string())?;
        let [
            core_encoded,
            operation_encoded,
            route_encoded,
            fault_encoded,
        ]: [Option<Bytes>; 4] = values
            .try_into()
            .map_err(|_| "connector state bulk read returned wrong cardinality".to_owned())?;

        let core = core_encoded
            .as_deref()
            .map(|encoded| decode_job_record(encoded).map_err(|error| error.to_string()))
            .transpose()?;
        let operation_present = operation_encoded.is_some();
        let operation = operation_encoded
            .as_deref()
            .map(OperationState::decode)
            .transpose()?
            .unwrap_or_else(default_operation);
        let route_present = route_encoded.is_some();
        let route = route_encoded
            .as_deref()
            .map(|encoded| {
                let value = ValueCodec::decode(encoded).map_err(|error| error.to_string())?;
                if value.tag != ValueTag::Operation {
                    return Err("connector route receipt has wrong value tag".to_owned());
                }
                RouteState::decode(&value.body)
            })
            .transpose()?
            .unwrap_or_else(RouteState::empty);
        let fault_present = fault_encoded.is_some();
        let fault = fault_encoded
            .as_deref()
            .map(FaultState::decode)
            .transpose()?;

        Ok(Self {
            core,
            operation,
            operation_present,
            route,
            route_present,
            fault,
            fault_present,
        })
    }
}

pub(super) const fn default_operation() -> OperationState {
    OperationState {
        operation_id: ModelOperationId::OperationA,
        fence_high_water: 0,
        enqueue_fingerprint: 0,
        payload: false,
        manifest_bytes: 0,
        chunk_bytes: 0,
        digest_bytes: 0,
        attempt_id: 0,
        terminal: None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FaultState {
    pub kind: RecordKind,
    pub dangling: bool,
}

impl FaultState {
    pub(super) fn encode(self) -> Result<Bytes, String> {
        if self.kind == RecordKind::Valid {
            return Err("valid records do not have connector fault state".to_owned());
        }
        ValueCodec::encode(
            ValueTag::Operation,
            &[
                FAULT_VERSION,
                record_kind_tag(self.kind),
                u8::from(self.dangling),
            ],
        )
        .map_err(|error| error.to_string())
    }

    fn decode(encoded: &[u8]) -> Result<Self, String> {
        let value = ValueCodec::decode(encoded).map_err(|error| error.to_string())?;
        if value.tag != ValueTag::Operation || value.body.len() != 3 {
            return Err("connector fault state has wrong value".to_owned());
        }
        if value.body[0] != FAULT_VERSION {
            return Err("unsupported connector fault state version".to_owned());
        }
        let kind = record_kind(value.body[1])?;
        if kind == RecordKind::Valid {
            return Err("connector fault state cannot be valid".to_owned());
        }
        if value.body[2] > 1 {
            return Err("invalid connector fault state boolean".to_owned());
        }
        Ok(Self {
            kind,
            dangling: value.body[2] != 0,
        })
    }
}

/// The authority/readback needed to reconcile one ambiguous transition. It is
/// stored as a single narrow receipt, not as a copy of the live job record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct UnknownState {
    pub job: ModelJobId,
    pub operation: ModelOperationId,
    pub node: Node,
    pub revision: i64,
    pub generation: i64,
    pub fence: i64,
    pub token: i64,
    pub lease_until: i64,
    pub readback: ModelStoreResult,
}

impl UnknownState {
    pub(super) fn encode(self) -> Result<Bytes, String> {
        let mut body = Vec::with_capacity(1 + 8 + (6 * 8));
        body.push(1);
        body.push(job_tag(self.job));
        body.push(operation_tag(self.operation));
        body.push(node_tag(self.node));
        body.push(match self.readback {
            ModelStoreResult::Committed => 0,
            ModelStoreResult::Conflict => 1,
            _ => return Err("unknown state readback must be committed or conflict".to_owned()),
        });
        for value in [
            self.revision,
            self.generation,
            self.fence,
            self.token,
            self.lease_until,
        ] {
            put_i64(&mut body, value);
        }
        ValueCodec::encode(ValueTag::Operation, &body).map_err(|error| error.to_string())
    }

    fn decode(encoded: &[u8]) -> Result<Self, String> {
        let value = ValueCodec::decode(encoded).map_err(|error| error.to_string())?;
        if value.tag != ValueTag::Operation {
            return Err("connector unknown state has wrong value tag".to_owned());
        }
        let mut reader = Reader::new(&value.body);
        if reader.byte()? != 1 {
            return Err("unsupported connector unknown state version".to_owned());
        }
        let job = model_job(reader.byte()?)?;
        let operation = operation(reader.byte()?)?;
        let node = node(reader.byte()?)?;
        let readback = match reader.byte()? {
            0 => ModelStoreResult::Committed,
            1 => ModelStoreResult::Conflict,
            _ => return Err("invalid connector unknown state readback".to_owned()),
        };
        let revision = reader.i64()?;
        let generation = reader.i64()?;
        let fence = reader.i64()?;
        let token = reader.i64()?;
        let lease_until = reader.i64()?;
        reader.finish()?;
        Ok(Self {
            job,
            operation,
            node,
            revision,
            generation,
            fence,
            token,
            lease_until,
            readback,
        })
    }
}

/// The result of the read phase that precedes a claim commit. This is a
/// narrow opaque handle; the selected job value remains in FakeStore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ClaimState {
    pub job: ModelJobId,
    pub reader: Node,
    pub revision: i64,
}

impl ClaimState {
    pub(super) fn encode(self) -> Result<Bytes, String> {
        let mut body = vec![1, job_tag(self.job), node_tag(self.reader)];
        put_i64(&mut body, self.revision);
        ValueCodec::encode(ValueTag::Operation, &body).map_err(|error| error.to_string())
    }

    fn decode(encoded: &[u8]) -> Result<Self, String> {
        let value = ValueCodec::decode(encoded).map_err(|error| error.to_string())?;
        if value.tag != ValueTag::Operation {
            return Err("connector claim state has wrong value tag".to_owned());
        }
        let mut reader = Reader::new(&value.body);
        if reader.byte()? != 1 {
            return Err("unsupported connector claim state version".to_owned());
        }
        let job = model_job(reader.byte()?)?;
        let reader_node = node(reader.byte()?)?;
        let revision = reader.i64()?;
        reader.finish()?;
        Ok(Self {
            job,
            reader: reader_node,
            revision,
        })
    }
}

pub(super) fn route_key(namespace: &Namespace, job: &ModelJobId) -> Result<StoreKey, String> {
    let actual = actual_job_id(*job);
    KeyCodec::encode(
        namespace,
        KeyTag::Operation,
        &[ROUTE_COMPONENT, actual.as_bytes()],
    )
    .map_err(|error| error.to_string())
}

pub(super) fn operation_key(namespace: &Namespace, job: &ModelJobId) -> Result<StoreKey, String> {
    let actual = actual_job_id(*job);
    KeyCodec::encode(namespace, KeyTag::Operation, &[actual.as_bytes()])
        .map_err(|error| error.to_string())
}

pub(super) fn receipt_key(namespace: &Namespace, job: &ModelJobId) -> Result<StoreKey, String> {
    // Kept as a test-only compatibility name for the focused deletion test.
    // The key is the narrow operation metadata value, never a model-record
    // receipt.
    operation_key(namespace, job)
}

pub(super) fn read_operation(
    store: &impl JobStore<Error = FakeStoreError>,
    namespace: &Namespace,
    job: &ModelJobId,
) -> Result<Option<OperationState>, String> {
    let key = operation_key(namespace, job)?;
    let Some(encoded) = block_on(store.get(key)).map_err(|error| error.to_string())? else {
        return Ok(None);
    };
    OperationState::decode(&encoded).map(Some)
}

pub(super) fn read_fault(
    store: &impl JobStore<Error = FakeStoreError>,
    namespace: &Namespace,
    job: &ModelJobId,
) -> Result<Option<FaultState>, String> {
    let key = fault_key(namespace, job)?;
    let Some(encoded) = block_on(store.get(key)).map_err(|error| error.to_string())? else {
        return Ok(None);
    };
    FaultState::decode(&encoded).map(Some)
}

pub(super) fn fault_key(namespace: &Namespace, job: &ModelJobId) -> Result<StoreKey, String> {
    let actual = actual_job_id(*job);
    KeyCodec::encode(
        namespace,
        KeyTag::Operation,
        &[FAULT_COMPONENT, actual.as_bytes()],
    )
    .map_err(|error| error.to_string())
}

pub(super) fn read_route(
    store: &impl JobStore<Error = FakeStoreError>,
    namespace: &Namespace,
    job: &ModelJobId,
) -> Result<RouteState, String> {
    let key = route_key(namespace, job)?;
    let Some(encoded) = block_on(store.get(key)).map_err(|error| error.to_string())? else {
        return Ok(RouteState::empty());
    };
    let value = ValueCodec::decode(&encoded).map_err(|error| error.to_string())?;
    if value.tag != ValueTag::Operation {
        return Err("connector route receipt has wrong value tag".to_owned());
    }
    RouteState::decode(&value.body)
}

pub(super) fn unknown_key(namespace: &Namespace) -> Result<StoreKey, String> {
    KeyCodec::encode(namespace, KeyTag::Operation, &[UNKNOWN_COMPONENT])
        .map_err(|error| error.to_string())
}

pub(super) fn read_unknown(
    store: &impl JobStore<Error = FakeStoreError>,
    namespace: &Namespace,
) -> Result<Option<UnknownState>, String> {
    let key = unknown_key(namespace)?;
    let Some(encoded) = block_on(store.get(key)).map_err(|error| error.to_string())? else {
        return Ok(None);
    };
    UnknownState::decode(&encoded).map(Some)
}

pub(super) fn claim_key(namespace: &Namespace) -> Result<StoreKey, String> {
    KeyCodec::encode(namespace, KeyTag::Operation, &[CLAIM_COMPONENT])
        .map_err(|error| error.to_string())
}

pub(super) fn read_claim(
    store: &impl JobStore<Error = FakeStoreError>,
    namespace: &Namespace,
) -> Result<Option<ClaimState>, String> {
    let key = claim_key(namespace)?;
    let Some(encoded) = block_on(store.get(key)).map_err(|error| error.to_string())? else {
        return Ok(None);
    };
    ClaimState::decode(&encoded).map(Some)
}

pub(super) fn terminal_from_core(core: &JobRecordV1) -> Result<TerminalState, String> {
    let JobState::Leased(lease) = &core.state else {
        return Err("terminal authority requires leased core".to_owned());
    };
    let node = if lease.owner.as_bytes()[0] == 2 {
        Node::NodeB
    } else {
        Node::NodeA
    };
    let fence = i64::try_from(lease.fence.get())
        .map_err(|_| "lease fence exceeds model range".to_owned())?;
    Ok(TerminalState {
        revision: i64::try_from(core.revision)
            .map_err(|_| "stored revision exceeds model range".to_owned())?,
        node,
        generation: i64::from(core.generation),
        fence,
        token: number_from_bytes(lease.token.as_bytes()),
        lease_until: lease.expires_at.as_millis() / 1_000,
        expires_at: core.expires_at.map_or(0, |value| value.as_millis() / 1_000),
        execution_id: number_from_bytes(core.execution_id.as_bytes()),
        attempt_id: 0,
        attempts: core
            .attempts
            .as_ref()
            .map_or(0, |value| i64::from(value.attempts.get())),
        checkpoint_bytes: core
            .checkpoint
            .as_ref()
            .map_or(0, |value| i64::try_from(value.len()).unwrap_or(i64::MAX)),
    })
}

pub(super) fn write_initial(
    store: &bg_jobs::test_support::FakeStore,
    namespace: &Namespace,
    queue: &QueueName,
    records: &[(ModelJobId, Record)],
) -> Result<(), String> {
    for (job, record) in records {
        let core = initial_core_from_fixture(namespace, queue, job, record)?;
        if record.exists {
            let job_key =
                KeyCodec::job(namespace, &core.job_id).map_err(|error| error.to_string())?;
            store
                .put_raw(
                    job_key,
                    encode_job_record(&core).map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?;
            if record.payload && record.payload_bytes > 0 {
                let payload_key = KeyCodec::encode(
                    namespace,
                    KeyTag::PayloadChunk,
                    &[core.job_id.as_bytes(), &0_u32.to_be_bytes()],
                )
                .map_err(|error| error.to_string())?;
                let payload_bytes = usize::try_from(record.payload_bytes)
                    .map_err(|_| "payload length exceeds platform capacity".to_owned())?;
                store
                    .put_raw(
                        payload_key,
                        ValueCodec::encode(ValueTag::PayloadChunk, &vec![0; payload_bytes])
                            .map_err(|error| error.to_string())?,
                    )
                    .map_err(|error| error.to_string())?;
            }
        }
        if record.exists {
            let operation_key = operation_key(namespace, job)?;
            store
                .put_raw(
                    operation_key,
                    OperationState::live_from_fixture(record).encode()?,
                )
                .map_err(|error| error.to_string())?;
        }
        if record.kind != RecordKind::Valid {
            store
                .put_raw(
                    fault_key(namespace, job)?,
                    FaultState {
                        kind: record.kind,
                        dangling: record.dangling,
                    }
                    .encode()?,
                )
                .map_err(|error| error.to_string())?;
        }
        let route = RouteState::from_record(record);
        if route.has_state() {
            let route_key = route_key(namespace, job)?;
            store
                .put_raw(
                    route_key,
                    ValueCodec::encode(ValueTag::Operation, &route.encode())
                        .map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

/// Build only the fixed initial fixture. Runtime transitions never call this
/// model-shaped setup helper; they mutate a decoded `JobRecordV1` instead.
fn initial_core_from_fixture(
    namespace: &Namespace,
    queue: &QueueName,
    job: &ModelJobId,
    record: &Record,
) -> Result<JobRecordV1, String> {
    let actual_job = actual_job_id(*job);
    let kind = JobKind::try_new("email").map_err(|error| error.to_string())?;
    let policy = JobPolicySnapshot {
        effect_mode: EffectMode::Idempotent,
        cost_units: NonZeroU16::MIN,
        execution_timeout: Some(Duration::from_secs(3)),
        retry_policy: RetryPolicy::try_from(RetryPolicyInput {
            maximum_attempts: NonZeroU16::new(3).ok_or_else(|| "zero attempts".to_owned())?,
            maximum_age: Duration::from_secs(12),
            minimum_backoff: Duration::from_secs(1),
            maximum_backoff: Duration::from_secs(1),
            multiplier: BackoffMultiplier::try_from(1_u32).map_err(|error| error.to_string())?,
        })
        .map_err(|error| error.to_string())?,
    };
    let payload_len = u32::try_from(record.payload_bytes.max(0))
        .map_err(|_| "payload length does not fit core record".to_owned())?;
    let chunk_key = KeyCodec::encode(
        namespace,
        KeyTag::PayloadChunk,
        &[actual_job.as_bytes(), &0_u32.to_be_bytes()],
    )
    .map_err(|error| error.to_string())?;
    let payload = PayloadManifest::try_new(
        payload_len,
        [0; 32],
        if payload_len == 0 {
            Vec::new()
        } else {
            vec![chunk_key]
        },
    )
    .map_err(|error| error.to_string())?;
    let state = match record.state {
        ModelJobState::Absent => JobState::Scheduled,
        ModelJobState::Scheduled | ModelJobState::RetryWaiting => JobState::Scheduled,
        ModelJobState::DeadLettered => JobState::DeadLettered,
        ModelJobState::Cancelled => JobState::Cancelled,
        ModelJobState::Completed => JobState::Scheduled,
        ModelJobState::Leased => JobState::Leased(
            Lease::try_new(
                owner_id(record.node),
                lease_token(record.token),
                NonZeroU64::new(record.fence.max(1) as u64)
                    .ok_or_else(|| "zero lease fence".to_owned())?,
                Timestamp::from_millis(record.lease_until.saturating_mul(1_000)),
            )
            .map_err(|error| error.to_string())?,
        ),
    };
    let attempts = NonZeroU32::new(record.attempts.max(0) as u32).map(|attempts| AttemptHistory {
        attempts,
        first_attempt_at: Timestamp::ZERO,
        last_attempt_at: Timestamp::ZERO,
        last_outcome: None,
    });
    let checkpoint = if record.checkpoint_bytes > 0 {
        Some(Bytes::from(vec![0; record.checkpoint_bytes as usize]))
    } else {
        None
    };
    let core = JobRecordV1 {
        job_id: actual_job,
        namespace: namespace.clone(),
        queue: queue.clone(),
        kind,
        schema_version: NonZeroU16::MIN,
        generation: record.generation.max(0) as u32,
        execution_id: ExecutionId::from(number_bytes(record.execution_id)),
        payload,
        fairness: FairnessClass::low_volume(),
        ordering_key: None,
        priority: Priority::Default,
        created_at: Timestamp::ZERO,
        scheduled_at: Timestamp::ZERO,
        expires_at: Some(Timestamp::from_millis(
            record.expires_at.saturating_mul(1_000),
        )),
        policy,
        attempts,
        state,
        checkpoint,
        retention_deadline: Timestamp::from_millis(record.expires_at.saturating_mul(1_000)),
        deduplication: None,
        revision: record.revision.max(0) as u64,
    };
    core.validate().map_err(|error| error.to_string())?;
    Ok(core)
}

/// Construct the live value for a new enqueue directly from command inputs.
/// Existing jobs are never reconstructed through this function.
pub(super) struct NewScheduledCoreInput<'a> {
    pub namespace: &'a Namespace,
    pub queue: &'a QueueName,
    pub job: ModelJobId,
    pub payload_bytes: i64,
    pub checkpoint_bytes: i64,
    pub expires_at: i64,
    pub revision: i64,
    pub execution_id: i64,
}

pub(super) fn new_scheduled_core(input: NewScheduledCoreInput<'_>) -> Result<JobRecordV1, String> {
    let NewScheduledCoreInput {
        namespace,
        queue,
        job,
        payload_bytes,
        checkpoint_bytes,
        expires_at,
        revision,
        execution_id,
    } = input;
    let actual_job = actual_job_id(job);
    let payload_len = u32::try_from(payload_bytes.max(0))
        .map_err(|_| "payload length does not fit core record".to_owned())?;
    let chunk_key = KeyCodec::encode(
        namespace,
        KeyTag::PayloadChunk,
        &[actual_job.as_bytes(), &0_u32.to_be_bytes()],
    )
    .map_err(|error| error.to_string())?;
    let payload = PayloadManifest::try_new(
        payload_len,
        [0; 32],
        if payload_len == 0 {
            Vec::new()
        } else {
            vec![chunk_key]
        },
    )
    .map_err(|error| error.to_string())?;
    let policy = JobPolicySnapshot {
        effect_mode: EffectMode::Idempotent,
        cost_units: NonZeroU16::MIN,
        execution_timeout: Some(Duration::from_secs(3)),
        retry_policy: RetryPolicy::try_from(RetryPolicyInput {
            maximum_attempts: NonZeroU16::new(3).ok_or_else(|| "zero attempts".to_owned())?,
            maximum_age: Duration::from_secs(12),
            minimum_backoff: Duration::from_secs(1),
            maximum_backoff: Duration::from_secs(1),
            multiplier: BackoffMultiplier::try_from(1_u32).map_err(|error| error.to_string())?,
        })
        .map_err(|error| error.to_string())?,
    };
    let checkpoint = if checkpoint_bytes > 0 {
        Some(Bytes::from(vec![0; checkpoint_bytes as usize]))
    } else {
        None
    };
    let core = JobRecordV1 {
        job_id: actual_job,
        namespace: namespace.clone(),
        queue: queue.clone(),
        kind: JobKind::try_new("email").map_err(|error| error.to_string())?,
        schema_version: NonZeroU16::MIN,
        generation: 0,
        execution_id: ExecutionId::from(number_bytes(execution_id)),
        payload,
        fairness: FairnessClass::low_volume(),
        ordering_key: None,
        priority: Priority::Default,
        created_at: Timestamp::ZERO,
        scheduled_at: Timestamp::ZERO,
        expires_at: Some(Timestamp::from_millis(expires_at.saturating_mul(1_000))),
        policy,
        attempts: None,
        state: JobState::Scheduled,
        checkpoint,
        retention_deadline: Timestamp::from_millis(expires_at.saturating_mul(1_000)),
        deduplication: None,
        revision: revision.max(0) as u64,
    };
    core.validate().map_err(|error| error.to_string())?;
    Ok(core)
}

pub(super) fn actual_job_id(job: ModelJobId) -> ActualJobId {
    ActualJobId::from(match job {
        ModelJobId::JobA => [1; 16],
        ModelJobId::JobB => [2; 16],
        ModelJobId::JobC => [3; 16],
    })
}

pub(super) fn owner_id(node: Node) -> bg_jobs::OwnerId {
    bg_jobs::OwnerId::from(match node {
        Node::NodeA => [1; 16],
        Node::NodeB => [2; 16],
    })
}

pub(super) fn lease_token(token: i64) -> LeaseToken {
    LeaseToken::from(number_bytes(token))
}

fn number_bytes(value: i64) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[8..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn put_i64(target: &mut Vec<u8>, value: i64) {
    target.extend_from_slice(&value.to_be_bytes());
}

fn record_kind_tag(kind: RecordKind) -> u8 {
    match kind {
        RecordKind::Valid => 0,
        RecordKind::Missing => 1,
        RecordKind::Corrupt => 2,
        RecordKind::UnknownVersion => 3,
    }
}

fn record_kind(tag: u8) -> Result<RecordKind, String> {
    match tag {
        0 => Ok(RecordKind::Valid),
        1 => Ok(RecordKind::Missing),
        2 => Ok(RecordKind::Corrupt),
        3 => Ok(RecordKind::UnknownVersion),
        _ => Err("invalid connector record kind".to_owned()),
    }
}

fn node_tag(node: Node) -> u8 {
    match node {
        Node::NodeA => 0,
        Node::NodeB => 1,
    }
}

fn node(tag: u8) -> Result<Node, String> {
    match tag {
        0 => Ok(Node::NodeA),
        1 => Ok(Node::NodeB),
        _ => Err("invalid connector node".to_owned()),
    }
}

fn operation_tag(operation: ModelOperationId) -> u8 {
    match operation {
        ModelOperationId::OperationA => 0,
        ModelOperationId::OperationB => 1,
        ModelOperationId::OperationC => 2,
        ModelOperationId::OperationD => 3,
    }
}

fn job_tag(job: ModelJobId) -> u8 {
    match job {
        ModelJobId::JobA => 0,
        ModelJobId::JobB => 1,
        ModelJobId::JobC => 2,
    }
}

fn model_job(tag: u8) -> Result<ModelJobId, String> {
    match tag {
        0 => Ok(ModelJobId::JobA),
        1 => Ok(ModelJobId::JobB),
        2 => Ok(ModelJobId::JobC),
        _ => Err("invalid connector job".to_owned()),
    }
}

fn operation(tag: u8) -> Result<ModelOperationId, String> {
    match tag {
        0 => Ok(ModelOperationId::OperationA),
        1 => Ok(ModelOperationId::OperationB),
        2 => Ok(ModelOperationId::OperationC),
        3 => Ok(ModelOperationId::OperationD),
        _ => Err("invalid connector operation".to_owned()),
    }
}

fn number_from_bytes(bytes: &[u8; 16]) -> i64 {
    let mut tail = [0; 8];
    tail.copy_from_slice(&bytes[8..]);
    i64::from_be_bytes(tail)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> Result<u8, String> {
        let value = self
            .bytes
            .get(self.offset)
            .copied()
            .ok_or_else(|| "truncated connector record receipt".to_owned())?;
        self.offset += 1;
        Ok(value)
    }

    fn bool(&mut self) -> Result<bool, String> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("invalid connector record receipt boolean".to_owned()),
        }
    }

    fn i64(&mut self) -> Result<i64, String> {
        let end = self
            .offset
            .checked_add(8)
            .ok_or_else(|| "connector record receipt length overflow".to_owned())?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| "truncated connector record receipt integer".to_owned())?;
        self.offset = end;
        Ok(i64::from_be_bytes(bytes.try_into().map_err(|_| {
            "invalid connector receipt integer".to_owned()
        })?))
    }

    fn finish(self) -> Result<(), String> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err("trailing connector record receipt bytes".to_owned())
        }
    }
}

pub(super) fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        if let std::task::Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        std::thread::yield_now();
    }
}
