//! Runtime-neutral contracts and deterministic v1 codecs for durable background
//! jobs.
//!
//! The crate owns validation, persistence shapes, and atomic store contracts.
//! It does not choose an async runtime, provide a network route, or embed
//! product identity concepts.
//!
//! The optional `test-support` feature exposes `FakeStore` and `TestProfile`
//! for deterministic tests and conformance only. They are not production
//! persistence or runtime scheduling. Consumers of this crate must provide
//! their own production [`JobStore`] implementation, backend adapter, and
//! runtime-owned wake scheduler.
#![deny(unsafe_code)]

#[cfg(any(test, feature = "test-support"))]
mod active_pulse;
mod admin;
mod batch;
mod budget;
mod builder;
#[cfg(test)]
mod builder_tests;
mod catalog;
#[cfg(test)]
mod catalog_tests;
mod codec;
mod drive;
mod engine;
#[cfg(test)]
mod engine_tests;
mod enqueue;
mod error;
mod failure;
mod fairness;
mod ids;
mod keys;
mod lifecycle;
pub mod metrics_observer;
mod model;
pub mod observer;
mod policy;
mod polling_job;
#[cfg(test)]
mod polling_job_tests;
#[cfg(test)]
mod quint;
mod registry;
mod schedule;
pub mod store;
#[cfg(any(test, feature = "test-support"))]
mod test_helper;
mod time;
mod transition;
mod wake;

/// The portable inline payload ceiling used by application codecs.
pub use crate::model::MAX_INLINE_PAYLOAD_BYTES;
/// The small, routine construction surface for application-owned jobs.
pub use crate::{
    budget::{DriveBudget, DriveBudgetInput, DriveReport, DriveStopReason, QueueSelection},
    catalog::JobCatalog,
    error::{JobResult, JobSystemError, ValidationError},
    ids::{
        AttemptId, DeduplicationKey, ExecutionId, FairnessKey, IdentifierError, JobId, JobKind,
        Namespace, OrderingKey, OwnerId, QueueName,
    },
    model::{
        CancellationToken, ClaimLeasePolicy, ClaimPublicationFuture, EnqueueDisposition,
        EnqueueOptions, EnqueueResult, ExecutionContext, HandlerFuture, JobEffectAuthority,
        JobExecution, JobHandle, JobHandler, JobOutcome, JobSeed, JobSpec, JobState,
        JobTerminalAuthority, LifecycleObservation, RemoteJobClaim, poll_checkpoint_payload,
    },
    policy::{
        Deduplication, EffectMode, FairnessClass, FairnessPath, FairnessPolicy, OutcomeCode,
        Priority, RetryClass, RetryPreset, RetrySelection,
    },
    polling_job::{JobPoller, PollActivity, PollFuture, PollingJob},
    store::JobStore,
    time::{Timestamp, WakeHint},
};

/// Narrow runtime-construction boundary used by runtime adapters.
///
/// Application code should use the runtime-specific facade (for example
/// `bg_jobs_tokio::JobRuntime`) instead of constructing a `JobSystem` directly.
pub mod runtime {
    /// Low-level engine construction for runtime adapters and deterministic
    /// conformance harnesses. Routine applications should use a runtime
    /// facade such as `bg_jobs_tokio::JobRuntime`.
    pub use crate::{
        builder::JobSystemBuilder,
        engine::JobSystem,
        model::{WakeFuture, WakeScheduler, WakeSchedulerError},
        time::MonotonicDeadline,
    };
}

// Keep deep implementation modules readable without widening the public API.
// These aliases are crate-private and are retained only for names used across
// the implementation and its adjacent unit tests.
#[cfg(test)]
pub(crate) use crate::{
    active_pulse::{ActivePulseRequest, ActivePulseStopReason},
    batch::{AuthConfigId, BatchKey},
    budget::{DriveCounts, DriveProfile, DriveProfileInput, DriveRequest, DriveRequestInput},
    builder::JobSystemBuilder,
    engine::JobSystem,
    error::{StoreContractError, StoreDataError, StoreFailure},
    failure::{
        CancellationResult, ExpiryResult, OutcomeResult, RedriveExecution, RedriveRequest,
        RenewalResult,
    },
    fairness::FairCandidateState,
    ids::{CommitOperationId, LeaseToken, OccurrenceId, OperationId, ScheduleId},
    lifecycle::ClaimedJob,
    metrics_observer::{BatchMetricOutcome, HttpMetricOutcome, MetricsObserver},
    model::{
        HandlerDefinition, JobRecordV1, Lease, LifecycleRecordStatus, NewJob, PayloadManifest,
        TerminalDisposition, WakeFuture, WakeScheduler, WakeSchedulerError,
    },
    observer::AttemptBucket,
    policy::{
        BackoffMultiplier, Cadence, FullJitter, MisfirePolicy, OverlapPolicy, RetryPolicy,
        RetryPolicyInput,
    },
    registry::HandlerRegistry,
    schedule::{
        JobTemplate, JobTemplateInput, RecurringSchedule, RecurringScheduleInput, ScheduleControl,
        ScheduleControlResult, ScheduleCursor, ScheduleEvaluation, ScheduleMaterializationBudget,
        ScheduleOccurrence,
    },
    store::{
        CommitOutcome, RangePage, RangeRequest, StoreCapabilities, StoreCapabilitiesInput,
        StoreKey, StoreLevel, StoreTransaction,
    },
    test_helper::{FakeStore, FakeStoreError},
    time::{CronExpression, MonotonicDeadline},
    transition::ReconciliationOutcome,
    wake::{WakeCandidates, WakeWatermark},
};
pub(crate) use crate::{
    fairness::{FairScope, FairVolumeMode, NORMALIZATION_SCALE, PriorityDeficit},
    observer::{JobEvent, JobObserver, SafeJobErrorEvent, SafeJobErrorKind},
};

/// Test-only reference storage is explicit so it is not mistaken for a
/// production adapter. Enable the `test-support` feature to use it.
#[cfg(feature = "test-support")]
pub mod test_support {
    pub use crate::test_helper::{FakeStore, FakeStoreError, TestProfile};

    /// Codec fixtures used by conformance tests.
    pub mod codec {
        pub use crate::codec::{
            DecodedKey, DecodedKeyRef, DecodedValue, KeyCodec, KeyTag, ValueCodec, ValueTag,
            decode_job_record, encode_job_record,
        };
    }

    /// Raw engine and persistence values needed only by conformance and test
    /// profiles. Enable the `test-support` feature explicitly; routine
    /// consumers should use the root facade or a runtime adapter instead.
    pub mod raw {
        pub use crate::{
            active_pulse::{ActivePulseReport, ActivePulseRequest, ActivePulseStopReason},
            batch::{
                AuthConfigId, Batch, BatchApplication, BatchBuilder, BatchCompatibility, BatchItem,
                BatchItemResolution, BatchKey, BatchLimits, BatchLimitsInput, BatchOutcome,
                BatchRejection, BatchResult, BatchResultError, ScratchStorage,
            },
            budget::{
                CompletionDetails, DriveCounts, DriveProfile, DriveProfileInput, DriveRequest,
                DriveRequestInput,
            },
            failure::{
                CancellationResult, CheckpointResult, ExpiryResult, OutcomeResult,
                RedriveExecution, RedriveRequest, RedriveResult, RenewalResult,
            },
            fairness::{
                CandidateBlock, FairCandidate, FairCandidateInput, FairCandidateState, FairPermit,
                FairRelease, FairScope, FairVolumeMode, FairnessBudget, FairnessBudgetInput,
                FairnessLedger, FairnessRejection, NORMALIZATION_SCALE, PriorityDeficit,
                ScopeSnapshot, normalized_service, normalized_service_error,
            },
            ids::{IdentifierError, LeaseToken, OccurrenceId, OperationId, ScheduleId},
            lifecycle::ClaimedJob,
            model::{
                AttemptHistory, CancellationToken, HandlerDefinition, JobPolicySnapshot,
                JobRecordV1, Lease, LifecycleObservation, LifecyclePayload, LifecycleRecord,
                LifecycleRecordStatus, LifecycleRoutes, MAX_CHECKPOINT_BYTES, MAX_COST_UNITS,
                NewJob, OperationReceipt, PayloadManifest, TerminalDisposition,
            },
            policy::{
                BackoffMultiplier, Cadence, FullJitter, MisfirePolicy, OverlapPolicy, RetryPolicy,
                RetryPolicyInput, TINY_MAX_COMPLETION_DETAILS, TINY_MAX_PAYLOAD_BYTES_IN_FLIGHT,
            },
            schedule::{
                JobTemplate, JobTemplateInput, MaterializedOccurrence, RecurringSchedule,
                RecurringScheduleInput, ScheduleControl, ScheduleControlResult, ScheduleCursor,
                ScheduleEvaluation, ScheduleMaterialization, ScheduleMaterializationBudget,
                ScheduleOccurrence,
            },
            time::CronExpression,
            transition::{ReconciliationOutcome, TransitionAuthority},
            wake::{WakeCandidates, WakeWatermark},
        };
    }
}
