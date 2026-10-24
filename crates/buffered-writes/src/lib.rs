#![doc = include_str!("../README.md")]
#![cfg_attr(not(test), deny(clippy::print_stderr, clippy::print_stdout))]
#![deny(unsafe_code)]

mod batch;
mod buffer;
mod configuration;
mod constants;
#[cfg(feature = "disk")]
mod disk_buffer;
mod engine;
mod error;
mod flush_summary;
#[cfg(feature = "ec2")]
mod imds_spot_source;
#[cfg(feature = "lambda")]
mod lambda_lifecycle;
mod lifecycle;
mod lifecycle_mailbox;
mod memory_buffer;
mod observer;
mod queue;
mod replay;
mod retention;
mod sink;
#[cfg(feature = "tokio")]
mod spot_lifecycle;
#[cfg(feature = "sqs")]
mod sqs_queue;
#[cfg(feature = "tokio")]
mod tokio_lifecycle;
#[cfg(feature = "valkey")]
mod valkey_buffer;
mod write_attempt;
mod write_outcome;
mod write_sink;
mod writer;

pub use batch::{
    AdmissionFingerprint, AdmittedRecord, BatchItems, ClosureWriteBatch, DefaultItemGrouping,
    PersistedRecord, PreparationLayout, PreparedOperation, PreparedPayload, PreparedWrites,
    RawBytesCodec, RecordCodec, ScopedWrite, SealedBatch, SealedBatchInput, SerdeJsonCodec,
    WriteBatch, WriteItem,
};
pub use buffer::{
    AdmissionReceipt, BufferAppendRequest, BufferAppendResult, BufferClaimRequest,
    BufferInspectRequest, BufferRenewRequest, BufferSealAction, BufferSealRequest,
    BufferSettleRequest, BufferSnapshot, ClaimedWork, LeasedSealedBatch, OpenBatchCandidate,
    SettleDisposition, WriteBuffer,
};
pub use configuration::{
    Admission, AdmissionStatus, BackpressurePolicy, BatchId, BufferCapacity, BufferConfig,
    BufferStats, Deadline, DeliveryPolicy, DurabilityClass, FencingToken, FlushPolicy,
    FlushThresholds, Namespace, OperationId, SinkLimits, TenantScope, ValkeyCredentials,
    WriteOptions,
};
#[cfg(feature = "disk")]
pub use disk_buffer::DiskBuffer;
pub use error::{
    BufferError, ConfigurationError, EncodeError, LifecycleError, PrepareError, QueueError,
    SinkError, WriteError,
};
pub use flush_summary::FlushReportSummary;
#[cfg(feature = "ec2")]
pub use imds_spot_source::ImdsSpotSource;
#[cfg(feature = "lambda")]
pub use lambda_lifecycle::{
    LambdaExtensionClient, LambdaExtensionServer, LambdaInvocation, LambdaIpcConfig,
};
pub use lifecycle::{
    ChannelLifecycle, Lifecycle, LifecycleController, LifecycleEvents, LifecycleTrigger,
    RuntimeGuard,
};
pub use memory_buffer::MemoryBuffer;
pub use observer::{
    AdmissionRejectReason, Clock, DeliveryMode, DrainReport, FlushReport, NoopWriteObserver,
    ProductionClock, QuarantineReason, QueueFailureKind, RecordingWriteObserver, ReplayObservation,
    SinkFailureKind, SinkHealth, TestClock, WriteEvent, WriteObserver,
};
pub use queue::{
    InMemoryQueue, QueueConfig, QueueLimits, QueueReceipt, ReceivedEnvelope, ReplayQueue,
    WriteQueue,
};
pub use replay::{ReplayBuilder, ReplayReport, ReplayWorker};
pub use sink::{AtomicSink, AtomicWriteStatus, IntoAtomicWriteStatus, PartialSink};
#[cfg(feature = "tokio")]
pub use spot_lifecycle::{
    InjectedSpotSource, SpotActionKind, SpotActionSource, SpotInstanceAction, SpotLifecycle,
};
#[cfg(feature = "sqs")]
pub use sqs_queue::SqsQueue;
#[cfg(feature = "tokio")]
pub use tokio_lifecycle::TokioLifecycle;
#[cfg(feature = "valkey")]
pub use valkey_buffer::ValkeyBuffer;
pub use write_attempt::{PendingItem, WriteAttempt};
pub use write_outcome::{OperationStatus, WriteOutcome};
pub use write_sink::{ReplayGuarantee, WriteSink};
pub use writer::{BufferedWrites, WritesBuilder};

#[cfg(all(test, feature = "valkey"))]
mod constants_tests;
