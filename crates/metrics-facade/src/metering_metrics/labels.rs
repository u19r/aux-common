use buffered_writes::{
    AdmissionRejectReason, AdmissionStatus, DeliveryMode, DurabilityClass, QuarantineReason,
    QueueFailureKind, ReplayObservation, SinkFailureKind, SinkHealth,
};

pub(super) fn mode(value: DeliveryMode) -> usize {
    match value {
        DeliveryMode::Buffered => 0,
        DeliveryMode::Synchronous => 1,
        DeliveryMode::Draining => 2,
        DeliveryMode::Stopped => 3,
    }
}

pub(super) fn health(value: SinkHealth) -> usize {
    match value {
        SinkHealth::Closed => 0,
        SinkHealth::Open => 1,
        SinkHealth::HalfOpen => 2,
    }
}

pub(super) fn admission(value: AdmissionStatus) -> &'static str {
    match value {
        AdmissionStatus::Buffered => "buffered",
        AdmissionStatus::Written => "written",
        AdmissionStatus::Queued => "queued",
    }
}

pub(super) fn durability(value: DurabilityClass) -> &'static str {
    match value {
        DurabilityClass::Volatile => "volatile",
        DurabilityClass::DiskSynced => "disk_synced",
        DurabilityClass::RemoteValkey => "remote_valkey",
        DurabilityClass::SinkCommittedAtomic => "sink_atomic",
        DurabilityClass::SinkCommittedIdempotent => "sink_idempotent",
        DurabilityClass::QueueHandedOff => "queue_handoff",
    }
}

pub(super) fn rejection(value: AdmissionRejectReason) -> &'static str {
    match value {
        AdmissionRejectReason::Full => "full",
        AdmissionRejectReason::Closed => "closed",
        AdmissionRejectReason::Oversized => "oversized",
        AdmissionRejectReason::IdentityConflict => "identity_conflict",
        AdmissionRejectReason::InvalidInput => "invalid_input",
        AdmissionRejectReason::Unavailable => "unavailable",
        AdmissionRejectReason::DeadlineExceeded => "deadline_exceeded",
    }
}

pub(super) fn failure(value: SinkFailureKind) -> &'static str {
    match value {
        SinkFailureKind::Retryable => "retryable",
        SinkFailureKind::Permanent => "permanent",
        SinkFailureKind::IdentityConflict => "identity_conflict",
        SinkFailureKind::UnknownOutcome => "unknown_outcome",
        SinkFailureKind::InvalidOutcome => "invalid_outcome",
        SinkFailureKind::DeadlineExceeded => "deadline_exceeded",
    }
}

pub(super) fn quarantine(value: QuarantineReason) -> &'static str {
    match value {
        QuarantineReason::OversizedSingleton => "oversized_singleton",
        QuarantineReason::PermanentPrepareError => "permanent_prepare",
        QuarantineReason::PermanentSinkFailure => "permanent_sink",
        QuarantineReason::IdentityConflict => "identity_conflict",
        QuarantineReason::PoisonReplayEnvelope => "poison_replay",
        QuarantineReason::ExpiredReplayEnvelope => "expired_replay",
        QuarantineReason::UncertainReplayAge => "uncertain_replay_age",
        QuarantineReason::CorruptJournalFrame => "corrupt_journal",
    }
}

pub(super) fn replay(value: ReplayObservation) -> &'static str {
    match value {
        ReplayObservation::Delivered => "delivered",
        ReplayObservation::RetainedForRetry => "retained_for_retry",
        ReplayObservation::Quarantined => "quarantined",
    }
}

pub(super) fn attempt(retry_attempt: u32) -> &'static str {
    if retry_attempt > 0 {
        "retry"
    } else {
        "initial"
    }
}

pub(super) fn queue_failure(kind: QueueFailureKind) -> &'static str {
    match kind {
        QueueFailureKind::Oversized => "oversized",
        QueueFailureKind::Unavailable => "unavailable",
        QueueFailureKind::Permanent => "permanent",
        QueueFailureKind::UnknownOutcome => "unknown_outcome",
        QueueFailureKind::DeadlineExceeded => "deadline_exceeded",
        QueueFailureKind::InvalidReceipt => "invalid_receipt",
        QueueFailureKind::PoisonEnvelope => "poison_envelope",
    }
}
