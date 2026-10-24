use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bg_jobs::{
    EffectMode, EnqueueDisposition, ExecutionContext, ExecutionId, FairnessPolicy, HandlerFuture,
    JobCatalog, JobHandler, JobId, JobKind, JobOutcome, JobState, JobSystemError, OutcomeCode,
    OwnerId, QueueName, RetryClass, RetryPreset, RetrySelection, Timestamp,
    observer::{JobEvent, JobObserver, SafeJobErrorEvent},
    runtime::{JobSystem, MonotonicDeadline},
    test_support::{
        FakeStore,
        codec::{KeyCodec, KeyTag, decode_job_record, encode_job_record},
        raw::{
            BackoffMultiplier, CancellationResult, ClaimedJob, ExpiryResult, HandlerDefinition,
            JobRecordV1, Lease, LifecycleObservation, NewJob, OperationId, OutcomeResult,
            RedriveExecution, RedriveRequest, RetryPolicy, RetryPolicyInput, TransitionAuthority,
        },
    },
};
use bytes::Bytes;
use cucumber::{given, then, when};

use super::lifecycle;
use crate::{BddWorld, RecoveryEvidence};

const RAW_MARKER: &str = "payload=private-body url=https://private.invalid headers=authorization \
                          secret-id=private-credential";

#[given("two distributed drivers discover the same due job")]
async fn given_distributed_race(world: &mut BddWorld) -> Result<(), String> {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::distributed();
    let system = lifecycle::build_system_with_owner(store.clone(), calls.clone(), 1)?;
    let now = Timestamp::ZERO;
    let job = lifecycle::new_job(
        10,
        Bytes::from_static(b"race"),
        lifecycle::scoped_fairness(),
        now,
    )?;
    let enqueue = system
        .enqueue_raw(job.clone(), now)
        .await
        .map_err(display_error)?;
    if enqueue.disposition != EnqueueDisposition::Enqueued {
        return Err(format!(
            "race fixture enqueue returned {:?}",
            enqueue.disposition
        ));
    }
    lifecycle::save_system(world, store, system, calls, job, now);
    Ok(())
}

#[when("both commit a claim")]
async fn when_distributed_drivers_claim(world: &mut BddWorld) -> Result<(), String> {
    let system = lifecycle::take_system(world)?;
    let store = world
        .store
        .as_ref()
        .ok_or("store was not configured")?
        .clone();
    let calls = world
        .handler_calls
        .as_ref()
        .ok_or("handler was not configured")?
        .clone();
    let contender = lifecycle::build_system_with_owner(store.clone(), calls, 2)?;
    let job_id = world.job.as_ref().ok_or("job was not configured")?.job_id;
    let claim = system
        .claim(job_id, world.now)
        .await
        .map_err(display_error)?;
    let authoritative = claim.authority().ok_or("claim had no lease authority")?;
    let contender_result = contender.claim(job_id, world.now).await;
    let stored = record_if_present(&store, job_id)?.ok_or("claimed record disappeared")?;
    let stored_authority = authority(&stored).ok_or("stored record was not leased")?;
    world.recovery = Some(RecoveryEvidence {
        authoritative_claim: Some(authoritative),
        stored_authority: Some(stored_authority),
        contender_conflicted: matches!(contender_result, Err(JobSystemError::LeaseConflict)),
        ..RecoveryEvidence::default()
    });
    world.system = Some(system);
    Ok(())
}

#[then("only one token and fence become authoritative")]
async fn then_one_authoritative_claim(world: &mut BddWorld) -> Result<(), String> {
    let evidence = world.recovery.as_ref().ok_or("race evidence was missing")?;
    if !evidence.contender_conflicted {
        return Err("the competing distributed claim did not conflict".to_owned());
    }
    if evidence.authoritative_claim != evidence.stored_authority {
        return Err("stored token or fence differs from the committed claimant".to_owned());
    }
    Ok(())
}

#[given("an old lease expires and a successor claims the job")]
async fn given_expired_lease(world: &mut BddWorld) -> Result<(), String> {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::distributed();
    let system = lifecycle::build_system_with_owner(store.clone(), calls.clone(), 1)?;
    let now = Timestamp::ZERO;
    let job = lifecycle::new_job(
        20,
        Bytes::from_static(b"reclaim"),
        lifecycle::scoped_fairness(),
        now,
    )?;
    system
        .enqueue_raw(job.clone(), now)
        .await
        .map_err(display_error)?;
    lifecycle::save_system(world, store, system, calls, job, now);
    Ok(())
}

#[when("the old worker renews checkpoints or completes")]
async fn when_stale_worker_mutates(world: &mut BddWorld) -> Result<(), String> {
    let system = lifecycle::take_system(world)?;
    let store = world
        .store
        .as_ref()
        .ok_or("store was not configured")?
        .clone();
    let calls = world
        .handler_calls
        .as_ref()
        .ok_or("handler was not configured")?
        .clone();
    let successor_system = lifecycle::build_system_with_owner(store.clone(), calls, 2)?;
    let job_id = world.job.as_ref().ok_or("job was not configured")?.job_id;
    let mut stale = system
        .claim(job_id, world.now)
        .await
        .map_err(display_error)?;
    let expired = successor_system
        .expire_job(job_id, Timestamp::from_millis(2_000))
        .await
        .map_err(display_error)?;
    if !matches!(expired, ExpiryResult::LeaseExpired) {
        return Err(format!("expected lease reclaim, got {expired:?}"));
    }
    let successor = successor_system
        .claim(job_id, Timestamp::from_millis(2_000))
        .await
        .map_err(display_error)?;
    let before = successor.record().clone();
    let renew = system
        .renew(&mut stale, Timestamp::from_millis(2_000))
        .await;
    let checkpoint = system
        .checkpoint(
            &mut stale,
            Bytes::from_static(b"stale-checkpoint"),
            Timestamp::from_millis(2_000),
        )
        .await;
    let complete = system
        .complete(
            stale,
            JobOutcome::Complete(outcome_code("stale-complete")?),
            Timestamp::from_millis(2_000),
        )
        .await;
    let after = record_if_present(&store, job_id)?.ok_or("successor record disappeared")?;
    world.recovery = Some(RecoveryEvidence {
        stale_mutations_rejected: matches!(renew, Err(JobSystemError::LeaseLost))
            && matches!(checkpoint, Err(JobSystemError::LeaseLost))
            && matches!(complete, Err(JobSystemError::LeaseLost)),
        successor_unchanged: before == after,
        ..RecoveryEvidence::default()
    });
    world.system = Some(system);
    Ok(())
}

#[then("every stale mutation is rejected without changing successor state")]
async fn then_stale_mutations_rejected(world: &mut BddWorld) -> Result<(), String> {
    let evidence = world
        .recovery
        .as_ref()
        .ok_or("stale-worker evidence was missing")?;
    if !evidence.stale_mutations_rejected || !evidence.successor_unchanged {
        return Err(
            "a stale mutation changed or was accepted against successor authority".to_owned(),
        );
    }
    Ok(())
}

#[given("a transient or ambiguous effect failure")]
async fn given_network_retry(world: &mut BddWorld) -> Result<(), String> {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::distributed();
    let system = lifecycle::build_system_with_owner(store.clone(), calls.clone(), 1)?;
    let mut job = lifecycle::new_job(
        30,
        Bytes::from_static(b"retry"),
        lifecycle::scoped_fairness(),
        Timestamp::ZERO,
    )?;
    job.retry_override = Some(RetrySelection::Preset(RetryPreset::Network));
    lifecycle::save_system(world, store, system, calls, job, Timestamp::ZERO);
    Ok(())
}

#[when("the job retries under Network policy")]
async fn when_network_retry(world: &mut BddWorld) -> Result<(), String> {
    let system = lifecycle::take_system(world)?;
    let store = world
        .store
        .as_ref()
        .ok_or("store was not configured")?
        .clone();
    let job = world.job.clone().ok_or("job was not configured")?;
    let enqueue = system
        .enqueue_raw(job.clone(), world.now)
        .await
        .map_err(display_error)?;
    if enqueue.disposition != EnqueueDisposition::Enqueued {
        return Err(format!(
            "retry fixture enqueue returned {:?}",
            enqueue.disposition
        ));
    }
    let record = record_if_present(&store, job.job_id)?.ok_or("retry record missing")?;
    let first = system
        .claim(job.job_id, world.now)
        .await
        .map_err(display_error)?;
    let execution = first.record().execution_id;
    let first_attempt = first.attempt_id();
    let retry = system
        .apply_outcome(first, retry_outcome()?, world.now)
        .await
        .map_err(display_error)?;
    let not_before = match retry {
        OutcomeResult::Retried { not_before, .. } => not_before,
        other => return Err(format!("expected retry, got {other:?}")),
    };
    let second = system
        .claim(job.job_id, not_before)
        .await
        .map_err(display_error)?;
    world.recovery = Some(RecoveryEvidence {
        network_policy: record.policy.retry_policy == RetryPolicy::preset(RetryPreset::Network),
        execution_ids: vec![execution, second.record().execution_id],
        attempt_ids: vec![first_attempt, second.attempt_id()],
        ..RecoveryEvidence::default()
    });
    world.system = Some(system);
    Ok(())
}

#[then("every attempt receives the same execution ID")]
async fn then_execution_id_is_stable(world: &mut BddWorld) -> Result<(), String> {
    let evidence = world
        .recovery
        .as_ref()
        .ok_or("retry evidence was missing")?;
    if !evidence.network_policy
        || evidence.execution_ids.len() != 2
        || evidence.execution_ids[0] != evidence.execution_ids[1]
    {
        return Err("Network retry did not preserve the execution identity".to_owned());
    }
    Ok(())
}

#[then("each attempt receives a unique attempt ID")]
async fn then_attempt_id_is_unique(world: &mut BddWorld) -> Result<(), String> {
    let evidence = world
        .recovery
        .as_ref()
        .ok_or("retry evidence was missing")?;
    if evidence.attempt_ids.len() != 2 || evidence.attempt_ids[0] == evidence.attempt_ids[1] {
        return Err("automatic retry reused an attempt identity".to_owned());
    }
    Ok(())
}

#[given("a handler fails until attempts or maximum age is exhausted")]
async fn given_poison_and_peer(world: &mut BddWorld) -> Result<(), String> {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::distributed();
    let system = lifecycle::build_system_with_owner(store.clone(), calls.clone(), 1)?;
    let mut poison = lifecycle::new_job(
        40,
        Bytes::from_static(b"poison"),
        lifecycle::scoped_fairness(),
        Timestamp::ZERO,
    )?;
    poison.retry_override = Some(
        RetryPreset::Interactive
            .with_limits(lifecycle::nonzero_u16(3)?, Duration::from_secs(120))
            .map_err(display_error)?,
    );
    lifecycle::save_system(world, store, system, calls, poison, Timestamp::ZERO);
    Ok(())
}

#[when("other due jobs are present")]
async fn when_poison_exhausts(world: &mut BddWorld) -> Result<(), String> {
    let system = lifecycle::take_system(world)?;
    let store = world
        .store
        .as_ref()
        .ok_or("store was not configured")?
        .clone();
    let poison = world.job.clone().ok_or("poison job was not configured")?;
    let peer = lifecycle::new_job(
        41,
        Bytes::from_static(b"peer"),
        lifecycle::scoped_fairness(),
        Timestamp::ZERO,
    )?;
    system
        .enqueue_raw(poison.clone(), world.now)
        .await
        .map_err(display_error)?;
    system
        .enqueue_raw(peer.clone(), world.now)
        .await
        .map_err(display_error)?;
    let first = system
        .claim(poison.job_id, world.now)
        .await
        .map_err(display_error)?;
    let next = retry_at(&system, first, world.now).await?;
    let second = system
        .claim(poison.job_id, next)
        .await
        .map_err(display_error)?;
    let next = retry_at(&system, second, next).await?;
    let third = system
        .claim(poison.job_id, next)
        .await
        .map_err(display_error)?;
    let terminal = system
        .apply_outcome(third, retry_outcome()?, next)
        .await
        .map_err(display_error)?;
    if !matches!(terminal, OutcomeResult::DeadLettered { .. }) {
        return Err(format!("poison work did not dead-letter: {terminal:?}"));
    }
    let peer_claim = system
        .claim(peer.job_id, world.now)
        .await
        .map_err(display_error)?;
    let peer_completion = system
        .complete(
            peer_claim,
            JobOutcome::Complete(outcome_code("peer-complete")?),
            world.now,
        )
        .await
        .map_err(display_error)?;
    let poison_record = record_if_present(&store, poison.job_id)?;
    let peer_record = record_if_present(&store, peer.job_id)?;
    world.recovery = Some(RecoveryEvidence {
        poison_dead_lettered: poison_record
            .is_some_and(|record| matches!(record.state, JobState::DeadLettered)),
        unrelated_completed: peer_completion.job_id == peer.job_id && peer_record.is_none(),
        ..RecoveryEvidence::default()
    });
    world.system = Some(system);
    Ok(())
}

#[then("the failed job becomes dead-lettered")]
async fn then_poison_dead_letters(world: &mut BddWorld) -> Result<(), String> {
    if !world
        .recovery
        .as_ref()
        .ok_or("poison evidence was missing")?
        .poison_dead_lettered
    {
        return Err("poison work did not remain dead-lettered".to_owned());
    }
    Ok(())
}

#[then("unrelated work continues without head-of-line blocking")]
async fn then_peer_completes(world: &mut BddWorld) -> Result<(), String> {
    if !world
        .recovery
        .as_ref()
        .ok_or("poison evidence was missing")?
        .unrelated_completed
    {
        return Err("unrelated due work did not complete".to_owned());
    }
    Ok(())
}

#[given("the store committed completion but returned Unknown")]
async fn given_unknown_completion(world: &mut BddWorld) -> Result<(), String> {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::distributed();
    let system = lifecycle::build_system_with_owner(store.clone(), calls.clone(), 1)?;
    let job = lifecycle::new_job(
        50,
        Bytes::from_static(b"unknown-completion"),
        lifecycle::scoped_fairness(),
        Timestamp::ZERO,
    )?;
    lifecycle::save_system(world, store, system, calls, job, Timestamp::ZERO);
    Ok(())
}

#[when("the engine reconciles by job ID token fence and operation ID")]
async fn when_unknown_completion_reconciles(world: &mut BddWorld) -> Result<(), String> {
    let system = lifecycle::take_system(world)?;
    let store = world
        .store
        .as_ref()
        .ok_or("store was not configured")?
        .clone();
    let job = world.job.clone().ok_or("job was not configured")?;
    system
        .enqueue_raw(job.clone(), world.now)
        .await
        .map_err(display_error)?;
    let claim = system
        .claim(job.job_id, world.now)
        .await
        .map_err(display_error)?;
    let outcome = system
        .execute_claimed(&claim, world.now, || MonotonicDeadline::ZERO)
        .await
        .map_err(display_error)?;
    store.queue_unknown_after_commit().map_err(display_error)?;
    let completion = system
        .complete(claim, outcome, world.now)
        .await
        .map_err(display_error)?;
    let handler_calls = world
        .handler_calls
        .as_ref()
        .ok_or("handler was not configured")?
        .load(Ordering::SeqCst);
    world.completion = Some(completion);
    world.recovery = Some(RecoveryEvidence {
        completion_reconciled: handler_calls == 1
            && record_if_present(&store, job.job_id)?.is_none(),
        ..RecoveryEvidence::default()
    });
    world.system = Some(system);
    Ok(())
}

#[then("it reports one success without invoking the handler again")]
async fn then_unknown_completion_is_single_success(world: &mut BddWorld) -> Result<(), String> {
    if world.completion.is_none()
        || !world
            .recovery
            .as_ref()
            .ok_or("unknown-completion evidence was missing")?
            .completion_reconciled
    {
        return Err("unknown completion was not reconciled as one success".to_owned());
    }
    Ok(())
}

#[given("a dead-lettered job may already have caused an effect")]
async fn given_redrive_candidate(world: &mut BddWorld) -> Result<(), String> {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::distributed();
    let system = lifecycle::build_system_with_owner(store.clone(), calls.clone(), 1)?;
    let job = lifecycle::new_job(
        60,
        Bytes::from_static(b"redrive"),
        lifecycle::scoped_fairness(),
        Timestamp::ZERO,
    )?;
    lifecycle::save_system(world, store, system, calls, job, Timestamp::ZERO);
    Ok(())
}

#[when("redrive selects reuse or rotation of the execution ID")]
async fn when_redrive_selects_identity(world: &mut BddWorld) -> Result<(), String> {
    let system = lifecycle::take_system(world)?;
    let store = world
        .store
        .as_ref()
        .ok_or("store was not configured")?
        .clone();
    let first_job = world.job.clone().ok_or("redrive job was not configured")?;
    let first = dead_letter_job(&system, &store, first_job, world.now).await?;
    let reused = system
        .redrive_job(
            first.0,
            RedriveRequest::new(
                first.3,
                first.4,
                RedriveExecution::ReuseExecutionId,
                Timestamp::from_millis(10),
            ),
        )
        .await
        .map_err(display_error)?;
    let second_job = lifecycle::new_job(
        61,
        Bytes::from_static(b"redrive-rotate"),
        lifecycle::scoped_fairness(),
        Timestamp::ZERO,
    )?;
    let second = dead_letter_job(&system, &store, second_job, world.now).await?;
    let rotated = system
        .redrive_job(
            second.0,
            RedriveRequest::new(
                second.3,
                second.4,
                RedriveExecution::NewExecutionId,
                Timestamp::from_millis(10),
            ),
        )
        .await
        .map_err(display_error)?;
    world.recovery = Some(RecoveryEvidence {
        redrive_reuse: Some(reused),
        redrive_rotation: Some(rotated),
        redrive_reuse_before: Some((first.1, first.2)),
        redrive_rotation_before: Some((second.1, second.2)),
        ..RecoveryEvidence::default()
    });
    world.system = Some(system);
    Ok(())
}

#[then("generation increments and the selected identity is returned for caller auditing")]
async fn then_redrive_identity_is_explicit(world: &mut BddWorld) -> Result<(), String> {
    let evidence = world
        .recovery
        .as_ref()
        .ok_or("redrive evidence was missing")?;
    let reuse = evidence.redrive_reuse.ok_or("reuse receipt was missing")?;
    let rotate = evidence
        .redrive_rotation
        .ok_or("rotation receipt was missing")?;
    let (reuse_id, reuse_generation) = evidence
        .redrive_reuse_before
        .ok_or("reuse input was missing")?;
    let (rotate_id, rotate_generation) = evidence
        .redrive_rotation_before
        .ok_or("rotation input was missing")?;
    if reuse.generation != reuse_generation + 1
        || reuse.execution_id != reuse_id
        || !reuse.reused_execution
    {
        return Err("reuse redrive did not return the selected identity and generation".to_owned());
    }
    if rotate.generation != rotate_generation + 1
        || rotate.execution_id == rotate_id
        || rotate.reused_execution
    {
        return Err("rotation redrive did not return a new identity and generation".to_owned());
    }
    Ok(())
}

#[given("raw errors contain payloads URLs headers identifiers and credentials")]
async fn given_sensitive_failure(world: &mut BddWorld) -> Result<(), String> {
    let calls = Arc::new(AtomicUsize::new(0));
    let events = Arc::new(Mutex::new(Vec::new()));
    let errors = Arc::new(Mutex::new(Vec::new()));
    let observer = RecordingObserver {
        events: events.clone(),
        errors: errors.clone(),
    };
    let store = FakeStore::distributed();
    let (system, observed_events, observed_errors) =
        raw_error_system(store.clone(), calls.clone(), observer)?;
    let mut job = lifecycle::new_job(
        70,
        Bytes::from_static(b"safe-telemetry"),
        lifecycle::scoped_fairness(),
        Timestamp::ZERO,
    )?;
    job.retry_override = Some(RetrySelection::Custom(
        RetryPolicy::try_from(RetryPolicyInput {
            maximum_attempts: lifecycle::nonzero_u16(2)?,
            maximum_age: Duration::from_secs(60),
            minimum_backoff: Duration::from_millis(1),
            maximum_backoff: Duration::from_millis(1),
            multiplier: BackoffMultiplier::try_from(2_u32).map_err(display_error)?,
        })
        .map_err(display_error)?,
    ));
    lifecycle::save_system(world, store, system, calls, job, Timestamp::ZERO);
    world.observed_events = Some(observed_events);
    world.observed_errors = Some(observed_errors);
    world.recovery = Some(RecoveryEvidence::default());
    Ok(())
}

#[when("retry and DLQ events are observed")]
async fn when_sensitive_failure_is_observed(world: &mut BddWorld) -> Result<(), String> {
    let system = lifecycle::take_system(world)?;
    let job = world
        .job
        .clone()
        .ok_or("telemetry job was not configured")?;
    system
        .enqueue_raw(job, world.now)
        .await
        .map_err(display_error)?;
    let first = system
        .drive(lifecycle::drive_request(), world.now, || {
            MonotonicDeadline::ZERO
        })
        .await
        .map_err(display_error)?;
    let second = system
        .drive(lifecycle::drive_request(), world.now, || {
            MonotonicDeadline::ZERO
        })
        .await
        .map_err(display_error)?;
    if first.counts.retried != 1 || second.counts.dead_lettered != 1 {
        return Err(format!(
            "unexpected safe-failure drive reports: {first:?}, {second:?}"
        ));
    }
    let events = world
        .observed_events
        .as_ref()
        .ok_or("observer events were not configured")?
        .lock()
        .map_err(display_error)?
        .clone();
    let errors = world
        .observed_errors
        .as_ref()
        .ok_or("observer errors were not configured")?
        .lock()
        .map_err(display_error)?
        .clone();
    let text = format!("{events:?}{errors:?}");
    let has_retry = events
        .iter()
        .any(|event| matches!(event, JobEvent::Retried { .. }));
    let has_dead_letter = events
        .iter()
        .any(|event| matches!(event, JobEvent::DeadLettered { .. }));
    let safe = has_retry
        && has_dead_letter
        && !text.contains("private-body")
        && !text.contains("private.invalid")
        && !text.contains("authorization")
        && !text.contains("private-credential");
    if let Some(evidence) = &mut world.recovery {
        evidence.safe_telemetry = safe;
    }
    world.system = Some(system);
    Ok(())
}

#[then("events and metric labels contain only proven bounded fields")]
async fn then_sensitive_failure_is_safe(world: &mut BddWorld) -> Result<(), String> {
    if !world
        .recovery
        .as_ref()
        .ok_or("safe-telemetry evidence was missing")?
        .safe_telemetry
    {
        return Err("raw failure data entered the observed telemetry surface".to_owned());
    }
    Ok(())
}

#[given("a handler panics while a peer is due")]
async fn given_panicking_handler(world: &mut BddWorld) -> Result<(), String> {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::distributed();
    let system = panic_system(store.clone(), calls.clone())?;
    let panic_job = lifecycle::new_job(
        72,
        Bytes::from_static(b"panic"),
        lifecycle::scoped_fairness(),
        Timestamp::ZERO,
    )?;
    lifecycle::save_system(world, store, system, calls, panic_job, Timestamp::ZERO);
    Ok(())
}

#[when("the public drive handles both")]
async fn when_public_drive_handles_panic(world: &mut BddWorld) -> Result<(), String> {
    let system = lifecycle::take_system(world)?;
    let store = world
        .store
        .as_ref()
        .ok_or("store was not configured")?
        .clone();
    let peer = lifecycle::new_job(
        73,
        Bytes::from_static(b"peer"),
        lifecycle::scoped_fairness(),
        world.now,
    )?;
    let panic_job = world.job.clone().ok_or("panic job was not configured")?;
    system
        .enqueue_raw(panic_job.clone(), world.now)
        .await
        .map_err(display_error)?;
    system
        .enqueue_raw(peer.clone(), world.now)
        .await
        .map_err(display_error)?;
    let report = system
        .drive(lifecycle::drive_request(), world.now, || {
            MonotonicDeadline::ZERO
        })
        .await
        .map_err(display_error)?;
    let panic_record = record_if_present(&store, panic_job.job_id)?;
    let panic_retried = report.counts.retried == 1
        && panic_record.is_some_and(|record| {
            matches!(record.state, JobState::Scheduled)
                && record
                    .attempts
                    .as_ref()
                    .and_then(|history| history.last_outcome.as_ref())
                    .is_some_and(|code| code.as_str() == "handler_panic")
        });
    let peer_completed = report.counts.succeeded == 1
        && report
            .completions
            .iter()
            .any(|completion| completion.job_id == peer.job_id)
        && world
            .handler_calls
            .as_ref()
            .ok_or("handler was not configured")?
            .load(Ordering::SeqCst)
            == 1;
    world.recovery = Some(RecoveryEvidence {
        panic_retried,
        panic_peer_completed: peer_completed,
        ..RecoveryEvidence::default()
    });
    world.drive_report = Some(report);
    world.system = Some(system);
    Ok(())
}

#[then("the panic becomes a durable retry and the peer completes")]
async fn then_panic_isolated(world: &mut BddWorld) -> Result<(), String> {
    let evidence = world
        .recovery
        .as_ref()
        .ok_or("panic evidence was missing")?;
    if !evidence.panic_retried || !evidence.panic_peer_completed {
        return Err("panicking work was not durably retried while peer work continued".to_owned());
    }
    Ok(())
}

#[given("a persisted job record has a foreign identity and an unrelated peer is due")]
async fn given_tampered_identity(world: &mut BddWorld) -> Result<(), String> {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::distributed();
    let system = lifecycle::build_system_with_owner(store.clone(), calls.clone(), 1)?;
    let tampered = lifecycle::new_job(
        74,
        Bytes::from_static(b"tampered"),
        lifecycle::scoped_fairness(),
        Timestamp::ZERO,
    )?;
    let peer = lifecycle::new_job(
        75,
        Bytes::from_static(b"peer"),
        lifecycle::scoped_fairness(),
        Timestamp::ZERO,
    )?;
    system
        .enqueue_raw(tampered.clone(), Timestamp::ZERO)
        .await
        .map_err(display_error)?;
    system
        .enqueue_raw(peer, Timestamp::ZERO)
        .await
        .map_err(display_error)?;
    let job_key = store
        .snapshot()
        .map_err(display_error)?
        .into_iter()
        .find_map(|(key, value)| {
            let decoded = KeyCodec::decode(&lifecycle::test_namespace(), &key).ok()?;
            if decoded.tag != KeyTag::Job
                || decoded.components.len() != 1
                || decoded.components[0].as_slice() != tampered.job_id.as_bytes()
            {
                return None;
            }
            Some((key, value))
        })
        .ok_or("tampered job record was missing")?;
    let mut record = decode_job_record(&job_key.1).map_err(display_error)?;
    record.namespace = bg_jobs::Namespace::try_new(b"foreign").map_err(display_error)?;
    store
        .put_raw(
            job_key.0,
            encode_job_record(&record).map_err(display_error)?,
        )
        .map_err(display_error)?;
    lifecycle::save_system(world, store, system, calls, tampered, Timestamp::ZERO);
    Ok(())
}

#[when("the public drive encounters the tampered record")]
async fn when_public_drive_encounters_tamper(world: &mut BddWorld) -> Result<(), String> {
    let system = lifecycle::take_system(world)?;
    let store = world
        .store
        .as_ref()
        .ok_or("store was not configured")?
        .clone();
    let report = system
        .drive(lifecycle::drive_request(), world.now, || {
            MonotonicDeadline::ZERO
        })
        .await
        .map_err(display_error)?;
    let tampered_remains = store
        .snapshot()
        .map_err(display_error)?
        .iter()
        .filter_map(|(key, value)| {
            let decoded = KeyCodec::decode(&lifecycle::test_namespace(), key).ok()?;
            if decoded.tag != KeyTag::Job || decoded.components.len() != 1 {
                return None;
            }
            decode_job_record(value).ok()
        })
        .any(|record| record.namespace.as_bytes() == b"foreign");
    let peer_completed = report.counts.succeeded == 1
        && report
            .completions
            .iter()
            .any(|completion| completion.job_id == JobId::from([75; 16]));
    world.recovery = Some(RecoveryEvidence {
        identity_isolated: tampered_remains && peer_completed,
        ..RecoveryEvidence::default()
    });
    world.drive_report = Some(report);
    world.store = Some(store);
    world.system = Some(system);
    Ok(())
}

#[then("the tampered record is isolated and the peer completes")]
async fn then_tamper_isolated(world: &mut BddWorld) -> Result<(), String> {
    if !world
        .recovery
        .as_ref()
        .ok_or("identity evidence was missing")?
        .identity_isolated
    {
        return Err("persisted identity tampering was not isolated from peer work".to_owned());
    }
    Ok(())
}

#[given("a due job is claimed before cancellation acknowledgement")]
async fn given_claimed_cancellation(world: &mut BddWorld) -> Result<(), String> {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::distributed();
    let system = lifecycle::build_system_with_owner(store.clone(), calls.clone(), 1)?;
    let job = lifecycle::new_job(
        76,
        Bytes::from_static(b"cancel"),
        lifecycle::scoped_fairness(),
        Timestamp::ZERO,
    )?;
    lifecycle::save_system(world, store, system, calls, job, Timestamp::ZERO);
    Ok(())
}

#[when("the public cancellation acknowledgement commits")]
async fn when_cancellation_acknowledges(world: &mut BddWorld) -> Result<(), String> {
    let system = lifecycle::take_system(world)?;
    let job = world
        .job
        .clone()
        .ok_or("cancellation job was not configured")?;
    system
        .enqueue_raw(job.clone(), world.now)
        .await
        .map_err(display_error)?;
    let claim = system
        .claim(job.job_id, world.now)
        .await
        .map_err(display_error)?;
    let requested = system
        .request_job_cancellation(&claim, world.now)
        .await
        .map_err(display_error)?;
    let terminal = system
        .cancel_claim(claim, world.now)
        .await
        .map_err(display_error)?;
    let reused = system.claim(job.job_id, world.now).await;
    world.recovery = Some(RecoveryEvidence {
        cancellation_requested: requested == CancellationResult::Requested,
        cancellation_terminal: terminal == CancellationResult::Cancelled,
        cancellation_authority_rejected: matches!(reused, Err(JobSystemError::LeaseConflict)),
        ..RecoveryEvidence::default()
    });
    world.system = Some(system);
    Ok(())
}

#[then("no claimant can reuse the terminal cancellation authority")]
async fn then_cancellation_consumes_authority(world: &mut BddWorld) -> Result<(), String> {
    let evidence = world
        .recovery
        .as_ref()
        .ok_or("cancellation evidence was missing")?;
    if !evidence.cancellation_requested
        || !evidence.cancellation_terminal
        || !evidence.cancellation_authority_rejected
    {
        return Err("terminal cancellation did not consume claimant authority".to_owned());
    }
    Ok(())
}

#[derive(Clone)]
struct PanickingHandler {
    healthy_calls: Arc<AtomicUsize>,
}

impl JobHandler for PanickingHandler {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        if payload == b"panic" {
            panic!("BDD handler panic is contained by the public drive");
        }
        self.healthy_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Ok(JobOutcome::Complete(
                OutcomeCode::try_new("peer_complete").expect("fixed BDD outcome code is valid"),
            ))
        })
    }
}

fn panic_system(
    store: FakeStore,
    healthy_calls: Arc<AtomicUsize>,
) -> Result<JobSystem<FakeStore>, String> {
    let kind = JobKind::try_new("email").map_err(display_error)?;
    let queue = QueueName::try_new("default").map_err(display_error)?;
    let mut catalog = JobCatalog::new();
    catalog
        .register_raw(
            HandlerDefinition {
                kind,
                schema_version: lifecycle::nonzero_u16(1)?,
                queue,
                effect_mode: EffectMode::Idempotent,
                cost_units: lifecycle::nonzero_u16(1)?,
                fairness_policy: FairnessPolicy::from(lifecycle::nonzero_u16(1)?),
                default_retry: RetrySelection::Preset(RetryPreset::Interactive),
                default_timeout: Duration::from_secs(1),
                handler: PanickingHandler { healthy_calls },
            },
            None,
        )
        .map_err(display_error)?;
    crate::build_system(store, catalog, OwnerId::from([7; 16]), None)
}

#[derive(Clone)]
struct RecordingObserver {
    events: ObserverEvents,
    errors: ObserverErrors,
}

type ObserverEvents = Arc<Mutex<Vec<JobEvent>>>;
type ObserverErrors = Arc<Mutex<Vec<SafeJobErrorEvent>>>;

impl JobObserver for RecordingObserver {
    fn observe(&self, event: JobEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }

    fn observe_error(&self, event: SafeJobErrorEvent) {
        if let Ok(mut errors) = self.errors.lock() {
            errors.push(event);
        }
    }
}

#[derive(Clone)]
struct RawErrorHandler {
    calls: Arc<AtomicUsize>,
}

impl JobHandler for RawErrorHandler {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(Box::new(RawFailure) as Box<dyn std::error::Error + Send + Sync>) })
    }
}

#[derive(Debug)]
struct RawFailure;

impl fmt::Display for RawFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(RAW_MARKER)
    }
}

impl std::error::Error for RawFailure {}

fn raw_error_system(
    store: FakeStore,
    calls: Arc<AtomicUsize>,
    observer: RecordingObserver,
) -> Result<(JobSystem<FakeStore>, ObserverEvents, ObserverErrors), String> {
    let kind = JobKind::try_new("email").map_err(display_error)?;
    let queue = bg_jobs::QueueName::try_new("default").map_err(display_error)?;
    let mut catalog = JobCatalog::new();
    catalog
        .register_raw(
            HandlerDefinition {
                kind,
                schema_version: lifecycle::nonzero_u16(1)?,
                queue,
                effect_mode: EffectMode::AtLeastOnce,
                cost_units: lifecycle::nonzero_u16(1)?,
                fairness_policy: FairnessPolicy::from(lifecycle::nonzero_u16(1)?),
                default_retry: RetrySelection::Preset(RetryPreset::Interactive),
                default_timeout: Duration::from_secs(1),
                handler: RawErrorHandler { calls },
            },
            None,
        )
        .map_err(display_error)?;
    let system = crate::build_system(
        store,
        catalog,
        OwnerId::from([7; 16]),
        Some(Arc::new(observer.clone())),
    )?;
    Ok((system, observer.events, observer.errors))
}

async fn dead_letter_job(
    system: &JobSystem<FakeStore>,
    store: &FakeStore,
    job: NewJob,
    now: Timestamp,
) -> Result<(JobId, ExecutionId, u32, u64, OperationId), String> {
    system
        .enqueue_raw(job.clone(), now)
        .await
        .map_err(display_error)?;
    let claim = system.claim(job.job_id, now).await.map_err(display_error)?;
    let execution = claim.record().execution_id;
    let result = system
        .apply_outcome(
            claim,
            JobOutcome::DeadLetter {
                code: outcome_code("permanent")?,
            },
            now,
        )
        .await
        .map_err(display_error)?;
    if !matches!(result, OutcomeResult::DeadLettered { .. }) {
        return Err(format!("expected dead-letter result, got {result:?}"));
    }
    let record = record_if_present(store, job.job_id)?.ok_or("dead-lettered record was missing")?;
    let operation = match system
        .observe_lifecycle(job.job_id)
        .await
        .map_err(display_error)?
    {
        LifecycleObservation::Current {
            operation_id: Some(operation),
            ..
        } => operation,
        observation => {
            return Err(format!(
                "dead-letter observation did not expose an operation marker: {observation:?}"
            ));
        }
    };
    Ok((
        job.job_id,
        execution,
        record.generation,
        record.revision,
        operation,
    ))
}

async fn retry_at(
    system: &JobSystem<FakeStore>,
    claim: ClaimedJob,
    now: Timestamp,
) -> Result<Timestamp, String> {
    match system
        .apply_outcome(claim, retry_outcome()?, now)
        .await
        .map_err(display_error)?
    {
        OutcomeResult::Retried { not_before, .. } => Ok(not_before),
        other => Err(format!("expected retry, got {other:?}")),
    }
}

fn retry_outcome() -> Result<JobOutcome, String> {
    Ok(JobOutcome::Retry {
        class: RetryClass::AmbiguousEffect,
        not_before: None,
        code: outcome_code("ambiguous_effect")?,
    })
}

fn outcome_code(value: &'static str) -> Result<OutcomeCode, String> {
    OutcomeCode::try_new(value).map_err(display_error)
}

fn authority(record: &JobRecordV1) -> Option<TransitionAuthority> {
    match &record.state {
        JobState::Leased(Lease {
            owner,
            token,
            fence,
            ..
        }) => Some(TransitionAuthority {
            owner: *owner,
            token: *token,
            generation: record.generation,
            fence: *fence,
        }),
        _ => None,
    }
}

fn record_if_present(store: &FakeStore, job_id: JobId) -> Result<Option<JobRecordV1>, String> {
    for (key, value) in store.snapshot().map_err(display_error)? {
        let decoded =
            KeyCodec::decode(&lifecycle::test_namespace(), &key).map_err(display_error)?;
        if decoded.tag != KeyTag::Job || decoded.components.len() != 1 {
            continue;
        }
        let candidate = JobId::try_from_slice(&decoded.components[0]).map_err(display_error)?;
        if candidate == job_id {
            return decode_job_record(&value).map(Some).map_err(display_error);
        }
    }
    Ok(None)
}

fn display_error<E: fmt::Display>(error: E) -> String {
    error.to_string()
}
