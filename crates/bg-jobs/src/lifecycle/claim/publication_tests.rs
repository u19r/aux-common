use std::{
    future::{Future, pending},
    num::NonZeroU16,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use crate::{
    ClaimPublicationFuture, EffectMode, ExecutionContext, FairnessPolicy, FakeStore,
    HandlerDefinition, HandlerFuture, HandlerRegistry, JobCatalog, JobHandler, JobId, JobKind,
    JobOutcome, JobState, JobStore, JobSystem, JobSystemError, MonotonicDeadline, Namespace,
    OutcomeCode, OwnerId, QueueName, RemoteJobClaim, RetryPreset, RetrySelection, Timestamp,
    test_helper::{TestProfile, block_on, low_volume_job},
};

#[derive(Clone, Copy)]
enum Publication {
    Acknowledge,
    AcknowledgeAndWait,
    Reject,
    LoseAcknowledgement,
    Wait,
    Panic,
}

#[derive(Clone, Default)]
struct Destination {
    accepted: Arc<Mutex<Option<RemoteJobClaim>>>,
    executions: Arc<AtomicUsize>,
}

struct PublishingHandler {
    publication: Publication,
    destination: Destination,
}

impl JobHandler for PublishingHandler {
    fn publish_claim<'a>(
        &'a self,
        context: &ExecutionContext<'_>,
    ) -> Option<ClaimPublicationFuture<'a>> {
        let claim = RemoteJobClaim::from(context);
        Some(Box::pin(async move {
            match self.publication {
                Publication::Wait => pending::<()>().await,
                Publication::Panic => panic!("publication panic"),
                Publication::Reject => {
                    return Err(std::io::Error::other("publication rejected").into());
                }
                Publication::Acknowledge
                | Publication::AcknowledgeAndWait
                | Publication::LoseAcknowledgement => {}
            }
            let mut accepted = self.destination.accepted.lock().unwrap();
            if accepted
                .as_ref()
                .is_some_and(|current| *current != claim && !claim.is_replacement_of(current))
            {
                return Err(std::io::Error::other("stale publication").into());
            }
            *accepted = Some(claim);
            if matches!(self.publication, Publication::LoseAcknowledgement) {
                return Err(std::io::Error::other("acknowledgement lost").into());
            }
            Ok(())
        }))
    }

    fn execute<'a>(
        &'a self,
        context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        Box::pin(async move {
            if matches!(self.publication, Publication::AcknowledgeAndWait) {
                pending::<()>().await;
            }
            assert_eq!(
                self.destination.accepted.lock().unwrap().as_ref(),
                Some(&RemoteJobClaim::from(&context))
            );
            self.destination.executions.fetch_add(1, Ordering::SeqCst);
            Ok(JobOutcome::Complete(
                OutcomeCode::try_new("completed").unwrap(),
            ))
        })
    }
}

fn publishing_system(
    store: FakeStore,
    publication: Publication,
    destination: Destination,
    clock: TestProfile,
) -> JobSystem<FakeStore> {
    let mut registry = HandlerRegistry::new();
    registry
        .register(HandlerDefinition {
            kind: JobKind::try_new("email").unwrap(),
            schema_version: NonZeroU16::MIN,
            queue: QueueName::try_new("default").unwrap(),
            effect_mode: EffectMode::Fenced,
            cost_units: NonZeroU16::MIN,
            fairness_policy: FairnessPolicy::low_volume(),
            default_retry: RetrySelection::Preset(RetryPreset::Interactive),
            default_timeout: Duration::from_secs(1),
            handler: PublishingHandler {
                publication,
                destination,
            },
        })
        .unwrap();
    JobSystem::new(
        store,
        JobCatalog::from_registry(registry),
        Namespace::try_new(b"jobs").unwrap(),
        OwnerId::from([1; 16]),
        Arc::new(clock),
    )
}

#[test]
fn given_pending_destination_publication_when_claiming_then_no_usable_claim_is_returned_before_acknowledgement()
 {
    let destination = Destination::default();
    let clock = TestProfile::new();
    let store = FakeStore::new();
    let engine = publishing_system(store, Publication::Wait, destination.clone(), clock.clone());
    block_on(engine.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    let mut claim = Box::pin(engine.claim(JobId::from([1; 16]), Timestamp::ZERO));
    let mut context = Context::from_waker(Waker::noop());
    assert!(claim.as_mut().poll(&mut context).is_pending());
    assert_eq!(destination.executions.load(Ordering::SeqCst), 0);
    clock.advance(Duration::from_secs(1));
    assert!(matches!(
        claim.as_mut().poll(&mut context),
        Poll::Ready(Err(JobSystemError::LeaseLost))
    ));
}

#[test]
fn given_failed_or_lost_publication_acknowledgement_when_reclaiming_then_only_acknowledged_claim_executes()
 {
    for publication in [
        Publication::Reject,
        Publication::LoseAcknowledgement,
        Publication::Panic,
    ] {
        let store = FakeStore::new();
        let destination = Destination::default();
        let clock = TestProfile::new();
        let old = publishing_system(
            store.clone(),
            publication,
            destination.clone(),
            clock.clone(),
        );
        let id = JobId::from([2; 16]);
        block_on(old.enqueue_raw(low_volume_job(2, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
        assert!(matches!(
            block_on(old.claim(id, Timestamp::ZERO)),
            Err(JobSystemError::ClaimPublicationUnacknowledged)
        ));
        assert_eq!(destination.executions.load(Ordering::SeqCst), 0);
        let new = publishing_system(store, Publication::Acknowledge, destination.clone(), clock);
        let now = Timestamp::from_millis(1000);
        let claim = block_on(new.claim(id, now)).unwrap();
        assert!(matches!(claim.record().state, JobState::Leased(_)));
        assert!(matches!(
            block_on(new.execute_claimed(&claim, now, || MonotonicDeadline::ZERO)),
            Ok(JobOutcome::Complete(_))
        ));
        assert_eq!(destination.executions.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn given_replacement_publication_when_an_old_claim_is_republished_then_the_destination_rejects_it()
{
    let store = FakeStore::new();
    let destination = Destination::default();
    let clock = TestProfile::new();
    let old = publishing_system(
        store.clone(),
        Publication::Acknowledge,
        destination.clone(),
        clock.clone(),
    );
    let id = JobId::from([3; 16]);
    block_on(old.enqueue_raw(low_volume_job(3, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    let first = block_on(old.claim(id, Timestamp::ZERO)).unwrap();
    let new = publishing_system(store, Publication::Acknowledge, destination.clone(), clock);
    let second = block_on(new.claim(id, Timestamp::from_millis(1000))).unwrap();
    assert!(matches!(
        block_on(super::publication::publish_claim(&old, &first, None)),
        Err(JobSystemError::ClaimPublicationUnacknowledged)
    ));
    assert_eq!(
        destination.accepted.lock().unwrap().as_ref(),
        Some(&RemoteJobClaim::from(&second.context().unwrap()))
    );
}

async fn bounded_claim(
    system: &JobSystem<FakeStore>,
    job_id: JobId,
    deadline: super::ClaimDeadline<'_>,
) -> crate::error::JobResult<super::ClaimedJob, crate::test_helper::FakeStoreError> {
    let key = crate::keys::job_key(system.namespace(), &job_id).unwrap();
    let encoded = system.store().get(key).await.unwrap().unwrap();
    let record = crate::codec::decode_job_record(&encoded).unwrap();
    let due = crate::keys::due_key(
        system.namespace(),
        &record.queue,
        record.scheduled_at,
        &job_id,
    )
    .unwrap();
    let value = system.store().get(due.clone()).await.unwrap().unwrap();
    super::claim_record_with_capacity(
        system,
        super::ClaimRecordInput {
            record,
            encoded,
            route: super::ClaimRoute::Due { key: due, value },
            now: Timestamp::ZERO,
            capacity: NonZeroU16::MIN,
            deadline: Some(deadline),
        },
    )
    .await
}

#[test]
fn given_bounded_claim_when_renewing_and_replacing_then_deadline_and_stale_fence_remain_enforced() {
    let destination = Destination::default();
    let clock = TestProfile::new();
    let store = FakeStore::local();
    let engine = publishing_system(store, Publication::Acknowledge, destination, clock);
    let id = JobId::from([94; 16]);
    block_on(engine.enqueue_raw(low_volume_job(94, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    let now = || Ok(Timestamp::ZERO);
    let mut original = block_on(bounded_claim(
        &engine,
        id,
        super::ClaimDeadline {
            until: Timestamp::from_millis(500),
            wall_now: &now,
        },
    ))
    .unwrap();
    let original_fence = original.authority().unwrap().fence;
    assert!(
        matches!(block_on(engine.renew(&mut original, Timestamp::from_millis(200))),
        Ok(crate::RenewalResult::Renewed { expires_at }) if expires_at == Timestamp::from_millis(500))
    );
    assert!(matches!(
        block_on(engine.claim(id, Timestamp::from_millis(499))),
        Err(JobSystemError::LeaseConflict)
    ));
    let replacement = block_on(engine.claim(id, Timestamp::from_millis(501))).unwrap();
    assert!(replacement.authority().unwrap().fence > original_fence);
    let replacement_bytes = replacement.encoded().clone();
    assert!(matches!(
        block_on(engine.renew(&mut original, Timestamp::from_millis(501))),
        Err(JobSystemError::LeaseLost)
    ));
    assert!(original.context().is_none());
    let key = crate::keys::job_key(engine.namespace(), &id).unwrap();
    assert_eq!(
        block_on(engine.store().get(key)).unwrap().unwrap(),
        replacement_bytes
    );
}

#[test]
fn given_pending_publication_when_bounded_claim_expires_then_no_handler_authority_is_exposed() {
    let destination = Destination::default();
    let clock = TestProfile::new();
    let engine = publishing_system(
        FakeStore::local(),
        Publication::Wait,
        destination.clone(),
        clock.clone(),
    );
    let id = JobId::from([95; 16]);
    block_on(engine.enqueue_raw(low_volume_job(95, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    let millis = std::sync::atomic::AtomicI64::new(0);
    let now = || Ok(Timestamp::from_millis(millis.load(Ordering::SeqCst)));
    let mut pending = Box::pin(bounded_claim(
        &engine,
        id,
        super::ClaimDeadline {
            until: Timestamp::from_millis(5),
            wall_now: &now,
        },
    ));
    let mut context = Context::from_waker(Waker::noop());
    assert!(pending.as_mut().poll(&mut context).is_pending());
    millis.store(6, Ordering::SeqCst);
    clock.advance(Duration::from_millis(6));
    assert!(matches!(
        pending.as_mut().poll(&mut context),
        Poll::Ready(Err(JobSystemError::LeaseLost))
    ));
    assert_eq!(destination.executions.load(Ordering::SeqCst), 0);
    assert!(destination.accepted.lock().unwrap().is_none());
}

#[test]
fn given_acknowledged_remote_claim_when_short_drive_stops_then_registered_lease_is_preserved() {
    let destination = Destination::default();
    let profile = TestProfile::new();
    let engine = publishing_system(
        FakeStore::local(),
        Publication::AcknowledgeAndWait,
        destination.clone(),
        profile.clone(),
    );
    let id = JobId::from([96; 16]);
    block_on(engine.enqueue_raw(low_volume_job(96, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    let nanos = std::sync::atomic::AtomicU64::new(0);
    let request = crate::DriveRequest::try_from(crate::DriveRequestInput {
        queues: crate::QueueSelection::all(),
        max_claims: std::num::NonZeroU32::MIN,
        max_concurrency: NonZeroU16::MIN,
        max_payload_bytes_in_flight: std::num::NonZeroUsize::new(1024).unwrap(),
        max_completion_details: 1,
        max_store_operations: std::num::NonZeroU32::new(128).unwrap(),
        stop_claiming_at: MonotonicDeadline::from_nanos(1_000_000),
        finish_by: MonotonicDeadline::from_nanos(5_000_000),
    })
    .unwrap();
    let mut drive = Box::pin(engine.drive(request, Timestamp::ZERO, || {
        MonotonicDeadline::from_nanos(nanos.load(Ordering::SeqCst))
    }));
    let mut context = Context::from_waker(Waker::noop());
    assert!(drive.as_mut().poll(&mut context).is_pending());
    assert!(
        destination.accepted.lock().unwrap().is_some(),
        "remote authority was acknowledged"
    );
    nanos.store(6_000_000, Ordering::SeqCst);
    profile.advance(Duration::from_millis(6));
    assert!(
        matches!(drive.as_mut().poll(&mut context), Poll::Ready(Ok(report))
        if report.stop_reason == crate::DriveStopReason::Deadline)
    );
    let key = crate::keys::job_key(engine.namespace(), &id).unwrap();
    let encoded = block_on(engine.store().get(key)).unwrap().unwrap();
    let record = crate::codec::decode_job_record(&encoded).unwrap();
    assert!(
        matches!(record.state, JobState::Leased(lease)
        if lease.expires_at == Timestamp::from_millis(1000)),
        "a remote descriptor cannot authorize a shortened source lease"
    );
    assert_eq!(destination.executions.load(Ordering::SeqCst), 0);
}
