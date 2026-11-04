use std::{collections::BTreeSet, num::NonZeroU16};

use bytes::Bytes;

use crate::{test_helper::block_on, *};

fn system<S: crate::store::JobStore>(store: S, policy: FairnessPolicy, owner: u8) -> JobSystem<S> {
    let reference = crate::test_helper::system(FakeStore::distributed(), policy, owner);
    let manifest = CatalogManifest::try_new(
        CatalogRevision::from(std::num::NonZeroU64::MIN),
        Vec::new(),
        vec![ScheduleId::from([7; 16])],
    )
    .unwrap();
    let catalog = JobCatalog::from_registry(reference.registry().clone()).with_manifest(manifest);
    let engine = JobSystem::new(
        store,
        catalog,
        reference.namespace().clone(),
        *reference.owner(),
        crate::test_helper::wake_scheduler(),
    );
    block_on(engine.initialize_catalog()).unwrap();
    engine
}

fn schedule(misfire: MisfirePolicy, overlap: OverlapPolicy) -> RecurringSchedule {
    RecurringSchedule::new(RecurringScheduleInput {
        schedule_id: ScheduleId::from([7; 16]),
        job_template: JobTemplate::try_new(JobTemplateInput {
            kind: JobKind::try_new("email").expect("kind is valid"),
            schema_version: NonZeroU16::new(1).expect("schema is non-zero"),
            payload: Bytes::from_static(b"scheduled"),
            fairness: FairnessClass::low_volume(),
            ordering_key: None,
            priority: Priority::Default,
            expires_after: None,
            retry_override: None,
            deduplication: None,
        })
        .expect("template is valid"),
        cadence: Cadence::CronUtc(
            CronExpression::try_new("0 * * * *").expect("hourly cron parses"),
        ),
        misfire,
        overlap,
        enabled: true,
    })
}

fn cursor() -> ScheduleCursor {
    ScheduleCursor::new(Some(Timestamp::ZERO), true)
}

#[test]
fn given_two_nodes_materialising_the_same_occurrence_when_the_store_is_shared_then_identity_is_stable_and_one_enqueue_wins()
 {
    let store = FakeStore::distributed();
    let first = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let second = system(store, FairnessPolicy::low_volume(), 2);
    let schedule = schedule(MisfirePolicy::FireOnce, OverlapPolicy::Allow);
    let initial = cursor();
    let now = Timestamp::from_millis(3 * 60 * 60 * 1_000);

    let first_result = block_on(first.materialize_schedule(&schedule, &initial, now))
        .expect("first materialisation succeeds");
    let second_result = block_on(second.materialize_schedule(&schedule, &initial, now))
        .expect("second materialisation reconciles");

    assert_eq!(first_result.occurrences.len(), 1);
    assert_eq!(
        second_result.occurrences.len(),
        0,
        "the stored cursor already passed this occurrence"
    );
    assert_eq!(
        first_result.occurrences[0].enqueue.disposition,
        EnqueueDisposition::Enqueued
    );
    assert_eq!(first_result.cursor, second_result.cursor);
    assert_eq!(
        second_result.next_wake,
        WakeHint::At(Timestamp::from_millis(4 * 60 * 60 * 1_000)),
        "idle wake must follow durable next_due"
    );
}

#[test]
fn given_a_long_downtime_when_each_misfire_policy_is_evaluated_then_emission_is_exact_and_bounded()
{
    let now = Timestamp::from_millis(5 * 60 * 60 * 1_000);
    let skip = schedule(MisfirePolicy::Skip, OverlapPolicy::Allow)
        .evaluate(&cursor(), now)
        .expect("skip evaluates");
    let fire_once = schedule(MisfirePolicy::FireOnce, OverlapPolicy::Allow)
        .evaluate(&cursor(), now)
        .expect("fire-once evaluates");
    let catch_up = schedule(
        MisfirePolicy::CatchUp {
            maximum_occurrences: NonZeroU16::new(2).expect("catch-up limit is non-zero"),
        },
        OverlapPolicy::Allow,
    )
    .evaluate(&cursor(), now)
    .expect("catch-up evaluates");

    assert!(skip.occurrences.is_empty());
    assert_eq!(skip.skipped, 6);
    assert_eq!(
        skip.cursor.next_due(),
        Some(Timestamp::from_millis(6 * 60 * 60 * 1_000))
    );

    assert_eq!(fire_once.occurrences.len(), 1);
    assert_eq!(fire_once.skipped, 5);
    assert_eq!(
        fire_once.occurrences[0].intended_at,
        Timestamp::from_millis(5 * 60 * 60 * 1_000)
    );
    assert_eq!(
        fire_once.cursor.watermark(),
        Some(fire_once.occurrences[0].intended_at)
    );

    assert_eq!(catch_up.occurrences.len(), 2);
    assert_eq!(catch_up.skipped, 4);
    assert_eq!(
        catch_up.cursor.watermark(),
        Some(Timestamp::from_millis(60 * 60 * 1_000))
    );
    assert!(catch_up.cursor.next_due().is_some_and(|next| next > now));
}

#[test]
fn given_repeated_evaluation_after_the_cursor_advanced_when_no_new_time_is_due_then_it_does_not_reemit()
 {
    let schedule = schedule(
        MisfirePolicy::CatchUp {
            maximum_occurrences: NonZeroU16::new(2).expect("catch-up limit is non-zero"),
        },
        OverlapPolicy::Allow,
    );
    let now = Timestamp::from_millis(2 * 60 * 60 * 1_000);
    let first = schedule
        .evaluate(&cursor(), now)
        .expect("first evaluation succeeds");
    let second = schedule
        .evaluate(&first.cursor, now)
        .expect("second evaluation succeeds");

    assert_eq!(first.occurrences.len(), 2);
    assert!(second.occurrences.is_empty());
    assert_eq!(second.skipped, 0);
}

#[test]
fn given_a_large_catch_up_backlog_when_materialization_budget_is_small_then_the_cursor_resumes() {
    let schedule = schedule(
        MisfirePolicy::CatchUp {
            maximum_occurrences: NonZeroU16::new(u16::MAX).expect("catch-up limit is non-zero"),
        },
        OverlapPolicy::Allow,
    );
    let initial = cursor();
    let now = Timestamp::from_millis(10 * 60 * 60 * 1_000);
    let budget = ScheduleMaterializationBudget::try_new(
        3,
        1024,
        crate::MonotonicDeadline::from_nanos(u64::MAX),
    )
    .expect("materialization budget is valid");
    let system = system(
        crate::FakeStore::distributed(),
        crate::FairnessPolicy::low_volume(),
        17,
    );

    let first = crate::test_helper::block_on(system.materialize_schedule_with_budget(
        ScheduleMaterializationRequest::new(&schedule, &initial, now, budget),
        || crate::MonotonicDeadline::from_nanos(u64::MAX - 1),
    ))
    .expect("first bounded materialization succeeds");

    assert_eq!(first.occurrences.len(), 3);
    assert_eq!(first.skipped, 0);
    assert!(first.cursor.next_due().is_some_and(|next| next <= now));
    assert_eq!(first.next_wake, WakeHint::Now);

    let second = crate::test_helper::block_on(system.materialize_schedule_with_budget(
        ScheduleMaterializationRequest::new(&schedule, &first.cursor, now, budget),
        || crate::MonotonicDeadline::from_nanos(u64::MAX - 1),
    ))
    .expect("second bounded materialization succeeds");

    assert_eq!(second.occurrences.len(), 3);
    assert_eq!(second.skipped, 0);
    assert_ne!(
        first.occurrences[0].occurrence.occurrence_id(),
        second.occurrences[0].occurrence.occurrence_id()
    );

    let mut seen = first
        .occurrences
        .iter()
        .chain(second.occurrences.iter())
        .map(|entry| entry.occurrence.occurrence_id())
        .collect::<BTreeSet<_>>();
    let mut cursor = second.cursor;
    let mut total = 6;
    let mut complete = second.complete;
    for _ in 0..4 {
        if complete {
            break;
        }
        let next = crate::test_helper::block_on(system.materialize_schedule_with_budget(
            ScheduleMaterializationRequest::new(&schedule, &cursor, now, budget),
            || crate::MonotonicDeadline::from_nanos(u64::MAX - 1),
        ))
        .expect("continuation materialization succeeds");
        for occurrence in &next.occurrences {
            assert!(seen.insert(occurrence.occurrence.occurrence_id()));
        }
        total += next.occurrences.len();
        cursor = next.cursor;
        complete = next.complete;
    }
    assert!(complete, "the resumable cursor must eventually complete");
    assert_eq!(total, 11);
    assert_eq!(
        seen.len(),
        11,
        "continuations must not duplicate identities"
    );
}

#[test]
fn given_a_materialization_operation_budget_below_one_enqueue_then_no_occurrence_is_emitted() {
    let system = system(FakeStore::distributed(), FairnessPolicy::low_volume(), 18);
    let schedule = schedule(
        MisfirePolicy::CatchUp {
            maximum_occurrences: NonZeroU16::new(3).expect("catch-up limit is non-zero"),
        },
        OverlapPolicy::Allow,
    );
    let initial = cursor();
    let budget =
        ScheduleMaterializationBudget::try_new(3, 3, MonotonicDeadline::from_nanos(u64::MAX))
            .expect("materialization budget is valid");

    let result = block_on(system.materialize_schedule_with_budget(
        ScheduleMaterializationRequest::new(
            &schedule,
            &initial,
            Timestamp::from_millis(3 * 60 * 60 * 1_000),
            budget,
        ),
        || MonotonicDeadline::from_nanos(u64::MAX - 1),
    ))
    .expect("empty bounded materialization succeeds");

    assert!(result.occurrences.is_empty());
    assert_eq!(result.cursor, initial);
    assert!(!result.complete);
    assert_eq!(result.next_wake, WakeHint::Now);
}

#[test]
fn given_a_materialization_deadline_between_occurrences_then_the_cursor_remains_resumable() {
    let system = system(FakeStore::distributed(), FairnessPolicy::low_volume(), 19);
    let schedule = schedule(
        MisfirePolicy::CatchUp {
            maximum_occurrences: NonZeroU16::new(3).expect("catch-up limit is non-zero"),
        },
        OverlapPolicy::Allow,
    );
    let initial = cursor();
    let budget = ScheduleMaterializationBudget::try_new(3, 1024, MonotonicDeadline::from_nanos(5))
        .expect("materialization budget is valid");
    let mut clock = [
        MonotonicDeadline::ZERO,
        MonotonicDeadline::ZERO,
        MonotonicDeadline::from_nanos(5),
    ]
    .into_iter();

    let result = block_on(system.materialize_schedule_with_budget(
        ScheduleMaterializationRequest::new(
            &schedule,
            &initial,
            Timestamp::from_millis(3 * 60 * 60 * 1_000),
            budget,
        ),
        || clock.next().unwrap_or(MonotonicDeadline::from_nanos(5)),
    ))
    .expect("deadline-bounded materialization succeeds");

    assert_eq!(result.occurrences.len(), 1);
    assert!(!result.complete);
    assert_eq!(result.next_wake, WakeHint::Now);
    assert_eq!(
        result.cursor.watermark(),
        Some(result.occurrences[0].occurrence.intended_at)
    );
    assert!(
        result
            .cursor
            .next_due()
            .is_some_and(|next| next > result.occurrences[0].occurrence.intended_at)
    );
}

#[test]
fn given_forbidden_overlap_when_occurrence_terminates_then_replacement_materializes_the_next_one() {
    for outcome in [
        crate::test_helper::completion(),
        JobOutcome::Cancelled,
        JobOutcome::DeadLetter {
            code: OutcomeCode::try_new("failed").unwrap(),
        },
    ] {
        let store = FakeStore::distributed();
        let first = system(store.clone(), FairnessPolicy::low_volume(), 31);
        let definition = schedule(MisfirePolicy::FireOnce, OverlapPolicy::Forbid);
        let initial = cursor();
        let now = Timestamp::from_millis(3 * 60 * 60 * 1_000);
        let admitted = block_on(first.materialize_schedule(&definition, &initial, now)).unwrap();
        assert_eq!(admitted.occurrences.len(), 1);
        assert!(admitted.cursor.is_active());
        let blocked = block_on(first.materialize_schedule(&definition, &initial, now)).unwrap();
        assert!(blocked.occurrences.is_empty());
        let claim =
            block_on(first.claim(admitted.occurrences[0].occurrence.job_id(), now)).unwrap();
        block_on(first.apply_outcome(claim, outcome, now)).unwrap();
        drop(first);
        let replacement = system(store, FairnessPolicy::low_volume(), 32);
        let next = block_on(replacement.materialize_schedule(
            &definition,
            &initial,
            Timestamp::from_millis(4 * 60 * 60 * 1_000),
        ))
        .unwrap();
        assert_eq!(next.occurrences.len(), 1);
        assert_eq!(
            next.occurrences[0].occurrence.intended_at,
            Timestamp::from_millis(4 * 60 * 60 * 1_000)
        );
        assert_ne!(
            next.occurrences[0].occurrence.job_id(),
            admitted.occurrences[0].occurrence.job_id()
        );
    }
}

#[test]
fn given_persisted_schedule_controls_when_restarted_then_stale_initial_state_and_control_cannot_override_them()
 {
    let store = FakeStore::distributed();
    let first = system(store.clone(), FairnessPolicy::low_volume(), 33);
    let definition = schedule(MisfirePolicy::FireOnce, OverlapPolicy::Allow);
    let initial = ScheduleCursor::new(Some(Timestamp::from_millis(60 * 60 * 1_000)), true);
    block_on(first.materialize_schedule(&definition, &initial, Timestamp::ZERO)).unwrap();
    assert!(matches!(
        block_on(first.control_schedule(definition.schedule_id, 0, 0, ScheduleControl::Pause))
            .unwrap(),
        ScheduleControlResult::Applied {
            revision: 1,
            generation: 1
        }
    ));
    let replacement = system(store.clone(), FairnessPolicy::low_volume(), 34);
    let before = store.snapshot().unwrap();
    let now = Timestamp::from_millis(3 * 60 * 60 * 1_000);
    let paused = block_on(replacement.materialize_schedule(&definition, &cursor(), now)).unwrap();
    assert!(paused.occurrences.is_empty());
    assert!(paused.cursor.is_paused());
    assert_eq!(store.snapshot().unwrap(), before);
    assert!(matches!(
        block_on(replacement.control_schedule(
            definition.schedule_id,
            1,
            1,
            ScheduleControl::Resume
        ))
        .unwrap(),
        ScheduleControlResult::Applied {
            revision: 2,
            generation: 2
        }
    ));
    let resumed = block_on(replacement.materialize_schedule(&definition, &cursor(), now)).unwrap();
    assert_eq!(resumed.occurrences.len(), 1);
    let before = store.snapshot().unwrap();
    assert!(matches!(
        block_on(first.control_schedule(definition.schedule_id, 0, 0, ScheduleControl::Pause))
            .unwrap(),
        ScheduleControlResult::Conflict { .. }
    ));
    assert_eq!(store.snapshot().unwrap(), before);
}

#[derive(Clone)]
struct ScheduleRaceStore {
    inner: FakeStore,
    competing: std::sync::Arc<JobSystem<FakeStore>>,
    action: std::sync::Arc<std::sync::Mutex<Option<ScheduleRace>>>,
    target: crate::store::StoreKey,
}

enum ScheduleRace {
    Admit,
    Pause,
    LoseAdmission,
}

impl crate::store::JobStore for ScheduleRaceStore {
    type Error = crate::test_helper::FakeStoreError;
    fn capabilities(&self) -> crate::store::StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, key: crate::store::StoreKey) -> Result<Option<Bytes>, Self::Error> {
        self.inner.get(key).await
    }
    async fn get_many(
        &self,
        keys: &[crate::store::StoreKey],
    ) -> Result<Vec<Option<Bytes>>, Self::Error> {
        self.inner.get_many(keys).await
    }
    async fn read_range(
        &self,
        request: crate::store::RangeRequest,
    ) -> Result<crate::store::RangePage, Self::Error> {
        self.inner.read_range(request).await
    }
    async fn transact(
        &self,
        input: &crate::store::StoreTransaction,
    ) -> Result<crate::store::CommitOutcome, Self::Error> {
        let is_application = input.mutations().iter().any(|mutation| matches!(mutation, crate::store::Mutation::Put(key, _) if key == &self.target));
        let action = {
            let mut action = self.action.lock().unwrap();
            if is_application || matches!(*action, Some(ScheduleRace::LoseAdmission)) {
                action.take()
            } else {
                None
            }
        };
        match action {
            Some(ScheduleRace::Admit) => {
                let report = self
                    .competing
                    .materialize_schedule(
                        &schedule(MisfirePolicy::FireOnce, OverlapPolicy::Allow),
                        &cursor(),
                        Timestamp::from_millis(3 * 60 * 60 * 1_000),
                    )
                    .await
                    .unwrap();
                assert_eq!(report.occurrences.len(), 1);
            }
            Some(ScheduleRace::Pause) => {
                assert!(matches!(
                    self.competing
                        .control_schedule(ScheduleId::from([7; 16]), 0, 0, ScheduleControl::Pause)
                        .await
                        .unwrap(),
                    ScheduleControlResult::Applied { .. }
                ));
            }
            Some(ScheduleRace::LoseAdmission) => {
                assert_eq!(
                    self.inner.transact(input).await?,
                    crate::store::CommitOutcome::Committed
                );
                return std::future::pending().await;
            }
            None => {}
        }
        self.inner.transact(input).await
    }
}

fn schedule_race_fixture() -> (JobSystem<ScheduleRaceStore>, ScheduleRaceStore) {
    let inner = FakeStore::distributed();
    let competing = std::sync::Arc::new(system(inner.clone(), FairnessPolicy::low_volume(), 41));
    let occurrence = ScheduleOccurrence {
        schedule_id: ScheduleId::from([7; 16]),
        intended_at: Timestamp::from_millis(3 * 60 * 60 * 1_000),
        generation: 0,
    };
    let store = ScheduleRaceStore {
        target: crate::keys::job_key(competing.namespace(), &occurrence.job_id()).unwrap(),
        inner,
        competing,
        action: std::sync::Arc::new(std::sync::Mutex::new(None)),
    };
    (
        system(store.clone(), FairnessPolicy::low_volume(), 40),
        store,
    )
}

#[test]
fn given_concurrent_materializers_when_both_read_the_same_progress_then_one_occurrence_and_cursor_advance_commit()
 {
    let (first, store) = schedule_race_fixture();
    *store.action.lock().unwrap() = Some(ScheduleRace::Admit);
    let definition = schedule(MisfirePolicy::FireOnce, OverlapPolicy::Allow);
    let now = Timestamp::from_millis(3 * 60 * 60 * 1_000);
    block_on(first.materialize_schedule(&definition, &cursor(), now)).unwrap();
    let after = block_on(
        store
            .competing
            .materialize_schedule(&definition, &cursor(), now),
    )
    .unwrap();
    assert!(after.occurrences.is_empty());
    assert_eq!(after.cursor.revision(), 1);
    assert_eq!(
        after.cursor.next_due(),
        Some(Timestamp::from_millis(4 * 60 * 60 * 1_000))
    );
    let claim = block_on(
        store.competing.claim(
            ScheduleOccurrence {
                schedule_id: definition.schedule_id,
                intended_at: now,
                generation: 0,
            }
            .job_id(),
            now,
        ),
    )
    .unwrap();
    assert_eq!(claim.payload(), &Bytes::from_static(b"scheduled"));
}

#[test]
fn given_control_races_with_admission_when_pause_commits_first_then_stale_admission_cannot_create_work()
 {
    let (first, store) = schedule_race_fixture();
    let definition = schedule(MisfirePolicy::FireOnce, OverlapPolicy::Allow);
    let initial = ScheduleCursor::new(Some(Timestamp::from_millis(3 * 60 * 60 * 1_000)), true);
    block_on(first.materialize_schedule(&definition, &initial, Timestamp::ZERO)).unwrap();
    *store.action.lock().unwrap() = Some(ScheduleRace::Pause);
    let now = Timestamp::from_millis(3 * 60 * 60 * 1_000);
    let result = block_on(first.materialize_schedule(&definition, &initial, now)).unwrap();
    assert!(result.occurrences.is_empty());
    assert!(result.cursor.is_paused());
    assert!(!store.inner.contains(&store.target).unwrap());
    assert_eq!(block_on(store.competing.recover_commits()).unwrap(), 0);
}

#[test]
fn given_accepted_schedule_admission_when_producer_is_permanently_lost_then_replacement_finishes_cursor_and_work()
 {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    let (first, store) = schedule_race_fixture();
    let definition = schedule(MisfirePolicy::FireOnce, OverlapPolicy::Allow);
    let initial = cursor();
    let now = Timestamp::from_millis(3 * 60 * 60 * 1_000);
    *store.action.lock().unwrap() = Some(ScheduleRace::LoseAdmission);
    let mut future = Box::pin(first.materialize_schedule(&definition, &initial, now));
    assert!(matches!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(future);
    drop(first);
    assert!(
        store.inner.contains(&store.target).unwrap(),
        "atomic acceptance already published the work"
    );
    assert_eq!(block_on(store.competing.recover_commits()).unwrap(), 1);
    let report = block_on(
        store
            .competing
            .materialize_schedule(&definition, &initial, now),
    )
    .unwrap();
    assert!(report.occurrences.is_empty());
    assert_eq!(report.cursor.revision(), 1);
    let job_id = ScheduleOccurrence {
        schedule_id: definition.schedule_id,
        intended_at: now,
        generation: 0,
    }
    .job_id();
    let claim = block_on(store.competing.claim(job_id, now)).unwrap();
    block_on(
        store
            .competing
            .apply_outcome(claim, crate::test_helper::completion(), now),
    )
    .unwrap();
    let restarted = system(store.inner, FairnessPolicy::low_volume(), 42);
    let report = block_on(restarted.materialize_schedule(&definition, &initial, now)).unwrap();
    assert!(
        report.occurrences.is_empty(),
        "completed occurrences remain suppressed by bounded cursor progress"
    );
}
