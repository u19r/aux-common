use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use bg_jobs::{
    DriveStopReason, EnqueueDisposition, JobKind, Priority, QueueSelection, Timestamp, WakeHint,
    runtime::MonotonicDeadline,
    test_support::{
        FakeStore,
        codec::{KeyCodec, KeyTag},
        raw::{
            ActivePulseRequest, ActivePulseStopReason, Cadence, CancellationResult, CronExpression,
            DriveRequest, DriveRequestInput, JobTemplate, JobTemplateInput, MisfirePolicy,
            OverlapPolicy, RecurringSchedule, RecurringScheduleInput, ScheduleControl,
            ScheduleControlResult, ScheduleCursor, ScheduleId, WakeCandidates,
        },
    },
};
use bytes::Bytes;
use cucumber::{given, then, when};

use super::lifecycle;
use crate::{BddWorld, WakeEvidence};

const HOUR: i64 = 60 * 60 * 1_000;

fn evidence(world: &mut BddWorld) -> &mut WakeEvidence {
    world.wake.get_or_insert_with(WakeEvidence::default)
}

fn schedule(expression: &str, misfire: MisfirePolicy) -> Result<RecurringSchedule, String> {
    let kind = JobKind::try_new("email").map_err(lifecycle::display_error)?;
    let template = JobTemplate::try_new(JobTemplateInput {
        kind,
        schema_version: nonzero_u16(1)?,
        payload: Bytes::from_static(b"scheduled"),
        fairness: lifecycle::scoped_fairness(),
        ordering_key: None,
        priority: Priority::Default,
        expires_after: None,
        retry_override: None,
        deduplication: None,
    })
    .map_err(lifecycle::display_error)?;
    let cadence = CronExpression::try_new(expression).map_err(lifecycle::display_error)?;
    Ok(RecurringSchedule::new(RecurringScheduleInput {
        schedule_id: ScheduleId::from([91; 16]),
        job_template: template,
        cadence: Cadence::CronUtc(cadence),
        misfire,
        overlap: OverlapPolicy::Allow,
        enabled: true,
    }))
}

fn nonzero_u16(value: u16) -> Result<NonZeroU16, String> {
    NonZeroU16::new(value).ok_or_else(|| "fixed value must be non-zero".to_owned())
}

fn nonzero_u32(value: u32) -> Result<NonZeroU32, String> {
    NonZeroU32::new(value).ok_or_else(|| "fixed value must be non-zero".to_owned())
}

fn nonzero_usize(value: usize) -> Result<NonZeroUsize, String> {
    NonZeroUsize::new(value).ok_or_else(|| "fixed value must be non-zero".to_owned())
}

fn pulse_request(max_claims: u32) -> Result<DriveRequest, String> {
    DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: nonzero_u32(max_claims)?,
        max_concurrency: nonzero_u16(1)?,
        max_payload_bytes_in_flight: nonzero_usize(512 * 1024)?,
        max_completion_details: max_claims,
        max_store_operations: nonzero_u32(64)?,
        stop_claiming_at: MonotonicDeadline::from_nanos(u64::MAX),
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .map_err(lifecycle::display_error)
}

fn deadline_request() -> Result<DriveRequest, String> {
    DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: nonzero_u32(4)?,
        max_concurrency: nonzero_u16(1)?,
        max_payload_bytes_in_flight: nonzero_usize(512 * 1024)?,
        max_completion_details: 4,
        max_store_operations: nonzero_u32(64)?,
        stop_claiming_at: MonotonicDeadline::ZERO,
        finish_by: MonotonicDeadline::from_nanos(1),
    })
    .map_err(lifecycle::display_error)
}

fn schedule_cursor() -> ScheduleCursor {
    ScheduleCursor::new(Some(Timestamp::ZERO), true)
}

#[given("a valid five-field UTC expression")]
async fn given_valid_cron(world: &mut BddWorld) -> Result<(), String> {
    evidence(world).expression = Some("0 * * * *".to_owned());
    Ok(())
}

#[when("two nodes materialise the same occurrence")]
async fn when_two_nodes_materialise(world: &mut BddWorld) -> Result<(), String> {
    let expression = evidence(world)
        .expression
        .clone()
        .ok_or("cron expression was not configured")?;
    let store = FakeStore::distributed();
    let calls = Arc::new(AtomicUsize::new(0));
    let first = lifecycle::build_system_with_owner(store.clone(), calls.clone(), 1)?;
    let second = lifecycle::build_system_with_owner(store.clone(), calls, 2)?;
    let recurring = schedule(&expression, MisfirePolicy::FireOnce)?;
    let cursor = schedule_cursor();
    let now = Timestamp::from_millis(3 * HOUR);
    let first_result = first
        .materialize_schedule(&recurring, &cursor, now)
        .await
        .map_err(lifecycle::display_error)?;
    let second_result = second
        .materialize_schedule(&recurring, &cursor, now)
        .await
        .map_err(lifecycle::display_error)?;
    let first_occurrence = first_result
        .occurrences
        .first()
        .ok_or("first node emitted no occurrence")?;
    let second_occurrence = second_result
        .occurrences
        .first()
        .ok_or("second node emitted no occurrence")?;
    let state = evidence(world);
    state.deterministic_intended = Some(first_occurrence.occurrence.intended_at);
    state.deterministic_ids_match =
        first_occurrence.occurrence.occurrence_id() == second_occurrence.occurrence.occurrence_id();
    state.deterministic_enqueued =
        usize::from(first_occurrence.enqueue.disposition == EnqueueDisposition::Enqueued)
            + usize::from(second_occurrence.enqueue.disposition == EnqueueDisposition::Enqueued);
    world.store = Some(store);
    Ok(())
}

#[then("the cron crate calculates one intended time and one deterministic job commits")]
async fn then_cron_is_deterministic(world: &mut BddWorld) -> Result<(), String> {
    let state = world.wake.as_ref().ok_or("wake evidence was missing")?;
    if state.deterministic_intended.is_none()
        || !state.deterministic_ids_match
        || state.deterministic_enqueued != 1
    {
        return Err(format!(
            "cron materialisation was not deterministic: {state:?}"
        ));
    }
    Ok(())
}

#[given("seconds years aliases local time or provider extensions")]
async fn given_nonportable_cron(world: &mut BddWorld) -> Result<(), String> {
    evidence(world).invalid_expressions = vec![
        "0 0 0 * * *".to_owned(),
        "0 0 * * * 2026".to_owned(),
        "@hourly".to_owned(),
        "0 0 * * * Europe/London".to_owned(),
        "0 0 * * 1L".to_owned(),
    ];
    world.store = Some(FakeStore::new());
    Ok(())
}

#[when("schedule registration validates the expression")]
async fn when_nonportable_cron_is_validated(world: &mut BddWorld) -> Result<(), String> {
    let expressions = evidence(world).invalid_expressions.clone();
    let store = world.store.as_ref().ok_or("store was not configured")?;
    let before = store.snapshot().map_err(lifecycle::display_error)?;
    let mut rejected = 0;
    for expression in expressions {
        if schedule(&expression, MisfirePolicy::Skip).is_err() {
            rejected += 1;
        }
    }
    let after = store.snapshot().map_err(lifecycle::display_error)?;
    let state = evidence(world);
    state.cron_rejections = rejected;
    state.cron_state_unchanged = before == after;
    Ok(())
}

#[then("it fails before durable state changes")]
async fn then_nonportable_cron_rejected(world: &mut BddWorld) -> Result<(), String> {
    let state = world.wake.as_ref().ok_or("wake evidence was missing")?;
    if state.cron_rejections != 5 || !state.cron_state_unchanged {
        return Err(format!(
            "non-portable cron was not rejected early: {state:?}"
        ));
    }
    Ok(())
}

#[given("several occurrences were missed while offline")]
async fn given_missed_occurrences(world: &mut BddWorld) -> Result<(), String> {
    evidence(world).expression = Some("0 * * * *".to_owned());
    Ok(())
}

#[when("Skip FireOnce or CatchUp is selected")]
async fn when_misfire_policies_selected(world: &mut BddWorld) -> Result<(), String> {
    let expression = evidence(world)
        .expression
        .clone()
        .ok_or("cron expression was not configured")?;
    let now = Timestamp::from_millis(5 * HOUR);
    let cursor = schedule_cursor();
    let skip = schedule(&expression, MisfirePolicy::Skip)?
        .evaluate(&cursor, now)
        .map_err(lifecycle::display_error)?;
    let fire_once = schedule(&expression, MisfirePolicy::FireOnce)?
        .evaluate(&cursor, now)
        .map_err(lifecycle::display_error)?;
    let catch_up = schedule(
        &expression,
        MisfirePolicy::CatchUp {
            maximum_occurrences: nonzero_u16(2)?,
        },
    )?
    .evaluate(&cursor, now)
    .map_err(lifecycle::display_error)?;
    evidence(world).misfire_counts = Some((
        skip.occurrences.len(),
        skip.skipped,
        fire_once.occurrences.len(),
        fire_once.skipped,
        catch_up.occurrences.len(),
        catch_up.skipped,
    ));
    Ok(())
}

#[then("each policy emits its defined bounded occurrence count")]
async fn then_misfires_bounded(world: &mut BddWorld) -> Result<(), String> {
    let state = world.wake.as_ref().ok_or("wake evidence was missing")?;
    if state.misfire_counts != Some((0, 6, 1, 5, 2, 4)) {
        return Err(format!("misfire counts were not exact: {state:?}"));
    }
    Ok(())
}

#[given("wake delivery is duplicated or the prompt notification is lost")]
async fn given_lost_or_duplicate_wake(world: &mut BddWorld) -> Result<(), String> {
    let store = FakeStore::distributed();
    let calls = Arc::new(AtomicUsize::new(0));
    let system = lifecycle::build_system_with_owner(store.clone(), calls.clone(), 1)?;
    let job = lifecycle::new_job(
        92,
        Bytes::from_static(b"wake"),
        lifecycle::scoped_fairness(),
        Timestamp::ZERO,
    )?;
    lifecycle::save_system(world, store, system, calls, job, Timestamp::ZERO);
    Ok(())
}

#[when("a one-minute safety trigger later drives work")]
async fn when_safety_trigger_drives(world: &mut BddWorld) -> Result<(), String> {
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
    let job = world.job.clone().ok_or("job was not configured")?;
    let enqueue = system
        .enqueue_raw(job, Timestamp::ZERO)
        .await
        .map_err(lifecycle::display_error)?;
    let merged = WakeCandidates {
        watermarks: vec![enqueue.wake, enqueue.wake],
        due_heads: Vec::new(),
        schedule_heads: Vec::new(),
    }
    .merge(nonzero_u32(2)?);
    let first = system
        .drive(lifecycle::drive_request(), Timestamp::ZERO, || {
            MonotonicDeadline::ZERO
        })
        .await
        .map_err(lifecycle::display_error)?;
    let safety_system = lifecycle::build_system_with_owner(store.clone(), calls.clone(), 2)?;
    let safety = safety_system
        .drive(
            lifecycle::drive_request(),
            Timestamp::from_millis(60_000),
            || MonotonicDeadline::ZERO,
        )
        .await
        .map_err(lifecycle::display_error)?;
    let state = evidence(world);
    state.merged_wake = Some(merged);
    state.wake_claims = first.counts.claimed + safety.counts.claimed;
    state.wake_completions = first.counts.succeeded + safety.counts.succeeded;
    state.wake_handler_calls = calls.load(Ordering::SeqCst);
    let mut has_live_state = false;
    for (key, _) in store.snapshot().map_err(lifecycle::display_error)? {
        let tag = KeyCodec::decode_borrowed(&lifecycle::test_namespace(), &key)
            .map_err(lifecycle::display_error)?
            .tag;
        if matches!(
            tag,
            KeyTag::Job | KeyTag::PayloadChunk | KeyTag::Due | KeyTag::Lease
        ) {
            has_live_state = true;
            break;
        }
    }
    // The fake store retains fair-owner accounting and operation receipts;
    // those metadata records are not executable work after completion.
    state.wake_snapshot_empty = !has_live_state;
    Ok(())
}

#[then("no duplicate claim becomes authoritative and accepted work starts")]
async fn then_wake_is_idempotent(world: &mut BddWorld) -> Result<(), String> {
    let state = world.wake.as_ref().ok_or("wake evidence was missing")?;
    if state.merged_wake != Some(WakeHint::Now)
        || state.wake_claims != 1
        || state.wake_completions != 1
        || state.wake_handler_calls != 1
        || !state.wake_snapshot_empty
    {
        return Err(format!("wake recovery was not idempotent: {state:?}"));
    }
    Ok(())
}

#[given("a burst exceeds one drive but fits the invocation budget")]
async fn given_active_burst(world: &mut BddWorld) -> Result<(), String> {
    let store = FakeStore::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let system = lifecycle::build_system(store.clone(), calls.clone())?;
    let job = lifecycle::new_job(
        100,
        Bytes::from_static(b"burst"),
        lifecycle::scoped_fairness(),
        Timestamp::ZERO,
    )?;
    lifecycle::save_system(world, store, system, calls, job, Timestamp::ZERO);
    Ok(())
}

#[when("repeated reports return WakeHint Now")]
async fn when_active_pulse_runs(world: &mut BddWorld) -> Result<(), String> {
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
    for id in 100..103 {
        let job = lifecycle::new_job(
            id,
            Bytes::from_static(b"burst"),
            lifecycle::scoped_fairness(),
            Timestamp::ZERO,
        )?;
        system
            .enqueue_raw(job, Timestamp::ZERO)
            .await
            .map_err(lifecycle::display_error)?;
    }
    let drive_request = pulse_request(1)?;
    let invocations = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&invocations);
    let pulse = ActivePulseRequest::new(nonzero_u16(8)?, MonotonicDeadline::from_nanos(u64::MAX))
        .drive(
            || MonotonicDeadline::ZERO,
            || {
                observed.fetch_add(1, Ordering::SeqCst);
                system.drive(drive_request.clone(), Timestamp::ZERO, || {
                    MonotonicDeadline::ZERO
                })
            },
        )
        .await
        .map_err(lifecycle::display_error)?;
    let state = evidence(world);
    state.pulse_drives = pulse.drives.len();
    state.pulse_stop = Some(pulse.stop_reason);
    state.pulse_handler_calls = calls.load(Ordering::SeqCst);
    state.pulse_invocations = invocations.load(Ordering::SeqCst);
    if let Some(first) = pulse.drives.first() {
        state.pulse_first_has_immediate = first.has_immediately_visible_work;
        state.pulse_first_wake = Some(first.next_wake);
        state.pulse_first_stop = Some(first.stop_reason);
    }
    world.store = Some(store);
    Ok(())
}

#[then("the adapter yields and drives again until no work is immediately useful")]
async fn then_pulse_drains(world: &mut BddWorld) -> Result<(), String> {
    let state = world.wake.as_ref().ok_or("wake evidence was missing")?;
    if state.pulse_drives != 3
        || state.pulse_stop != Some(ActivePulseStopReason::NoImmediateWork)
        || state.pulse_handler_calls != 3
        || !state.pulse_first_has_immediate
        || state.pulse_first_wake != Some(WakeHint::Now)
        || state.pulse_first_stop != Some(DriveStopReason::ClaimsExhausted)
    {
        return Err(format!("active pulse did not drain the burst: {state:?}"));
    }
    Ok(())
}

#[then("it does not poll the empty store for the rest of the minute")]
async fn then_pulse_stops_without_empty_poll(world: &mut BddWorld) -> Result<(), String> {
    let state = world.wake.as_ref().ok_or("wake evidence was missing")?;
    if state.pulse_invocations != state.pulse_drives {
        return Err(format!("pulse performed an extra empty poll: {state:?}"));
    }
    Ok(())
}

#[given("due work exceeds the remaining Lambda or Worker budget")]
async fn given_deadline_work(world: &mut BddWorld) -> Result<(), String> {
    let store = FakeStore::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let system = lifecycle::build_system(store.clone(), calls.clone())?;
    let job = lifecycle::new_job(
        110,
        Bytes::from_static(b"deadline"),
        lifecycle::scoped_fairness(),
        Timestamp::ZERO,
    )?;
    lifecycle::save_system(world, store, system, calls, job, Timestamp::ZERO);
    Ok(())
}

#[when("stop-claiming time is reached")]
async fn when_stop_claiming_time_reached(world: &mut BddWorld) -> Result<(), String> {
    let system = lifecycle::take_system(world)?;
    let store = world
        .store
        .as_ref()
        .ok_or("store was not configured")?
        .clone();
    for id in 110..112 {
        let job = lifecycle::new_job(
            id,
            Bytes::from_static(b"deadline"),
            lifecycle::scoped_fairness(),
            Timestamp::ZERO,
        )?;
        system
            .enqueue_raw(job, Timestamp::ZERO)
            .await
            .map_err(lifecycle::display_error)?;
    }
    let first = system
        .drive(pulse_request(1)?, Timestamp::ZERO, || {
            MonotonicDeadline::ZERO
        })
        .await
        .map_err(lifecycle::display_error)?;
    let deadline = system
        .drive(deadline_request()?, Timestamp::ZERO, || {
            MonotonicDeadline::ZERO
        })
        .await
        .map_err(lifecycle::display_error)?;
    let state = evidence(world);
    state.deadline_succeeded = first.counts.succeeded;
    state.deadline_remaining_claimed = deadline.counts.claimed;
    state.deadline_stop = Some(deadline.stop_reason);
    state.deadline_wake = Some(deadline.next_wake);
    world.store = Some(store);
    Ok(())
}

#[then("active outcomes are persisted and remaining work returns WakeHint Now")]
async fn then_deadline_preserves_work(world: &mut BddWorld) -> Result<(), String> {
    let state = world.wake.as_ref().ok_or("wake evidence was missing")?;
    if state.deadline_succeeded != 1
        || state.deadline_remaining_claimed != 0
        || state.deadline_stop != Some(DriveStopReason::Deadline)
        || state.deadline_wake != Some(WakeHint::Now)
    {
        return Err(format!(
            "deadline did not preserve remaining work: {state:?}"
        ));
    }
    Ok(())
}

#[given("due work is present while the drive clock is already expired")]
async fn given_already_expired_drive(world: &mut BddWorld) -> Result<(), String> {
    let store = FakeStore::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let system = lifecycle::build_system(store.clone(), calls.clone())?;
    let job = lifecycle::new_job(
        130,
        Bytes::from_static(b"expired-clock"),
        lifecycle::scoped_fairness(),
        Timestamp::ZERO,
    )?;
    lifecycle::save_system(world, store, system, calls, job, Timestamp::ZERO);
    Ok(())
}

#[when("the public drive observes the expired clock")]
async fn when_already_expired_drive(world: &mut BddWorld) -> Result<(), String> {
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
    system
        .enqueue_raw(
            world.job.clone().ok_or("job was not configured")?,
            world.now,
        )
        .await
        .map_err(lifecycle::display_error)?;
    let report = system
        .drive(deadline_request()?, world.now, || MonotonicDeadline::ZERO)
        .await
        .map_err(lifecycle::display_error)?;
    let state = evidence(world);
    state.already_expired_claimed = report.counts.claimed;
    state.already_expired_handler_calls = calls.load(Ordering::SeqCst);
    state.already_expired_stop = Some(report.stop_reason);
    world.store = Some(store);
    Ok(())
}

#[then("it stops before invoking a handler and leaves due work durable")]
async fn then_already_expired_preserves_work(world: &mut BddWorld) -> Result<(), String> {
    let state = world.wake.as_ref().ok_or("wake evidence was missing")?;
    let store = world.store.as_ref().ok_or("store was not configured")?;
    if state.already_expired_claimed != 0
        || state.already_expired_handler_calls != 0
        || state.already_expired_stop != Some(DriveStopReason::Deadline)
        || store
            .snapshot()
            .map_err(lifecycle::display_error)?
            .is_empty()
    {
        return Err(format!(
            "already-expired drive was not fail-closed: {state:?}"
        ));
    }
    Ok(())
}

#[given("a schedule queue or job is paused or cancelled")]
async fn given_pause_or_cancel(world: &mut BddWorld) -> Result<(), String> {
    let store = FakeStore::distributed();
    let calls = Arc::new(AtomicUsize::new(0));
    let system = lifecycle::build_system(store.clone(), calls.clone())?;
    let job = lifecycle::new_job(
        120,
        Bytes::from_static(b"cancel"),
        lifecycle::scoped_fairness(),
        Timestamp::ZERO,
    )?;
    lifecycle::save_system(world, store, system, calls, job, Timestamp::ZERO);
    evidence(world).expression = Some("0 * * * *".to_owned());
    Ok(())
}

#[when("drive and resume operations race")]
async fn when_pause_resume_races(world: &mut BddWorld) -> Result<(), String> {
    let mut cursor = schedule_cursor();
    let revision = cursor.revision();
    let generation = cursor.generation();
    let paused = cursor.apply_control(revision, generation, ScheduleControl::Pause);
    let stale_resume = cursor.apply_control(revision, generation, ScheduleControl::Resume);
    let resumed = cursor.apply_control(
        cursor.revision(),
        cursor.generation(),
        ScheduleControl::Resume,
    );
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
    let cancelled_job = world.job.clone().ok_or("job was not configured")?;
    let peer_job = lifecycle::new_job(
        121,
        Bytes::from_static(b"peer"),
        lifecycle::scoped_fairness(),
        Timestamp::ZERO,
    )?;
    system
        .enqueue_raw(cancelled_job.clone(), Timestamp::ZERO)
        .await
        .map_err(lifecycle::display_error)?;
    system
        .enqueue_raw(peer_job, Timestamp::ZERO)
        .await
        .map_err(lifecycle::display_error)?;
    let cancellation = system
        .cancel_job(cancelled_job.job_id, Timestamp::ZERO)
        .await
        .map_err(lifecycle::display_error)?;
    let report = system
        .drive(lifecycle::drive_request(), Timestamp::ZERO, || {
            MonotonicDeadline::ZERO
        })
        .await
        .map_err(lifecycle::display_error)?;
    let state = evidence(world);
    state.control_applied = matches!(paused, ScheduleControlResult::Applied { .. });
    state.control_conflict = matches!(stale_resume, ScheduleControlResult::Conflict { .. });
    state.control_resumed = matches!(resumed, ScheduleControlResult::Applied { .. })
        && !cursor.is_paused()
        && cursor.is_enabled();
    state.cancelled = cancellation == CancellationResult::Cancelled;
    state.peer_succeeded = report.counts.succeeded;
    state.peer_handler_calls = calls.load(Ordering::SeqCst);
    world.store = Some(store);
    Ok(())
}

#[then("checked generations produce one valid state and unrelated work remains runnable")]
async fn then_pause_cancel_safe(world: &mut BddWorld) -> Result<(), String> {
    let state = world.wake.as_ref().ok_or("wake evidence was missing")?;
    if !state.control_applied
        || !state.control_conflict
        || !state.control_resumed
        || !state.cancelled
        || state.peer_succeeded != 1
        || state.peer_handler_calls != 1
    {
        return Err(format!(
            "pause/cancel race was not safely settled: {state:?}"
        ));
    }
    Ok(())
}
