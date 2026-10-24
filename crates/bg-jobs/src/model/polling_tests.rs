use std::time::Duration;

use bytes::Bytes;

use crate::{
    FairnessPolicy, JobId, JobOutcome, Timestamp,
    test_helper::{FakeStore, block_on, low_volume_job, system},
};

#[test]
fn given_empty_cycles_when_resuming_durable_checkpoints_then_delays_grow_and_cap_with_jitter() {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 1);
    let id = JobId::from([1; 16]);
    let mut now = Timestamp::ZERO;
    block_on(system.enqueue_raw(low_volume_job(1, now), now)).unwrap();
    for cycle in 1..=12 {
        let claim = block_on(system.claim(id, now)).unwrap();
        let context = claim.context().unwrap();
        if cycle > 1 {
            assert_eq!(context.poll_checkpoint(), Some(b"page".as_slice()));
        }
        let outcome = context
            .continue_poll(Bytes::from_static(b"page"), Duration::from_secs(1), true)
            .unwrap();
        let JobOutcome::Continue { not_before, .. } = &outcome else {
            panic!("poll must continue")
        };
        let cap = (1u64 << cycle).min(300) * 1000;
        let delay = not_before.duration_since(now).unwrap().as_millis() as u64;
        assert!(
            (cap * 80 / 100..=cap).contains(&delay),
            "cycle {cycle}: {delay}"
        );
        let next = *not_before;
        block_on(system.apply_outcome(claim, outcome, now)).unwrap();
        now = next;
    }
}

#[test]
fn given_work_on_an_earlier_page_when_the_cycle_finishes_then_idle_backoff_resets() {
    let system = system(FakeStore::new(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([1; 16]);
    let mut now = Timestamp::ZERO;
    block_on(system.enqueue_raw(low_volume_job(1, now), now)).unwrap();
    for (index, (work, complete)) in [(false, true), (false, true), (true, false), (false, true)]
        .into_iter()
        .enumerate()
    {
        let claim = block_on(system.claim(id, now)).unwrap();
        let context = claim.context().unwrap();
        if work {
            context.clone().record_poll_work_found();
        }
        let outcome = context
            .continue_poll(
                Bytes::from_static(b"page"),
                Duration::from_secs(1),
                complete,
            )
            .unwrap();
        let JobOutcome::Continue { not_before, .. } = &outcome else {
            panic!("poll must continue")
        };
        if index == 3 {
            let delay = not_before.duration_since(now).unwrap();
            assert!((Duration::from_millis(800)..=Duration::from_secs(1)).contains(&delay));
        }
        let next = *not_before;
        block_on(system.apply_outcome(claim, outcome, now)).unwrap();
        now = next;
    }
}

#[test]
fn given_invalid_poll_envelopes_when_decoding_then_application_validation_remains_fail_closed() {
    for bytes in [
        b"AUXPOLL1".as_slice(),
        b"AUXPOLL1\0\0\0\0\x02invalid".as_slice(),
    ] {
        assert_eq!(super::poll_checkpoint_payload(bytes), bytes);
    }
}

#[test]
fn given_different_jobs_when_the_same_empty_cycle_finishes_then_jitter_spreads_their_due_times() {
    let system = system(FakeStore::new(), FairnessPolicy::low_volume(), 1);
    let mut times = std::collections::BTreeSet::new();
    for id in 1..=20 {
        block_on(system.enqueue_raw(low_volume_job(id, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
        let claim = block_on(system.claim(JobId::from([id; 16]), Timestamp::ZERO)).unwrap();
        let outcome = claim
            .context()
            .unwrap()
            .continue_poll(Bytes::new(), Duration::from_secs(60), true)
            .unwrap();
        let JobOutcome::Continue { not_before, .. } = outcome else {
            panic!("must continue")
        };
        times.insert(not_before.as_millis());
    }
    assert!(times.len() > 1);
    assert!(times.iter().all(|time| (96_000..=120_000).contains(time)));
}

#[test]
fn given_a_partial_page_when_continuing_then_the_attempt_clock_and_application_bytes_are_preserved()
{
    let system = system(FakeStore::new(), FairnessPolicy::low_volume(), 1);
    let now = Timestamp::from_millis(1000);
    block_on(system.enqueue_raw(low_volume_job(1, now), now)).unwrap();
    let claim = block_on(system.claim(JobId::from([1; 16]), now)).unwrap();
    let outcome = claim
        .context()
        .unwrap()
        .continue_poll(
            Bytes::from_static(b"next-page"),
            Duration::from_millis(25),
            false,
        )
        .unwrap();
    let JobOutcome::Continue {
        not_before,
        checkpoint,
    } = &outcome
    else {
        panic!("must continue")
    };
    assert_eq!(*not_before, Timestamp::from_millis(1025));
    assert_eq!(super::poll_checkpoint_payload(checkpoint), b"next-page");
    block_on(system.apply_outcome(claim, outcome, now)).unwrap();
    let resumed =
        block_on(system.claim(JobId::from([1; 16]), Timestamp::from_millis(1025))).unwrap();
    assert_eq!(
        resumed.context().unwrap().poll_checkpoint(),
        Some(b"next-page".as_slice())
    );
}

#[test]
fn given_an_oversized_poll_payload_when_scheduling_then_the_envelope_cannot_exceed_the_checkpoint_bound()
 {
    let system = system(FakeStore::new(), FairnessPolicy::low_volume(), 1);
    block_on(system.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    let claim = block_on(system.claim(JobId::from([1; 16]), Timestamp::ZERO)).unwrap();
    let context = claim.context().unwrap();
    let maximum = super::MAX_CHECKPOINT_BYTES - super::constants::POLL_CHECKPOINT_PREFIX_BYTES;
    assert!(
        context
            .continue_poll(Bytes::from(vec![0; maximum]), Duration::from_secs(1), true)
            .is_ok()
    );
    assert!(
        context
            .continue_poll(
                Bytes::from(vec![0; maximum + 1]),
                Duration::from_secs(1),
                true
            )
            .is_err()
    );
}
