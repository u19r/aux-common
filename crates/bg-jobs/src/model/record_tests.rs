use bytes::Bytes;

use crate::{
    FairnessClass, FairnessKey, FairnessPath, JobOutcome, Timestamp,
    test_helper::{dedupe, job},
};

#[test]
fn given_job_input_with_customer_bytes_when_debugged_then_only_lengths_are_rendered() {
    let fairness = FairnessClass::from(FairnessPath::new(
        FairnessKey::try_new(b"tenant-identifier").expect("fairness key"),
        None,
    ));
    let new_job = job(
        1,
        Bytes::from_static(b"customer-secret-payload"),
        fairness,
        Timestamp::ZERO,
        None,
        Some(dedupe(b"tenant-identifier", Timestamp::from_millis(1))),
    );
    let outcome = JobOutcome::Continue {
        not_before: Timestamp::ZERO,
        checkpoint: Bytes::from_static(b"customer-secret-checkpoint"),
    };

    let rendered = format!("{new_job:?} {outcome:?}");

    assert!(rendered.contains("payload_bytes: 23"));
    assert!(rendered.contains("checkpoint_bytes: 26"));
    assert!(!rendered.contains("customer-secret"));
    // "ten" as the derived `Vec<u8>` rendering would print it.
    assert!(!rendered.contains("116, 101, 110"));
    assert!(!rendered.contains("tenant-identifier"));
}
