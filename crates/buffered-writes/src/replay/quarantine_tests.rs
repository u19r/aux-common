use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};

use super::quarantine::ReplayQuarantine;
use crate::{QuarantineReason, ReceivedEnvelope};

const SQS_LIMIT: usize = 1024 * 1024;

fn received(bytes: Vec<u8>) -> ReceivedEnvelope {
    ReceivedEnvelope {
        message_id: "msg-1".to_owned(),
        receipt_handle: "rh-1".to_owned(),
        envelope_bytes: Bytes::from(bytes),
    }
}

fn record(quarantine: &ReplayQuarantine<'_>) -> serde_json::Value {
    let bytes = quarantine.encode(SQS_LIMIT).unwrap();
    assert!(bytes.len() <= SQS_LIMIT, "record of {} bytes", bytes.len());
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn given_envelope_near_queue_limit_when_quarantined_then_record_fits_and_names_the_envelope() {
    let envelope = received(vec![b'x'; 800 * 1024]);
    let quarantine = ReplayQuarantine::from((&envelope, QuarantineReason::PermanentSinkFailure));

    let record = record(&quarantine);

    let kept = STANDARD
        .decode(record["envelope_base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(record["truncated"], true);
    assert_eq!(record["envelope_bytes"], 800 * 1024);
    assert!(envelope.envelope_bytes.starts_with(&kept));
    let digest = Sha256::digest(&envelope.envelope_bytes);
    let expected = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(record["envelope_sha256"], expected);
}

#[test]
fn given_small_poison_envelope_when_quarantined_then_record_keeps_it_whole() {
    let envelope = received(b"{}".to_vec());
    let quarantine = ReplayQuarantine::from((&envelope, QuarantineReason::PoisonReplayEnvelope));

    let record = record(&quarantine);

    assert_eq!(record["truncated"], false);
    assert_eq!(
        STANDARD
            .decode(record["envelope_base64"].as_str().unwrap())
            .unwrap(),
        b"{}"
    );
}
