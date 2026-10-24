use std::time::{Duration, Instant};

use super::record::AdmittedRecord;
use crate::configuration::{OperationId, TenantScope};

#[test]
fn given_canonical_record_when_identity_changes_then_distinguish_content_but_ignore_retry_times() {
    let record = AdmittedRecord {
        operation_id: OperationId::try_from("operation").unwrap(),
        scope: TenantScope::try_from("scope").unwrap(),
        codec_version: "json/v1".to_owned(),
        admitted_at_utc_ms: 1,
        admitted_at_mono: Instant::now(),
        payload: bytes::Bytes::from_static(b"7"),
    };
    let fingerprint = record.admission_fingerprint();
    let mut later = record.clone();
    later.admitted_at_utc_ms = 100;
    later.admitted_at_mono += Duration::from_secs(1);
    assert_eq!(fingerprint, later.admission_fingerprint());
    for changed in [
        AdmittedRecord {
            operation_id: OperationId::try_from("other").unwrap(),
            ..record.clone()
        },
        AdmittedRecord {
            scope: TenantScope::try_from("other").unwrap(),
            ..record.clone()
        },
        AdmittedRecord {
            codec_version: "json/v2".to_owned(),
            ..record.clone()
        },
        AdmittedRecord {
            payload: bytes::Bytes::from_static(b"8"),
            ..record.clone()
        },
    ] {
        assert_ne!(fingerprint, changed.admission_fingerprint());
    }
    let delimited = AdmittedRecord {
        scope: TenantScope::try_from("a:b").unwrap(),
        codec_version: "c".to_owned(),
        ..record.clone()
    };
    let shifted = AdmittedRecord {
        scope: TenantScope::try_from("a").unwrap(),
        codec_version: "b:c".to_owned(),
        ..record
    };
    assert_ne!(
        delimited.admission_fingerprint(),
        shifted.admission_fingerprint()
    );
}
