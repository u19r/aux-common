use super::state::{RetentionState, StoredAdmissionReceipt};
use crate::{AdmissionStatus, Namespace, OperationId, TenantScope};

#[test]
fn given_unsettled_identity_when_completed_receipts_fill_cache_then_preserve_unsettled_receipt() {
    let namespace = Namespace::try_from("receipt-retention/v1".to_owned()).unwrap();
    let scope = TenantScope::from_namespace(&namespace);
    let active_id = OperationId::generate_v7();
    let receipt = StoredAdmissionReceipt {
        status: AdmissionStatus::Buffered,
        scope,
        codec_version: "v1".to_owned(),
        payload_digest: [0; 32],
        watermark: 1,
    };
    let mut state = RetentionState::default();
    state.insert_receipt(active_id.clone(), receipt.clone());
    for _ in 0..crate::constants::MAX_COMPLETED_OPERATION_RECEIPTS + 10 {
        state.insert_receipt(
            OperationId::generate_v7(),
            StoredAdmissionReceipt {
                status: AdmissionStatus::Written,
                ..receipt.clone()
            },
        );
    }
    assert!(state.admission_receipts.contains_key(&active_id));
    assert!(!state.completed_receipt_order.contains(&active_id));
    assert_eq!(
        state.admission_receipts.len(),
        crate::constants::MAX_COMPLETED_OPERATION_RECEIPTS + 1
    );
}

#[test]
fn given_more_active_receipts_than_cache_when_completed_then_bound_completed_receipts() {
    let scope = TenantScope::from_namespace(&Namespace::try_from("receipt/v1".to_owned()).unwrap());
    let receipt = StoredAdmissionReceipt {
        status: AdmissionStatus::Buffered,
        scope,
        codec_version: "v1".to_owned(),
        payload_digest: [0; 32],
        watermark: 1,
    };
    let ids: Vec<_> = (0..crate::constants::MAX_COMPLETED_OPERATION_RECEIPTS + 10)
        .map(|_| OperationId::generate_v7())
        .collect();
    let mut state = RetentionState::default();
    for id in &ids {
        state.insert_receipt(id.clone(), receipt.clone());
    }
    assert_eq!(state.admission_receipts.len(), ids.len());
    for id in ids {
        state.insert_receipt(
            id,
            StoredAdmissionReceipt {
                status: AdmissionStatus::Written,
                ..receipt.clone()
            },
        );
    }
    assert_eq!(
        state.admission_receipts.len(),
        crate::constants::MAX_COMPLETED_OPERATION_RECEIPTS
    );
}
