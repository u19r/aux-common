use crate::{ApiBatchEvaluationRequest, BatchEvaluationRequest, MAX_BATCH_EVALUATIONS};

#[test]
fn evaluation_batch_deserialization_rejects_more_than_the_batch_limit() {
    let evaluations = (0..=MAX_BATCH_EVALUATIONS)
        .map(|_| {
            serde_json::json!({
                "subject": { "type": "user", "id": "user_123" },
                "resource": { "type": "document", "id": "doc_123" },
                "action": { "name": "read" }
            })
        })
        .collect::<Vec<_>>();

    let payload = serde_json::json!({ "evaluations": evaluations });
    assert!(
        serde_json::from_value::<BatchEvaluationRequest>(payload.clone())
            .expect_err("evaluation batches must be bounded")
            .to_string()
            .contains("evaluations exceeds maximum")
    );
    assert!(
        serde_json::from_value::<ApiBatchEvaluationRequest>(payload)
            .expect_err("API evaluation batches must be bounded")
            .to_string()
            .contains("evaluations exceeds maximum")
    );
}
