use super::{
    RequestCostContext, active_request_id, begin_database_call, begin_request_cost_collection,
    finish_request_cost_collection,
};

#[tokio::test(start_paused = true)]
async fn given_finalized_capture_when_reused_in_another_request_then_current_owner_is_preserved() {
    let context = begin_request_cost_collection(Some("finished-owner".to_owned()), || async {
        let context = RequestCostContext::capture();
        super::finish_request_cost_snapshot(1.0, None)
            .await
            .unwrap();
        context
    })
    .await;
    let snapshot = begin_request_cost_collection(Some("current-owner".to_owned()), || async {
        context
            .scope(async {
                assert_eq!(active_request_id().as_deref(), Some("current-owner"));
                drop(begin_database_call("current.completed"));
            })
            .await;
        super::finish_request_cost_snapshot(1.0, None)
            .await
            .unwrap()
    })
    .await;
    assert_eq!(snapshot.db_calls, 1);
}

#[tokio::test(start_paused = true)]
async fn given_inherited_unpolled_work_when_snapshot_finishes_then_detached_costs_are_settled_without_idle_delay()
 {
    begin_request_cost_collection(Some("detached-work".to_owned()), || async {
        let work = super::inherit_request_cost(async {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            drop(begin_database_call("detached.completed"));
        });
        // The reservation exists before spawn/poll, including timeout-detached
        // work.
        tokio::spawn(work);
        let started = tokio::time::Instant::now();
        let snapshot = super::finish_request_cost_snapshot(1.0, None)
            .await
            .unwrap();
        assert_eq!(snapshot.db_calls, 1);
        assert_eq!(started.elapsed(), std::time::Duration::from_millis(20));
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn given_unpolled_work_when_cancelled_then_snapshot_does_not_wait_for_a_leaked_reservation() {
    begin_request_cost_collection(None, || async {
        let context = RequestCostContext::capture();
        let work = context.scope(std::future::pending::<()>());
        drop(context);
        drop(work);
        let started = tokio::time::Instant::now();
        let snapshot = super::finish_request_cost_snapshot(1.0, None)
            .await
            .unwrap();
        assert_eq!(snapshot.db_calls, 0);
        assert!(started.elapsed().is_zero());
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn given_outstanding_work_when_settlement_deadline_expires_then_partial_measurement_is_rejected()
 {
    begin_request_cost_collection(Some("unsettled-work".to_owned()), || async {
        let work = super::inherit_request_cost(std::future::pending::<()>());
        let result = super::finish_request_cost_snapshot(1.0, None).await;
        assert_eq!(
            result.unwrap_err(),
            super::RequestCostSettlementError::DeadlineExceeded
        );
        assert!(!super::request_cost::active_request_has_registration());
        drop(work);
    })
    .await;
}

#[tokio::test]
async fn given_captured_collector_when_shared_worker_reuses_context_then_attempts_keep_original_owner()
 {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let worker = tokio::spawn(async move {
        let context: RequestCostContext = receiver.await.unwrap();
        for _ in 0..2 {
            context
                .scope(async {
                    assert_eq!(active_request_id().as_deref(), Some("scope-owner"));
                    let _attempt = begin_database_call("test.shared-worker");
                })
                .await;
        }
        assert!(active_request_id().is_none());
    });
    let snapshot = begin_request_cost_collection(Some("scope-owner".to_owned()), || async {
        sender.send(RequestCostContext::capture()).ok().unwrap();
        worker.await.unwrap();
        finish_request_cost_collection(None, 1.0, None).await
    })
    .await;
    assert_eq!(snapshot.db_calls, 2);
}

#[tokio::test]
async fn given_empty_capture_when_scoped_within_another_request_then_existing_context_is_preserved()
{
    let context = RequestCostContext::capture();
    let snapshot = begin_request_cost_collection(Some("current-owner".to_owned()), || async {
        context
            .scope(async {
                assert_eq!(active_request_id().as_deref(), Some("current-owner"));
                let _attempt = begin_database_call("test.current-worker");
            })
            .await;
        finish_request_cost_collection(None, 1.0, None).await
    })
    .await;
    assert_eq!(snapshot.db_calls, 1);
}
