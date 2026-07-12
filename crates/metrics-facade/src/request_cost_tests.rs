use std::sync::Arc;

use tokio::sync::{Barrier, Notify};

use crate::{
    begin_request_cost_collection, finish_request_cost_collection,
    record_analytics_request_cost_by_request_id,
};

#[tokio::test]
async fn duplicate_request_ids_do_not_overwrite_or_cross_attribute_collectors() {
    let registered = Arc::new(Barrier::new(3));
    let finish_first = Arc::new(Notify::new());
    let finish_second = Arc::new(Notify::new());

    let first = tokio::spawn({
        let registered = Arc::clone(&registered);
        let finish_first = Arc::clone(&finish_first);
        async move {
            begin_request_cost_collection(Some("duplicate".to_string()), || async move {
                registered.wait().await;
                finish_first.notified().await;
                finish_request_cost_collection(Some("duplicate"), 1.0, None).await
            })
            .await
        }
    });
    let second = tokio::spawn({
        let registered = Arc::clone(&registered);
        let finish_second = Arc::clone(&finish_second);
        async move {
            begin_request_cost_collection(Some("duplicate".to_string()), || async move {
                registered.wait().await;
                finish_second.notified().await;
                finish_request_cost_collection(Some("duplicate"), 2.0, None).await
            })
            .await
        }
    });

    registered.wait().await;
    record_analytics_request_cost_by_request_id("duplicate", 1, 10);
    finish_first.notify_one();
    let first_snapshot = first.await.expect("first collector task");
    assert_eq!(first_snapshot.analytics_rows_inserted, 0);
    assert_eq!(first_snapshot.analytics_bytes_written, 0);

    record_analytics_request_cost_by_request_id("duplicate", 1, 20);
    finish_second.notify_one();
    let second_snapshot = second.await.expect("second collector task");
    assert_eq!(second_snapshot.analytics_rows_inserted, 1);
    assert_eq!(second_snapshot.analytics_bytes_written, 20);
}
