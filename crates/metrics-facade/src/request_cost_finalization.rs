use std::{sync::Arc, time::Instant};

use crate::{
    RequestCostSnapshot,
    constants::{COST_STABILIZE_IDLE_WINDOW, COST_STABILIZE_POLL_INTERVAL, COST_STABILIZE_TIMEOUT},
    request_cost::{REQUEST_COST_COLLECTOR, RequestCostCollectorHandle, unregister_request},
};

/// Finalize the existing cost-header contract. A registered correlation can
/// receive late analytics reports, so this explicit diagnostic path retains its
/// bounded idle wait. Operational buffering uses
/// `finish_request_cost_snapshot`.
pub async fn finish_request_cost_collection(
    request_id: Option<&str>,
    wall_ms: f64,
    response_bytes: Option<u64>,
) -> RequestCostSnapshot {
    let Some((collector, registered)) = prepare_snapshot(wall_ms, response_bytes) else {
        return RequestCostSnapshot::default();
    };
    if request_id.is_some() && registered {
        wait_for_cost_settle(&collector).await;
    }
    finish_snapshot(&collector)
}

/// Failure to obtain a settled operational measurement. Never admit a partial
/// snapshot as complete. This is independent from billing and durability ACKs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestCostSettlementError {
    CollectorUnavailable,
    DeadlineExceeded,
}

/// Wait for explicitly inherited work and active database calls, without an
/// idle delay. Raw correlation-only reports still use the diagnostic header
/// path.
pub async fn finish_request_cost_snapshot(
    wall_ms: f64,
    response_bytes: Option<u64>,
) -> Result<RequestCostSnapshot, RequestCostSettlementError> {
    let Some((collector, _)) = prepare_snapshot(wall_ms, response_bytes) else {
        return Err(RequestCostSettlementError::CollectorUnavailable);
    };
    let settled =
        tokio::time::timeout(COST_STABILIZE_TIMEOUT, wait_for_owned_work(&collector)).await;
    match settled {
        Ok(Ok(snapshot)) => Ok(snapshot),
        failure => {
            // Unregister even on failure; never admit partial measurements.
            finish_snapshot(&collector);
            failure.unwrap_or(Err(RequestCostSettlementError::DeadlineExceeded))
        }
    }
}

async fn wait_for_owned_work(
    collector: &RequestCostCollectorHandle,
) -> Result<RequestCostSnapshot, RequestCostSettlementError> {
    let notify = collector
        .lock()
        .map_err(|_| RequestCostSettlementError::CollectorUnavailable)?
        .settlement_notification();
    loop {
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let finished = {
            let mut collector = collector
                .lock()
                .map_err(|_| RequestCostSettlementError::CollectorUnavailable)?;
            collector
                .is_work_idle()
                .then(|| collector.take_finished_snapshot())
        };
        if let Some((snapshot, registration)) = finished {
            if let Some(registration) = registration {
                unregister_request(registration);
            }
            return Ok(snapshot);
        }
        notified.await;
    }
}

fn prepare_snapshot(
    wall_ms: f64,
    response_bytes: Option<u64>,
) -> Option<(RequestCostCollectorHandle, bool)> {
    let collector = REQUEST_COST_COLLECTOR.try_with(Arc::clone).ok()?;
    let registered = collector
        .lock()
        .ok()?
        .prepare_snapshot(wall_ms, response_bytes);
    Some((collector, registered))
}

fn finish_snapshot(collector: &RequestCostCollectorHandle) -> RequestCostSnapshot {
    let Ok((snapshot, registration)) = collector
        .lock()
        .map(|mut collector| collector.take_finished_snapshot())
    else {
        return RequestCostSnapshot::default();
    };
    if let Some(registration) = registration {
        unregister_request(registration);
    }
    snapshot
}

async fn wait_for_cost_settle(collector: &RequestCostCollectorHandle) {
    let deadline = Instant::now() + COST_STABILIZE_TIMEOUT;
    loop {
        let settled = collector.lock().map_or(true, |collector| {
            collector.has_settled(COST_STABILIZE_IDLE_WINDOW)
        });
        if settled || Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(COST_STABILIZE_POLL_INTERVAL).await;
    }
}
