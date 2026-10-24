/// Select request-cost observation independently from response header exposure.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RequestCostCollection {
    /// Do not create a request-cost collector.
    #[default]
    Disabled,
    /// Settle explicitly inherited work without a fixed idle wait, then attach
    /// the snapshot. A settlement timeout emits a warning instead of partial
    /// data.
    Snapshot,
    /// Finalize the same snapshot and expose the existing cost response
    /// headers.
    Headers,
}

impl RequestCostCollection {
    pub(crate) fn is_enabled(self) -> bool {
        self != Self::Disabled
    }

    pub(crate) async fn finalize_response(
        self,
        response: &mut axum::response::Response,
        request_id: Option<&str>,
        duration_ms: f64,
        response_bytes: u64,
    ) {
        let snapshot = match self {
            Self::Disabled => return,
            Self::Snapshot => {
                match metrics_facade::finish_request_cost_snapshot(
                    duration_ms,
                    Some(response_bytes),
                )
                .await
                {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        tracing::warn!(target: "request_metering", error = ?error, "request cost settlement failed");
                        return;
                    }
                }
            }
            Self::Headers => {
                metrics_facade::finish_request_cost_collection(
                    request_id,
                    duration_ms,
                    Some(response_bytes),
                )
                .await
            }
        };
        let costs = metrics_facade::CostResponseHeaders::from_snapshot(snapshot);
        if self == Self::Headers {
            costs.write_to_headers(response.headers_mut());
        }
        response.extensions_mut().insert(costs);
    }
}
