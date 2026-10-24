use serde::{Deserialize, Serialize};

use super::FlushReport;

/// Common response-completion facts available from local and remote writers.
/// This summary does not assert durability for a young retained batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlushReportSummary {
    pub batches_flushed: usize,
    pub items_settled: usize,
    pub batches_queued: usize,
    pub batches_failed: usize,
    pub has_failures: bool,
}

impl From<FlushReport> for FlushReportSummary {
    fn from(report: FlushReport) -> Self {
        let has_failures = report.has_failures();
        Self {
            has_failures,
            batches_flushed: report.batches_flushed,
            items_settled: report.items_settled,
            batches_queued: report.batches_queued,
            batches_failed: report.batches_failed,
        }
    }
}
