use std::{future::Future, time::Duration};

use crate::constants::MINIMUM_LEASE_RENEWAL_INTERVAL;

/// Renews a caller-owned resource lease while one operation is in flight.
/// This grants no job authority; the adapter enforces its native lease.
#[derive(Clone, Copy, Debug)]
pub enum LeaseHeartbeat {
    /// Drop a read or transport handler when renewal fails.
    CancelOnLoss(Duration),
    /// Let a potentially committed native write settle before reporting loss.
    DrainOnLoss(Duration),
}

impl LeaseHeartbeat {
    /// Return the operation's output, or the renewal error. No task is spawned.
    /// A ready operation wins over another renewal; successful renewals restart
    /// the interval. Dropping this future drops both in-flight futures.
    pub async fn run<T, E, R>(
        self,
        operation: impl Future<Output = T>,
        mut renew: impl FnMut() -> R,
    ) -> Result<T, E>
    where
        R: Future<Output = Result<(), E>>,
    {
        let interval = match self {
            Self::CancelOnLoss(interval) | Self::DrainOnLoss(interval) => interval,
        }
        .max(MINIMUM_LEASE_RENEWAL_INTERVAL);
        tokio::pin!(operation);
        let renewal = tokio::time::sleep(interval);
        tokio::pin!(renewal);
        loop {
            tokio::select! {
                biased;
                output = &mut operation => return Ok(output),
                () = &mut renewal => {
                    if let Err(error) = renew().await {
                        if matches!(self, Self::DrainOnLoss(_)) {
                            let _ = operation.await;
                        }
                        return Err(error);
                    }
                    renewal.as_mut().reset(tokio::time::Instant::now() + interval);
                }
            }
        }
    }
}
