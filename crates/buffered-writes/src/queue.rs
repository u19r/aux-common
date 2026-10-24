use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use futures_util::future::BoxFuture;

use crate::{
    batch::SealedBatch,
    configuration::Deadline,
    constants::SQS_MAX_MESSAGE_BYTES,
    error::{ConfigurationError, QueueError},
};

/// Capability and size limits of a [`WriteQueue`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueLimits {
    max_envelope_bytes: usize,
    independent_failure_domain: bool,
}

impl Default for QueueLimits {
    fn default() -> Self {
        Self {
            max_envelope_bytes: SQS_MAX_MESSAGE_BYTES,
            independent_failure_domain: true,
        }
    }
}

impl QueueLimits {
    pub fn try_new(
        max_envelope_bytes: usize,
        independent_failure_domain: bool,
    ) -> Result<Self, ConfigurationError> {
        if max_envelope_bytes == 0 {
            return Err(ConfigurationError::ZeroCapacity {
                field: "queue_limits.max_envelope_bytes",
            });
        }
        Ok(Self {
            max_envelope_bytes,
            independent_failure_domain,
        })
    }

    #[must_use]
    pub const fn max_envelope_bytes(&self) -> usize {
        self.max_envelope_bytes
    }

    #[must_use]
    pub const fn is_independent_failure_domain(&self) -> bool {
        self.independent_failure_domain
    }
}

/// Queue publication receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueReceipt {
    pub message_id: String,
}

/// Envelope received by a [`ReplayQueue`] consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedEnvelope {
    pub message_id: String,
    pub receipt_handle: String,
    pub envelope_bytes: Bytes,
}

/// Outage fallback producer contract.
pub trait WriteQueue: Send + Sync + 'static {
    fn limits(&self) -> &QueueLimits;

    fn publish(
        &self,
        batch: SealedBatch,
        deadline: Deadline,
    ) -> BoxFuture<'static, Result<QueueReceipt, QueueError>>;
}

/// Replay consumer contract extending [`WriteQueue`].
pub trait ReplayQueue: WriteQueue {
    fn receive(
        &self,
        max_messages: usize,
        deadline: Deadline,
    ) -> BoxFuture<'static, Result<Vec<ReceivedEnvelope>, QueueError>>;

    fn renew_visibility(
        &self,
        receipt_handle: &str,
        extension: Duration,
        deadline: Deadline,
    ) -> BoxFuture<'static, Result<(), QueueError>>;

    fn acknowledge(
        &self,
        receipt_handle: &str,
        deadline: Deadline,
    ) -> BoxFuture<'static, Result<(), QueueError>>;

    /// Persist the worker's versioned JSON quarantine record before removing
    /// the source message. It contains the original opaque envelope as
    /// base64 and known completed operation IDs; transport quotas apply to
    /// this expanded body.
    fn quarantine(
        &self,
        receipt_handle: &str,
        envelope_bytes: Bytes,
        reason: &'static str,
        deadline: Deadline,
    ) -> BoxFuture<'static, Result<(), QueueError>>;
}

/// Fallback queue configuration for a writer builder.
#[derive(Clone)]
pub struct QueueConfig {
    pub(crate) inner: QueueConfigKind,
}

#[derive(Clone)]
pub(crate) enum QueueConfigKind {
    Sqs {
        queue_url: String,
        endpoint: Option<String>,
        region: Option<String>,
        quarantine_url: Option<String>,
        fifo_group_id: Option<String>,
        max_envelope_bytes: usize,
    },
    Custom(Arc<dyn WriteQueue>),
}

impl std::fmt::Debug for QueueConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            QueueConfigKind::Sqs {
                queue_url,
                endpoint: _,
                region,
                quarantine_url,
                fifo_group_id,
                ..
            } => formatter
                .debug_struct("QueueConfig::Sqs")
                .field("queue_url_configured", &!queue_url.is_empty())
                .field("region_configured", &region.is_some())
                .field("quarantine_configured", &quarantine_url.is_some())
                .field("fifo_group_configured", &fifo_group_id.is_some())
                .finish(),
            QueueConfigKind::Custom(_) => formatter.write_str("QueueConfig::Custom"),
        }
    }
}

impl QueueConfig {
    #[must_use]
    pub fn sqs(queue_url: impl Into<String>) -> Self {
        Self {
            inner: QueueConfigKind::Sqs {
                queue_url: queue_url.into(),
                endpoint: None,
                region: None,
                quarantine_url: None,
                fifo_group_id: None,
                max_envelope_bytes: SQS_MAX_MESSAGE_BYTES,
            },
        }
    }

    #[must_use]
    pub fn custom<Q: WriteQueue>(queue: Q) -> Self {
        Self {
            inner: QueueConfigKind::Custom(Arc::new(queue)),
        }
    }

    /// Override the SQS queue's configured body limit (up to the service
    /// maximum).
    #[must_use]
    pub fn with_max_envelope_bytes(mut self, bytes: usize) -> Self {
        if let QueueConfigKind::Sqs {
            max_envelope_bytes, ..
        } = &mut self.inner
        {
            *max_envelope_bytes = bytes;
        }
        self
    }

    #[must_use]
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        if let QueueConfigKind::Sqs {
            endpoint: ref mut ep,
            ..
        } = self.inner
        {
            *ep = Some(endpoint.into());
        }
        self
    }

    #[must_use]
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        if let QueueConfigKind::Sqs {
            region: ref mut reg,
            ..
        } = self.inner
        {
            *reg = Some(region.into());
        }
        self
    }

    #[must_use]
    pub fn with_quarantine_url(mut self, url: impl Into<String>) -> Self {
        if let QueueConfigKind::Sqs {
            quarantine_url: ref mut q_url,
            ..
        } = self.inner
        {
            *q_url = Some(url.into());
        }
        self
    }

    #[must_use]
    pub fn with_fifo_group_id(mut self, group_id: impl Into<String>) -> Self {
        if let QueueConfigKind::Sqs {
            fifo_group_id: ref mut group,
            ..
        } = self.inner
        {
            *group = Some(group_id.into());
        }
        self
    }
}

#[derive(Clone, Debug)]
struct InMemoryQueueEntry {
    message_id: String,
    receipt_handle: String,
    envelope_bytes: Bytes,
    in_flight: bool,
}

#[derive(Default)]
struct InMemoryQueueState {
    next_id: u64,
    available: bool,
    messages: VecDeque<InMemoryQueueEntry>,
    quarantined: Vec<(String, Bytes)>,
    visibility_renewals: usize,
    acknowledged_count: usize,
}

/// Fault-controllable in-memory [`ReplayQueue`] for deterministic tests.
#[derive(Clone)]
pub struct InMemoryQueue {
    limits: QueueLimits,
    state: Arc<Mutex<InMemoryQueueState>>,
}

impl Default for InMemoryQueue {
    fn default() -> Self {
        Self::new(QueueLimits::default())
    }
}

impl std::fmt::Debug for InMemoryQueue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("InMemoryQueue")
    }
}

impl InMemoryQueue {
    #[must_use]
    pub fn new(limits: QueueLimits) -> Self {
        Self {
            limits,
            state: Arc::new(Mutex::new(InMemoryQueueState {
                next_id: 0,
                available: true,
                messages: VecDeque::new(),
                quarantined: Vec::new(),
                visibility_renewals: 0,
                acknowledged_count: 0,
            })),
        }
    }

    pub fn set_available(&self, available: bool) {
        if let Ok(mut guard) = self.state.lock() {
            guard.available = available;
        }
    }

    pub fn inject_raw_envelope(&self, envelope_bytes: impl Into<Bytes>) {
        if let Ok(mut guard) = self.state.lock() {
            guard.next_id = guard.next_id.saturating_add(1);
            let id = guard.next_id;
            guard.messages.push_back(InMemoryQueueEntry {
                message_id: format!("msg-{id}"),
                receipt_handle: format!("rh-{id}"),
                envelope_bytes: envelope_bytes.into(),
                in_flight: false,
            });
        }
    }

    pub fn duplicate_front_delivery(&self) {
        if let Ok(mut guard) = self.state.lock()
            && let Some(front) = guard.messages.front().cloned()
        {
            guard.next_id = guard.next_id.saturating_add(1);
            let id = guard.next_id;
            guard.messages.push_back(InMemoryQueueEntry {
                message_id: front.message_id,
                receipt_handle: format!("rh-dup-{id}"),
                envelope_bytes: front.envelope_bytes,
                in_flight: false,
            });
        }
    }

    pub fn expire_all_in_flight_visibilities(&self) {
        if let Ok(mut guard) = self.state.lock() {
            for entry in &mut guard.messages {
                entry.in_flight = false;
            }
        }
    }

    #[must_use]
    pub fn queued_len(&self) -> usize {
        self.state.lock().map_or(0, |guard| guard.messages.len())
    }

    #[must_use]
    pub fn quarantined_len(&self) -> usize {
        self.state.lock().map_or(0, |guard| guard.quarantined.len())
    }

    #[must_use]
    pub fn acknowledged_count(&self) -> usize {
        self.state
            .lock()
            .map_or(0, |guard| guard.acknowledged_count)
    }

    #[must_use]
    pub fn visibility_renewals(&self) -> usize {
        self.state
            .lock()
            .map_or(0, |guard| guard.visibility_renewals)
    }
}

impl WriteQueue for InMemoryQueue {
    fn limits(&self) -> &QueueLimits {
        &self.limits
    }

    fn publish(
        &self,
        batch: SealedBatch,
        _deadline: Deadline,
    ) -> BoxFuture<'static, Result<QueueReceipt, QueueError>> {
        let limits = self.limits;
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let envelope_bytes = batch
                .to_envelope_bytes()
                .map_err(|_| QueueError::Permanent {
                    reason: "failed to encode sealed batch envelope",
                })?;
            if envelope_bytes.len() > limits.max_envelope_bytes() {
                return Err(QueueError::EnvelopeTooLarge {
                    size: envelope_bytes.len(),
                    limit: limits.max_envelope_bytes(),
                });
            }
            let mut guard = state.lock().map_err(|_| QueueError::Unavailable {
                reason: "queue mutex poisoned",
            })?;
            if !guard.available {
                return Err(QueueError::Unavailable {
                    reason: "queue is unavailable",
                });
            }
            guard.next_id = guard.next_id.saturating_add(1);
            let id = guard.next_id;
            let message_id = format!("msg-{id}");
            guard.messages.push_back(InMemoryQueueEntry {
                message_id: message_id.clone(),
                receipt_handle: format!("rh-{id}"),
                envelope_bytes,
                in_flight: false,
            });
            Ok(QueueReceipt { message_id })
        })
    }
}

impl ReplayQueue for InMemoryQueue {
    fn receive(
        &self,
        max_messages: usize,
        _deadline: Deadline,
    ) -> BoxFuture<'static, Result<Vec<ReceivedEnvelope>, QueueError>> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let mut guard = state.lock().map_err(|_| QueueError::Unavailable {
                reason: "queue mutex poisoned",
            })?;
            if !guard.available {
                return Err(QueueError::Unavailable {
                    reason: "queue is unavailable",
                });
            }
            let mut received = Vec::new();
            for entry in &mut guard.messages {
                if received.len() >= max_messages {
                    break;
                }
                if !entry.in_flight {
                    entry.in_flight = true;
                    received.push(ReceivedEnvelope {
                        message_id: entry.message_id.clone(),
                        receipt_handle: entry.receipt_handle.clone(),
                        envelope_bytes: entry.envelope_bytes.clone(),
                    });
                }
            }
            Ok(received)
        })
    }

    fn renew_visibility(
        &self,
        receipt_handle: &str,
        _extension: Duration,
        _deadline: Deadline,
    ) -> BoxFuture<'static, Result<(), QueueError>> {
        let handle = receipt_handle.to_owned();
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let mut guard = state.lock().map_err(|_| QueueError::Unavailable {
                reason: "queue mutex poisoned",
            })?;
            if !guard.available {
                return Err(QueueError::Unavailable {
                    reason: "queue is unavailable",
                });
            }
            if !guard.messages.iter().any(|m| m.receipt_handle == handle) {
                return Err(QueueError::InvalidReceipt);
            }
            guard.visibility_renewals = guard.visibility_renewals.saturating_add(1);
            Ok(())
        })
    }

    fn acknowledge(
        &self,
        receipt_handle: &str,
        _deadline: Deadline,
    ) -> BoxFuture<'static, Result<(), QueueError>> {
        let handle = receipt_handle.to_owned();
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let mut guard = state.lock().map_err(|_| QueueError::Unavailable {
                reason: "queue mutex poisoned",
            })?;
            if !guard.available {
                return Err(QueueError::Unavailable {
                    reason: "queue is unavailable",
                });
            }
            let before = guard.messages.len();
            guard.messages.retain(|m| m.receipt_handle != handle);
            if guard.messages.len() == before {
                return Err(QueueError::InvalidReceipt);
            }
            guard.acknowledged_count = guard.acknowledged_count.saturating_add(1);
            Ok(())
        })
    }

    fn quarantine(
        &self,
        receipt_handle: &str,
        envelope_bytes: Bytes,
        reason: &'static str,
        _deadline: Deadline,
    ) -> BoxFuture<'static, Result<(), QueueError>> {
        let handle = receipt_handle.to_owned();
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let mut guard = state.lock().map_err(|_| QueueError::Unavailable {
                reason: "queue mutex poisoned",
            })?;
            if !guard.available {
                return Err(QueueError::Unavailable {
                    reason: "queue is unavailable",
                });
            }
            guard.messages.retain(|m| m.receipt_handle != handle);
            guard.quarantined.push((reason.to_owned(), envelope_bytes));
            Ok(())
        })
    }
}
