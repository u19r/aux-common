use std::{sync::Arc, time::Duration};

use futures_util::future::BoxFuture;

use super::{
    action::SpotInstanceAction,
    polling::{PollWaitGuard, SpotPolling},
    spot_action_source::SpotActionSource,
};
use crate::{
    Deadline,
    constants::DEFAULT_SPOT_SHUTDOWN_CAP,
    lifecycle::{
        ChannelLifecycle, Lifecycle, LifecycleController, LifecycleEvents, LifecycleTrigger,
    },
};

/// EC2 / Spot lifecycle adapter. The source owns interruption discovery;
/// the host forwards response completion and termination deadlines.
#[derive(Clone)]
pub struct SpotLifecycle {
    source: Arc<dyn SpotActionSource>,
    controller: LifecycleController,
    events: ChannelLifecycle,
    polling: Arc<SpotPolling>,
    terminate_grace: Duration,
    observer: Arc<dyn crate::WriteObserver>,
}

impl std::fmt::Debug for SpotLifecycle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SpotLifecycle")
    }
}

impl SpotLifecycle {
    #[must_use]
    pub fn new(source: impl SpotActionSource) -> Self {
        let (controller, events) = Lifecycle::channel();
        Self {
            source: Arc::new(source),
            controller,
            events,
            polling: Arc::new(SpotPolling::default()),
            terminate_grace: DEFAULT_SPOT_SHUTDOWN_CAP,
            observer: Arc::new(crate::NoopWriteObserver),
        }
    }

    #[must_use]
    pub fn with_observer(mut self, observer: impl crate::WriteObserver) -> Self {
        self.observer = Arc::new(observer);
        self
    }

    pub fn try_with_poll_interval(self, interval: Duration) -> Result<Self, crate::LifecycleError> {
        self.polling.set_interval(interval)?;
        Ok(self)
    }

    /// Cap the remaining action-time window; this does not extend a Spot
    /// notice.
    #[must_use]
    pub fn with_terminate_grace(mut self, grace: Duration) -> Self {
        self.terminate_grace = grace;
        self
    }

    pub fn forward_spot_notice(&self, notice: &SpotInstanceAction) {
        self.controller.send(LifecycleTrigger::Shutdown {
            deadline: notice.shutdown_deadline(self.terminate_grace),
        });
    }

    pub fn notify_response_completed(&self) {
        self.controller.send(LifecycleTrigger::ResponseCompleted);
    }

    pub fn notify_shutdown(&self, deadline: impl Into<Deadline>) {
        self.controller.send(LifecycleTrigger::Shutdown {
            deadline: deadline.into(),
        });
    }

    pub fn close(&self) {
        if let Err(error) = self.polling.close() {
            self.observer
                .observe(crate::WriteEvent::LifecycleSourceFailed { error });
        }
        self.controller.close();
    }
}

impl LifecycleEvents for SpotLifecycle {
    fn can_flush_between_responses(&self) -> bool {
        true
    }

    fn next_event(&self) -> BoxFuture<'static, Option<LifecycleTrigger>> {
        let adapter = self.clone();
        Box::pin(async move {
            let guard =
                match PollWaitGuard::try_new(adapter.polling.clone(), adapter.observer.clone()) {
                    Ok(guard) => guard,
                    Err(error) => {
                        adapter
                            .observer
                            .observe(crate::WriteEvent::LifecycleSourceFailed { error });
                        return adapter.complete_host_event(adapter.events.next_event().await);
                    }
                };
            let event = adapter.await_next_event().await;
            guard.finish();
            event
        })
    }
}

impl SpotLifecycle {
    async fn await_next_event(&self) -> Option<LifecycleTrigger> {
        let mut host = self.events.next_event();
        loop {
            let turn = match self.polling.next_turn(self.source.as_ref()) {
                Ok(turn) => turn,
                Err(error) => {
                    self.observer
                        .observe(crate::WriteEvent::LifecycleSourceFailed { error });
                    return self.complete_host_event(host.await);
                }
            };
            let output = tokio::select! {
                event = &mut host => return self.complete_host_event(event),
                output = turn.await_output() => output,
            };
            let Some((poll, notice)) = output else {
                continue;
            };
            if let Err(error) = self.polling.complete_poll(&poll) {
                self.observer
                    .observe(crate::WriteEvent::LifecycleSourceFailed { error });
            }
            let Ok(notice) = notice else {
                return None;
            };
            if let Some(event) = self.observe_notice(notice) {
                return Some(event);
            }
        }
    }

    fn observe_notice(
        &self,
        notice: Result<Option<SpotInstanceAction>, crate::LifecycleError>,
    ) -> Option<LifecycleTrigger> {
        match notice {
            Ok(Some(notice)) => Some(LifecycleTrigger::Shutdown {
                deadline: notice.shutdown_deadline(self.terminate_grace),
            }),
            Ok(None) => None,
            Err(error) => {
                self.observer
                    .observe(crate::WriteEvent::LifecycleSourceFailed { error });
                None
            }
        }
    }

    fn complete_host_event(&self, event: Option<LifecycleTrigger>) -> Option<LifecycleTrigger> {
        match event {
            None | Some(LifecycleTrigger::Shutdown { .. }) => {
                if let Err(error) = self.polling.cancel_poll() {
                    self.observer
                        .observe(crate::WriteEvent::LifecycleSourceFailed { error });
                }
            }
            Some(
                LifecycleTrigger::ResponseCompleted
                | LifecycleTrigger::PeriodicTick
                | LifecycleTrigger::ExplicitFlush,
            ) => {}
        }
        event
    }
}
