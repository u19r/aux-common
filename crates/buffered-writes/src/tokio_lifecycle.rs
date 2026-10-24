use futures_util::future::BoxFuture;

use crate::{
    configuration::Deadline,
    lifecycle::{
        ChannelLifecycle, Lifecycle, LifecycleController, LifecycleEvents, LifecycleTrigger,
    },
};

/// Persistent-process lifecycle adapter (ECS, Docker, Kubernetes, EC2).
///
/// The host forwards termination with its actual remaining deadline. This
/// adapter does not install a competing process signal handler.
#[derive(Clone, Debug)]
pub struct TokioLifecycle {
    controller: LifecycleController,
    events: ChannelLifecycle,
}

impl Default for TokioLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl TokioLifecycle {
    #[must_use]
    pub fn new() -> Self {
        let (controller, events) = Lifecycle::channel();
        Self { controller, events }
    }

    pub fn notify_response_completed(&self) {
        self.controller.send(LifecycleTrigger::ResponseCompleted);
    }

    pub fn notify_explicit_flush(&self) {
        self.controller.send(LifecycleTrigger::ExplicitFlush);
    }

    pub fn notify_shutdown(&self, deadline: impl Into<Deadline>) {
        self.controller.send(LifecycleTrigger::Shutdown {
            deadline: deadline.into(),
        });
    }

    pub fn close(&self) {
        self.controller.close();
    }
}

impl LifecycleEvents for TokioLifecycle {
    fn next_event(&self) -> BoxFuture<'static, Option<LifecycleTrigger>> {
        self.events.next_event()
    }

    fn can_flush_between_responses(&self) -> bool {
        true
    }
}
