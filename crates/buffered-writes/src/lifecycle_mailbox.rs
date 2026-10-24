use std::time::Instant;

use crate::lifecycle::LifecycleTrigger;

/// Bounded pending work: ordinary triggers coalesce, shutdown takes priority.
#[derive(Default)]
pub(crate) struct LifecycleMailbox {
    pending: Option<LifecycleTrigger>,
    terminating: bool,
}

impl LifecycleMailbox {
    pub(crate) fn push(&mut self, trigger: LifecycleTrigger) {
        use LifecycleTrigger::{ExplicitFlush, Shutdown};
        match (self.pending, trigger) {
            (Some(Shutdown { deadline }), Shutdown { deadline: incoming }) => {
                self.pending = Some(Shutdown {
                    deadline: deadline.shorten_to(incoming, Instant::now()),
                });
            }
            (_, Shutdown { .. }) => {
                self.terminating = true;
                self.pending = Some(trigger);
            }
            _ if self.terminating => {}
            (Some(ExplicitFlush), _) => {}
            _ => self.pending = Some(trigger),
        }
    }

    pub(crate) fn take(&mut self) -> Option<LifecycleTrigger> {
        self.pending.take()
    }
}
