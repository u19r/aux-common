use std::{
    sync::{Mutex, MutexGuard},
    time::Instant,
};

use tokio::sync::Notify;

use crate::{
    Deadline, FlushReportSummary, LifecycleError, constants::LAMBDA_MAX_INVOCATION_ID_BYTES,
};

struct Binding {
    attempt_id: String,
    session: uuid::Uuid,
    report: Option<FlushReportSummary>,
}

struct Phase {
    event_id: String,
    request_id: String,
    deadline: Deadline,
    binding: Option<Binding>,
    expired: bool,
}

#[derive(Default)]
enum InvocationState {
    #[default]
    Idle,
    Phase(Phase),
    Stopped,
}

pub(super) enum InvocationPermission {
    Active(Deadline),
    Completed(FlushReportSummary),
}

#[derive(Default)]
struct CoordinationState {
    invocation: InvocationState,
    previous_attempt: Option<String>,
    service_active: bool,
}

#[derive(Default)]
pub(super) struct InvocationCoordination {
    state: Mutex<CoordinationState>,
    notify: Notify,
}

impl InvocationCoordination {
    pub(super) fn claim_service(&self) -> Result<ServiceGuard<'_>, LifecycleError> {
        let mut state = self.lock()?;
        if matches!(state.invocation, InvocationState::Stopped) {
            return Err(LifecycleError::ShutdownFailed {
                reason: "Lambda extension is already shut down",
            });
        }
        if state.service_active {
            return Err(LifecycleError::DriverAlreadyStarted);
        }
        state.service_active = true;
        Ok(ServiceGuard { coordination: self })
    }

    pub(super) fn begin(
        &self,
        event_id: &str,
        request_id: &str,
        deadline: Deadline,
    ) -> Result<(), LifecycleError> {
        validate_id(event_id)?;
        validate_id(request_id)?;
        if Instant::now()
            .checked_add(deadline.remaining_at(Instant::now()))
            .is_none()
        {
            return Err(LifecycleError::InvalidConfiguration {
                reason: "Lambda invocation requires a finite monotonic deadline",
            });
        }
        let mut state = self.lock()?;
        match &state.invocation {
            InvocationState::Stopped => return Err(invalid_invocation()),
            InvocationState::Phase(phase) => {
                if phase.event_id == event_id || !phase.is_terminal() {
                    return Err(invalid_invocation());
                }
                if let Some(binding) = &phase.binding {
                    state.previous_attempt = Some(binding.attempt_id.clone());
                }
            }
            InvocationState::Idle => {}
        }
        state.invocation = InvocationState::Phase(Phase {
            event_id: event_id.to_owned(),
            request_id: request_id.to_owned(),
            deadline,
            binding: None,
            expired: false,
        });
        self.notify.notify_waiters();
        Ok(())
    }

    pub(super) async fn bind(
        &self,
        request_id: &str,
        attempt_id: &str,
    ) -> Result<uuid::Uuid, LifecycleError> {
        validate_id(request_id)?;
        validate_id(attempt_id)?;
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(session) = self.try_bind(request_id, attempt_id)? {
                return Ok(session);
            }
            notified.await;
        }
    }

    fn try_bind(
        &self,
        request_id: &str,
        attempt_id: &str,
    ) -> Result<Option<uuid::Uuid>, LifecycleError> {
        let mut state = self.lock()?;
        let previous = state.previous_attempt.as_deref() == Some(attempt_id);
        match &mut state.invocation {
            InvocationState::Stopped => Err(invalid_invocation()),
            InvocationState::Idle => Ok(None),
            InvocationState::Phase(phase) => phase.bind(request_id, attempt_id, previous),
        }
    }

    pub(super) fn permission(
        &self,
        session: &uuid::Uuid,
    ) -> Result<InvocationPermission, LifecycleError> {
        match &self.lock()?.invocation {
            InvocationState::Phase(phase) => phase.permission(session),
            InvocationState::Idle | InvocationState::Stopped => Err(invalid_invocation()),
        }
    }

    pub(super) fn complete(
        &self,
        session: &uuid::Uuid,
        report: FlushReportSummary,
    ) -> Result<(), LifecycleError> {
        let mut state = self.lock()?;
        let InvocationState::Phase(phase) = &mut state.invocation else {
            return Err(invalid_invocation());
        };
        phase.permission(session)?;
        let binding = phase.binding.as_mut().ok_or_else(invalid_invocation)?;
        binding.report = Some(report);
        self.notify.notify_waiters();
        Ok(())
    }

    pub(super) async fn completed(
        &self,
        event_id: &str,
    ) -> Result<FlushReportSummary, LifecycleError> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let deadline = {
                let state = self.lock()?;
                let InvocationState::Phase(phase) = &state.invocation else {
                    return Err(invalid_invocation());
                };
                if phase.event_id != event_id || phase.expired {
                    return Err(invalid_invocation());
                }
                if let Some(report) = phase.binding.as_ref().and_then(|binding| binding.report) {
                    return Ok(report);
                }
                phase.deadline
            };
            if deadline.is_expired_at(Instant::now())
                || tokio::time::timeout(deadline.remaining_at(Instant::now()), notified)
                    .await
                    .is_err()
            {
                self.expire(event_id)?;
                return Err(LifecycleError::DeadlineExceeded);
            }
        }
    }

    fn expire(&self, event_id: &str) -> Result<(), LifecycleError> {
        let mut state = self.lock()?;
        if let InvocationState::Phase(phase) = &mut state.invocation
            && phase.event_id == event_id
            && !phase.is_terminal()
        {
            phase.expired = true;
            self.notify.notify_waiters();
        }
        Ok(())
    }

    pub(super) fn stop(&self) -> Result<(), LifecycleError> {
        self.lock()?.invocation = InvocationState::Stopped;
        self.notify.notify_waiters();
        Ok(())
    }

    pub(super) async fn stopped(&self) -> Result<(), LifecycleError> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if matches!(&self.lock()?.invocation, InvocationState::Stopped) {
                return Ok(());
            }
            notified.await;
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, CoordinationState>, LifecycleError> {
        self.state
            .lock()
            .map_err(|_| LifecycleError::IpcUnavailable {
                reason: "Lambda invocation state is unavailable",
            })
    }
}

impl Phase {
    fn is_terminal(&self) -> bool {
        self.expired
            || self
                .binding
                .as_ref()
                .is_some_and(|binding| binding.report.is_some())
    }

    fn bind(
        &mut self,
        request_id: &str,
        attempt_id: &str,
        previous: bool,
    ) -> Result<Option<uuid::Uuid>, LifecycleError> {
        if let Some(binding) = &self.binding
            && binding.attempt_id == attempt_id
        {
            if self.request_id != request_id || self.expired {
                return Err(invalid_invocation());
            }
            return Ok(Some(binding.session));
        }
        if previous {
            return Err(invalid_invocation());
        }
        if self.is_terminal() {
            return Ok(None);
        }
        self.issue_session(request_id, attempt_id)
    }

    fn issue_session(
        &mut self,
        request_id: &str,
        attempt_id: &str,
    ) -> Result<Option<uuid::Uuid>, LifecycleError> {
        if self.request_id != request_id
            || self.binding.is_some()
            || self.deadline.is_expired_at(Instant::now())
        {
            return Err(invalid_invocation());
        }
        let session = uuid::Uuid::now_v7();
        self.binding = Some(Binding {
            attempt_id: attempt_id.to_owned(),
            session,
            report: None,
        });
        Ok(Some(session))
    }

    fn permission(&self, session: &uuid::Uuid) -> Result<InvocationPermission, LifecycleError> {
        let binding = self.binding.as_ref().ok_or_else(invalid_invocation)?;
        if self.expired || &binding.session != session {
            return Err(invalid_invocation());
        }
        if let Some(report) = binding.report {
            return Ok(InvocationPermission::Completed(report));
        }
        if self.deadline.is_expired_at(Instant::now()) {
            return Err(invalid_invocation());
        }
        Ok(InvocationPermission::Active(self.deadline))
    }
}

fn validate_id(id: &str) -> Result<(), LifecycleError> {
    if id.is_empty()
        || id.len() > LAMBDA_MAX_INVOCATION_ID_BYTES
        || !id.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(invalid_invocation());
    }
    Ok(())
}

fn invalid_invocation() -> LifecycleError {
    LifecycleError::IpcProtocolViolation {
        reason: "Lambda invocation identity or lifecycle state is invalid",
    }
}

pub(super) struct ServiceGuard<'a> {
    coordination: &'a InvocationCoordination,
}
impl Drop for ServiceGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.coordination.state.lock() {
            state.service_active = false;
        }
    }
}
