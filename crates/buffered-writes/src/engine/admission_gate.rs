use std::{collections::BTreeMap, future::poll_fn, sync::Mutex, task::Poll};

use super::wake::WakeSet;
use crate::{
    batch::AdmissionFingerprint,
    configuration::OperationId,
    error::{BufferError, WriteError},
};

#[derive(Default)]
pub(super) struct AdmissionGate {
    state: Mutex<AdmissionState>,
    changes: WakeSet,
}

#[derive(Default)]
struct AdmissionState {
    closed: bool,
    active_mutations: usize,
    submissions: usize,
    dispatches: BTreeMap<OperationId, DispatchState>,
}

struct DispatchState {
    active: usize,
    unknown: bool,
    bytes: usize,
    fingerprint: AdmissionFingerprint,
}

pub(super) struct SubmissionPermit<'a> {
    gate: &'a AdmissionGate,
}

pub(super) struct AdmissionLease<'a> {
    gate: &'a AdmissionGate,
    dispatched: Option<OperationId>,
}

impl AdmissionGate {
    pub(super) fn begin(
        &self,
        limit: usize,
    ) -> Result<(SubmissionPermit<'_>, AdmissionLease<'_>), WriteError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.closed {
            return Err(WriteError::Closed);
        }
        if state.submissions >= limit {
            return Err(WriteError::Full);
        }
        state.submissions += 1;
        state.active_mutations += 1;
        Ok((
            SubmissionPermit { gate: self },
            AdmissionLease {
                gate: self,
                dispatched: None,
            },
        ))
    }

    pub(super) fn close(&self) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .closed = true;
        self.changes.wake_all();
    }

    pub(super) fn is_closed(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .closed
    }

    pub(super) fn unknown_ids(&self) -> Vec<OperationId> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .dispatches
            .iter()
            .filter(|(_, dispatch)| dispatch.unknown)
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub(super) fn unresolved_ids(&self) -> Vec<OperationId> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .dispatches
            .keys()
            .cloned()
            .collect()
    }

    pub(super) fn pending_capacity(&self, exclude: Option<&OperationId>) -> (usize, usize) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .dispatches
            .iter()
            .filter(|(id, _)| Some(*id) != exclude)
            .fold((0usize, 0usize), |(items, bytes), (_, dispatch)| {
                (
                    items.saturating_add(1),
                    bytes.saturating_add(dispatch.bytes),
                )
            })
    }

    pub(super) fn confirm(&self, id: &OperationId, fingerprint: AdmissionFingerprint) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(dispatch) = state.dispatches.get_mut(id) {
            if dispatch.fingerprint != fingerprint {
                return;
            }
            dispatch.unknown = false;
            if dispatch.active == 0 {
                state.dispatches.remove(id);
            }
        }
    }

    pub(super) async fn wait_mutations_idle(&self) {
        let waiter = self.changes.subscribe();
        poll_fn(|context| {
            waiter.register(context.waker());
            let state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.active_mutations == 0 {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
}

impl AdmissionLease<'_> {
    pub(super) fn dispatch(
        &mut self,
        id: &OperationId,
        bytes: usize,
        limit: usize,
        fingerprint: AdmissionFingerprint,
    ) -> Result<(), BufferError> {
        let mut state = self
            .gate
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.dispatches.contains_key(id) && state.dispatches.len() >= limit {
            return Err(BufferError::Full);
        }
        let dispatch = state.dispatches.entry(id.clone()).or_insert(DispatchState {
            active: 0,
            unknown: false,
            bytes,
            fingerprint,
        });
        if dispatch.fingerprint != fingerprint {
            return Err(BufferError::DuplicateIdentityConflict {
                operation_id: id.clone(),
            });
        }
        dispatch.active += 1;
        dispatch.bytes = dispatch.bytes.max(bytes);
        self.dispatched = Some(id.clone());
        Ok(())
    }

    pub(super) fn finish(&mut self, confirmed: bool) {
        let Some(id) = self.dispatched.take() else {
            return;
        };
        let mut state = self
            .gate
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(dispatch) = state.dispatches.get_mut(&id) {
            dispatch.active = dispatch.active.saturating_sub(1);
            if confirmed {
                dispatch.unknown = false;
            }
            if dispatch.active == 0 && !dispatch.unknown {
                state.dispatches.remove(&id);
            }
        }
    }

    pub(super) fn was_dispatched(&self) -> bool {
        self.dispatched.is_some()
    }
}

impl Drop for AdmissionLease<'_> {
    fn drop(&mut self) {
        {
            let mut state = self
                .gate
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.active_mutations = state.active_mutations.saturating_sub(1);
            if let Some(id) = &self.dispatched
                && let Some(dispatch) = state.dispatches.get_mut(id)
            {
                dispatch.active = dispatch.active.saturating_sub(1);
                dispatch.unknown = true;
            }
        }
        self.gate.changes.wake_all();
    }
}

impl Drop for SubmissionPermit<'_> {
    fn drop(&mut self) {
        let mut state = self
            .gate
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.submissions = state.submissions.saturating_sub(1);
    }
}
