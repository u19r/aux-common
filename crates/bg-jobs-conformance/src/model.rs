use std::{
    collections::BTreeMap,
    num::{NonZeroU32, NonZeroUsize},
};

use bg_jobs::store::{
    Check, CommitOperationId, CommitOutcome, Mutation, RangeDirection, RangeEntry, RangePage,
    RangeRequest, StoreCapabilities, StoreContractError, StoreKey, StoreTransaction,
};
use bytes::Bytes;

/// Deterministic test/conformance reference model for ordered checked key/value
/// semantics.
///
/// The model is intentionally independent from `FakeStore` internals. It is
/// useful to compare a consumer's production adapter with the public contract
/// and to construct bounded repair fixtures; it is not a persistence adapter.
#[derive(Clone, Debug)]
pub struct StoreModel {
    capabilities: StoreCapabilities,
    entries: BTreeMap<StoreKey, Bytes>,
    commits: BTreeMap<CommitOperationId, ModelCommit>,
}

#[derive(Clone, Debug)]
struct ModelCommit {
    transaction: StoreTransaction,
    outcome: CommitOutcome,
}

impl StoreModel {
    pub fn new(capabilities: StoreCapabilities) -> Self {
        Self {
            capabilities,
            entries: BTreeMap::new(),
            commits: BTreeMap::new(),
        }
    }

    pub fn capabilities(&self) -> StoreCapabilities {
        self.capabilities
    }

    pub fn get(&self, key: &StoreKey) -> Option<&Bytes> {
        self.entries.get(key)
    }

    pub fn put(&mut self, key: StoreKey, value: Bytes) -> Result<(), StoreModelError> {
        if key.as_bytes().len() > self.capabilities.max_key_bytes().get() {
            return Err(StoreModelError::Capability("key bytes"));
        }
        if value.len() > self.capabilities.max_value_bytes().get() {
            return Err(StoreModelError::Capability("value bytes"));
        }
        self.entries.insert(key, value);
        Ok(())
    }

    pub fn snapshot(&self) -> Vec<(StoreKey, Bytes)> {
        self.entries
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    pub fn read_range(&self, request: &RangeRequest) -> Result<RangePage, StoreModelError> {
        self.capabilities.validate_range(request)?;
        let mut candidates: Vec<_> = self
            .entries
            .iter()
            .filter(|(key, _)| in_bounds(key, request) && after_cursor(key, request))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        if request.direction() == RangeDirection::Reverse {
            candidates.reverse();
        }
        let mut entries = Vec::new();
        let mut total_bytes = 0usize;
        for (key, value) in candidates.iter().take(request.item_limit().get() as usize) {
            let entry_bytes = key.as_bytes().len().saturating_add(value.len());
            if entry_bytes > request.byte_limit().get() && entries.is_empty() {
                return Err(StoreModelError::RangeItemTooLarge);
            }
            if total_bytes.saturating_add(entry_bytes) > request.byte_limit().get() {
                break;
            }
            total_bytes = total_bytes.saturating_add(entry_bytes);
            entries.push(RangeEntry {
                key: key.clone(),
                value: value.clone(),
            });
        }
        let continuation = (entries.len() < candidates.len())
            .then(|| entries.last().map(|entry| entry.key.clone()))
            .flatten();
        RangePage::new(entries, continuation).map_err(StoreModelError::Contract)
    }

    pub fn commit(
        &mut self,
        transaction: &StoreTransaction,
    ) -> Result<CommitOutcome, StoreModelError> {
        self.capabilities.validate_transaction(transaction)?;
        if let Some(recorded) = self.commits.get(&transaction.operation_id()) {
            return if recorded.transaction == *transaction {
                Ok(recorded.outcome)
            } else {
                Err(StoreModelError::CommitOperationReused)
            };
        }
        if !checks_match(&self.entries, transaction.checks()) {
            self.commits.insert(
                transaction.operation_id(),
                ModelCommit {
                    transaction: transaction.clone(),
                    outcome: CommitOutcome::Conflict,
                },
            );
            return Ok(CommitOutcome::Conflict);
        }
        let mut next = self.entries.clone();
        for mutation in transaction.mutations() {
            match mutation {
                Mutation::Put(key, value) => {
                    next.insert(key.clone(), value.clone());
                }
                Mutation::Delete(key) => {
                    next.remove(key);
                }
            }
        }
        self.entries = next;
        self.commits.insert(
            transaction.operation_id(),
            ModelCommit {
                transaction: transaction.clone(),
                outcome: CommitOutcome::Committed,
            },
        );
        Ok(CommitOutcome::Committed)
    }

    /// Plans only bounded, fail-closed route repair. A missing route is
    /// reported for the caller to rebuild from its authoritative record; this
    /// model never invents a persisted route value.
    pub fn repair_plan(&self, entries: &[RepairEntry], budget: RepairBudget) -> RepairPlan {
        let mut plan = RepairPlan::default();
        for entry in entries {
            if !self.inspect_repair_entry(entry, budget, &mut plan) {
                break;
            }
        }
        plan
    }

    fn inspect_repair_entry(
        &self,
        entry: &RepairEntry,
        budget: RepairBudget,
        plan: &mut RepairPlan,
    ) -> bool {
        if entry.unknown_version {
            return plan.inspect_if(
                true,
                RepairAction {
                    key: entry.authoritative.clone(),
                    reason: RepairReason::UnknownVersion,
                },
                budget,
            );
        }
        let authoritative_exists = self.entries.contains_key(&entry.authoritative);
        let (routes, reason, action_when_present) = if authoritative_exists {
            (&entry.required_routes, RepairReason::MissingIndex, false)
        } else {
            (&entry.routes, RepairReason::DanglingIndex, true)
        };
        for key in routes {
            if !plan.inspect_if(
                self.entries.contains_key(key) == action_when_present,
                RepairAction {
                    key: key.clone(),
                    reason,
                },
                budget,
            ) {
                return false;
            }
        }
        true
    }
}

impl RepairPlan {
    fn inspect_if(&mut self, actionable: bool, action: RepairAction, budget: RepairBudget) -> bool {
        let cost = action.key.as_bytes().len();
        if self.inspected >= budget.max_items.get()
            || self.bytes.saturating_add(cost) > budget.max_bytes.get()
        {
            self.truncated = true;
            return false;
        }
        self.inspected += 1;
        self.bytes = self.bytes.saturating_add(cost);
        if actionable {
            self.actions.push(action);
        }
        true
    }
}

fn checks_match(entries: &BTreeMap<StoreKey, Bytes>, checks: &[Check]) -> bool {
    checks.iter().all(|check| match check {
        Check::Absent(key) => !entries.contains_key(key),
        Check::Value(key, expected) => entries.get(key) == Some(expected),
    })
}

fn in_bounds(key: &StoreKey, request: &RangeRequest) -> bool {
    request.start().is_none_or(|start| key >= start) && request.end().is_none_or(|end| key < end)
}

fn after_cursor(key: &StoreKey, request: &RangeRequest) -> bool {
    request
        .continuation()
        .is_none_or(|cursor| match request.direction() {
            RangeDirection::Forward => key > cursor,
            RangeDirection::Reverse => key < cursor,
        })
}

/// Errors produced while evaluating the reference model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreModelError {
    Contract(StoreContractError),
    Capability(&'static str),
    RangeItemTooLarge,
    CommitOperationReused,
}

impl std::fmt::Display for StoreModelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Contract(error) => error.fmt(formatter),
            Self::Capability(field) => write!(formatter, "model capability exceeded: {field}"),
            Self::RangeItemTooLarge => formatter.write_str("model range item exceeds limit"),
            Self::CommitOperationReused => {
                formatter.write_str("commit operation ID was reused with different content")
            }
        }
    }
}

impl std::error::Error for StoreModelError {}

impl From<StoreContractError> for StoreModelError {
    fn from(error: StoreContractError) -> Self {
        Self::Contract(error)
    }
}

/// The bounded route inventory inspected by [`StoreModel::repair_plan`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairEntry {
    pub authoritative: StoreKey,
    pub routes: Vec<StoreKey>,
    pub required_routes: Vec<StoreKey>,
    pub unknown_version: bool,
}

/// Maximum route records and key bytes to inspect in one repair pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepairBudget {
    pub max_items: NonZeroU32,
    pub max_bytes: NonZeroUsize,
}

/// Why a route needs caller-owned repair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RepairReason {
    DanglingIndex,
    MissingIndex,
    UnknownVersion,
}

/// One fail-closed route repair action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairAction {
    pub key: StoreKey,
    pub reason: RepairReason,
}

/// Bounded repair output. Unknown versions are reported, never decoded or
/// deleted; missing routes remain the caller's responsibility to rebuild.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepairPlan {
    pub actions: Vec<RepairAction>,
    pub inspected: u32,
    pub bytes: usize,
    pub truncated: bool,
}
