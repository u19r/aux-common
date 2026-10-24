//! Wake-watermark mutation and bounded due-index reconciliation.

use std::future::poll_fn;

use bytes::Bytes;

use super::due::{DueScan, next_due};
use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    keys,
    store::{Check, JobStore, Mutation, StoreKey, StoreTransaction},
};

pub(crate) async fn wake_mutation<S: JobStore>(
    system: &JobSystem<S>,
    queue: &crate::ids::QueueName,
    skip: Option<&StoreKey>,
    include: Option<&StoreKey>,
    mutations: &mut Vec<Mutation>,
) -> JobResult<Option<Check>, S::Error> {
    let wake_key = keys::wake_key(system.namespace(), queue)?;
    let (current, due) = join_wake_and_due(system, wake_key.clone(), queue, skip, include).await?;
    let current_time = current
        .as_deref()
        .map(|encoded| keys::decode_timestamp_value(encoded, crate::codec::ValueTag::Wake))
        .transpose()?;
    let next = if due.complete {
        due.next
    } else {
        // A bounded scan cannot prove that a stale watermark is clear. Keep it
        // as a safe lower bound, while still accepting an earlier due item
        // observed before the page limit.
        due.next
            .or(current_time)
            .map(|candidate| current_time.map_or(candidate, |current| current.min(candidate)))
    };
    crate::wake::apply(
        wake_key,
        current,
        crate::wake::WakeUpdate::Reconcile(next),
        mutations,
    )
}

async fn join_wake_and_due<S: JobStore>(
    system: &JobSystem<S>,
    wake_key: StoreKey,
    queue: &crate::ids::QueueName,
    skip: Option<&StoreKey>,
    include: Option<&StoreKey>,
) -> JobResult<(Option<Bytes>, DueScan), S::Error> {
    let wake_future = system.store().get(wake_key);
    let due_future = next_due(system, queue, skip, include);
    let mut wake = std::pin::pin!(wake_future);
    let mut due = std::pin::pin!(due_future);
    let mut wake_result = None;
    let mut due_result = None;
    let (wake_result, due_result) = poll_fn(|context| {
        if wake_result.is_none()
            && let std::task::Poll::Ready(result) = wake.as_mut().poll(context)
        {
            wake_result = Some(result);
        }
        if due_result.is_none()
            && let std::task::Poll::Ready(result) = due.as_mut().poll(context)
        {
            due_result = Some(result);
        }
        if wake_result.is_some() && due_result.is_some() {
            match (wake_result.take(), due_result.take()) {
                (Some(wake), Some(due)) => std::task::Poll::Ready((wake, due)),
                _ => std::task::Poll::Pending,
            }
        } else {
            std::task::Poll::Pending
        }
    })
    .await;
    Ok((wake_result.map_err(JobSystemError::Store)?, due_result?))
}

/// Keeps the latest advisory lower bound after a known conditional conflict.
/// A stale deletion must never erase an enqueue's newer wake. A stale put can
/// only lower the current wake; all business and authority conditions survive.
pub(super) async fn refresh_conflicted_wake<S: JobStore>(
    system: &JobSystem<S>,
    transaction: &StoreTransaction,
) -> JobResult<Option<StoreTransaction>, S::Error> {
    let Some(check) = find_wake_check(system.namespace(), transaction)? else {
        return Ok(None);
    };
    let current = system
        .store()
        .get(check.key().clone())
        .await
        .map_err(JobSystemError::Store)?;
    let unchanged = match check {
        Check::Absent(_) => current.is_none(),
        Check::Value(_, expected) => current.as_ref() == Some(expected),
    };
    if unchanged {
        return Ok(None);
    }
    let next = retain_wake_bound(transaction, check.key(), current.as_deref())?;
    let (mut checks, mut mutations) = retain_authority(transaction, check.key());
    if let Some(next) = next
        && let Some(fresh_check) = crate::wake::apply(
            check.key().clone(),
            current,
            crate::wake::WakeUpdate::Lower(next),
            &mut mutations,
        )?
    {
        checks.push(fresh_check);
    }
    super::checked_transaction(system, checks, mutations).map(Some)
}

fn find_wake_check<'a, E>(
    namespace: &crate::ids::Namespace,
    transaction: &'a StoreTransaction,
) -> JobResult<Option<&'a Check>, E> {
    for check in transaction.checks() {
        if crate::codec::KeyCodec::decode_borrowed(namespace, check.key())?.tag
            == crate::codec::KeyTag::Wake
            && transaction
                .mutations()
                .iter()
                .any(|mutation| mutation.key() == check.key())
        {
            return Ok(Some(check));
        }
    }
    Ok(None)
}

fn retain_wake_bound<E>(
    transaction: &StoreTransaction,
    wake_key: &StoreKey,
    current: Option<&[u8]>,
) -> JobResult<Option<crate::time::Timestamp>, E> {
    let current_time = current
        .map(|encoded| keys::decode_timestamp_value(encoded, crate::codec::ValueTag::Wake))
        .transpose()?;
    match transaction
        .mutations()
        .iter()
        .find(|mutation| mutation.key() == wake_key)
    {
        Some(Mutation::Put(_, encoded)) => {
            keys::decode_timestamp_value(encoded, crate::codec::ValueTag::Wake)
                .map(Some)
                .map_err(Into::into)
        }
        Some(Mutation::Delete(_)) | None => Ok(current_time),
    }
}

fn retain_authority(
    transaction: &StoreTransaction,
    wake_key: &StoreKey,
) -> (Vec<Check>, Vec<Mutation>) {
    let checks = transaction
        .checks()
        .iter()
        .filter(|check| check.key() != wake_key)
        .cloned()
        .collect();
    let mutations = transaction
        .mutations()
        .iter()
        .filter(|mutation| mutation.key() != wake_key)
        .cloned()
        .collect();
    (checks, mutations)
}
