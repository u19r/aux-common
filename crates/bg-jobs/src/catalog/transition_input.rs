use super::{CatalogManifest, ledger::CatalogLedger, schedule::ScheduleAdvance};
use crate::{
    codec::{KeyCodec, KeyTag, decode_job_record, job_definition_digest},
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    ids::JobId,
    lifecycle::TerminalEffect,
    model::JobDefinition,
    store::{Check, JobStore, Mutation, StoreTransaction},
};

pub(super) enum CatalogTransition {
    Terminal(Box<TerminalEffect>),
    Schedule(ScheduleAdvance),
    Ensure {
        job_id: JobId,
        digest: [u8; 32],
        manifest: CatalogManifest,
    },
    Configure(CatalogManifest),
}

impl CatalogTransition {
    pub(super) fn from_input<S: JobStore>(
        system: &JobSystem<S>,
        input: &StoreTransaction,
        catalog: &Check,
    ) -> JobResult<Self, S::Error> {
        if let Some(effect) = system.terminal_effect(input)? {
            return Ok(Self::Terminal(Box::new(effect)));
        }
        if let Some(advance) = ScheduleAdvance::from_input(input, catalog)? {
            return Ok(Self::Schedule(advance));
        }
        for check in input.checks() {
            if KeyCodec::decode_borrowed(system.namespace(), check.key())?.tag == KeyTag::Job {
                return Self::from_job_input(system, input, catalog, check);
            }
        }
        let next = input
            .mutations()
            .iter()
            .find_map(|mutation| match mutation {
                Mutation::Put(key, value) if key == catalog.key() => Some(value),
                Mutation::Put(_, _) | Mutation::Delete(_) => None,
            })
            .ok_or(JobSystemError::PayloadCorrupt)?;
        Ok(Self::Configure(CatalogLedger::decode(next)?.manifest))
    }

    fn from_job_input<S: JobStore>(
        system: &JobSystem<S>,
        input: &StoreTransaction,
        catalog: &Check,
        job: &Check,
    ) -> JobResult<Self, S::Error> {
        let mutation = input
            .mutations()
            .iter()
            .find(|mutation| mutation.key() == job.key());
        let encoded = match (job, mutation) {
            (Check::Absent(_), Some(Mutation::Put(_, encoded))) => encoded,
            (Check::Value(_, encoded), None) => encoded,
            _ => return Err(JobSystemError::PayloadCorrupt),
        };
        let record = decode_job_record(encoded)?;
        crate::lifecycle::validate_persisted_identity(system, record.job_id, &record)?;
        if KeyCodec::job(system.namespace(), &record.job_id)? != *job.key() {
            return Err(JobSystemError::PayloadCorrupt);
        }
        let digest = job_definition_digest(&JobDefinition::from(&record))?;
        let Check::Value(_, expected) = catalog else {
            return Err(JobSystemError::PayloadCorrupt);
        };
        Ok(Self::Ensure {
            job_id: record.job_id,
            digest,
            manifest: CatalogLedger::decode(expected)?.manifest,
        })
    }
}
