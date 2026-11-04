use sha2::{Digest, Sha256};

use crate::{
    engine::JobSystem,
    error::{JobResult, StoreDataError, ValidationError},
    policy::{Cadence, MisfirePolicy, OverlapPolicy},
    schedule::{RecurringSchedule, ScheduleOccurrence},
    store::JobStore,
    time::Timestamp,
};

impl RecurringSchedule {
    pub(crate) fn definition_digest<S: JobStore>(
        &self,
        system: &JobSystem<S>,
    ) -> JobResult<[u8; 32], S::Error> {
        if self.job_template.deduplication.is_some() {
            return Err(ValidationError::InvalidValue {
                field: "configured schedule deduplication",
            }
            .into());
        }
        let occurrence = ScheduleOccurrence {
            schedule_id: self.schedule_id,
            intended_at: Timestamp::ZERO,
            generation: 0,
        };
        let job = self
            .job_template
            .occurrence_job(&occurrence, self.overlap)?;
        let mut hash = Sha256::new();
        hash.update(super::constants::SCHEDULE_BINDING_DOMAIN);
        hash.update(system.enqueue_definition_digest(&job)?);
        let Cadence::CronUtc(cron) = &self.cadence;
        let length =
            u32::try_from(cron.as_str().len()).map_err(|_| StoreDataError::LengthOverflow)?;
        hash.update(length.to_be_bytes());
        hash.update(cron.as_str().as_bytes());
        match self.misfire {
            MisfirePolicy::Skip => hash.update([0]),
            MisfirePolicy::FireOnce => hash.update([1]),
            MisfirePolicy::CatchUp {
                maximum_occurrences,
            } => {
                hash.update([2]);
                hash.update(maximum_occurrences.get().to_be_bytes());
            }
        }
        hash.update([match self.overlap {
            OverlapPolicy::Allow => 0,
            OverlapPolicy::Forbid => 1,
        }]);
        hash.update([u8::from(self.enabled)]);
        Ok(hash.finalize().into())
    }
}
