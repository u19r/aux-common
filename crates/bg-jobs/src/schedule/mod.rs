//! Portable recurring schedules and bounded occurrence materialisation.

mod constants;
mod cursor_codec;
mod evaluation;
mod schedule_control;
mod schedule_materialise;
mod types;

#[cfg(test)]
mod cursor_codec_tests;
#[cfg(test)]
mod schedule_control_tests;
#[cfg(test)]
mod schedule_materialise_tests;

pub(crate) use constants::CATALOG_CURSOR_BYTES;
pub use evaluation::{ScheduleEvaluation, ScheduleOccurrence};
pub use schedule_control::{ScheduleControl, ScheduleControlResult, ScheduleCursor};
pub use schedule_materialise::{
    MaterializedOccurrence, ScheduleMaterialization, ScheduleMaterializationRequest,
};
pub use types::{
    JobTemplate, JobTemplateInput, RecurringSchedule, RecurringScheduleInput,
    ScheduleMaterializationBudget,
};
