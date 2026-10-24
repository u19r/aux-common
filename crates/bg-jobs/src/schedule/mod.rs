//! Portable recurring schedules and bounded occurrence materialisation.

mod constants;
mod evaluation;
mod schedule_control;
mod schedule_materialise;
mod types;

#[cfg(test)]
mod schedule_control_tests;
#[cfg(test)]
mod schedule_materialise_tests;

pub use evaluation::{ScheduleEvaluation, ScheduleOccurrence};
pub use schedule_control::ScheduleCursor;
#[cfg(any(test, feature = "test-support"))]
pub use schedule_control::{ScheduleControl, ScheduleControlResult};
#[cfg(feature = "test-support")]
pub use schedule_materialise::MaterializedOccurrence;
pub use schedule_materialise::ScheduleMaterialization;
pub(crate) use schedule_materialise::materialize;
#[cfg(any(test, feature = "test-support"))]
pub use types::{JobTemplate, JobTemplateInput, RecurringScheduleInput};
pub use types::{RecurringSchedule, ScheduleMaterializationBudget};
