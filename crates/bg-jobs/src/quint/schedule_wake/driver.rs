use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    time::Duration,
};

use bytes::Bytes;
use quint_connect::{Driver, Result, State, Step};
use serde::Deserialize;

use super::types::*;
use crate::{
    ActivePulseRequest, Cadence, CronExpression, DriveReport, DriveRequest, DriveRequestInput,
    FairnessClass, FakeStore, JobKind, JobSystem, JobTemplate, JobTemplateInput, MisfirePolicy,
    MonotonicDeadline, Namespace, OverlapPolicy, OwnerId, QueueSelection, RecurringSchedule,
    RecurringScheduleInput, ScheduleControl, ScheduleCursor, ScheduleId, Timestamp, WakeHint,
    WakeWatermark,
};

pub(crate) struct ScheduleWakeDriver {
    system: JobSystem<FakeStore>,
    schedule: RecurringSchedule,
    cursor: ScheduleCursor,
    now: Timestamp,
    wake: WakeWatermark,
    wake_pending: bool,
    wake_token: u64,
    occurrences: BTreeMap<Occurrence, OccurrenceEvidence>,
    pending_selection: Option<MaterializeSelection>,
    terminal_records: BTreeMap<Occurrence, crate::model::JobRecordV1>,
    last_report: Option<DriveReport>,
    last_drive: DriveEvidence,
    active_pulses: u64,
    pulse_actions: u64,
    pulse_exited: bool,
    progress_counter: u64,
    last_outcome: ScheduleOutcome,
    pub(super) projection: StateProjection,
}

#[derive(Clone, Copy, Debug)]
struct OccurrenceEvidence {
    actual: crate::ScheduleOccurrence,
    previous_identity: i64,
    emitted: bool,
    completed: bool,
}

#[derive(Clone, Copy, Debug)]
struct MaterializeSelection {
    occurrence: Occurrence,
    reader: Node,
    revision: u64,
}

#[derive(Clone, Copy, Debug)]
struct DriveEvidence {
    result: DriveResult,
    branch: DriveKernelBranch,
    work: DriveWork,
    stop: DriveStopReason,
    progress_before: u64,
    progress_after: u64,
}

impl State<ScheduleWakeDriver> for StateProjection {
    fn from_driver(driver: &ScheduleWakeDriver) -> Result<Self> {
        Ok(driver.projection.clone())
    }
}

impl Default for ScheduleWakeDriver {
    fn default() -> Self {
        Self::try_default().unwrap_or_else(|error| panic!("schedule connector setup: {error}"))
    }
}

impl ScheduleWakeDriver {
    pub(super) fn try_default() -> Result<Self> {
        let schedule = schedule_definition()?;
        let cursor = ScheduleCursor::new(Some(Timestamp::from_millis(5 * 60 * 1_000)), true);
        let system = JobSystem::new(
            FakeStore::distributed(),
            crate::JobCatalog::from_registry(crate::test_helper::registry(
                crate::FairnessPolicy::low_volume(),
            )),
            Namespace::try_new(b"jobs")?,
            OwnerId::from([43; 16]),
            crate::test_helper::wake_scheduler(),
        );
        Ok(Self {
            system,
            schedule,
            cursor,
            now: Timestamp::ZERO,
            wake: WakeWatermark::new(),
            wake_pending: false,
            wake_token: 0,
            occurrences: BTreeMap::new(),
            pending_selection: None,
            terminal_records: BTreeMap::new(),
            last_report: None,
            last_drive: DriveEvidence {
                result: DriveResult::DriveNoWork,
                branch: DriveKernelBranch::KernelNoWork,
                work: DriveWork::DriveNoImmediateWork,
                stop: DriveStopReason::StopNoWork,
                progress_before: 0,
                progress_after: 0,
            },
            active_pulses: 0,
            pulse_actions: 0,
            pulse_exited: false,
            progress_counter: 0,
            last_outcome: ScheduleOutcome::Initialised,
            projection: initial_projection(),
        })
    }

    /// `mbtDispatchNondet` wraps the typed command in `mbtStep`.  Quint
    /// Connect reports that inner action without a command pick, so recover
    /// only the command tag from the serialized next state and derive its
    /// inputs from the actual projection.  Direct `mbtStep` traces still carry
    /// the typed command pick and take the deserialization path below.
    fn command_from_step(&self, step: &Step) -> Result<Command> {
        if let Some(value) = step.nondet_picks.get("command") {
            return Ok(Command::deserialize(value.clone())?);
        }
        let rendered = step.to_string();
        let line = rendered
            .lines()
            .find(|line| line.contains("+ lastCommand: "))
            .ok_or_else(|| std::io::Error::other("schedule step has no serialized command"))?;
        let name = line
            .split_once("+ lastCommand: ")
            .and_then(|(_, value)| value.split(['(', '{']).next())
            .map(str::trim)
            .ok_or_else(|| std::io::Error::other("schedule command tag is missing"))?;
        let state = &self.projection.state;
        match name {
            "ScheduleAdvance" => Ok(Command::ScheduleAdvance { amount: 5 }),
            "ScheduleEvaluate" => Ok(Command::ScheduleEvaluate {
                mode: state.misfire,
                catch_up_limit: state.catch_up_limit,
                now: state.now,
                next_due: state.next_due,
            }),
            "ScheduleSelectMaterialize" => Ok(Command::ScheduleSelectMaterialize {
                occurrence: state.materialize_occurrence,
                reader: state.materialize_reader,
                revision: state.revision,
            }),
            "ScheduleMaterialize" => Ok(Command::ScheduleMaterialize {
                occurrence: state.materialize_occurrence,
                contender: state.materialize_reader,
                revision: state.materialize_revision,
            }),
            "ScheduleComplete" => Ok(Command::ScheduleComplete {
                occurrence: state.materialize_occurrence,
                job: state
                    .occurrence_job
                    .get(&state.materialize_occurrence)
                    .copied()
                    .unwrap_or(JobId::JobA),
                revision: state
                    .job_revision
                    .get(
                        state
                            .occurrence_job
                            .get(&state.materialize_occurrence)
                            .unwrap_or(&JobId::JobA),
                    )
                    .copied()
                    .unwrap_or_default(),
            }),
            "ScheduleWake" => Ok(Command::ScheduleWake {
                revision: state.wake_revision,
                token: state.wake_token,
                lose: false,
                duplicate: false,
            }),
            "SchedulePolicy" => Ok(Command::SchedulePolicy {
                enabled: state.enabled,
                paused: state.paused,
                overlap: state.overlap,
            }),
            "ScheduleCron" => Ok(Command::ScheduleCron {
                form: CronForm::PortableFiveField,
            }),
            "SchedulePulse" => Ok(Command::SchedulePulse {
                active: state.active_pulses,
                actions: state.pulse_actions,
            }),
            "ScheduleDrive" => Ok(Command::ScheduleDrive {
                node: Node::NodeA,
                active: state.active_pulses,
                actions: state.pulse_actions,
            }),
            other => {
                Err(std::io::Error::other(format!("unknown schedule command tag: {other}")).into())
            }
        }
    }

    fn apply_command(&mut self, command: Command) -> Result<()> {
        match command {
            Command::ScheduleAdvance { amount } => self.advance(amount),
            Command::ScheduleEvaluate {
                mode,
                catch_up_limit,
                now,
                next_due,
            } => self.evaluate(mode, catch_up_limit, now, next_due),
            Command::ScheduleSelectMaterialize {
                occurrence,
                reader,
                revision,
            } => self.select_materialize(occurrence, reader, revision),
            Command::ScheduleMaterialize {
                occurrence,
                contender,
                revision,
            } => self.materialize(occurrence, contender, revision),
            Command::ScheduleComplete {
                occurrence,
                job,
                revision,
            } => self.complete(occurrence, job, revision),
            Command::ScheduleWake {
                revision,
                token,
                lose,
                duplicate,
            } => self.wake(revision, token, lose, duplicate),
            Command::SchedulePolicy {
                enabled,
                paused,
                overlap,
            } => self.policy(enabled, paused, overlap),
            Command::ScheduleCron { form } => self.cron(form),
            Command::SchedulePulse { active, actions } => self.pulse(active, actions),
            Command::ScheduleDrive {
                node,
                active,
                actions,
            } => self.drive(node, active, actions),
        }
    }

    fn advance(&mut self, amount: i64) -> Result<()> {
        let millis = amount
            .checked_mul(60_000)
            .ok_or_else(|| std::io::Error::other("schedule time overflow"))?;
        self.now = Timestamp::from_millis(
            self.now
                .as_millis()
                .checked_add(millis)
                .ok_or_else(|| std::io::Error::other("schedule time overflow"))?,
        );
        self.last_outcome = ScheduleOutcome::TimeAdvanced;
        self.record(
            Command::ScheduleAdvance { amount },
            ResultClass::AppliedClass,
            ScheduleOutcome::TimeAdvanced,
            Occurrence::Occ1,
        )
    }

    fn evaluate(
        &mut self,
        mode: Misfire,
        catch_up_limit: i64,
        expected_now: i64,
        expected_next_due: i64,
    ) -> Result<()> {
        if expected_now != ticks(Some(self.now))
            || expected_next_due != ticks(self.cursor.next_due())
        {
            return Err(std::io::Error::other("schedule evaluation prestate drift").into());
        }
        let maximum_occurrences = NonZeroU16::new(
            u16::try_from(catch_up_limit)
                .map_err(|_| std::io::Error::other("catch-up limit outside u16"))?,
        )
        .ok_or_else(|| std::io::Error::other("catch-up limit is zero"))?;
        let misfire = match mode {
            Misfire::Skip => MisfirePolicy::Skip,
            Misfire::FireOnce => MisfirePolicy::FireOnce,
            Misfire::CatchUp => MisfirePolicy::CatchUp {
                maximum_occurrences,
            },
        };
        self.schedule = schedule_definition_with_options(
            self.schedule.cadence.clone(),
            misfire,
            self.schedule.overlap,
            self.schedule.enabled,
        )?;
        let evaluation = self.schedule.evaluate(&self.cursor, self.now)?;
        self.cursor = evaluation.cursor.clone();
        let selected = self.record_evaluation(&evaluation)?;
        self.pending_selection = None;
        self.last_outcome = if selected == 0 {
            ScheduleOutcome::NotDue
        } else {
            match mode {
                Misfire::Skip => ScheduleOutcome::Skipped,
                Misfire::FireOnce => ScheduleOutcome::FireOnceEmitted,
                Misfire::CatchUp => ScheduleOutcome::CatchUpEmitted,
            }
        };
        self.record(
            Command::ScheduleEvaluate {
                mode,
                catch_up_limit,
                now: expected_now,
                next_due: expected_next_due,
            },
            ResultClass::AppliedClass,
            self.last_outcome,
            Occurrence::Occ1,
        )
    }

    fn record_evaluation(&mut self, evaluation: &crate::ScheduleEvaluation) -> Result<usize> {
        let slots = available_slots(&self.occurrences).collect::<Vec<_>>();
        let selected = evaluation.occurrences.len();
        for (actual, slot) in evaluation.occurrences.iter().zip(slots) {
            let previous_identity = self
                .occurrences
                .get(&slot)
                .map_or(0, |evidence| ticks(Some(evidence.actual.intended_at)));
            self.occurrences.insert(
                slot,
                OccurrenceEvidence {
                    actual: *actual,
                    previous_identity,
                    emitted: true,
                    completed: false,
                },
            );
        }
        if selected > 0 {
            self.progress_counter = self
                .progress_counter
                .saturating_add(u64::try_from(selected).unwrap_or(u64::MAX));
            self.wake_pending = !matches!(self.schedule.misfire, MisfirePolicy::Skip);
            self.wake = WakeWatermark::from_hint(evaluation.wake);
        }
        Ok(selected)
    }

    fn select_materialize(
        &mut self,
        occurrence: Occurrence,
        reader: Node,
        revision: i64,
    ) -> Result<()> {
        let expected_revision = u64::try_from(revision)
            .map_err(|_| std::io::Error::other("materialization revision is negative"))?;
        if expected_revision != self.cursor.revision()
            || !self
                .occurrences
                .get(&occurrence)
                .is_some_and(|evidence| evidence.emitted && !evidence.completed)
        {
            return self.record(
                Command::ScheduleSelectMaterialize {
                    occurrence,
                    reader,
                    revision,
                },
                ResultClass::ConflictClass,
                ScheduleOutcome::MaterializeConflict,
                occurrence,
            );
        }
        self.pending_selection = Some(MaterializeSelection {
            occurrence,
            reader,
            revision: expected_revision,
        });
        self.record(
            Command::ScheduleSelectMaterialize {
                occurrence,
                reader,
                revision,
            },
            ResultClass::AppliedClass,
            ScheduleOutcome::MaterializeSelected,
            occurrence,
        )
    }

    fn materialize(
        &mut self,
        occurrence: Occurrence,
        contender: Node,
        revision: i64,
    ) -> Result<()> {
        let expected_revision = u64::try_from(revision).unwrap_or(0);
        let command = Command::ScheduleMaterialize {
            occurrence,
            contender,
            revision,
        };
        let Some(selection) = self.pending_selection else {
            return self.record(
                command,
                ResultClass::ConflictClass,
                ScheduleOutcome::MaterializeConflict,
                occurrence,
            );
        };
        let Some(evidence) = self.occurrences.get(&occurrence).copied() else {
            return self.record(
                command,
                ResultClass::ConflictClass,
                ScheduleOutcome::MaterializeConflict,
                occurrence,
            );
        };
        if selection.occurrence != occurrence
            || selection.revision != expected_revision
            || selection.reader != contender
            || expected_revision != self.cursor.revision()
            || !evidence.emitted
            || evidence.completed
        {
            self.pending_selection = None;
            return self.record(
                command,
                ResultClass::ConflictClass,
                ScheduleOutcome::MaterializeConflict,
                occurrence,
            );
        }
        let mut target_cursor = ScheduleCursor::new(Some(evidence.actual.intended_at), true);
        let target_schedule = schedule_definition_with_options(
            self.schedule.cadence.clone(),
            MisfirePolicy::FireOnce,
            self.schedule.overlap,
            true,
        )?;
        let materialization = crate::test_helper::block_on(self.system.materialize_schedule(
            &target_schedule,
            &target_cursor,
            evidence.actual.intended_at,
        ));
        match materialization {
            Ok(materialization) if materialization.occurrences.len() == 1 => {
                target_cursor = materialization.cursor;
                let actual = materialization
                    .occurrences
                    .first()
                    .map(|entry| entry.occurrence)
                    .ok_or_else(|| std::io::Error::other("missing materialized occurrence"))?;
                if actual != evidence.actual {
                    return Err(std::io::Error::other(
                        "materialization changed deterministic occurrence identity",
                    )
                    .into());
                }
                self.pending_selection = None;
                self.progress_counter = self.progress_counter.saturating_add(1);
                // The returned cursor is caller-owned evidence. The schedule
                // cursor itself remains the authority for the next evaluation.
                let _ = target_cursor;
                self.wake_pending = true;
                self.wake_token = self.wake_token.saturating_add(1);
                self.record(
                    command,
                    ResultClass::AppliedClass,
                    ScheduleOutcome::Materialized,
                    occurrence,
                )
            }
            Ok(_) | Err(_) => {
                self.pending_selection = None;
                self.record(
                    command,
                    ResultClass::ConflictClass,
                    ScheduleOutcome::MaterializeConflict,
                    occurrence,
                )
            }
        }
    }

    fn complete(&mut self, occurrence: Occurrence, job: JobId, revision: i64) -> Result<()> {
        let command = Command::ScheduleComplete {
            occurrence,
            job,
            revision,
        };
        let Some(evidence) = self.occurrences.get(&occurrence).copied() else {
            return self.record(
                command,
                ResultClass::ConflictClass,
                ScheduleOutcome::CompletionConflict,
                occurrence,
            );
        };
        let expected_revision = u64::try_from(revision).unwrap_or(0);
        let model_job = model_job_for_occurrence(occurrence);
        if self
            .pending_selection
            .is_some_and(|selection| selection.occurrence == occurrence)
            || !evidence.emitted
            || !self.has_materialized_job(evidence.actual.job_id())
            || job != model_job
            || i64::try_from(expected_revision).unwrap_or(i64::MAX)
                != self.projected_job_revision(occurrence)
        {
            return self.record(
                command,
                ResultClass::ConflictClass,
                ScheduleOutcome::CompletionConflict,
                occurrence,
            );
        }
        let actual_job = evidence.actual.job_id();
        let claim_now = self.now.max(evidence.actual.intended_at);
        let claim = match crate::test_helper::block_on(self.system.claim(actual_job, claim_now)) {
            Ok(claim) => claim,
            Err(_) => {
                return self.record(
                    command,
                    ResultClass::ConflictClass,
                    ScheduleOutcome::CompletionConflict,
                    occurrence,
                );
            }
        };
        let terminal_record = claim.record().clone();
        let outcome =
            crate::JobOutcome::Complete(crate::OutcomeCode::try_new("schedule_complete")?);
        if crate::test_helper::block_on(self.system.complete(claim, outcome, claim_now)).is_err() {
            return self.record(
                command,
                ResultClass::ConflictClass,
                ScheduleOutcome::CompletionConflict,
                occurrence,
            );
        }
        self.terminal_records.insert(occurrence, terminal_record);
        if let Some(evidence) = self.occurrences.get_mut(&occurrence) {
            evidence.emitted = false;
            evidence.completed = true;
        }
        self.pending_selection = None;
        self.wake_pending = self
            .occurrences
            .values()
            .any(|value| value.emitted && !value.completed);
        self.progress_counter = self.progress_counter.saturating_add(1);
        self.record(
            command,
            ResultClass::AppliedClass,
            ScheduleOutcome::ScheduleCompleted,
            occurrence,
        )
    }

    pub(super) fn wake(
        &mut self,
        revision: i64,
        token: i64,
        lose: bool,
        duplicate: bool,
    ) -> Result<()> {
        let command = Command::ScheduleWake {
            revision,
            token,
            lose,
            duplicate,
        };
        if lose {
            let _ = self.wake.raise_stale(None);
            self.wake_pending = false;
            return self.record(
                command,
                ResultClass::AppliedClass,
                ScheduleOutcome::WakeLost,
                Occurrence::Occ1,
            );
        }
        let durable_work = self.has_durable_work();
        if duplicate {
            let allowed = self.wake_pending && durable_work;
            return self.record(
                command,
                if allowed {
                    ResultClass::AppliedClass
                } else {
                    ResultClass::RejectedClass
                },
                if allowed {
                    ScheduleOutcome::WakeDuplicate
                } else {
                    ScheduleOutcome::WakeStale
                },
                Occurrence::Occ1,
            );
        }
        let exact = i64::try_from(self.cursor.revision()).unwrap_or(i64::MAX) == revision
            && i64::try_from(self.wake_token).unwrap_or(i64::MAX) == token;
        let requested = if durable_work {
            self.now
        } else {
            self.cursor.next_due().unwrap_or(self.now)
        };
        let wake_required = durable_work
            || (self.cursor.is_enabled()
                && !self.cursor.is_paused()
                && self.cursor.next_due().is_some_and(|next| next >= self.now));
        let accepted = exact && wake_required;
        if accepted {
            let _ = self.wake.lower(requested);
            self.wake_pending = true;
            self.wake_token = self.wake_token.saturating_add(1);
        }
        self.record(
            command,
            if accepted {
                ResultClass::AppliedClass
            } else {
                ResultClass::RejectedClass
            },
            if accepted {
                ScheduleOutcome::WakeSet
            } else {
                ScheduleOutcome::WakeStale
            },
            Occurrence::Occ1,
        )
    }

    pub(super) fn policy(&mut self, enabled: bool, paused: bool, overlap: bool) -> Result<()> {
        let command = Command::SchedulePolicy {
            enabled,
            paused,
            overlap,
        };
        if enabled != self.cursor.is_enabled() {
            let control = if enabled {
                ScheduleControl::Enable
            } else {
                ScheduleControl::Disable
            };
            let revision = self.cursor.revision();
            let generation = self.cursor.generation();
            if !matches!(
                self.cursor.apply_control(revision, generation, control),
                crate::ScheduleControlResult::Applied { .. }
            ) {
                return self.record(
                    command,
                    ResultClass::ConflictClass,
                    ScheduleOutcome::PauseChanged,
                    Occurrence::Occ1,
                );
            }
        }
        if paused != self.cursor.is_paused() {
            let control = if paused {
                ScheduleControl::Pause
            } else {
                ScheduleControl::Resume
            };
            let revision = self.cursor.revision();
            let generation = self.cursor.generation();
            if !matches!(
                self.cursor.apply_control(revision, generation, control),
                crate::ScheduleControlResult::Applied { .. }
            ) {
                return self.record(
                    command,
                    ResultClass::ConflictClass,
                    ScheduleOutcome::PauseChanged,
                    Occurrence::Occ1,
                );
            }
        }
        self.schedule = schedule_definition_with_options(
            self.schedule.cadence.clone(),
            self.schedule.misfire,
            if overlap {
                OverlapPolicy::Forbid
            } else {
                OverlapPolicy::Allow
            },
            self.schedule.enabled,
        )?;
        self.record(
            command,
            ResultClass::AppliedClass,
            ScheduleOutcome::PauseChanged,
            Occurrence::Occ1,
        )
    }

    fn cron(&mut self, form: CronForm) -> Result<()> {
        let command = Command::ScheduleCron { form };
        let expression = match form {
            CronForm::PortableFiveField => "*/5 * * * *",
            CronForm::SecondsField => "0 */5 * * * *",
            CronForm::YearField => "*/5 * * * * 2026",
            CronForm::AliasForm => "@hourly",
            CronForm::TimezoneForm => "*/5 * * * * TZ=UTC",
            CronForm::ProviderExtension => "*/5 * * * ?",
        };
        let Ok(cron) = CronExpression::try_new(expression) else {
            return self.record(
                command,
                ResultClass::RejectedClass,
                ScheduleOutcome::CronRejected,
                Occurrence::Occ1,
            );
        };
        self.schedule = schedule_definition_with_options(
            Cadence::CronUtc(cron),
            self.schedule.misfire,
            self.schedule.overlap,
            self.schedule.enabled,
        )?;
        self.record(
            command,
            ResultClass::AppliedClass,
            ScheduleOutcome::CronAccepted,
            Occurrence::Occ1,
        )
    }

    fn pulse(&mut self, active: i64, actions: i64) -> Result<()> {
        let command = Command::SchedulePulse { active, actions };
        if active != i64::try_from(self.active_pulses).unwrap_or(i64::MAX)
            || actions != i64::try_from(self.pulse_actions).unwrap_or(i64::MAX)
        {
            return Err(std::io::Error::other("active pulse prestate drift").into());
        }
        let max_pulses =
            NonZeroU16::new(1).ok_or_else(|| std::io::Error::other("pulse limit is zero"))?;
        let drive_request = empty_drive_request()?;
        let report = crate::test_helper::block_on(
            ActivePulseRequest::new(max_pulses, MonotonicDeadline::from_nanos(u64::MAX)).drive(
                || MonotonicDeadline::from_nanos(u64::MAX),
                || async {
                    crate::test_helper::block_on(self.system.drive(
                        drive_request.clone(),
                        self.now,
                        || MonotonicDeadline::from_nanos(u64::MAX),
                    ))
                },
            ),
        )?;
        self.last_report = report.drives.last().cloned();
        self.active_pulses = self.active_pulses.saturating_add(1);
        self.pulse_actions = 0;
        let allowed = active < 2;
        self.pulse_exited = !allowed;
        let outcome = if allowed {
            ScheduleOutcome::PulseStarted
        } else {
            self.active_pulses = 0;
            ScheduleOutcome::PulseExited
        };
        self.record(
            command,
            if allowed {
                ResultClass::AppliedClass
            } else {
                ResultClass::RejectedClass
            },
            outcome,
            Occurrence::Occ1,
        )
    }

    fn drive(&mut self, node: Node, active: i64, actions: i64) -> Result<()> {
        let command = Command::ScheduleDrive {
            node,
            active,
            actions,
        };
        if active != i64::try_from(self.active_pulses).unwrap_or(i64::MAX)
            || actions != i64::try_from(self.pulse_actions).unwrap_or(i64::MAX)
        {
            return Err(std::io::Error::other("drive pulse prestate drift").into());
        }
        // The public drive API only sees durable job routes.  A schedule's
        // future wake is owned by its caller, so consult the real evaluator
        // alongside drive to retain the schedule branch in the projection.
        // This is an observation of production state, not a connector-side
        // recurrence reducer.
        let evaluation = self.schedule.evaluate(&self.cursor, self.now)?;
        let report = crate::test_helper::block_on(self.system.drive(
            empty_drive_request()?,
            self.now,
            || MonotonicDeadline::from_nanos(u64::MAX),
        ))?;
        self.last_report = Some(report.clone());
        let before = self.progress_counter;
        self.progress_counter = self
            .progress_counter
            .saturating_add(u64::from(report.counts.claimed));
        self.last_drive = if report.counts.claimed == 0
            && evaluation.occurrences.is_empty()
            && matches!(evaluation.wake, WakeHint::At(_))
        {
            DriveEvidence {
                result: DriveResult::DriveFuture,
                branch: DriveKernelBranch::KernelFuture,
                work: DriveWork::DriveNoImmediateWork,
                stop: DriveStopReason::StopFuture,
                progress_before: before,
                progress_after: self.progress_counter,
            }
        } else {
            drive_evidence(&report, before, self.progress_counter)
        };
        self.active_pulses = 0;
        self.pulse_actions = 0;
        self.pulse_exited = !matches!(
            self.last_drive.branch,
            DriveKernelBranch::KernelRecurrence
                | DriveKernelBranch::KernelMaterialize
                | DriveKernelBranch::KernelClaim
                | DriveKernelBranch::KernelTerminal
        );
        let (outcome, class) = match report.stop_reason {
            crate::DriveStopReason::NoVisibleWork => {
                (ScheduleOutcome::PulseExited, ResultClass::RejectedClass)
            }
            crate::DriveStopReason::Deadline => {
                (ScheduleOutcome::PulseExited, ResultClass::RejectedClass)
            }
            _ if report.counts.claimed == 0 => {
                (ScheduleOutcome::PulseExited, ResultClass::RejectedClass)
            }
            _ => (
                ScheduleOutcome::DriveClaimCommitted,
                ResultClass::AppliedClass,
            ),
        };
        self.record(command, class, outcome, Occurrence::Occ1)
    }

    fn apply_portable_cron(&mut self) -> Result<()> {
        self.cron(CronForm::PortableFiveField)
    }

    fn record(
        &mut self,
        command: Command,
        class: ResultClass,
        outcome: ScheduleOutcome,
        occurrence: Occurrence,
    ) -> Result<()> {
        self.last_outcome = outcome;
        let mut state = self.project_state()?;
        state.last_outcome = outcome;
        let transition = transition_for(command.clone(), class, outcome, occurrence, state);
        let command_result = match (&command, transition.branch) {
            (Command::ScheduleDrive { .. }, DriveKernelBranch::KernelFuture) => {
                CommandResult::ScheduleFuture(transition.clone())
            }
            (Command::ScheduleDrive { .. }, DriveKernelBranch::KernelNoWork) => {
                CommandResult::ScheduleNoWork(transition.clone())
            }
            _ => match class {
                ResultClass::AppliedClass => CommandResult::ScheduleApplied(transition.clone()),
                ResultClass::RejectedClass => CommandResult::ScheduleRejected(transition.clone()),
                ResultClass::ConflictClass => {
                    CommandResult::ScheduleConflictResult(transition.clone())
                }
                ResultClass::UnknownClass => CommandResult::ScheduleRejected(transition.clone()),
            },
        };
        self.projection = StateProjection {
            state: transition.post.clone(),
            last_command: command,
            last_transition: transition.clone(),
            last_command_result: command_result,
        };
        Ok(())
    }

    /// Rebuild the complete model state from the caller-owned cursor, actual
    /// operation receipts, and the FakeStore's durable job/owner values.  The
    /// small occurrence map retains only the opaque `ScheduleOccurrence`
    /// returned by the production evaluator; it is not a second reducer.
    fn project_state(&self) -> Result<ScheduleState> {
        let values: BTreeMap<crate::store::StoreKey, Bytes> =
            self.system.store().inner.snapshot()?.into_iter().collect();
        let mut state = initial_state();
        state.enabled = self.cursor.is_enabled();
        state.paused = self.cursor.is_paused();
        state.overlap = self.schedule.overlap == OverlapPolicy::Forbid;
        state.misfire = model_misfire(self.schedule.misfire);
        state.now = ticks(Some(self.now));
        state.next_due = ticks(self.cursor.next_due());
        state.watermark = ticks(self.cursor.watermark());
        state.revision = i64::try_from(self.cursor.revision())?;
        state.emission_count = 0;
        state.materialize_pending = self.pending_selection.is_some();
        if let Some(selection) = self.pending_selection {
            state.materialize_occurrence = selection.occurrence;
            state.materialize_revision = i64::try_from(selection.revision)?;
            state.materialize_reader = selection.reader;
            state.materialize_other_reader = opposite_node(selection.reader);
            state.materialize_committed = false;
        }
        state.wake_pending = self.wake_pending;
        state.wake_revision = i64::try_from(self.cursor.revision())?;
        state.wake_token = i64::try_from(self.wake_token)?;
        state.wake_at = ticks(self.wake.value().or(self.cursor.next_due()));
        state.catch_up_limit = match self.schedule.misfire {
            MisfirePolicy::CatchUp {
                maximum_occurrences,
            } => i64::from(maximum_occurrences.get()),
            _ => state.catch_up_limit,
        };
        state.active_pulses = i64::try_from(self.active_pulses)?;
        state.pulse_actions = i64::try_from(self.pulse_actions)?;
        state.pulse_exited = self.pulse_exited;
        state.progress_counter = i64::try_from(self.progress_counter)?;
        state.last_drive = self.last_drive.result;
        state.last_drive_branch = self.last_drive.branch;
        state.last_drive_work = self.last_drive.work;
        state.last_drive_stop = self.last_drive.stop;
        state.drive_progress_before = i64::try_from(self.last_drive.progress_before)?;
        state.drive_progress_after = i64::try_from(self.last_drive.progress_after)?;

        for (occurrence, evidence) in &self.occurrences {
            let identity = ticks(Some(evidence.actual.intended_at));
            state.occurrence_identity.insert(*occurrence, identity);
            state
                .previous_identity
                .insert(*occurrence, evidence.previous_identity);
            state.emitted.insert(*occurrence, evidence.emitted);
            state.completed.insert(*occurrence, evidence.completed);
            if evidence.emitted {
                state.emission_count = state.emission_count.saturating_add(1);
            }
            let model_job = model_job_for_occurrence(*occurrence);
            state.occurrence_job.insert(*occurrence, model_job);
            if let Some(record) = self.job_record(&values, evidence.actual.job_id())? {
                project_record(
                    &mut state,
                    model_job,
                    &record,
                    &values,
                    self.system.namespace(),
                )?;
                state.materialized.insert(*occurrence, true);
                state.durable_route.insert(
                    *occurrence,
                    state.job_due_route[&model_job] || state.job_fair_route[&model_job],
                );
            } else if evidence.completed {
                state.materialized.insert(*occurrence, false);
                state.durable_route.insert(*occurrence, false);
                if let Some(record) = self.terminal_records.get(occurrence) {
                    state.job_revision.insert(
                        model_job,
                        i64::try_from(record.revision).unwrap_or(i64::MAX),
                    );
                    state
                        .job_generation
                        .insert(model_job, i64::from(record.generation));
                    state
                        .job_execution_id
                        .insert(model_job, i64::from(record.execution_id.as_bytes()[0]));
                }
            }
        }
        self.project_fair(&mut state, &values)?;
        Ok(state)
    }

    fn job_record(
        &self,
        values: &BTreeMap<crate::store::StoreKey, Bytes>,
        job_id: crate::JobId,
    ) -> Result<Option<crate::model::JobRecordV1>> {
        let key = crate::keys::job_key(self.system.namespace(), &job_id)?;
        values
            .get(&key)
            .map(|encoded| crate::codec::decode_job_record(encoded).map_err(Into::into))
            .transpose()
    }

    fn project_fair(
        &self,
        state: &mut ScheduleState,
        values: &BTreeMap<crate::store::StoreKey, Bytes>,
    ) -> Result<()> {
        let owner =
            crate::test_helper::block_on(crate::fairness::FairDispatchOwner::load(&self.system))?;
        for (occurrence, evidence) in &self.occurrences {
            let model_job = model_job_for_occurrence(*occurrence);
            let actual_job = evidence.actual.job_id();
            if let Some(candidate) = owner
                .as_ref()
                .and_then(|owner| owner.candidate_snapshot(actual_job))
            {
                state
                    .fair_ready
                    .insert(model_job, candidate.state.has_ready_route());
                state
                    .fair_priority
                    .insert(model_job, model_priority(candidate.priority));
                state
                    .fair_cost
                    .insert(model_job, i64::from(candidate.cost_units.get()));
                state
                    .fair_scope
                    .insert(model_job, model_scope(&candidate.scope)?);
                if let Some(scope) = owner
                    .as_ref()
                    .and_then(|owner| owner.ledger().scope_snapshot(&candidate.scope))
                {
                    state
                        .fair_weight
                        .insert(model_job, i64::from(scope.weight.get()));
                    state
                        .fair_permits
                        .insert(model_job, i64::from(scope.permits));
                    state.fair_rate.insert(model_job, i64::from(scope.rate));
                    state
                        .fair_in_flight
                        .insert(model_job, i64::from(scope.in_flight));
                    state
                        .fair_served
                        .insert(model_job, i64::try_from(scope.served_cost)?);
                }
            } else if let Some(record) = self.job_record(values, actual_job)? {
                state.fair_ready.insert(model_job, true);
                state
                    .fair_priority
                    .insert(model_job, model_priority(record.priority));
                state.fair_scope.insert(
                    model_job,
                    model_scope(&crate::FairScope::from(&record.fairness))?,
                );
            }
        }
        if let Some(owner) = owner {
            let priority = owner.priority_deficit();
            state.fair_critical = i64::from(priority.critical_window());
            state.fair_default = i64::from(priority.default_window());
            state.fair_bulk = i64::from(priority.bulk_window());
            state.fair_cycle = i64::from(priority.cycle());
        }
        Ok(())
    }

    fn has_materialized_job(&self, job_id: crate::JobId) -> bool {
        crate::keys::job_key(self.system.namespace(), &job_id)
            .ok()
            .and_then(|key| self.system.store().inner.contains(&key).ok())
            .unwrap_or(false)
    }

    fn projected_job_revision(&self, occurrence: Occurrence) -> i64 {
        let Some(evidence) = self.occurrences.get(&occurrence) else {
            return 0;
        };
        let Ok(key) = crate::keys::job_key(self.system.namespace(), &evidence.actual.job_id())
        else {
            return 0;
        };
        self.system
            .store()
            .inner
            .snapshot()
            .ok()
            .and_then(|entries| {
                entries
                    .into_iter()
                    .find(|(candidate, _)| candidate == &key)
                    .and_then(|(_, value)| crate::codec::decode_job_record(&value).ok())
                    .and_then(|record| i64::try_from(record.revision).ok())
            })
            .or_else(|| {
                self.terminal_records
                    .get(&occurrence)
                    .and_then(|record| i64::try_from(record.revision).ok())
            })
            .unwrap_or(0)
    }

    fn has_durable_work(&self) -> bool {
        self.occurrences.values().any(|evidence| {
            evidence.emitted
                && !evidence.completed
                && self.has_materialized_job(evidence.actual.job_id())
        })
    }
}

impl Driver for ScheduleWakeDriver {
    type State = StateProjection;

    fn step(&mut self, step: &Step) -> Result {
        match step.action_taken.as_str() {
            "mbtInit" => *self = Self::try_default()?,
            "fixedPortableCronTrace" | "fixedPortableCron" => self.apply_portable_cron()?,
            "mbtObserve" => {}
            "mbtNondetStep" | "mbtStep" => {
                let command = self.command_from_step(step)?;
                self.apply_command(command)?;
            }
            action => {
                return Err(std::io::Error::other(format!(
                    "schedule connector action not implemented: {action}"
                ))
                .into());
            }
        }
        Ok(())
    }
}

fn schedule_definition() -> Result<RecurringSchedule> {
    schedule_definition_with_cron(CronExpression::try_new("*/5 * * * *")?)
}

fn ticks(timestamp: Option<Timestamp>) -> i64 {
    timestamp.map_or(0, |value| value.as_millis() / 60_000)
}

fn available_slots(
    occurrences: &BTreeMap<Occurrence, OccurrenceEvidence>,
) -> impl Iterator<Item = Occurrence> + '_ {
    [Occurrence::Occ1, Occurrence::Occ2, Occurrence::Occ3]
        .into_iter()
        .filter(|occurrence| {
            occurrences
                .get(occurrence)
                .is_none_or(|evidence| !evidence.emitted || evidence.completed)
        })
}

fn model_job_for_occurrence(occurrence: Occurrence) -> JobId {
    match occurrence {
        Occurrence::Occ1 => JobId::JobA,
        Occurrence::Occ2 => JobId::JobB,
        Occurrence::Occ3 => JobId::JobC,
    }
}

fn opposite_node(node: Node) -> Node {
    match node {
        Node::NodeA => Node::NodeB,
        Node::NodeB => Node::NodeA,
    }
}

fn model_misfire(policy: MisfirePolicy) -> Misfire {
    match policy {
        MisfirePolicy::Skip => Misfire::Skip,
        MisfirePolicy::FireOnce => Misfire::FireOnce,
        MisfirePolicy::CatchUp { .. } => Misfire::CatchUp,
    }
}

fn model_priority(priority: crate::Priority) -> Priority {
    match priority {
        crate::Priority::Critical => Priority::Critical,
        crate::Priority::Default => Priority::Default,
        crate::Priority::Bulk => Priority::Bulk,
    }
}

fn model_scope(scope: &crate::FairScope) -> Result<Scope> {
    match scope {
        crate::FairScope::LowVolume => Ok(Scope::ScopeA1),
        crate::FairScope::Scoped { primary, secondary } => match (
            primary.as_bytes(),
            secondary.as_ref().map(crate::FairnessKey::as_bytes),
        ) {
            (b"a", None) => Ok(Scope::ScopeA),
            (b"b", None) => Ok(Scope::ScopeB),
            (b"a", Some(b"a1")) => Ok(Scope::ScopeA1),
            (b"a", Some(b"a2")) => Ok(Scope::ScopeA2),
            (b"b", Some(b"b1")) => Ok(Scope::ScopeB1),
            _ => Err(std::io::Error::other("unknown fair scope projection").into()),
        },
    }
}

fn model_job_state(state: &crate::model::JobState) -> JobState {
    match state {
        crate::model::JobState::Scheduled => JobState::Scheduled,
        crate::model::JobState::Leased(_) => JobState::Leased,
        crate::model::JobState::DeadLettered => JobState::DeadLettered,
        crate::model::JobState::Cancelled => JobState::Cancelled,
        crate::model::JobState::Suspended => JobState::Suspended,
    }
}

fn project_record(
    state: &mut ScheduleState,
    job: JobId,
    record: &crate::model::JobRecordV1,
    values: &BTreeMap<crate::store::StoreKey, Bytes>,
    namespace: &Namespace,
) -> Result<()> {
    state.job_state.insert(job, model_job_state(&record.state));
    state
        .job_revision
        .insert(job, i64::try_from(record.revision)?);
    state
        .job_generation
        .insert(job, i64::from(record.generation));
    state
        .job_execution_id
        .insert(job, i64::from(record.execution_id.as_bytes()[0]));
    state.job_attempts.insert(
        job,
        record
            .attempts
            .as_ref()
            .map_or(0, |attempts| i64::from(attempts.attempts.get())),
    );
    state.job_attempt_id.insert(
        job,
        record
            .attempts
            .as_ref()
            .map_or(0, |attempts| i64::from(attempts.attempts.get())),
    );
    state.job_node.insert(
        job,
        match &record.state {
            crate::model::JobState::Leased(lease) => {
                if lease.owner.as_bytes()[0] == 43 {
                    Node::NodeA
                } else {
                    Node::NodeB
                }
            }
            _ => Node::NodeA,
        },
    );
    if let crate::model::JobState::Leased(lease) = &record.state {
        state
            .job_fence
            .insert(job, i64::try_from(lease.fence.get()).unwrap_or(i64::MAX));
        state
            .job_token
            .insert(job, i64::from(lease.token.as_bytes()[0]));
        state
            .job_lease_until
            .insert(job, ticks(Some(lease.expires_at)));
    }
    let due_key = crate::keys::due_key(
        namespace,
        &record.queue,
        record.scheduled_at,
        &record.job_id,
    )?;
    let fair_key = crate::keys::fair_key(namespace, &record.queue, &record.job_id)?;
    let lease_key = crate::keys::lease_key(namespace, &record.queue, &record.job_id)?;
    let wake_key = crate::keys::wake_key(namespace, &record.queue)?;
    state
        .job_due_route
        .insert(job, values.contains_key(&due_key));
    state
        .job_fair_route
        .insert(job, values.contains_key(&fair_key));
    state
        .job_lease_route
        .insert(job, values.contains_key(&lease_key));
    state
        .job_wake_route
        .insert(job, values.contains_key(&wake_key));
    Ok(())
}

fn drive_evidence(report: &DriveReport, before: u64, after: u64) -> DriveEvidence {
    let (result, branch, work, stop) = if report.counts.claimed > 0 {
        (
            DriveResult::DriveClaimed,
            DriveKernelBranch::KernelClaim,
            DriveWork::DriveClaimWork,
            DriveStopReason::ContinuePulse,
        )
    } else {
        match report.stop_reason {
            crate::DriveStopReason::Capacity => (
                DriveResult::DriveBudgetExhausted,
                DriveKernelBranch::KernelBudget,
                DriveWork::DriveNoImmediateWork,
                DriveStopReason::StopBudget,
            ),
            crate::DriveStopReason::Deadline => (
                DriveResult::DriveBudgetExhausted,
                DriveKernelBranch::KernelBudget,
                DriveWork::DriveNoImmediateWork,
                DriveStopReason::StopBudget,
            ),
            _ if matches!(report.next_wake, crate::WakeHint::At(_)) => (
                DriveResult::DriveFuture,
                DriveKernelBranch::KernelFuture,
                DriveWork::DriveNoImmediateWork,
                DriveStopReason::StopFuture,
            ),
            _ => (
                DriveResult::DriveNoWork,
                DriveKernelBranch::KernelNoWork,
                DriveWork::DriveNoImmediateWork,
                DriveStopReason::StopNoWork,
            ),
        }
    };
    DriveEvidence {
        result,
        branch,
        work,
        stop,
        progress_before: before,
        progress_after: after,
    }
}

fn schedule_definition_with_cron(cron: CronExpression) -> Result<RecurringSchedule> {
    schedule_definition_with_options(
        Cadence::CronUtc(cron),
        MisfirePolicy::FireOnce,
        OverlapPolicy::Allow,
        true,
    )
}

fn schedule_definition_with_options(
    cadence: Cadence,
    misfire: MisfirePolicy,
    overlap: OverlapPolicy,
    enabled: bool,
) -> Result<RecurringSchedule> {
    Ok(RecurringSchedule::new(RecurringScheduleInput {
        schedule_id: ScheduleId::from([43; 16]),
        job_template: JobTemplate::try_new(JobTemplateInput {
            kind: JobKind::try_new("email")?,
            schema_version: std::num::NonZeroU16::MIN,
            payload: Bytes::from_static(b"connector"),
            fairness: FairnessClass::low_volume(),
            ordering_key: None,
            priority: crate::Priority::Default,
            expires_after: Some(Duration::from_secs(60)),
            retry_override: None,
            deduplication: None,
        })?,
        cadence,
        misfire,
        overlap,
        enabled,
    }))
}

fn transition_for(
    command: Command,
    class: ResultClass,
    outcome: ScheduleOutcome,
    occurrence: Occurrence,
    post: ScheduleState,
) -> LastTransition {
    let (drive, branch, work, stop, progress_before, progress_after) =
        if matches!(command, Command::ScheduleDrive { .. }) {
            (
                post.last_drive,
                post.last_drive_branch,
                post.last_drive_work,
                post.last_drive_stop,
                post.drive_progress_before,
                post.drive_progress_after,
            )
        } else {
            (
                DriveResult::DriveNoWork,
                DriveKernelBranch::KernelNoWork,
                DriveWork::DriveNoImmediateWork,
                DriveStopReason::StopNoWork,
                post.progress_counter,
                post.progress_counter,
            )
        };
    LastTransition {
        command,
        class,
        outcome,
        occurrence,
        drive,
        branch,
        work,
        stop,
        progress_before,
        progress_after,
        emission_count: post.emission_count,
        skipped: post.skipped_remainder,
        next_due: post.next_due,
        post,
    }
}

fn empty_drive_request() -> Result<DriveRequest> {
    Ok(DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: NonZeroU32::MIN,
        max_concurrency: NonZeroU16::MIN,
        max_payload_bytes_in_flight: NonZeroUsize::new(1_024).expect("bytes are non-zero"),
        max_completion_details: 1,
        max_store_operations: NonZeroU32::new(64).expect("budget is non-zero"),
        stop_claiming_at: MonotonicDeadline::from_nanos(u64::MAX),
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })?)
}
