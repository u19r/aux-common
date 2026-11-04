/// Durable cursor/admission coupling for one configured Forbid schedule.
/// Journal input survives producer death. Native application either checks
/// the exact cursor and advances it with its occurrence, or changes neither.
/// Control changes invalidate old cursor authority; replacing a process does
/// not reset progress. Historical sets are model observations, not storage.
module job_durable_schedule {
  type Intent = { revision: int, due: int, skip: bool }
  pure val WORKERS = Set(1, 2, 3)
  pure val EMPTY = { revision: -1, due: 0, skip: false }
  var revision: int
  var watermark: int
  var paused: bool
  var active: int
  var jobs: Set[int]
  var emitted: Set[int]
  var skipped: Set[int]
  var applications: int -> int
  var inputs: int -> Intent
  var crashed: Set[int]
  var recovered: Set[int]
  var rejected: Set[int]

  action init = all {
    revision' = 0, watermark' = 0, paused' = false, active' = 0,
    jobs' = Set(), emitted' = Set(), skipped' = Set(),
    applications' = 1.to(4).mapBy(_ => 0),
    inputs' = WORKERS.mapBy(_ => EMPTY),
    crashed' = Set(), recovered' = Set(), rejected' = Set(),
  }

  action accept = {
    nondet worker = WORKERS.oneOf()
    nondet skip = Set(true, false).oneOf()
    all {
      not(crashed.contains(worker)), inputs.get(worker) == EMPTY,
      not(paused), active == 0, watermark < 4,
      inputs' = inputs.set(worker, { revision: revision, due: watermark + 1, skip: skip }),
      revision' = revision, watermark' = watermark, paused' = paused,
      active' = active, jobs' = jobs, emitted' = emitted, skipped' = skipped,
      applications' = applications, crashed' = crashed, recovered' = recovered, rejected' = rejected,
    }
  }

  action crash = {
    nondet worker = WORKERS.oneOf()
    all {
      inputs.get(worker) != EMPTY, not(crashed.contains(worker)),
      crashed' = crashed.union(Set(worker)), inputs' = inputs,
      revision' = revision, watermark' = watermark, paused' = paused,
      active' = active, jobs' = jobs, emitted' = emitted, skipped' = skipped,
      applications' = applications, recovered' = recovered, rejected' = rejected,
    }
  }

  // Recovery consumes persisted input, with no action by the dead producer.
  action apply(loseOccurrence: bool, ignoreRevision: bool): bool = {
    nondet worker = WORKERS.oneOf()
    val input = inputs.get(worker)
    val matches = input.revision == revision or ignoreRevision
    val creates = matches and not(input.skip) and not(loseOccurrence)
    all {
      input != EMPTY,
      revision' = if (matches) revision + 1 else revision,
      watermark' = if (matches) input.due else watermark,
      jobs' = if (creates) jobs.union(Set(input.due)) else jobs,
      emitted' = if (creates) emitted.union(Set(input.due)) else emitted,
      skipped' = if (matches and input.skip) skipped.union(Set(input.due)) else skipped,
      applications' = if (matches) applications.set(input.due, applications.get(input.due) + 1) else applications,
      active' = if (creates) input.due else active,
      inputs' = inputs.set(worker, EMPTY), paused' = paused, crashed' = crashed,
      recovered' = if (crashed.contains(worker) and matches) recovered.union(Set(worker)) else recovered,
      rejected' = if (matches) rejected else rejected.union(Set(worker)),
    }
  }

  action control = all {
    paused' = not(paused), revision' = revision + 1,
    watermark' = watermark, active' = active, jobs' = jobs,
    emitted' = emitted, skipped' = skipped, applications' = applications,
    inputs' = inputs, crashed' = crashed, recovered' = recovered, rejected' = rejected,
  }

  action complete = all {
    active != 0,
    jobs' = jobs.exclude(Set(active)), active' = 0, revision' = revision + 1,
    watermark' = watermark, paused' = paused,
    emitted' = emitted, skipped' = skipped, applications' = applications,
    inputs' = inputs, crashed' = crashed, recovered' = recovered, rejected' = rejected,
  }

  action step = any { accept, crash, apply(false, false), control, complete }
  action unsafeMissingOccurrence = any { step, apply(true, false) }
  action unsafeStaleCursor = any { step, apply(false, true) }

  val inv = all {
    emitted.intersect(skipped).size() == 0,
    emitted.union(skipped) == (if (watermark == 0) Set() else 1.to(watermark)),
    1.to(4).forall(due => applications.get(due) <= 1),
    jobs.size() <= 1,
    jobs == (if (active == 0) Set() else Set(active)),
  }
  val producer_death_witness = recovered.size() > 0
  val competing_cursor_witness = rejected.size() > 0
  val persisted_progress_witness = watermark >= 2 and jobs.size() == 0
  val paused_witness = paused and watermark > 0
}
