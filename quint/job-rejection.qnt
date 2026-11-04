/// Authority diagnostics after a known native abort. Point reads can regress
/// or observe wake ABA; only a native non-wake probe establishes rejection.
/// Retirement reports must preserve the phase outcome of the same generation.
module job_rejection {
  type Snapshot = { generation: int, owner: int, phase: int }
  type Ticket = { before: Snapshot, expectedWake: int, kind: int, outcome: int }
  type State = {
    current: Snapshot, expectedWake: int, wake: int, wakeRead: int, authority: int,
    requests: Set[Ticket], aborted: Set[Ticket], good: Set[Snapshot], bad: Set[Snapshot], proof: Set[Snapshot],
    effect: int, rejected: bool, rejectProven: bool, reported: int,
    crashed: bool, wakeRestored: bool, authorityRestored: bool,
  }
  var s: State

  pure def snapshot(generation: int, owner: int, phase: int): Snapshot = { generation: generation, owner: owner, phase: phase }
  pure def ticket(before: Snapshot, expectedWake: int, kind: int, outcome: int): Ticket = {
    before: before, expectedWake: expectedWake, kind: kind, outcome: outcome,
  }
  pure def initial(current: Snapshot): State = {
    current: current, expectedWake: 0, wake: 0, wakeRead: 0, authority: 0,
    requests: Set(), aborted: Set(), good: Set(), bad: Set(), proof: Set(),
    effect: 0, rejected: false, rejectProven: false, reported: 0,
    crashed: false, wakeRestored: false, authorityRestored: false,
  }

  // The original enqueue is already durably accepted with its exact input.
  action init = s' = initial(snapshot(1, 1, 1))
  // Reachable: wake changed, the native application aborted, Conflict was
  // established, and the changed point read returns the original wake value.
  action initWakeConflict = s' = initial(snapshot(1, 1, 3)).with("wake", 1)
  // Reachable: a probe was dispatched by owner 1 before owner 2 took over.
  action initHandoff = s' = initial(snapshot(1, 2, 3)).with("wake", 1).with("wakeRead", 1)
    .with("crashed", true).with("requests", Set(ticket(snapshot(1, 1, 3), 0, 2, 0)))

  action changeWake = {
    val changed = 1 - s.wake
    s' = s.with("wake", changed).with("wakeRestored", s.wakeRestored or (s.wake == 1 and changed == 0))
  }
  action readWake = {
    nondet observed = Set(0, s.wake).oneOf()
    s' = s.with("wakeRead", observed)
  }
  action changeAuthority = {
    val changed = 1 - s.authority
    s' = s.with("authority", changed).with("authorityRestored", s.authorityRestored or (s.authority == 1 and changed == 0))
  }
  action crash = s' = s.with("crashed", true)
  action takeover = all {
    s.current.phase != 0, s.current.owner < 4,
    s' = s.with("current", s.current.with("owner", s.current.owner + 1)),
  }

  action queueApplication = all {
    s.current.phase == 1, not(s.crashed) or s.current.owner > 1,
    s' = s.with("requests", s.requests.union(Set(ticket(s.current, s.expectedWake, 1, 0)))),
  }
  action deliverApplication = {
    nondet request = s.requests.filter(request => request.kind == 1).oneOf()
    val applies = s.current == request.before and s.wake == request.expectedWake and s.authority == 0
    s' = if (applies) s.with("current", s.current.with("phase", 2)).with("effect", s.effect + 1)
      else s.with("aborted", s.aborted.union(Set(request)))
  }
  action establishConflict = {
    nondet request = s.aborted.oneOf()
    all {
      s.current == request.before, s.current.phase == 1,
      s' = s.with("current", s.current.with("phase", 3)),
    }
  }

  action queueProbe = all {
    s.current.phase == 3,
    s' = s.with("requests", s.requests.union(Set(ticket(s.current, 0, 2, 0)))),
  }
  action deliverProbe = {
    nondet request = s.requests.filter(request => request.kind == 2).oneOf()
    nondet acknowledge = Set(true, false).oneOf()
    val matchesCurrent = s.current == request.before
    val succeeds = matchesCurrent and s.authority == 0
    s' = if (not(acknowledge)) s
      else if (succeeds) s.with("good", s.good.union(Set(request.before)))
      else s.with("bad", s.bad.union(Set(request.before)))
        .with("proof", if (matchesCurrent and s.authority != 0) s.proof.union(Set(request.before)) else s.proof)
  }
  action refresh = all {
    s.current.phase == 3, s.good.contains(s.current), s.current.generation < 4,
    // Refresh never passes through a vacant state. Its input remains durable.
    s' = s.with("current", snapshot(s.current.generation + 1, s.current.owner, 1)).with("expectedWake", s.wakeRead),
  }

  action queueRejection = {
    nondet rejectedProbe = s.bad.oneOf()
    s' = s.with("requests", s.requests.union(Set(ticket(rejectedProbe, 0, 3, 2))))
  }
  action queueCommittedRetirement = all {
    s.current.phase == 2,
    s' = s.with("requests", s.requests.union(Set(ticket(s.current, 0, 3, 1)))),
  }
  action deliverRetirement = {
    nondet request = s.requests.filter(request => request.kind == 3).oneOf()
    nondet acknowledge = Set(true, false).oneOf()
    all {
      s.current == request.before,
      s' = s.with("current", snapshot(s.current.generation, 0, 0))
        .with("rejected", request.outcome == 2)
        .with("rejectProven", request.outcome == 2 and s.proof.contains(request.before))
        .with("reported", if (acknowledge) request.outcome else s.reported),
    }
  }
  action reportRetirement(unsafeHigherFrontier: bool): bool = {
    nondet request = s.requests.filter(request => request.kind == 3).oneOf()
    val exactRetirement = s.current.phase == 0 and s.current.generation == request.before.generation
    val advanced = s.current.generation > request.before.generation
    all {
      exactRetirement or (advanced and (request.outcome == 1 or unsafeHigherFrontier)),
      s' = s.with("reported", request.outcome),
    }
  }

  // Mutation: an unchanged stale/ABA observation is not proof that the
  // earlier abort was caused by a non-wake authority condition.
  action rejectFromWakeObservation = all {
    s.current.phase == 3, s.wakeRead == s.expectedWake,
    s' = s.with("requests", s.requests.union(Set(ticket(s.current, 0, 3, 2)))),
  }

  action step = any {
    changeWake, readWake, changeAuthority, crash, takeover,
    queueApplication, deliverApplication, establishConflict,
    queueProbe, deliverProbe, refresh, queueRejection,
    queueCommittedRetirement, deliverRetirement, reportRetirement(false),
  }
  action unsafeWakeStep = any { step, rejectFromWakeObservation }
  action unsafeRetirementStep = any { step, reportRetirement(true) }

  val inv = all {
    s.effect <= 1,
    s.current.phase != 0 or s.effect == 1 or (s.rejected and s.rejectProven),
    s.reported != 1 or s.effect == 1,
    s.reported != 2 or (s.effect == 0 and s.rejected and s.rejectProven),
  }
  val stale_wake_witness = s.current.phase == 3 and s.wakeRead != s.wake and s.wakeRead == s.expectedWake
  val wake_aba_witness = s.wakeRestored and s.current.phase == 3 and s.wake == s.expectedWake
  val non_wake_aba_rejection_witness = s.authorityRestored and s.rejected and s.rejectProven
  val takeover_probe_witness = s.bad.exists(before => before.owner < s.current.owner or before.generation < s.current.generation)
  val abandoned_work_finished_witness = s.crashed and s.effect == 1 and s.current.phase == 0
}
