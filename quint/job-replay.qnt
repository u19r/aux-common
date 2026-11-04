/// Bounded durable-input journal. Native requests can be delayed or duplicated
/// after their producer dies. Any replacement can fence a current and finish it.
/// Native rejection classification is covered by job-rejection.qnt. Here
/// retryable denotes an input whose wake-only abort cannot settle its work.
/// The command field represents the logical work obligation across a wake
/// refresh; the refreshed wire transaction has a new identity in Rust.
module job_replay {
  type Head = { generation: int, command: int, token: int, phase: int, binding: int, retry: int }
  type Input = { binding: int, check: int, retryable: bool }
  type Request = { slot: int, before: Head, after: Head, input: Input, kind: int }

  pure val SLOTS = Set(1, 2)
  pure val COMMANDS = Set(1, 2, 3, 4)
  pure val EMPTY_INPUT = { binding: 0, check: 0, retryable: false }
  pure def vacant(generation: int): Head = { generation: generation, command: 0, token: 0, phase: 0, binding: 0, retry: 0 }
  pure val EMPTY_REQUEST = { slot: 1, before: vacant(0), after: vacant(0), input: EMPTY_INPUT, kind: 0 }

  var heads: int -> Head
  var inputs: int -> Input
  var views: int -> Head
  var candidates: int -> Request
  var requests: Set[Request]
  var started: Set[int]
  var accepted: Set[int]
  var workRequired: Set[int]
  var settled: Set[int]
  var crashed: Set[int]
  var recovered: Set[int]
  var applied: int -> int
  var results: int -> int
  var knownAborts: Set[Head]
  var acknowledged: Set[Head]
  var businessVersion: int

  action init = all {
    heads' = SLOTS.mapBy(_ => vacant(0)),
    inputs' = SLOTS.mapBy(_ => EMPTY_INPUT),
    views' = SLOTS.mapBy(_ => vacant(0)),
    candidates' = COMMANDS.mapBy(_ => EMPTY_REQUEST),
    requests' = Set(), started' = Set(), accepted' = Set(), workRequired' = Set(), settled' = Set(),
    crashed' = Set(), recovered' = Set(), knownAborts' = Set(),
    applied' = COMMANDS.mapBy(_ => 0), results' = COMMANDS.mapBy(_ => 0),
    acknowledged' = Set(), businessVersion' = 0,
  }

  // Reachable focused initial state: command 2 advanced the business key and
  // settled; command 1 then established a known conflict and lost its producer.
  action initConflict = all {
    heads' = Map(1 -> { generation: 1, command: 1, token: 2, phase: 3, binding: 1, retry: 0 }, 2 -> vacant(1)),
    inputs' = Map(1 -> { binding: 1, check: 0, retryable: true }, 2 -> EMPTY_INPUT),
    views' = SLOTS.mapBy(_ => vacant(0)),
    candidates' = COMMANDS.mapBy(_ => EMPTY_REQUEST), requests' = Set(),
    started' = Set(1, 2), accepted' = Set(1, 2), workRequired' = Set(1, 2), settled' = Set(2),
    crashed' = Set(1), recovered' = Set(1), knownAborts' = Set(),
    applied' = COMMANDS.mapBy(command => if (command == 2) 1 else 0),
    results' = COMMANDS.mapBy(command => if (command == 1) 2 else if (command == 2) 1 else 0),
    acknowledged' = Set({ generation: 1, command: 2, token: 1, phase: 2, binding: 1, retry: 0 }), businessVersion' = 1,
  }

  // A point read can regress to the namespace's initial vacant frontier.
  action readHead = {
    nondet slot = SLOTS.oneOf()
    nondet fresh = Set(true, false).oneOf()
    all {
      views' = views.set(slot, if (fresh) heads.get(slot) else vacant(0)),
      heads' = heads, inputs' = inputs, candidates' = candidates, requests' = requests,
      started' = started, accepted' = accepted, workRequired' = workRequired, settled' = settled, crashed' = crashed,
      recovered' = recovered, applied' = applied, results' = results,
      knownAborts' = knownAborts, acknowledged' = acknowledged, businessVersion' = businessVersion,
    }
  }

  // Once dispatch is ambiguous, retain its exact reservation. Only observing
  // a different command at that target generation proves it lost admission.
  action reserve(unsafeReprobe: bool): bool = {
    nondet command = COMMANDS.oneOf()
    nondet slot = SLOTS.oneOf()
    nondet binding = Set(1, 2).oneOf()
    nondet retryable = Set(true, false).oneOf()
    nondet kind = Set(1, 7).oneOf()
    val before = views.get(slot)
    val previous = candidates.get(command)
    val competing = views.get(previous.slot)
    val mayReprobe = (previous.kind == 1 or previous.kind == 7) and competing.generation == previous.after.generation and competing.command != 0 and competing.command != command
    val fallback = previous.kind == 7 and kind == 1 and slot == previous.slot and before == previous.before
    val boundInput = if (fallback) previous.input else { binding: binding, check: businessVersion, retryable: retryable }
    val after = { generation: before.generation + 1, command: command, token: 1, phase: if (kind == 7) 2 else 1, binding: boundInput.binding, retry: 0 }
    val request = { slot: slot, before: before, after: after, input: boundInput, kind: kind }
    all {
      not(crashed.contains(command)), not(settled.contains(command)),
      (not(started.contains(command)) or mayReprobe or fallback or unsafeReprobe),
      (before.phase == 0 or (before.phase == 2 and inputs.get(slot) == EMPTY_INPUT and acknowledged.contains(before))), before.generation < 4,
      candidates' = candidates.set(command, request), requests' = requests.union(Set(request)),
      started' = started.union(Set(command)),
      heads' = heads, inputs' = inputs, views' = views, accepted' = accepted, workRequired' = workRequired,
      settled' = settled, crashed' = crashed, recovered' = recovered, applied' = applied,
      results' = results, knownAborts' = knownAborts, acknowledged' = acknowledged, businessVersion' = businessVersion,
    }
  }

  // Queue native requests against an exact current. Their delivery is separate
  // so a stale request can arrive after takeover, refresh, or retirement.
  action queuePhase = {
    nondet slot = SLOTS.oneOf()
    nondet kind = Set(2, 3, 4, 5, 6).oneOf()
    val current = heads.get(slot)
    val input = inputs.get(slot)
    val alive = not(crashed.contains(current.command)) or recovered.contains(current.command)
    val application = kind == 2 and current.phase == 1 and alive
    val conflict = kind == 3 and current.phase == 1 and knownAborts.contains(current)
    val retirement = kind == 4 and (current.phase == 2 or (current.phase == 3 and not(input.retryable))) and alive and acknowledged.contains(current)
    val takeover = kind == 5 and current.phase != 0 and inputs.get(slot) != EMPTY_INPUT and current.token < 4
    val refresh = kind == 6 and current.phase == 3 and input.retryable and current.generation < 4 and alive
    val nextHead = if (kind == 2) current.with("phase", 2)
      else if (kind == 3) current.with("phase", 3)
      else if (kind == 4) vacant(current.generation)
      else if (kind == 5) current.with("token", current.token + 1)
      else current.with("generation", current.generation + 1).with("phase", 1).with("binding", 3 - current.binding).with("retry", current.retry + 1)
    val nextInput = if (kind == 6) { binding: nextHead.binding, check: businessVersion, retryable: input.retryable } else input
    val request = { slot: slot, before: current, after: nextHead, input: nextInput, kind: kind }
    all {
      application or conflict or retirement or takeover or refresh,
      requests' = requests.union(Set(request)),
      heads' = heads, inputs' = inputs, views' = views, candidates' = candidates,
      started' = started, accepted' = accepted, workRequired' = workRequired, settled' = settled, crashed' = crashed,
      recovered' = recovered, applied' = applied, results' = results,
      knownAborts' = knownAborts, acknowledged' = acknowledged, businessVersion' = businessVersion,
    }
  }

  // A changed input submitted under the old prepared binding is rejected.
  action changeContent = {
    nondet request = requests.filter(request => request.kind == 2).oneOf()
    val changed = request.with("input", request.input.with("binding", 3 - request.input.binding))
    all {
      requests' = requests.union(Set(changed)),
      heads' = heads, inputs' = inputs, views' = views, candidates' = candidates,
      started' = started, accepted' = accepted, workRequired' = workRequired, settled' = settled, crashed' = crashed,
      recovered' = recovered, applied' = applied, results' = results,
      knownAborts' = knownAborts, acknowledged' = acknowledged, businessVersion' = businessVersion,
    }
  }

  action deliver = {
    nondet request = requests.oneOf()
    val current = heads.get(request.slot)
    val matchesHead = current == request.before
    val validInput = request.input == inputs.get(request.slot) and request.input.binding == current.binding
    val application = request.kind == 2 and matchesHead and validInput and request.input.check == businessVersion
    val abort = request.kind == 2 and matchesHead and validInput and request.input.check != businessVersion
    val atomicApplication = request.kind == 7 and matchesHead and request.input.binding == request.after.binding and request.input.check == businessVersion
    val control = request.kind != 2 and request.kind != 7 and matchesHead
    val admission = (control and request.kind == 1) or atomicApplication
    val retirement = control and request.kind == 4
    val takeover = control and request.kind == 5
    val refresh = control and request.kind == 6
    val changesHead = control or application or atomicApplication
    val command = if (admission) request.after.command else current.command
    all {
      heads' = if (changesHead) heads.set(request.slot, request.after) else heads,
      inputs' = if (atomicApplication) inputs.set(request.slot, EMPTY_INPUT)
        else if (admission or refresh) inputs.set(request.slot, request.input)
        else if (retirement) inputs.set(request.slot, EMPTY_INPUT) else inputs,
      accepted' = if (admission) accepted.union(Set(command)) else accepted,
      workRequired' = if (admission and request.input.retryable) workRequired.union(Set(command)) else workRequired,
      settled' = if (retirement) settled.union(Set(command))
        else if (admission and current.phase == 2) settled.union(Set(current.command)) else settled,
      recovered' = if (takeover) recovered.union(Set(command)) else recovered,
      applied' = if (application or atomicApplication) applied.set(command, applied.get(command) + 1) else applied,
      results' = if (application or atomicApplication) results.set(command, 1)
        else if (control and request.kind == 3) results.set(command, 2)
        else if (refresh) results.set(command, 0) else results,
      knownAborts' = if (abort) knownAborts.union(Set(current)) else knownAborts,
      acknowledged' = acknowledged, businessVersion' = if (application or atomicApplication) businessVersion + 1 else businessVersion,
      // Retain dispatched requests to model arbitrary delayed duplicates.
      requests' = requests, views' = views, candidates' = candidates,
      started' = started, crashed' = crashed,
    }
  }

  action crash = {
    nondet command = started.oneOf()
    all {
      crashed' = crashed.union(Set(command)), views' = SLOTS.mapBy(_ => vacant(0)),
      heads' = heads, inputs' = inputs, candidates' = candidates, requests' = requests,
      started' = started, accepted' = accepted, workRequired' = workRequired, settled' = settled, recovered' = recovered,
      applied' = applied, results' = results, knownAborts' = knownAborts,
      acknowledged' = acknowledged, businessVersion' = businessVersion,
    }
  }

  // Mutation: fencing/retirement alone cannot finish an accepted prepared
  // command. It must keep its full input until application or known abort.
  action retireUnresolved = {
    nondet slot = SLOTS.oneOf()
    val current = heads.get(slot)
    all {
      current.phase == 1,
      heads' = heads.set(slot, vacant(current.generation)),
      inputs' = inputs.set(slot, EMPTY_INPUT), settled' = settled.union(Set(current.command)),
      views' = views, candidates' = candidates, requests' = requests,
      started' = started, accepted' = accepted, workRequired' = workRequired, crashed' = crashed, recovered' = recovered,
      applied' = applied, results' = results, knownAborts' = knownAborts,
      acknowledged' = acknowledged, businessVersion' = businessVersion,
    }
  }

  action retireKnownWakeConflict = {
    nondet slot = SLOTS.oneOf()
    val current = heads.get(slot)
    all {
      current.phase == 3 and inputs.get(slot).retryable,
      heads' = heads.set(slot, vacant(current.generation)),
      inputs' = inputs.set(slot, EMPTY_INPUT), settled' = settled.union(Set(current.command)),
      views' = views, candidates' = candidates, requests' = requests,
      started' = started, accepted' = accepted, workRequired' = workRequired, crashed' = crashed, recovered' = recovered,
      applied' = applied, results' = results, knownAborts' = knownAborts,
      acknowledged' = acknowledged, businessVersion' = businessVersion,
    }
  }

  // JobSystem reconciles a durable outcome before making its slot reusable.
  // A replacement can do this without the producer or handler returning.
  action acknowledge = {
    nondet slot = SLOTS.oneOf()
    val current = heads.get(slot)
    all {
      current.phase == 2 or (current.phase == 3 and not(inputs.get(slot).retryable)),
      acknowledged' = acknowledged.union(Set(current)),
      recovered' = if (crashed.contains(current.command)) recovered.union(Set(current.command)) else recovered,
      heads' = heads, inputs' = inputs, views' = views, candidates' = candidates, requests' = requests,
      started' = started, accepted' = accepted, workRequired' = workRequired, settled' = settled, crashed' = crashed,
      applied' = applied, results' = results, knownAborts' = knownAborts, businessVersion' = businessVersion,
    }
  }

  action retireUnacknowledgedWitness = {
    nondet slot = SLOTS.oneOf()
    val current = heads.get(slot)
    all {
      current.phase == 2, not(acknowledged.contains(current)),
      heads' = heads.set(slot, vacant(current.generation)), inputs' = inputs.set(slot, EMPTY_INPUT),
      settled' = settled.union(Set(current.command)),
      views' = views, candidates' = candidates, requests' = requests, started' = started,
      accepted' = accepted, workRequired' = workRequired, crashed' = crashed, recovered' = recovered,
      applied' = applied, results' = results, knownAborts' = knownAborts,
      acknowledged' = acknowledged, businessVersion' = businessVersion,
    }
  }

  action step = any { readHead, reserve(false), queuePhase, changeContent, deliver, crash, acknowledge }
  action unsafeWitnessStep = any { step, retireUnacknowledgedWitness }
  action unsafeStep = any { step, retireUnresolved }
  action unsafeConflictStep = any { step, retireKnownWakeConflict }
  action unsafeAdmissionStep = any { readHead, reserve(true), queuePhase, changeContent, deliver, crash, acknowledge }

  val inv = all {
    COMMANDS.forall(command => applied.get(command) <= 1),
    accepted.exclude(settled).forall(command => SLOTS.filter(slot => heads.get(slot).phase != 0 and heads.get(slot).command == command and (heads.get(slot).phase == 2 or inputs.get(slot).binding != 0)).size() == 1),
    settled.forall(command => acknowledged.exists(witness => witness.command == command) and results.get(command) != 0 and SLOTS.forall(slot => heads.get(slot).command != command) and (not(workRequired.contains(command)) or applied.get(command) == 1)),
    SLOTS.forall(slot => {
      val current = heads.get(slot)
      (current.phase == 0 and inputs.get(slot) == EMPTY_INPUT) or
        (current.phase == 2 and inputs.get(slot) == EMPTY_INPUT and current.binding != 0) or
        (current.phase != 0 and inputs.get(slot).binding == current.binding and current.binding != 0)
    }),
  }

  val retired_replay_witness = requests.exists(request => request.kind == 2 and settled.contains(request.before.command))
  val contended_witness = requests.exists(left => left.kind == 1 and requests.exists(right => right.kind == 1 and left.slot == right.slot and left.before == right.before and left.after.command != right.after.command))
  val changed_content_witness = requests.exists(request => request.kind == 2 and request.input.binding != request.before.binding)
  val producer_death_recovery_witness = settled.intersect(crashed).intersect(recovered).size() > 0
  val atomic_reuse_witness = requests.exists(request => request.kind == 7 and request.before.phase == 2 and applied.get(request.after.command) == 1)
  val atomic_fallback_witness = requests.exists(left => left.kind == 7 and requests.exists(right => right.kind == 1 and left.before == right.before and left.after.command == right.after.command))
  val refreshed_intent_witness = SLOTS.exists(slot => heads.get(slot).retry == 1)
}
