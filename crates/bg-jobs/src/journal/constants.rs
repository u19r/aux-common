pub(super) const SLOT_COUNT: usize = 256;
pub(super) const MAX_ADMISSION_ATTEMPTS: usize = 4;
pub(super) const HEAD_SCAN_BYTES: usize = 64 * 1024;
pub(super) const HEAD_VERSION: u8 = 1;
pub(super) const VACANT_HEAD_BYTES: usize = 10;
pub(super) const ACTIVE_HEAD_BYTES: usize = 83;
pub(super) const MAX_CONTROL_ATTEMPTS: usize = 2;
pub(super) const MAX_APPLICATION_ATTEMPTS: usize = 2;
pub(super) const MAX_TRANSITION_REFRESHES_PER_PASS: usize = 1;
const APPLICATION_PHASES: u32 = MAX_TRANSITION_REFRESHES_PER_PASS as u32 + 1;
pub(super) const MAX_COMMAND_PHASES: usize = 2 * APPLICATION_PHASES as usize + 2;
const CONTROL_MAX_CALLS: u32 = 2 * MAX_CONTROL_ATTEMPTS as u32;
const RECONCILED_CONTROL_MAX_CALLS: u32 = CONTROL_MAX_CALLS + 1;
const APPLICATION_MAX_CALLS: u32 = 2 * MAX_APPLICATION_ATTEMPTS as u32;
// Slot probe, atomic application, conflict head read and pending admission;
// application/conflict phases with an authority probe;
// at most one wake refresh per pass;
// replacement input; retirement. Include the extra head load after a
// competing control result. Cached producer input needs no hydration read.
// Recovery substitutes takeover and one hydration for the larger admission
// allowance, so this also bounds recovery of one accepted command.
pub(crate) const COMMIT_WORST_CASE_STORE_OPERATIONS: u32 = MAX_ADMISSION_ATTEMPTS as u32
    * (3 + CONTROL_MAX_CALLS)
    + APPLICATION_PHASES * (APPLICATION_MAX_CALLS + RECONCILED_CONTROL_MAX_CALLS + 1)
    + 5 * MAX_TRANSITION_REFRESHES_PER_PASS as u32
    + CONTROL_MAX_CALLS
    + RECONCILED_CONTROL_MAX_CALLS;
