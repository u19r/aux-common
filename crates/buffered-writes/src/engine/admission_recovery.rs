use super::state::Engine;
use crate::Deadline;

impl<T: Send + Sync + 'static> Engine<T> {
    pub(super) async fn reconcile_uncertain_admissions(&self, deadline: Deadline) -> bool {
        for id in self.admissions.unknown_ids() {
            if let Some(receipt) = self.inspect_admission(&id, deadline).await {
                self.admissions.confirm(&id, receipt.fingerprint);
            }
        }
        self.admissions.unknown_ids().is_empty()
    }
}
