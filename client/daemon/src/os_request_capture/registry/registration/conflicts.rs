//! Compare immutable plan labels outside the input lock. The original writer
//! validates the exact published prefix and checks any intervening append.
use super::*;

pub(super) struct Prechecked {
    plans: Vec<Arc<RegisteredFlowPlan>>,
    conflict: bool,
}

impl Prechecked {
    pub(super) fn capture(scope: &CaptureSession, incoming: &[FlowState]) -> Self {
        // These are the same immutable plans already shared by source readers,
        // bounded by MAX_REQUESTS. No observed IO or mutable state is copied.
        let plans: Vec<_> = scope
            .sources
            .flows
            .iter()
            .map(|row| row.plan.clone())
            .collect();
        let conflict = incoming
            .iter()
            .any(|new| plans.iter().any(|old| overlaps(old, &new.plan)));
        #[cfg(all(unix, test))]
        registration_tests::conflicts::checked();
        Self { plans, conflict }
    }

    pub(super) fn recheck(&self, state: &RegistryState, incoming: &[FlowState]) -> bool {
        // A source prefix can have been published by a writer still appending.
        // Only the same canonical plan identities authorize reuse of its result.
        // On any mismatch, use the entire original authoritative flow list.
        let checked = if self.plans.len() <= state.flows.len()
            && self
                .plans
                .iter()
                .zip(&state.flows)
                .all(|(old, current)| Arc::ptr_eq(old, &current.plan))
        {
            if self.conflict {
                return true;
            }
            self.plans.len()
        } else {
            0
        };
        incoming.iter().any(|new| {
            state.flows[checked..]
                .iter()
                .any(|old| overlaps(&old.plan, &new.plan))
        })
    }
}

fn overlaps(old: &RegisteredFlowPlan, incoming: &RegisteredFlowPlan) -> bool {
    #[cfg(all(unix, test))]
    registration_tests::conflicts::comparing();
    (old.protocol == incoming.protocol && old.flow == incoming.flow)
        || (old.protocol == incoming.protocol
            && incoming
                .requests
                .iter()
                .any(|key| old.requests.contains(key)))
}
