//! Reuse the original unique-producer lookup only for the same registration
//! revision and length. Appends advance that sole owner's checked revision.
use super::*;

pub(super) struct RegistrationPrefix {
    revision: u64,
    flows: usize,
}

impl RegistrationPrefix {
    pub(super) fn capture(state: &RegistryState) -> Self {
        Self {
            revision: state.revision,
            flows: state.flows.len(),
        }
    }

    pub(super) fn current_index(
        &self,
        prepared: &OriginalWindowPlan,
        state: &RegistryState,
    ) -> Result<usize, CaptureFailure> {
        let (index, flow) = if self.revision == state.revision && self.flows == state.flows.len() {
            let flow = state
                .flows
                .get(prepared.flow)
                .ok_or(CaptureFailure::InvalidPlan)?;
            (prepared.flow, flow)
        } else {
            // Preserve the original unique-producer search after any append or
            // prefix mismatch. A revision is never used as native IO authority.
            let mut flows = state.flows.iter().enumerate().filter(|(_, flow)| {
                #[cfg(all(unix, test))]
                record_scan();
                flow.producer_scope == prepared.producer
            });
            let selected = flows.next().ok_or(CaptureFailure::InvalidPlan)?;
            if flows.next().is_some() {
                return Err(CaptureFailure::InvalidPlan);
            }
            selected
        };
        if flow.requests.len() != 8 || flow.plan.payload_bytes != 128 {
            return Err(CaptureFailure::InvalidPlan);
        }
        if !prepared.is_current(index, flow) {
            return Err(CaptureFailure::InvalidPlan);
        }
        Ok(index)
    }
}

#[cfg(all(unix, test))]
thread_local! {
    static SCANS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

#[cfg(all(unix, test))]
fn record_scan() {
    SCANS.with(|scans| scans.set(scans.get().map(|n| n.saturating_add(1))));
}

#[cfg(all(unix, test))]
pub(super) fn begin_scans() {
    SCANS.with(|scans| assert!(scans.replace(Some(0)).is_none()));
}

#[cfg(all(unix, test))]
pub(super) fn finish_scans() -> usize {
    SCANS.with(|scans| scans.replace(None).unwrap())
}
