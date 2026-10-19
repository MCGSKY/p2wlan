//! First original-read mutex error, separate from later Full publication.
use super::{observation, HolderSnapshot, Refusal, RefusalDiagnostics};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::os_request_capture::registry::control_lock) enum OriginalReadMutexFailure {
    WouldBlock,
    Poisoned,
}

pub(super) struct FirstReadRefusal {
    claimed: AtomicBool,
    first: OnceLock<(OriginalReadMutexFailure, Refusal)>,
}

#[derive(serde::Serialize)]
pub(in crate::os_request_capture) struct OriginalReadRefusalSnapshot {
    scope: &'static str,
    read_ordinal: u64,
    mutex_failure: OriginalReadMutexFailure,
    failed_try_started_monotonic_ns: Option<u64>,
    failed_try_returned_monotonic_ns: Option<u64>,
    holder: Option<HolderSnapshot>,
    holder_interval_covers_failed_try: bool,
    native_os_write_verified: bool,
    physical_send_verified: bool,
    canonical_current_owner_verified: bool,
}

impl FirstReadRefusal {
    #[cfg(any(target_os = "linux", test))]
    pub(super) fn new() -> Self {
        Self {
            claimed: AtomicBool::new(false),
            first: OnceLock::new(),
        }
    }

    pub(super) fn record(
        &self,
        diagnostics: &RefusalDiagnostics,
        read: u64,
        started: Option<u64>,
        returned: Option<u64>,
        failure: OriginalReadMutexFailure,
    ) {
        if read == 0
            || self
                .claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        // One claimant, no initializer wait and no new original mutex try.
        // A poisoned try acquired the inner guard; it did not observe a
        // blocking holder, so it must not borrow a previous holder interval.
        let mut original = diagnostics.observed_refusal(Some(read), started, returned);
        if matches!(failure, OriginalReadMutexFailure::Poisoned) {
            original.holder = None;
        }
        let _ = self.first.set((failure, original));
    }

    pub(super) fn observation(&self) -> Option<&Refusal> {
        self.first.get().map(|(_, original)| original)
    }

    pub(super) fn snapshot(&self) -> Option<OriginalReadRefusalSnapshot> {
        let (failure, original) = self.first.get()?;
        let observed = observation(original);
        Some(OriginalReadRefusalSnapshot {
            scope: "actual_original_read_registry_try_error_only",
            read_ordinal: original.original_ordinal?,
            mutex_failure: *failure,
            failed_try_started_monotonic_ns: original.started,
            failed_try_returned_monotonic_ns: original.returned,
            holder: observed.holder,
            holder_interval_covers_failed_try: observed.covers,
            native_os_write_verified: false,
            physical_send_verified: false,
            canonical_current_owner_verified: false,
        })
    }
}

#[cfg(test)]
mod tests;
