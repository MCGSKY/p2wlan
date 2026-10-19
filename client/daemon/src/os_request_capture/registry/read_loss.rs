//! First capture error metadata only; the original read-complete flag owns loss.
use super::CaptureFailure;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

pub(super) struct ReadLoss {
    claimed: AtomicBool,
    first: OnceLock<(u64, CaptureFailure)>,
}

#[derive(serde::Serialize)]
pub(super) struct ReadLossSnapshot {
    scope: &'static str,
    read_ordinal: u64,
    original_failure: &'static str,
    native_os_write_verified: bool,
    physical_send_verified: bool,
    canonical_current_owner_verified: bool,
}

impl ReadLoss {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn new() -> Self {
        Self {
            claimed: AtomicBool::new(false),
            first: OnceLock::new(),
        }
    }

    pub(super) fn record(&self, ordinal: u64, failure: CaptureFailure) {
        if ordinal == 0
            || self
                .claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        // The actual error is retained before the existing irreversible loss
        // transition. The sole claimant never waits for another initializer.
        let _ = self.first.set((ordinal, failure));
    }

    pub(super) fn snapshot(&self) -> Option<ReadLossSnapshot> {
        let (ordinal, failure) = self.first.get()?;
        let original_failure = match failure {
            CaptureFailure::Contended => "contended",
            CaptureFailure::ForeignDevice => "foreign_device",
            CaptureFailure::FrameConflict => "frame_conflict",
            CaptureFailure::MissingTcpOpen => "missing_tcp_open",
            CaptureFailure::InvalidPlan => "invalid_plan",
            CaptureFailure::CounterExhausted => "counter_exhausted",
            CaptureFailure::Capacity => "capacity",
            _ => "unclassified_capture_failure",
        };
        Some(ReadLossSnapshot {
            scope: "first_original_read_capture_error_metadata_only",
            read_ordinal: *ordinal,
            original_failure,
            native_os_write_verified: false,
            physical_send_verified: false,
            canonical_current_owner_verified: false,
        })
    }
}

#[cfg(test)]
mod tests;
