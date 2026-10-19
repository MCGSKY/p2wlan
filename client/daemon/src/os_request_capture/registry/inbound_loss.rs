//! First original inbound failure only. This byte cannot authorize native IO.
use super::CaptureFailure;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy)]
#[repr(u8)]
pub(super) enum InboundLossSite {
    RoomBinding = 1,
    AuthenticatedInput,
    SystemWriteRetention,
}

pub(super) struct InboundLoss(AtomicU8);

#[cfg(unix)]
#[derive(serde::Serialize)]
pub(super) struct InboundLossSnapshot {
    scope: &'static str,
    site: &'static str,
    original_failure: &'static str,
    native_os_write_verified: bool,
    physical_send_verified: bool,
    canonical_current_owner_verified: bool,
}

impl InboundLoss {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn new() -> Self {
        Self(AtomicU8::new(0))
    }

    pub(super) fn record(&self, site: InboundLossSite, error: Option<CaptureFailure>) {
        let reason = match error {
            None => 0, // The original room-binding boolean did not retain an error.
            Some(CaptureFailure::Capacity) => 1,
            Some(CaptureFailure::InvalidPlan) => 2,
            Some(CaptureFailure::Contended) => 3,
            Some(CaptureFailure::ForeignDevice) => 4,
            Some(CaptureFailure::FrameConflict) => 5,
            Some(CaptureFailure::MissingTcpOpen) => 6,
            Some(CaptureFailure::DuplicateWrite) => 7,
            Some(CaptureFailure::OriginalIngressSource) => 8,
            Some(_) => 9,
        };
        let _ = self.0.compare_exchange(
            0,
            ((site as u8) << 4) | reason,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }

    #[cfg(unix)]
    pub(super) fn snapshot(&self) -> Option<InboundLossSnapshot> {
        let code = self.0.load(Ordering::Acquire);
        let site = match code >> 4 {
            1 => "room_binding",
            2 => "authenticated_input",
            3 => "system_write_retention",
            _ => return None,
        };
        let original_failure = match code & 15 {
            0 => "not_observed",
            1 => "capacity",
            2 => "invalid_plan",
            3 => "contended",
            4 => "foreign_device",
            5 => "frame_conflict",
            6 => "missing_tcp_open",
            7 => "duplicate_write",
            8 => "original_ingress_source",
            _ => "unclassified_capture_failure",
        };
        Some(InboundLossSnapshot {
            scope: "first_original_inbound_loss_metadata_only",
            site,
            original_failure,
            native_os_write_verified: false,
            physical_send_verified: false,
            canonical_current_owner_verified: false,
        })
    }
}

#[cfg(all(unix, test))]
mod tests {
    use super::*;

    #[test]
    fn first_inbound_loss_preserves_error_and_does_not_borrow_another_capture() {
        let first = InboundLoss::new();
        let other = InboundLoss::new();
        assert!(first.snapshot().is_none());
        first.record(
            InboundLossSite::SystemWriteRetention,
            Some(CaptureFailure::ForeignDevice),
        );
        let original = serde_json::to_value(first.snapshot()).unwrap();
        first.record(
            InboundLossSite::AuthenticatedInput,
            Some(CaptureFailure::Contended),
        );
        assert_eq!(serde_json::to_value(first.snapshot()).unwrap(), original);
        assert_eq!(original["site"], "system_write_retention");
        assert_eq!(original["original_failure"], "foreign_device");
        assert!(other.snapshot().is_none());
        for key in [
            "native_os_write_verified",
            "physical_send_verified",
            "canonical_current_owner_verified",
        ] {
            assert_eq!(original[key], false);
        }
    }

    #[test]
    fn original_room_binding_boolean_never_infers_a_contention_reason() {
        let loss = InboundLoss::new();
        loss.record(InboundLossSite::RoomBinding, None);
        let original = serde_json::to_value(loss.snapshot()).unwrap();
        assert_eq!(original["site"], "room_binding");
        assert_eq!(original["original_failure"], "not_observed");
        loss.record(
            InboundLossSite::SystemWriteRetention,
            Some(CaptureFailure::InvalidPlan),
        );
        assert_eq!(serde_json::to_value(loss.snapshot()).unwrap(), original);
    }
}
