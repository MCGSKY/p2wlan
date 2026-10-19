//! Pure first-error metadata; no original read, device or completion is created.
use super::*;

#[test]
fn original_read_capture_error_keeps_first_ordinal_type_and_scope_without_credit() {
    for (error, expected) in [
        (CaptureFailure::Contended, "contended"),
        (CaptureFailure::ForeignDevice, "foreign_device"),
        (CaptureFailure::FrameConflict, "frame_conflict"),
        (CaptureFailure::MissingTcpOpen, "missing_tcp_open"),
        (CaptureFailure::InvalidPlan, "invalid_plan"),
        (CaptureFailure::CounterExhausted, "counter_exhausted"),
        (CaptureFailure::Capacity, "capacity"),
    ] {
        let loss = ReadLoss::new();
        let other = ReadLoss::new();
        loss.record(0, error);
        assert!(loss.snapshot().is_none());
        loss.record(u64::MAX, error);
        let first = serde_json::to_value(loss.snapshot().unwrap()).unwrap();
        assert_eq!(first["read_ordinal"], u64::MAX);
        assert_eq!(first["original_failure"], expected);
        loss.record(1, CaptureFailure::DuplicateWrite);
        assert_eq!(
            serde_json::to_value(loss.snapshot().unwrap()).unwrap(),
            first
        );
        assert!(other.snapshot().is_none());
        for key in [
            "native_os_write_verified",
            "physical_send_verified",
            "canonical_current_owner_verified",
        ] {
            assert_eq!(first[key], false);
        }
    }
}
