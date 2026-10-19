//! Actual mutex results and pure diagnostic intervals; no KernelRead is minted.
use super::*;
use crate::os_request_capture::registry::control_lock::ControlState;
use std::sync::{Arc, TryLockError};

#[test]
fn original_read_mutex_keeps_its_first_error_separate_from_publication() {
    let state = Arc::new(ControlState::new(7usize));
    assert_eq!(*state.try_original_read_lock(1).unwrap(), 7);
    assert!(state.original_read_refusal_snapshot().is_none());
    let held = state.try_lock().unwrap();
    let other = state.clone();
    std::thread::spawn(move || {
        assert!(matches!(
            other.try_original_read_lock(2),
            Err(TryLockError::WouldBlock)
        ));
        assert!(other.input_refusal_snapshot().is_none());
        assert!(other.authenticated_refusal_snapshot().is_none());
        assert!(other.system_write_refusal_snapshot().is_none());
        assert!(matches!(
            other.try_input_lock(3),
            Err(TryLockError::WouldBlock)
        ));
        assert!(matches!(
            other.try_original_read_lock(4),
            Err(TryLockError::WouldBlock)
        ));
    })
    .join()
    .unwrap();
    let before = serde_json::to_value(state.original_read_refusal_snapshot().unwrap()).unwrap();
    assert_eq!(before["read_ordinal"], 2);
    assert_eq!(before["mutex_failure"], "would_block");
    assert_eq!(before["holder"]["release_completion_observed"], false);
    drop(held);
    let after = serde_json::to_value(state.original_read_refusal_snapshot().unwrap()).unwrap();
    assert_eq!(after["read_ordinal"], 2);
    assert_eq!(after["holder"]["release_completion_observed"], true);
    assert_eq!(
        serde_json::to_value(state.input_refusal_snapshot().unwrap()).unwrap()["read_ordinal"],
        3
    );
    for key in [
        "native_os_write_verified",
        "physical_send_verified",
        "canonical_current_owner_verified",
    ] {
        assert_eq!(after[key], false);
    }
    assert_eq!(*state.try_original_read_lock(5).unwrap(), 7);
    assert_eq!(
        serde_json::to_value(state.original_read_refusal_snapshot().unwrap()).unwrap(),
        after
    );
}

#[test]
fn original_read_poison_is_not_would_block_and_has_no_borrowed_holder() {
    let state = Arc::new(ControlState::new(9usize));
    let other = state.clone();
    assert!(std::thread::spawn(move || {
        let _held = other.try_lock().unwrap();
        panic!("intentional original read metadata mutex poison control");
    })
    .join()
    .is_err());
    assert!(matches!(
        state.try_original_read_lock(11),
        Err(TryLockError::Poisoned(_))
    ));
    let first = serde_json::to_value(state.original_read_refusal_snapshot().unwrap()).unwrap();
    assert_eq!(first["read_ordinal"], 11);
    assert_eq!(first["mutex_failure"], "poisoned");
    assert!(first["holder"].is_null());
    assert_eq!(first["holder_interval_covers_failed_try"], false);
    assert!(state.input_refusal_snapshot().is_none());
    assert!(matches!(
        state.try_original_read_lock(12),
        Err(TryLockError::Poisoned(_))
    ));
    assert_eq!(
        serde_json::to_value(state.original_read_refusal_snapshot().unwrap()).unwrap(),
        first
    );
}

#[test]
fn original_read_missing_clock_holder_and_release_never_reopen_first_metadata() {
    let d = RefusalDiagnostics::new();
    d.original_read_refused(0, Some(1), Some(2), OriginalReadMutexFailure::WouldBlock);
    assert!(d.original_read_snapshot().is_none());
    d.original_read_refused(5, None, Some(3), OriginalReadMutexFailure::WouldBlock);
    let token = d.acquired_at(super::super::Site { code: 1, line: 7 }, Some(4));
    d.original_read_refused(6, Some(5), Some(6), OriginalReadMutexFailure::WouldBlock);
    d.released(token, Some(7));
    let first = serde_json::to_value(d.original_read_snapshot().unwrap()).unwrap();
    assert_eq!(first["read_ordinal"], 5);
    assert!(first["holder"].is_null() && first["failed_try_started_monotonic_ns"].is_null());
    assert_eq!(first["holder_interval_covers_failed_try"], false);
    let unclosed = RefusalDiagnostics::new();
    let token = unclosed.acquired_at(super::super::Site { code: 1, line: 19 }, Some(10));
    unclosed.original_read_refused(8, Some(11), Some(12), OriginalReadMutexFailure::WouldBlock);
    unclosed.released(token, None);
    unclosed.released(token, Some(14));
    let first = serde_json::to_value(unclosed.original_read_snapshot().unwrap()).unwrap();
    assert_eq!(first["holder"]["release_completion_observed"], true);
    assert!(first["holder"]["ended_before_unlock_monotonic_ns"].is_null());
    assert_eq!(first["holder_interval_covers_failed_try"], false);
}
