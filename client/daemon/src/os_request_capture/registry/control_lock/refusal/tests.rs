//! Real mutex controls and pure interval metadata; no KernelRead is constructed.
use super::super::ControlState;
use super::*;
use std::sync::{Arc, TryLockError};

#[test]
fn actual_input_try_refusal_keeps_first_read_and_original_mutex_unlocks() {
    let state = Arc::new(ControlState::new(7usize));
    let held = state.try_lock().unwrap();
    let other = state.clone();
    std::thread::spawn(move || {
        assert!(matches!(
            other.try_input_lock(17),
            Err(TryLockError::WouldBlock)
        ));
        assert!(matches!(
            other.try_input_lock(18),
            Err(TryLockError::WouldBlock)
        ));
    })
    .join()
    .unwrap();
    let before = state.input_refusal_snapshot().unwrap();
    assert_eq!(before.read_ordinal, 17);
    assert!(!before.holder.unwrap().release_completion_observed);
    drop(held);
    let after = state.input_refusal_snapshot().unwrap();
    assert_eq!(after.read_ordinal, 17);
    assert!(after.holder.as_ref().unwrap().release_completion_observed);
    assert_eq!(*state.try_input_lock(19).unwrap(), 7);
    #[cfg(target_os = "linux")]
    assert!(after.holder_interval_covers_failed_try);
    #[cfg(not(target_os = "linux"))]
    assert!(!after.holder_interval_covers_failed_try);
}

#[test]
fn pure_first_refusal_interval_never_refills_missing_clock() {
    let d = RefusalDiagnostics::new();
    let site = Site { code: 1, line: 7 };
    let token = d.acquired_at(site, Some(10));
    d.refused(3, Some(12), Some(13));
    d.released(token, None);
    d.released(token, Some(19));
    let next = d.acquired_at(site, Some(20));
    d.refused(4, Some(21), Some(22));
    d.released(next, Some(23));
    let s = d.snapshot().unwrap();
    assert_eq!(s.read_ordinal, 3);
    assert!(s.holder.as_ref().unwrap().release_completion_observed);
    assert!(s.holder.unwrap().ended_before_unlock_monotonic_ns.is_none());
    assert!(!s.holder_interval_covers_failed_try);
}

#[test]
fn pure_missing_unclosed_or_noncovering_interval_stays_unknown() {
    for (acquired, started, returned, ended, covered) in [
        (Some(10), Some(11), Some(12), Some(13), true),
        (None, Some(11), Some(12), Some(13), false),
        (Some(10), None, Some(12), Some(13), false),
        (Some(10), Some(11), None, Some(13), false),
        (Some(10), Some(11), Some(12), None, false),
        (Some(12), Some(11), Some(12), Some(13), false),
        (Some(10), Some(13), Some(12), Some(14), false),
        (Some(10), Some(11), Some(14), Some(13), false),
    ] {
        let d = RefusalDiagnostics::new();
        let token = d.acquired_at(Site { code: 4, line: 29 }, acquired);
        d.refused(7, started, returned);
        assert!(!d.snapshot().unwrap().holder_interval_covers_failed_try);
        d.released(token, ended);
        assert_eq!(
            d.snapshot().unwrap().holder_interval_covers_failed_try,
            covered
        );
    }
    let missing = RefusalDiagnostics::new();
    missing.refused(1, Some(2), Some(3));
    assert!(missing.snapshot().unwrap().holder.is_none());
    let token = missing.acquired_at(Site { code: 3, line: 137 }, Some(4));
    missing.refused(2, Some(5), Some(6));
    missing.released(token, Some(7));
    assert!(missing.snapshot().unwrap().holder.is_none());
}

#[test]
fn pure_empty_and_exhausted_diagnostics_cannot_replace_first_refusal() {
    let d = RefusalDiagnostics::new();
    assert!(d.snapshot().is_none());
    d.refused(0, Some(1), Some(2));
    assert!(d.snapshot().is_none());
    d.next.store(u64::MAX, Ordering::Relaxed);
    let token = d.acquired_at(Site { code: 1, line: 1 }, Some(3));
    assert_eq!(token, 0);
    d.refused(2, Some(4), Some(5));
    d.released(token, Some(6));
    let snapshot = d.snapshot().unwrap();
    assert!(snapshot.holder.is_none());
    let value = serde_json::to_value(snapshot).unwrap();
    assert_eq!(
        value["scope"],
        "actual_input_registry_try_lock_refusal_only"
    );
    for key in [
        "native_credit",
        "canonical_current_owner_verified",
        "physical_send_verified",
        "full128_owner_evidence_complete",
    ] {
        assert!(value.get(key).is_none());
    }
}
