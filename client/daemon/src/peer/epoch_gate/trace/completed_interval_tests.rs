//! Real gate controls. Recorded intervals never supply read/Full/owner facts.
use super::*;
use crate::peer::NetworkEpochGate;
use std::sync::Arc;
use std::time::Duration;

fn labels(sequence: u32) -> EpochTryContext {
    EpochTryContext {
        capture_owner: 7,
        capture_id: [1; 16],
        run: [2; 16],
        round: [3; 16],
        request_nonce: [4; 16],
        sequence,
        protocol: "tcp",
        kind: "request",
        first_read_ordinal: 0,
        read_peer_input_ordinal: Some(33),
    }
}
fn snapshot(lease: &crate::peer::epoch_gate::EpochTraceLease) -> serde_json::Value {
    let value = serde_json::to_value(lease.read_peer_snapshot().unwrap()).unwrap();
    for k in [
        "native_os_write_verified",
        "physical_send_verified",
        "canonical_current_owner_verified",
    ] {
        assert_eq!(value[k], false);
    }
    value
}

#[tokio::test]
async fn epoch_trace_completed_holder_survives_release_before_first_refusal_record() {
    let gate = Arc::new(NetworkEpochGate::new(()));
    let lease = gate.capture_diagnostics(7, [1; 16], Instant::now() + Duration::from_secs(30));
    let trace = gate.trace.get().unwrap();
    let held = gate.lock().await;
    let started = now_ns();
    assert!(gate.inner.try_lock().is_err()); // One real original mutex try.
    let returned = now_ns();
    drop(held); // Actual unlock precedes publication of the diagnostic slot.
    trace.refused(labels(0), started, returned);
    let result = snapshot(&lease);
    assert_eq!(
        result["last_completed_holder"]["release_completion_observed"],
        true
    );
    if cfg!(target_os = "linux") {
        assert_eq!(
            result["last_completed_holder_interval_covers_failed_try"],
            true
        );
    } else {
        assert!(result["last_completed_holder"]["acquired_observed_monotonic_ns"].is_null());
        assert_eq!(
            result["last_completed_holder_interval_covers_failed_try"],
            false
        );
    }
    let before = result.to_string();
    let later = gate.lock().await;
    drop(later);
    assert_eq!(snapshot(&lease).to_string(), before);
}

#[tokio::test]
async fn epoch_trace_completed_interval_never_refills_an_existing_first_refusal() {
    let gate = Arc::new(NetworkEpochGate::new(()));
    let lease = gate.capture_diagnostics(7, [1; 16], Instant::now() + Duration::from_secs(30));
    let held = gate.lock().await;
    assert!(gate.try_lock_original(Some(labels(1))).is_err());
    assert!(snapshot(&lease)["last_completed_holder"].is_null());
    drop(held);
    let result = snapshot(&lease);
    assert!(result["last_completed_holder"].is_null());
    assert_eq!(result["holder"]["release_completion_observed"], true);
}

#[tokio::test]
async fn epoch_trace_completed_past_interval_cannot_claim_a_later_actual_try() {
    let gate = Arc::new(NetworkEpochGate::new(()));
    let lease = gate.capture_diagnostics(7, [1; 16], Instant::now() + Duration::from_secs(30));
    let past = gate.lock().await;
    let old = past.token.unwrap();
    drop(past);
    let held = gate.lock().await;
    assert!(gate.try_lock_original(Some(labels(2))).is_err());
    let result = snapshot(&lease);
    assert_eq!(result["last_completed_holder"]["token"], old);
    assert_eq!(
        result["last_completed_holder_interval_covers_failed_try"],
        false
    );
    assert_ne!(result["holder"]["token"], old);
    drop(held);
}

#[tokio::test]
async fn epoch_trace_completed_single_slot_overwrite_stays_noncovering_not_refilled() {
    let gate = Arc::new(NetworkEpochGate::new(()));
    let lease = gate.capture_diagnostics(7, [1; 16], Instant::now() + Duration::from_secs(30));
    let trace = gate.trace.get().unwrap();
    let held = gate.lock().await;
    let started = now_ns();
    assert!(gate.inner.try_lock().is_err());
    let returned = now_ns();
    drop(held);
    let later = gate.lock().await;
    let token = later.token.unwrap();
    drop(later);
    trace.refused(labels(3), started, returned);
    let result = snapshot(&lease);
    assert_eq!(result["last_completed_holder"]["token"], token);
    assert_eq!(
        result["last_completed_holder_interval_covers_failed_try"],
        false
    );
    assert_eq!(result["holder_interval_covers_failed_try"], false);
}

#[tokio::test]
async fn epoch_trace_completed_foreign_context_never_claims_the_original_slot() {
    let gate = Arc::new(NetworkEpochGate::new(()));
    let lease = gate.capture_diagnostics(7, [1; 16], Instant::now() + Duration::from_secs(30));
    let trace = gate.trace.get().unwrap();
    let held = gate.lock().await;
    let started = now_ns();
    assert!(gate.inner.try_lock().is_err());
    let returned = now_ns();
    drop(held);
    trace.refused(
        EpochTryContext {
            capture_owner: 8,
            ..labels(4)
        },
        started,
        returned,
    );
    assert!(lease.read_peer_snapshot().is_none());
    trace.refused(labels(4), started, returned);
    assert_eq!(
        snapshot(&lease)["last_completed_holder"]["release_completion_observed"],
        true
    );
}

#[tokio::test]
async fn epoch_trace_completed_unobserved_preexisting_holder_stays_unknown() {
    let gate = Arc::new(NetworkEpochGate::new(()));
    let held = gate.lock().await;
    let lease = gate.capture_diagnostics(7, [1; 16], Instant::now() + Duration::from_secs(30));
    let trace = gate.trace.get().unwrap();
    let started = now_ns();
    assert!(gate.inner.try_lock().is_err());
    let returned = now_ns();
    drop(held);
    trace.refused(labels(5), started, returned);
    let result = snapshot(&lease);
    assert!(result["holder"].is_null() && result["last_completed_holder"].is_null());
    assert_eq!(
        result["last_completed_holder_interval_covers_failed_try"],
        false
    );
}

#[tokio::test]
async fn epoch_trace_completed_late_phase_cannot_become_the_failed_try_phase() {
    let gate = Arc::new(NetworkEpochGate::new(()));
    let lease = gate.capture_diagnostics(7, [1; 16], Instant::now() + Duration::from_secs(30));
    let trace = gate.trace.get().unwrap();
    let held = gate.lock().await;
    let started = now_ns();
    assert!(gate.inner.try_lock().is_err());
    let returned = now_ns();
    held.note_outbound_phase(OutboundEpochPhase::DirectBudget);
    drop(held);
    trace.refused(labels(6), started, returned);
    let result = snapshot(&lease);
    assert_eq!(
        result["last_completed_holder"]["phase"]["source"],
        "direct_budget"
    );
    assert_eq!(
        result["last_completed_holder"]["phase"]["interval_covers_failed_try"],
        false
    );
    assert_eq!(
        result["last_completed_holder_interval_covers_failed_try"],
        cfg!(target_os = "linux")
    );
}

#[tokio::test]
async fn epoch_trace_completed_observation_retains_no_gate_or_worker_owner() {
    let gate = Arc::new(NetworkEpochGate::new(()));
    let weak = Arc::downgrade(&gate);
    let lease = gate.capture_diagnostics(7, [1; 16], Instant::now() + Duration::from_secs(30));
    let trace = gate.trace.get().unwrap();
    let held = gate.lock().await;
    let started = now_ns();
    assert!(gate.inner.try_lock().is_err());
    let returned = now_ns();
    drop(held);
    trace.refused(labels(7), started, returned);
    let result = snapshot(&lease);
    drop(gate);
    assert!(weak.upgrade().is_none());
    assert!(lease.read_peer_snapshot().is_none());
    assert_eq!(result["canonical_current_owner_verified"], false);
}
