//! Actual epoch-mutex and negative metadata only. No KernelRead, Full,
//! SystemTun write, native owner permit or positive credit is constructed.
use crate::peer::{EpochTryContext, NetworkEpochGate, OutboundEpochPhase};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn context() -> EpochTryContext {
    EpochTryContext {
        capture_owner: 7,
        capture_id: [1; 16],
        run: [2; 16],
        round: [3; 16],
        request_nonce: [4; 16],
        sequence: 5,
        protocol: "tcp",
        kind: "response",
        first_read_ordinal: 9,
        read_peer_input_ordinal: None,
    }
}
fn no_credit(value: &Value) {
    for key in [
        "native_os_write_verified",
        "physical_send_verified",
        "canonical_current_owner_verified",
    ] {
        assert_eq!(value[key], false);
    }
}

#[tokio::test]
async fn epoch_phase_actual_guard_first_refusal_retains_phase_after_later_transitions() {
    let gate = Arc::new(NetworkEpochGate::new(()));
    let lease = gate.capture_diagnostics(7, [1; 16], Instant::now() + Duration::from_secs(1));
    let held = gate.lock().await;
    held.note_outbound_phase(OutboundEpochPhase::Encryption);
    let mut input = context();
    input.first_read_ordinal = 0;
    input.read_peer_input_ordinal = Some(4);
    assert!(gate.try_lock_original(Some(input)).is_err());
    let before = serde_json::to_value(lease.read_peer_snapshot().unwrap()).unwrap();
    assert_eq!(before["holder"]["phase"]["source"], "encryption");
    assert_eq!(before["holder"]["phase"]["version"], 1);
    assert_eq!(
        before["holder"]["phase"]["interval_covers_failed_try"],
        false
    );
    held.note_outbound_phase(OutboundEpochPhase::PhysicalMetadata);
    drop(held);
    let after = serde_json::to_value(lease.read_peer_snapshot().unwrap()).unwrap();
    assert_eq!(after["holder"]["phase"]["source"], "encryption");
    assert_eq!(after["holder"]["phase"]["version"], 1);
    assert_eq!(after["holder"]["release_completion_observed"], true);
    assert_eq!(after["original_input_read_ordinal"], 4);
    let phase_start = after["holder"]["phase"]["started_observed_monotonic_ns"].as_u64();
    let try_start = after["failed_try_started_monotonic_ns"].as_u64();
    let covers = after["holder_interval_covers_failed_try"] == true
        && matches!((phase_start, try_start), (Some(a), Some(b)) if a < b);
    assert_eq!(
        after["holder"]["phase"]["interval_covers_failed_try"],
        covers
    );
    no_credit(&after);
    let next = gate.try_lock().unwrap();
    next.note_outbound_phase(OutboundEpochPhase::DirectFirst);
    assert!(gate.try_lock_original(Some(input)).is_err());
    drop(next);
    assert_eq!(
        serde_json::to_value(lease.read_peer_snapshot().unwrap()).unwrap(),
        after
    );
    assert!(gate.try_lock().is_ok());
}

#[tokio::test]
async fn epoch_phase_absent_at_refusal_is_never_backfilled_or_enabled_by_a_stamp() {
    let disabled = Arc::new(NetworkEpochGate::new(()));
    let held = disabled.lock().await;
    held.note_outbound_phase(OutboundEpochPhase::Path);
    assert!(disabled.try_lock_original(Some(context())).is_err());
    drop(held);
    let lease = disabled.capture_diagnostics(7, [1; 16], Instant::now() + Duration::from_secs(1));
    assert!(lease.snapshot().is_none());
    let held = disabled.lock().await;
    assert!(disabled.try_lock_original(Some(context())).is_err());
    held.note_outbound_phase(OutboundEpochPhase::OriginalEcho);
    drop(held);
    let value = serde_json::to_value(lease.snapshot().unwrap()).unwrap();
    assert!(value["holder"].get("phase").is_none());
    no_credit(&value);
}

#[tokio::test]
async fn epoch_guard_metadata_default_disabled_cannot_reconstruct_an_earlier_refusal() {
    let gate = Arc::new(NetworkEpochGate::new(()));
    let disabled = gate.capture_diagnostics(0, [1; 16], Instant::now() + Duration::from_secs(1));
    let held = gate.lock().await;
    assert!(gate.try_lock_original(Some(context())).is_err());
    assert!(disabled.snapshot().is_none());
    drop(held);
    assert!(gate.try_lock().is_ok());
    let lease = gate.capture_diagnostics(7, [1; 16], Instant::now() + Duration::from_secs(1));
    assert!(lease.snapshot().is_none());
}

#[tokio::test]
async fn epoch_guard_metadata_first_actual_borrowed_refusal_and_release_are_not_replaced() {
    let gate = Arc::new(NetworkEpochGate::new(()));
    let lease = gate.capture_diagnostics(7, [1; 16], Instant::now() + Duration::from_secs(1));
    let held = gate.lock().await;
    assert!(gate.try_lock_original(Some(context())).is_err());
    let open = serde_json::to_value(lease.snapshot().unwrap()).unwrap();
    assert_eq!(open["holder"]["release_completion_observed"], false);
    assert_eq!(open["holder_interval_covers_failed_try"], false);
    drop(held); // Actual unlock precedes metadata completion.
    assert!(gate.try_lock().is_ok());
    let closed = serde_json::to_value(lease.snapshot().unwrap()).unwrap();
    assert_eq!(closed["holder"]["release_completion_observed"], true);
    assert_eq!(closed["first_read_ordinal"], 9);
    assert_eq!(closed["request_nonce"], "04".repeat(16));
    no_credit(&closed);
    let held = gate.try_lock().unwrap();
    let mut later = context();
    later.request_nonce = [5; 16];
    later.sequence = 6;
    assert!(gate.try_lock_original(Some(later)).is_err());
    drop(held);
    assert_eq!(
        serde_json::to_value(lease.snapshot().unwrap()).unwrap(),
        closed
    );
}

#[tokio::test]
async fn epoch_guard_metadata_owned_cancellation_releases_real_mutex_and_cannot_rearm_scope() {
    let gate = Arc::new(NetworkEpochGate::new(()));
    let lease = gate.capture_diagnostics(7, [1; 16], Instant::now() + Duration::from_secs(1));
    let task_gate = gate.clone();
    let (ready, received) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _held = task_gate.try_lock_owned().unwrap();
        ready.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    received.await.unwrap();
    assert!(gate.try_lock_original(Some(context())).is_err());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(gate.try_lock().is_ok());
    let value = serde_json::to_value(lease.snapshot().unwrap()).unwrap();
    assert_eq!(value["holder"]["release_completion_observed"], true);
    no_credit(&value);
    lease.deactivate();
    let replacement = gate.capture_diagnostics(8, [2; 16], Instant::now() + Duration::from_secs(1));
    assert!(replacement.snapshot().is_none());
    assert_eq!(
        serde_json::to_value(lease.snapshot().unwrap()).unwrap(),
        value
    );
}

#[tokio::test]
async fn epoch_guard_metadata_wrong_scope_expiry_and_token_exhaustion_remain_unknown() {
    let gate = Arc::new(NetworkEpochGate::new(()));
    let lease = gate.capture_diagnostics(7, [1; 16], Instant::now() + Duration::from_secs(1));
    let held = gate.try_lock().unwrap();
    let mut foreign = context();
    foreign.capture_id = [2; 16];
    assert!(gate.try_lock_original(Some(foreign)).is_err());
    assert!(lease.snapshot().is_none());
    drop(held);
    gate.exhaust_diagnostic_tokens();
    let held = gate.try_lock().unwrap();
    assert!(gate.try_lock_original(Some(context())).is_err());
    drop(held);
    let value = serde_json::to_value(lease.snapshot().unwrap()).unwrap();
    assert_eq!(value["holder"], json!(null));
    assert_eq!(value["holder_interval_covers_failed_try"], false);
    no_credit(&value);
    let expired_gate = Arc::new(NetworkEpochGate::new(()));
    let expired = expired_gate.capture_diagnostics(7, [1; 16], Instant::now());
    let held = expired_gate.try_lock().unwrap();
    assert!(expired_gate.try_lock_original(Some(context())).is_err());
    assert!(expired.snapshot().is_none());
    drop(held);
}
