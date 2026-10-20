//! Actual mutex/weak ownership controls. Labels and clocks grant no IO facts.
use super::*;
use crate::peer::EpochTryContext;
use crate::transport::WireGuardTransport;
use futures_util::poll;
use std::task::Poll;
use std::time::{Duration, Instant};

fn trace() -> Arc<EmitTrace> {
    EmitTrace::new(7, [1; 16], Instant::now() + Duration::from_secs(30))
}
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
        first_read_ordinal: 34,
        read_peer_input_ordinal: None,
    }
}
fn snapshot(trace: &EmitTrace) -> serde_json::Value {
    let value = serde_json::to_value(trace.snapshot().unwrap()).unwrap();
    for flag in [
        "native_os_write_verified",
        "physical_send_verified",
        "canonical_current_owner_verified",
    ] {
        assert_eq!(value[flag], false);
    }
    if !cfg!(target_os = "linux") {
        assert!(value["failed_try_started_monotonic_ns"].is_null());
        assert_eq!(value["holder_interval_covers_failed_try"], false);
    }
    value
}

#[tokio::test]
async fn emit_trace_borrowed_holder_and_first_actual_refusal_survive_peer_incarnation() {
    let (transport, _) = WireGuardTransport::new();
    let trace = trace();
    transport.bind_original_emit_diagnostics(&trace);
    let gate = transport.outbound_emit_lock("peer-a").await;
    let weak = Arc::downgrade(&gate);
    let line = line!() + 1;
    let held = gate.lock().await;
    assert!(gate
        .clone()
        .try_lock_original(trace.context(labels(7)))
        .is_err());
    let before = snapshot(&trace);
    assert_eq!(before["sequence"], 7);
    assert_eq!(before["first_read_ordinal"], 34);
    assert_eq!(before["request_nonce"], hex::encode([4; 16]));
    assert_eq!(before["holder"]["source_line"], line);
    assert_eq!(before["holder"]["release_completion_observed"], false);
    drop(held);
    let after = snapshot(&trace);
    assert_eq!(after["holder"]["release_completion_observed"], true);
    drop(gate);
    assert!(weak.upgrade().is_none());
    let next = transport.outbound_emit_lock("peer-b").await;
    let held = next.clone().lock_owned().await;
    assert!(next
        .clone()
        .try_lock_original(trace.context(labels(8)))
        .is_err());
    drop(held);
    assert_eq!(
        snapshot(&trace),
        after,
        "another peer/token cannot replace the first refusal"
    );
}

#[tokio::test]
async fn emit_trace_owned_guard_retains_only_its_original_weak_registry_incarnation() {
    let (transport, _) = WireGuardTransport::new();
    let trace = trace();
    transport.bind_original_emit_diagnostics(&trace);
    let held = transport.acquire_outbound_emit_guard("peer-a").await;
    let weak = transport.outbound_emit_locks.lock().await["peer-a"].clone();
    let gate = transport.outbound_emit_lock("peer-a").await;
    assert!(weak.ptr_eq(&Arc::downgrade(&gate)));
    assert!(gate
        .clone()
        .try_lock_original(trace.context(labels(3)))
        .is_err());
    drop(gate);
    assert!(weak.upgrade().is_some());
    drop(held);
    assert!(weak.upgrade().is_none());
    assert_eq!(
        snapshot(&trace)["holder"]["release_completion_observed"],
        true
    );
    let next = transport.outbound_emit_lock("peer-a").await;
    assert!(!weak.ptr_eq(&Arc::downgrade(&next)));
    assert!(
        next.holder.get().is_none(),
        "creating a gate cannot invent a holder"
    );
    assert!(next.try_lock_owned().is_ok());
}

#[tokio::test]
async fn emit_trace_disabled_or_wrong_transport_does_not_observe_or_change_real_contention() {
    let (transport, _) = WireGuardTransport::new();
    let foreign = trace();
    let gate = transport.outbound_emit_lock("peer-a").await;
    let held = gate.lock().await;
    assert!(gate.holder.get().is_none());
    assert!(gate
        .clone()
        .try_lock_original(foreign.context(labels(1)))
        .is_err());
    assert!(foreign.snapshot().is_none());
    let own = trace();
    transport.bind_original_emit_diagnostics(&own);
    assert!(gate
        .clone()
        .try_lock_original(foreign.context(labels(2)))
        .is_err());
    assert!(own.snapshot().is_none() && foreign.snapshot().is_none());
    drop(held);
    assert!(gate.try_lock_owned().is_ok());
}

#[tokio::test]
async fn emit_trace_preexisting_unobserved_holder_stays_unknown_after_later_success() {
    let (transport, _) = WireGuardTransport::new();
    let gate = transport.outbound_emit_lock("peer-a").await;
    let held = gate.clone().lock_owned().await;
    let trace = trace();
    transport.bind_original_emit_diagnostics(&trace);
    assert!(gate
        .clone()
        .try_lock_original(trace.context(labels(1)))
        .is_err());
    let first = snapshot(&trace);
    assert!(first["holder"].is_null());
    drop(held);
    let later = gate.clone().lock_owned().await;
    assert!(gate
        .clone()
        .try_lock_original(trace.context(labels(2)))
        .is_err());
    drop(later);
    assert_eq!(snapshot(&trace), first);
}

#[tokio::test]
async fn emit_trace_cancelled_original_waiter_never_becomes_a_holder() {
    let (transport, _) = WireGuardTransport::new();
    let trace = trace();
    transport.bind_original_emit_diagnostics(&trace);
    let gate = transport.outbound_emit_lock("peer-a").await;
    let held = gate.clone().lock_owned().await;
    assert!(gate
        .clone()
        .try_lock_original(trace.context(labels(1)))
        .is_err());
    let first = snapshot(&trace);
    let token = first["holder"]["token"].as_u64().unwrap();
    let mut waiter = Box::pin(transport.acquire_outbound_emit_guard("peer-a"));
    assert!(matches!(poll!(&mut waiter), Poll::Pending));
    drop(waiter);
    assert_eq!(snapshot(&trace), first);
    assert!(gate
        .clone()
        .try_lock_original(trace.context(labels(1)))
        .is_err());
    assert_eq!(snapshot(&trace)["holder"]["token"], token);
    drop(held);
    assert!(gate.try_lock_owned().is_ok());
}

#[tokio::test]
async fn emit_trace_retirement_expiry_bad_labels_and_second_capture_never_rearm() {
    let (transport, _) = WireGuardTransport::new();
    let trace = trace();
    transport.bind_original_emit_diagnostics(&trace);
    let gate = transport.outbound_emit_lock("peer-a").await;
    let held = gate.lock().await;
    for bad in [
        EpochTryContext {
            capture_owner: 8,
            ..labels(1)
        },
        EpochTryContext {
            capture_id: [9; 16],
            ..labels(1)
        },
        EpochTryContext {
            first_read_ordinal: 0,
            ..labels(1)
        },
        EpochTryContext {
            read_peer_input_ordinal: Some(34),
            ..labels(1)
        },
    ] {
        assert!(trace.context(bad).is_none());
    }
    let pending = trace.context(labels(1));
    trace.deactivate();
    assert!(gate.clone().try_lock_original(pending).is_err());
    assert!(trace.snapshot().is_none());
    let second = EmitTrace::new(7, [1; 16], Instant::now() + Duration::from_secs(30));
    transport.bind_original_emit_diagnostics(&second);
    assert!(gate
        .clone()
        .try_lock_original(second.context(labels(2)))
        .is_err());
    assert!(second.snapshot().is_none());
    let expired = EmitTrace::new(7, [1; 16], Instant::now());
    assert!(expired.context(labels(3)).is_none());
    drop(held);
    assert!(gate.try_lock_owned().is_ok());
}

#[tokio::test]
async fn emit_trace_history_keeps_no_actual_mutex_or_transport_owner_alive() {
    let (transport, _) = WireGuardTransport::new();
    let owners = transport.original_kernel_transport_owners();
    let trace = trace();
    transport.bind_original_emit_diagnostics(&trace);
    let gate = transport.outbound_emit_lock("peer-a").await;
    let weak = Arc::downgrade(&gate);
    let held = gate.clone().lock_owned().await;
    assert!(gate
        .clone()
        .try_lock_original(trace.context(labels(1)))
        .is_err());
    drop(held);
    let first = snapshot(&trace);
    drop(gate);
    drop(transport);
    assert!(weak.upgrade().is_none());
    assert!(owners.upgrade().is_none());
    assert_eq!(snapshot(&trace), first);
}

#[tokio::test(flavor = "current_thread")]
async fn emit_trace_producer_reuses_live_canonical_gate_without_busy_index() {
    let (transport, _) = WireGuardTransport::new();
    let gate = transport.outbound_emit_lock("producer-cache-peer").await;
    let registry = transport.outbound_emit_locks.lock().await;
    let reused = transport.try_outbound_emit_lock("producer-cache-peer");
    assert!(
        reused
            .as_ref()
            .is_some_and(|other| Arc::ptr_eq(other, &gate)),
        "a producer's live canonical gate must not depend on reentering the busy weak index"
    );
    let current = transport
        .original_kernel_transport_owners()
        .upgrade()
        .unwrap();
    assert!(
        matches!(
            current.try_emit_guard("producer-cache-peer", None),
            Err(crate::transport::OriginalKernelEmitFailure::Registry)
        ),
        "the original native guard must still make its real single registry try"
    );
    drop(registry);
    drop(reused);
    drop(gate);
}

#[tokio::test(flavor = "current_thread")]
async fn emit_trace_producer_cache_cannot_borrow_another_registry_or_peer() {
    let (transport, _) = WireGuardTransport::new();
    let (foreign, _) = WireGuardTransport::new();
    let gate = transport.outbound_emit_lock("cache-peer").await;
    let foreign_index = foreign.outbound_emit_locks.lock().await;
    assert!(foreign.try_outbound_emit_lock("cache-peer").is_none());
    drop(foreign_index);
    let same = transport.outbound_emit_lock("cache-peer").await;
    assert!(Arc::ptr_eq(&same, &gate));
    let index = transport.outbound_emit_locks.lock().await;
    assert!(transport.try_outbound_emit_lock("different-peer").is_none());
    drop(index);
}

#[tokio::test(flavor = "current_thread")]
async fn emit_trace_producer_cache_never_retains_a_gate_or_registry_owner() {
    let (transport, _) = WireGuardTransport::new();
    let gate = transport.outbound_emit_lock("cache-lifetime-peer").await;
    let old = Arc::downgrade(&gate);
    let registry = Arc::downgrade(&transport.outbound_emit_locks);
    drop(gate);
    assert!(old.upgrade().is_none());
    let next = transport.outbound_emit_lock("cache-lifetime-peer").await;
    assert!(!old.ptr_eq(&Arc::downgrade(&next)));
    drop(next);
    drop(transport);
    assert!(registry.upgrade().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn emit_trace_producer_cached_resource_still_uses_the_actual_counter_mutex() {
    let (transport, _) = WireGuardTransport::new();
    let gate = transport.outbound_emit_lock("cache-counter-peer").await;
    let held = gate.clone().lock_owned().await;
    let index = transport.outbound_emit_locks.lock().await;
    let same = transport
        .try_outbound_emit_lock("cache-counter-peer")
        .unwrap();
    assert!(Arc::ptr_eq(&same, &gate));
    assert!(same.clone().try_lock_owned().is_err());
    assert!(transport
        .try_acquire_outbound_emit_guard("cache-counter-peer")
        .is_none());
    drop(index);
    drop(held);
    assert!(same.try_lock_owned().is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn emit_trace_producer_cache_key_bound_never_changes_long_peer_lookup() {
    let (transport, _) = WireGuardTransport::new();
    let peer = "x".repeat(cache::MAX_CACHED_PEER_BYTES + 1);
    let gate = transport.outbound_emit_lock(&peer).await;
    let index = transport.outbound_emit_locks.lock().await;
    assert!(transport.try_outbound_emit_lock(&peer).is_none());
    drop(index);
    let again = transport.try_outbound_emit_lock(&peer).unwrap();
    assert!(Arc::ptr_eq(&gate, &again));
}

#[tokio::test(flavor = "current_thread")]
async fn emit_trace_producer_cache_has_one_entry_and_cannot_refill_an_evicted_peer() {
    let (transport, _) = WireGuardTransport::new();
    let first = transport.outbound_emit_lock("cache-first-peer").await;
    let second = transport.outbound_emit_lock("cache-second-peer").await;
    let index = transport.outbound_emit_locks.lock().await;
    assert!(Arc::ptr_eq(
        &transport
            .try_outbound_emit_lock("cache-second-peer")
            .unwrap(),
        &second
    ));
    assert!(transport
        .try_outbound_emit_lock("cache-first-peer")
        .is_none());
    drop(index);
    assert!(Arc::ptr_eq(
        &transport
            .try_outbound_emit_lock("cache-first-peer")
            .unwrap(),
        &first
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn emit_trace_producer_alias_and_native_guard_share_the_one_canonical_gate() {
    let (transport, _) = WireGuardTransport::new();
    let gate = transport.outbound_emit_lock("cache-native-peer").await;
    let current = transport
        .original_kernel_transport_owners()
        .upgrade()
        .unwrap();
    let native = current.try_emit_guard("cache-native-peer", None).unwrap();
    assert!(gate.clone().try_lock_owned().is_err());
    assert!(transport
        .try_acquire_outbound_emit_guard("cache-native-peer")
        .is_none());
    drop(native);
    assert!(transport
        .try_acquire_outbound_emit_guard("cache-native-peer")
        .is_some());
}
