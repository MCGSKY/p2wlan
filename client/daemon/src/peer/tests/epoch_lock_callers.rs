//! Actual shared-gate contention checks. Synthetic labels provide no
//! KernelRead, Full, system TUN, final owner, or once credit.
use super::*;
use crate::peer::epoch_gate::EpochTraceLease;
use std::sync::Arc;

fn fixture() -> (Arc<PeerManager>, Arc<NetworkEpochGate>, EpochTraceLease) {
    let peers = Arc::new(PeerManager::new(test_config()));
    let gate = peers.network_epoch_gate();
    let lease = gate.capture_diagnostics(17, [1; 16], Instant::now() + Duration::from_secs(30));
    (peers, gate, lease)
}

fn assert_original_caller(
    gate: &NetworkEpochGate,
    lease: &EpochTraceLease,
    expected_line: u32,
    original_read: bool,
) {
    let context = EpochTryContext {
        capture_owner: 17,
        capture_id: [1; 16],
        run: [2; 16],
        round: [3; 16],
        request_nonce: [4; 16],
        sequence: 0,
        protocol: "tcp",
        kind: "request",
        first_read_ordinal: if original_read { 0 } else { 7 },
        read_peer_input_ordinal: original_read.then_some(7),
    };
    assert!(gate.try_lock_original(Some(context)).is_err());
    let snapshot = if original_read {
        lease.read_peer_snapshot()
    } else {
        lease.snapshot()
    };
    let value = serde_json::to_value(snapshot.unwrap()).unwrap();
    assert_eq!(
        value["holder"]["source_line"].as_u64(),
        Some(u64::from(expected_line)),
        "shared helper hid its actual caller: {value}"
    );
    // This test file intentionally has no production site classification.
    assert_eq!(value["holder"]["source"], "unclassified");
    assert_eq!(value["holder"]["release_completion_observed"], false);
    for name in [
        "native_os_write_verified",
        "physical_send_verified",
        "canonical_current_owner_verified",
    ] {
        assert_eq!(value[name], false);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn write_helper_retains_original_caller_when_first_polled() {
    let (peers, gate, lease) = fixture();
    let expected_line = line!() + 1;
    let future = peers.lock_epoch_and_connections_write();
    let (epoch, connections) = future.await;
    assert_original_caller(&gate, &lease, expected_line, false);
    drop(connections);
    drop(epoch);
}

#[tokio::test(flavor = "current_thread")]
async fn read_helper_retains_original_caller_when_first_polled() {
    let (peers, gate, lease) = fixture();
    let expected_line = line!() + 1;
    let future = peers.lock_epoch_and_connections_read();
    let (epoch, connections) = future.await;
    assert_original_caller(&gate, &lease, expected_line, true);
    drop(connections);
    drop(epoch);
}

#[tokio::test(flavor = "current_thread")]
async fn write_helper_preserves_caller_across_real_connection_wait() {
    let (peers, gate, lease) = fixture();
    let reader = peers.connections.read().await;
    let expected_line = line!() + 1;
    let future = peers.lock_epoch_and_connections_write();
    tokio::pin!(future);
    assert!(futures_util::poll!(future.as_mut()).is_pending());
    // The original algorithm releases epoch before its fair writer wait.
    assert!(gate.try_lock().is_ok());
    drop(reader);
    let (epoch, connections) = future.await;
    assert_original_caller(&gate, &lease, expected_line, false);
    drop(connections);
    drop(epoch);
}

#[tokio::test(flavor = "current_thread")]
async fn read_helper_preserves_caller_across_real_connection_wait() {
    let (peers, gate, lease) = fixture();
    let writer = peers.connections.write().await;
    let expected_line = line!() + 1;
    let future = peers.lock_epoch_and_connections_read();
    tokio::pin!(future);
    assert!(futures_util::poll!(future.as_mut()).is_pending());
    assert!(gate.try_lock().is_ok());
    drop(writer);
    let (epoch, connections) = future.await;
    assert_original_caller(&gate, &lease, expected_line, true);
    drop(connections);
    drop(epoch);
}

#[tokio::test(flavor = "current_thread")]
async fn independent_unpolled_futures_keep_their_own_caller_and_acquire_nothing() {
    let (peers, gate, lease) = fixture();
    let expected_line = line!() + 1;
    let first = peers.lock_epoch_and_connections_write();
    let later = peers.lock_epoch_and_connections_read();
    assert!(gate.try_lock().is_ok());
    assert!(peers.connections.try_write().is_ok());
    drop(later);
    let (epoch, connections) = first.await;
    assert_original_caller(&gate, &lease, expected_line, false);
    drop(connections);
    drop(epoch);
}
