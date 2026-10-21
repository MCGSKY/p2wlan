//! Actual canonical writer/epoch contention. Diagnostics here grant no
//! KernelRead, Full, native owner or once permission.
use super::*;

const PEER: &str = "authenticated-learning-owner";

async fn fixture() -> PeerManager {
    let peers = PeerManager::new(test_config());
    peers
        .add_peer(&test_peer(PEER, "127.0.0.1:41000".parse().unwrap()))
        .await;
    peers
}

#[tokio::test]
async fn learning_waits_for_actual_connection_writer_without_holding_epoch() {
    let peers = fixture().await;
    let writer = peers.connections.write().await;
    let endpoint = "127.0.0.1:42000".parse().unwrap();
    let mut learning = Box::pin(peers.learn_authenticated_endpoint(PEER, endpoint));
    assert!(futures_util::poll!(learning.as_mut()).is_pending());
    assert!(peers.network_epoch_gate().try_lock().is_ok());
    drop(writer);
    assert!(tokio::time::timeout(Duration::from_secs(2), learning)
        .await
        .unwrap());
    let connections = peers.connections.read().await;
    assert_eq!(connections[PEER].endpoint, Some(endpoint));
    assert!(connections[PEER].candidates.contains(&endpoint.to_string()));
}

#[tokio::test]
async fn learning_after_real_writer_wait_uses_the_current_generation() {
    let peers = fixture().await;
    let reader = peers.connections.read().await;
    let endpoint = "127.0.0.1:42001".parse().unwrap();
    let old_generation = peers.current_network_generation_sync();
    let mut learning = Box::pin(peers.learn_authenticated_endpoint(PEER, endpoint));
    assert!(futures_util::poll!(learning.as_mut()).is_pending());
    let mut advance = Box::pin(peers.advance_network_generation("learning writer wait"));
    assert!(futures_util::poll!(advance.as_mut()).is_pending());
    drop(reader);
    // Poll both actual queued owners: the fair writer reservation must not be
    // left in an unpolled future while waiting only for the generation writer.
    let (learned, generation) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(learning, advance)
    })
    .await
    .unwrap();
    assert!(learned && generation > old_generation);
    let connections = peers.connections.read().await;
    let pair = connections[PEER]
        .candidate_pairs
        .iter()
        .find(|p| p.remote_endpoint == endpoint)
        .unwrap();
    assert_eq!(pair.local_generation, generation);
}

#[tokio::test]
async fn learning_trace_classifies_actual_owner_and_in_epoch_entry_keeps_same_gate() {
    let peers = fixture().await;
    let gate = peers.network_epoch_gate();
    let trace = gate.capture_diagnostics(17, [1; 16], Instant::now() + Duration::from_secs(30));
    let recovery = peers.recovery_epochs.write().await;
    let endpoint = "127.0.0.1:42002".parse().unwrap();
    let mut learning = Box::pin(peers.learn_authenticated_endpoint(PEER, endpoint));
    assert!(futures_util::poll!(learning.as_mut()).is_pending());
    let context = EpochTryContext {
        capture_owner: 17,
        capture_id: [1; 16],
        run: [2; 16],
        round: [3; 16],
        request_nonce: [4; 16],
        sequence: 0,
        protocol: "tcp",
        kind: "request",
        first_read_ordinal: 1,
        read_peer_input_ordinal: None,
    };
    assert!(gate.try_lock_original(Some(context)).is_err());
    let refusal = serde_json::to_value(trace.snapshot().unwrap()).unwrap();
    assert_eq!(
        refusal["holder"]["source"],
        "authenticated_endpoint_learning"
    );
    for name in [
        "native_os_write_verified",
        "physical_send_verified",
        "canonical_current_owner_verified",
    ] {
        assert_eq!(refusal[name], false);
    }
    drop(recovery);
    assert!(tokio::time::timeout(Duration::from_secs(2), learning)
        .await
        .unwrap());
    let epoch = gate.lock().await;
    assert!(tokio::time::timeout(
        Duration::from_secs(2),
        peers.learn_authenticated_endpoint_in_epoch(
            &epoch,
            PEER,
            "127.0.0.1:42003".parse().unwrap(),
        )
    )
    .await
    .unwrap());
    assert!(gate.try_lock().is_err());
}
