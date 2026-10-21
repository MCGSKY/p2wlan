//! Poll the actual bounded send against its real epoch gate; no physical I/O.
use super::super::test_support::*;
use super::*;
use crate::config::Config;
use crate::dataplane_resources::{BufferStage, ResidencyStage, ResourceCapture};

fn packet() -> OutboundPacket {
    OutboundPacket {
        room_authorization: None,
        peer_id: "peer-a".into(),
        dst_ip: "10.20.0.2".into(),
        packet: Ipv4Packet::build_icmp_echo_request(
            "10.20.0.1".parse().unwrap(),
            "10.20.0.2".parse().unwrap(),
            3,
            4,
            b"prepared-epoch-storage",
        ),
        trace: None,
    }
}

fn assert_drained(capture: &ResourceCapture) {
    let residency = capture.residency_snapshot();
    assert!(residency.valid && residency.coherent);
    assert_eq!(residency.gap_bits, 0);
    assert_eq!(residency.total.unwrap().live_buffers, 0);
    for stage in [
        BufferStage::ActiveOriginal,
        BufferStage::RetryPlaintext,
        BufferStage::PreparationPlaintext,
        BufferStage::SerializedWire,
    ] {
        assert_eq!(capture.snapshot().buffer(stage).live_buffers, 0);
    }
}

async fn exercise(mode: u8) {
    let capture = ResourceCapture::new([0x95 + mode; 16]);
    let peers = PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    peers
        .add_peer(&test_peer("peer-a", "127.0.0.1:41000".parse().unwrap()))
        .await;
    let (session, mut remote) = establish_sessions();
    let (transport, mut receiver) = WireGuardTransport::new();
    let transport = transport.with_resource_capture(capture.clone()).unwrap();
    assert!(!transport.add_session("peer-a", session).await);
    let original = packet();
    let len = original.packet.len() as u64;
    let gate = peers.network_epoch_gate();
    let epoch = gate.lock().await;
    let udps = RwLock::new(None);
    let relays = RwLock::new(None);
    let generation = peers.current_network_generation_sync();
    let deadline = Instant::now()
        + if mode == 1 {
            Duration::from_millis(250)
        } else {
            Duration::from_secs(2)
        };
    // Queue the real generation writer first. Polling send first would give
    // the fair mutex's reserved turn to an unpolled future, deadlocking this
    // test driver rather than exercising the generation fence.
    let mut advance =
        Box::pin(peers.advance_network_generation("prepared buffer is not generation authority"));
    if mode == 2 {
        assert!(matches!(
            futures_util::poll!(advance.as_mut()),
            std::task::Poll::Pending
        ));
    }
    let mut attempt = Box::pin(encrypt_then_send_with_deadline(
        original.clone(),
        &transport,
        &peers,
        generation,
        true,
        &udps,
        &relays,
        false,
        Some(deadline),
        None,
    ));
    assert!(matches!(
        futures_util::poll!(attempt.as_mut()),
        std::task::Poll::Pending
    ));
    assert!(transport
        .try_acquire_outbound_emit_guard("peer-a")
        .is_none());
    drop(transport.hold_session_registry_for_test().await);
    let live = capture.residency_snapshot();
    assert!(live.valid && live.coherent);
    assert_eq!(live.gap_bits, 0);
    assert_eq!(live.unknown_bits, 1); // Fixture enters at the actual send boundary.
    assert_eq!(live.total.unwrap().live_buffers, 4);
    assert_eq!(live.total.unwrap().len_bytes, 4 * len + 32);
    let buffers = capture.snapshot();
    assert_eq!(
        buffers
            .buffer(BufferStage::PreparationPlaintext)
            .live_buffers,
        2
    );
    assert_eq!(
        buffers.buffer(BufferStage::PreparationPlaintext).len,
        2 * len + 32
    );
    assert_eq!(
        live.stage(ResidencyStage::SerializedWire)
            .unwrap()
            .live_buffers,
        0
    );
    assert_eq!(buffers.buffer(BufferStage::SerializedWire).live_buffers, 0);
    if mode == 2 {
        drop(epoch);
        assert_ne!(
            tokio::time::timeout(Duration::from_secs(2), advance.as_mut())
                .await
                .unwrap(),
            generation
        );
        let outcome = attempt.await;
        assert!(matches!(
            outcome,
            EncryptSendOutcome::Retryable {
                reason_code: REASON_OUTBOUND_GENERATION_CHANGED,
                ..
            }
        ));
    } else {
        if mode == 1 {
            let outcome = tokio::time::timeout(Duration::from_secs(2), attempt.as_mut())
                .await
                .unwrap();
            assert!(matches!(
                outcome,
                EncryptSendOutcome::Retryable {
                    reason_code: REASON_OUTBOUND_ADMISSION_TIMEOUT,
                    ..
                }
            ));
            assert!(Instant::now() >= deadline);
        }
        drop(attempt);
        drop(epoch);
    }
    assert_drained(&capture);
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    let emit = transport.acquire_outbound_emit_guard("peer-a").await;
    let encrypted = transport
        .encrypt_outbound_with_emit_guard(original.clone())
        .await
        .unwrap()
        .unwrap();
    drop(emit);
    assert_eq!(
        crate::transport::wire_counter(&encrypted.wire_bytes),
        Some(0)
    );
    assert_eq!(
        remote.decrypt_from_bytes(&encrypted.wire_bytes).unwrap(),
        original.packet
    );
    assert_drained(&capture);
}

#[tokio::test]
async fn prepared_send_cancelled_epoch_wait_releases_storage_and_original_emit() {
    exercise(0).await;
}

#[tokio::test]
async fn prepared_send_original_deadline_releases_epoch_wait_without_counter_or_handoff() {
    exercise(1).await;
}

#[tokio::test]
async fn prepared_send_generation_change_rejects_storage_before_counter_or_handoff() {
    exercise(2).await;
}
