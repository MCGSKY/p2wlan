use super::*;

pub(crate) async fn one_expiring_session_send_for_path_log_test(
    peers: &PeerManager,
    transport: &WireGuardTransport,
    peer_id: &str,
    deadline: Instant,
) -> bool {
    matches!(
        send::encrypt_then_send_with_deadline(
            OutboundPacket {
                room_authorization: None,
                peer_id: peer_id.to_owned(),
                dst_ip: "10.20.0.2".to_owned(),
                packet: vec![0; 20],
                trace: None,
            },
            transport,
            peers,
            peers.current_network_generation_sync(),
            false,
            &RwLock::new(None),
            &RwLock::new(None),
            true,
            Some(deadline),
            None,
        )
        .await,
        EncryptSendOutcome::Retryable {
            reason_code: REASON_OUTBOUND_ADMISSION_TIMEOUT,
            ..
        }
    )
}

/// One invocation of the real preparation path. No worker retry, socket,
/// original KernelRead/Full or native success capability is manufactured.
pub(crate) async fn one_missing_session_send_for_path_log_test(
    peers: &PeerManager,
    transport: &WireGuardTransport,
    peer_id: &str,
) -> bool {
    let packet = OutboundPacket {
        room_authorization: None,
        peer_id: peer_id.to_owned(),
        dst_ip: "10.20.0.2".to_owned(),
        packet: vec![0; 20],
        trace: None,
    };
    matches!(
        send::encrypt_then_send(
            packet,
            transport,
            peers,
            peers.current_network_generation_sync(),
            false,
            &RwLock::new(None),
            &RwLock::new(None),
            true,
        )
        .await,
        EncryptSendOutcome::Retryable {
            reason_code: REASON_OUTBOUND_SESSION_NOT_READY,
            ..
        }
    )
}
