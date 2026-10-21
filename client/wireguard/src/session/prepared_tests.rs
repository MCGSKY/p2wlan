use super::*;

fn sender(counter: u64) -> TransportSession {
    let mut session = TransportSession::new(TransportKeyPair {
        send_key: [0x42; 32],
        recv_key: [0x43; 32],
        our_index: 17,
        peer_index: 29,
    })
    .with_thresholds(u64::MAX, Duration::MAX, u64::MAX, Duration::MAX);
    session.send_counter = counter;
    session
}

#[test]
fn prepared_wire_matches_original_bytes_and_reuses_allocation() {
    for len in [0, 1, 195, 1510, 4096] {
        for counter in [0, 1, u64::MAX - 1] {
            let packet: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let prepared = PreparedTransportBuffer::new(len).unwrap();
            let ptr = prepared.buffer().as_ptr();
            let capacity = prepared.buffer().capacity();
            let mut actual = sender(counter);
            let expected = sender(counter).encrypt_to_bytes(&packet).unwrap();
            let wire = actual.encrypt_into_prepared(&packet, prepared).unwrap();
            assert_eq!(wire, expected);
            assert_eq!(wire.as_ptr(), ptr);
            assert_eq!(wire.capacity(), capacity);
            assert_eq!(actual.send_counter(), counter + 1);
        }
    }
}

#[test]
fn prepared_storage_has_only_zeroes_and_no_counter_effect() {
    let mut session = sender(9);
    let prepared = PreparedTransportBuffer::new(195).unwrap();
    assert_eq!(prepared.buffer().len(), 227);
    assert!(prepared.buffer().iter().all(|byte| *byte == 0));
    drop(prepared);
    assert_eq!(session.send_counter(), 9);
    assert_eq!(session.encrypt(b"actual").unwrap().counter, 9);
}

#[test]
fn prepared_length_mismatch_rejects_without_consuming_nonce() {
    let mut session = sender(7);
    let error = session.encrypt_into_prepared(b"abc", PreparedTransportBuffer::new(2).unwrap());
    assert!(matches!(error, Err(WireGuardError::InvalidPacket(_))));
    assert_eq!(session.send_counter(), 7);
    assert_eq!(session.encrypt(b"abc").unwrap().counter, 7);
}

#[test]
fn prepared_expiry_and_counter_limit_keep_original_error_priority() {
    for counter in [4, u64::MAX] {
        let mut actual = sender(counter);
        let mut legacy = sender(counter);
        if counter == 4 {
            actual.reject_after_messages = 4;
            legacy.reject_after_messages = 4;
        }
        let before = actual.send_counter();
        let error = actual
            .encrypt_into_prepared(b"abc", PreparedTransportBuffer::new(1).unwrap())
            .unwrap_err();
        let original_error = legacy.encrypt_to_bytes(b"abc").unwrap_err();
        assert_eq!(error.to_string(), original_error.to_string());
        assert!(matches!(error, WireGuardError::InvalidPacket(_)));
        assert_eq!(actual.send_counter(), before);
        assert_eq!(legacy.send_counter(), before);
    }
}

#[test]
fn prepared_and_legacy_entries_share_one_actual_session_counter() {
    let mut session = sender(0);
    let first = session.encrypt(b"first").unwrap();
    let wire = session
        .encrypt_into_prepared(b"second", PreparedTransportBuffer::new(6).unwrap())
        .unwrap();
    let second = MessageTransport::from_bytes(&wire).unwrap();
    let third = session.encrypt(b"third").unwrap();
    assert_eq!((first.counter, second.counter, third.counter), (0, 1, 2));
    assert_eq!(second.receiver_index, session.peer_index());
    assert_eq!(session.send_counter(), 3);
}

#[test]
fn prepared_real_noise_session_roundtrip_and_replay_protection() {
    use crate::handshake::{HandshakeInitiator, HandshakeResponder};
    use p2pnet_crypto::NodeIdentity;
    let alice = NodeIdentity::generate();
    let bob = NodeIdentity::generate();
    let mut initiator = HandshakeInitiator::new(alice, bob.public_key(), None);
    let mut responder = HandshakeResponder::new(bob, None);
    let initiation = initiator.create_initiation().unwrap();
    let (response, receive_keys) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let mut local = TransportSession::new(initiator.consume_response(&response).unwrap());
    let mut remote = TransportSession::new(receive_keys);
    for packet in [
        b"".as_slice(),
        b"actual plaintext",
        b"after previous counter",
    ] {
        let wire = local
            .encrypt_into_prepared(packet, PreparedTransportBuffer::new(packet.len()).unwrap())
            .unwrap();
        assert_eq!(remote.decrypt_from_bytes(&wire).unwrap(), packet);
        assert!(matches!(
            remote.decrypt_from_bytes(&wire),
            Err(WireGuardError::ReplayDetected(_))
        ));
    }
}

#[test]
fn prepared_length_overflow_is_a_recoverable_error() {
    assert!(matches!(
        PreparedTransportBuffer::new(usize::MAX),
        Err(WireGuardError::InvalidPacket(_))
    ));
}
