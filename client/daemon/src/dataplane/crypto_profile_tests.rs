use super::*;
use std::sync::{mpsc, Arc};
use std::time::Instant;

#[test]
fn crypto_profile_preserves_three_original_values_times_units_and_order() {
    let profiler = DataplaneProfiler::new();
    let mut deferred = DeferredCryptoProfile::new(&profiler);
    for (stage, value) in [
        (CryptoProfileStage::SessionWait, 7),
        (CryptoProfileStage::Crypto, 11),
        (CryptoProfileStage::SessionHold, 19),
    ] {
        record_crypto_profile(
            &profiler,
            Some(&mut deferred),
            true,
            stage,
            Duration::from_micros(value),
        );
    }
    let original = deferred.samples;
    assert!(profiler.state.lock().unwrap().stages.is_empty());
    drop(deferred);
    let state = profiler.state.lock().unwrap();
    assert_eq!(state.stages.len(), 3);
    for stage in [
        CryptoProfileStage::SessionWait,
        CryptoProfileStage::Crypto,
        CryptoProfileStage::SessionHold,
    ] {
        let samples = &state.stages[&(stage.key(), ProfileUnit::Microseconds)];
        assert_eq!(samples.total, 1);
        assert_eq!(samples.values.len(), 1);
        assert_eq!(
            (samples.values[0].value, samples.values[0].observed_at_us),
            original[stage as usize].unwrap()
        );
    }
}

#[test]
fn crypto_profile_unsampled_empty_partial_and_legacy_keep_actual_counts() {
    let profiler = DataplaneProfiler::new();
    let mut deferred = DeferredCryptoProfile::new(&profiler);
    record_crypto_profile(
        &profiler,
        Some(&mut deferred),
        false,
        CryptoProfileStage::Crypto,
        Duration::from_micros(5),
    );
    drop(deferred);
    drop(DeferredCryptoProfile::new(&profiler));
    assert!(profiler.state.lock().unwrap().stages.is_empty());
    let mut deferred = DeferredCryptoProfile::new(&profiler);
    record_crypto_profile(
        &profiler,
        Some(&mut deferred),
        true,
        CryptoProfileStage::SessionWait,
        Duration::from_micros(13),
    );
    drop(deferred);
    record_crypto_profile(
        &profiler,
        None,
        true,
        CryptoProfileStage::Crypto,
        Duration::from_micros(17),
    );
    let state = profiler.state.lock().unwrap();
    assert_eq!(state.stages.len(), 2);
    for (key, value) in [("tx_session_lock_wait_us", 13), ("tx_crypto_exec_us", 17)] {
        let samples = &state.stages[&(key, ProfileUnit::Microseconds)];
        assert_eq!(samples.total, 1);
        assert_eq!(samples.values[0].value, value);
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Real original carriage, Noise encryption, emit, epoch and session owners.
/// The histogram is held independently. There is no physical writer or ACK.
fn actual_crypto_unlocks_before_histogram(cancel: bool, installed: bool) {
    use crate::request_carriage::test_support::{mint_routed_request, PEER};
    use crate::transport::WireGuardTransport;
    use p2pnet_crypto::NodeIdentity;
    use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};
    use std::task::{Context, Poll, Waker};

    let rt = runtime();
    let mut f = rt.block_on(mint_routed_request());
    let now = Instant::now();
    f.delivery.trace = Some(crate::dataplane::DataplaneTxTrace {
        sampled: true,
        tun_read_started: now,
        tun_read_completed: now,
        route_ready: None,
        dataplane_queue_send_started: None,
        transport_queue_dequeued: None,
        transport_queue_send_started: None,
        network_queue_dequeued: None,
    });
    let (transport, _rx) = WireGuardTransport::new_with_request_carriage();
    let transport = Arc::new(transport);
    let mut remote = if installed {
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();
        let mut initiator = HandshakeInitiator::new(a, b.public_key(), None);
        let mut responder = HandshakeResponder::new(b, None);
        let first = initiator.create_initiation().unwrap();
        let (response, keys) = responder.consume_initiation_and_respond(&first).unwrap();
        let local = TransportSession::new(initiator.consume_response(&response).unwrap());
        let _ = rt.block_on(transport.replace_session_for_lifecycle(
            PEER,
            local,
            f.record.expected_target_lifecycle().unwrap(),
        ));
        Some(TransportSession::new(keys))
    } else {
        None
    };
    let gate = f.peers.network_epoch_gate();
    let profiler = Arc::new(DataplaneProfiler::new());
    let histogram = profiler.state.lock().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (released_tx, released_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    struct Released(mpsc::Sender<()>);
    impl Drop for Released {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }
    let worker = std::thread::spawn({
        let profiler = profiler.clone();
        let transport = transport.clone();
        let gate = gate.clone();
        move || {
            let rt = runtime();
            let _entered = rt.enter();
            let future = async {
                let _emit = transport.acquire_outbound_emit_guard(PEER).await;
                let mut deferred = DeferredCryptoProfile::new(&profiler);
                let _released = Released(released_tx);
                let _epoch = gate.lock().await;
                let encrypted = transport
                    .encrypt_request_with_emit_guard_profiled(f.delivery, Some(&mut deferred))
                    .await
                    .unwrap();
                if let Some(encrypted) = &encrypted {
                    assert_eq!(
                        remote
                            .as_mut()
                            .unwrap()
                            .decrypt_from_bytes(&encrypted.wire_bytes)
                            .unwrap(),
                        f.record.original_packet()
                    );
                    let source = encrypted.source().unwrap();
                    assert!(source.belongs_to(&transport));
                    assert_eq!(
                        source.authorized_peer_lifecycle(),
                        f.record.expected_target_lifecycle()
                    );
                    assert!(Arc::ptr_eq(
                        &encrypted.binding().unwrap().token().request().unwrap(),
                        &f.record
                    ));
                }
                assert_eq!(encrypted.is_some(), installed);
                ready_tx.send(()).unwrap();
                if cancel {
                    std::future::pending::<()>().await;
                }
            };
            let mut future = Box::pin(future);
            let mut context = Context::from_waker(Waker::noop());
            // Successful crypto reaches the independently blocked destructor;
            // cancellation first exposes a genuinely suspended original future.
            if cancel {
                assert!(matches!(
                    std::future::Future::poll(future.as_mut(), &mut context),
                    Poll::Pending
                ));
                drop(future);
            } else {
                rt.block_on(future);
            }
            done_tx.send(()).unwrap();
        }
    });
    let ready = ready_rx.recv_timeout(Duration::from_secs(3));
    let released = released_rx.recv_timeout(Duration::from_secs(3));
    let epoch_free = gate.try_lock().is_ok();
    let sessions_free = transport.try_session_status(PEER).is_some();
    let publication_blocked = matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty));
    drop(histogram);
    let done = done_rx.recv_timeout(Duration::from_secs(3));
    worker.join().unwrap();
    assert!(ready.is_ok() && released.is_ok() && done.is_ok());
    assert!(epoch_free && sessions_free && publication_blocked);
    let state = profiler.state.lock().unwrap();
    assert_eq!(state.stages.len(), if installed { 3 } else { 1 });
    assert!(state
        .stages
        .values()
        .all(|s| s.total == 1 && s.values.len() == 1));
}

#[test]
fn crypto_profile_actual_success_unlocks_epoch_and_session_before_blocked_histogram() {
    actual_crypto_unlocks_before_histogram(false, true);
}

#[test]
fn crypto_profile_actual_cancelled_ciphertext_unlocks_epoch_and_session_before_blocked_histogram() {
    actual_crypto_unlocks_before_histogram(true, true);
}

#[test]
fn crypto_profile_actual_unavailable_session_releases_epoch_and_keeps_only_original_wait() {
    actual_crypto_unlocks_before_histogram(false, false);
}

#[test]
fn crypto_profile_actual_fast_core_keeps_original_three_samples_until_guard_release() {
    use crate::request_carriage::{
        test_support::{mint_routed_request, PEER},
        RequestEncryptionAttempt,
    };
    use crate::transport::{DeferredEncryptionLog, WireGuardTransport};
    use p2pnet_crypto::NodeIdentity;
    use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};

    let rt = runtime();
    let mut f = rt.block_on(mint_routed_request());
    let now = Instant::now();
    f.delivery.trace = Some(crate::dataplane::DataplaneTxTrace {
        sampled: true,
        tun_read_started: now,
        tun_read_completed: now,
        route_ready: None,
        dataplane_queue_send_started: None,
        transport_queue_dequeued: None,
        transport_queue_send_started: None,
        network_queue_dequeued: None,
    });
    let a = NodeIdentity::generate();
    let b = NodeIdentity::generate();
    let mut initiator = HandshakeInitiator::new(a, b.public_key(), None);
    let mut responder = HandshakeResponder::new(b, None);
    let first = initiator.create_initiation().unwrap();
    let (response, keys) = responder.consume_initiation_and_respond(&first).unwrap();
    let local = TransportSession::new(initiator.consume_response(&response).unwrap());
    let mut remote = TransportSession::new(keys);
    let (transport, _rx) = WireGuardTransport::new_with_request_carriage();
    rt.block_on(transport.replace_session_for_lifecycle(
        PEER,
        local,
        f.record.expected_target_lifecycle().unwrap(),
    ));
    let instance = rt
        .block_on(transport.session_status(PEER))
        .active_session_instance
        .unwrap();
    let profiler = DataplaneProfiler::new();
    let mut deferred = DeferredCryptoProfile::new(&profiler);
    let mut log = DeferredEncryptionLog::new(PEER.into());
    let gate = f.peers.network_epoch_gate();
    let original;
    {
        let _emit = rt.block_on(transport.acquire_outbound_emit_guard(PEER));
        let _epoch = rt.block_on(gate.lock());
        let RequestEncryptionAttempt::Encrypted {
            packet, plaintext, ..
        } = transport.try_encrypt_request_with_emit_guard_diagnostics(
            f.delivery,
            instance,
            Some(&mut deferred),
            Some(&mut log),
        )
        else {
            panic!("original installed session must encrypt in the actual fast core");
        };
        assert_eq!(crate::transport::wire_counter(&packet.wire_bytes), Some(0));
        assert_eq!(
            remote.decrypt_from_bytes(&packet.wire_bytes).unwrap(),
            f.record.original_packet()
        );
        assert_eq!(plaintext.packet, f.record.original_packet());
        assert_eq!(packet.source().unwrap().session_instance(), instance);
        original = deferred.samples;
        assert!(
            original.iter().all(Option::is_some),
            "actual fast core did not freeze all original stage observations"
        );
        assert!(
            profiler.state.lock().unwrap().stages.is_empty(),
            "histogram was published while original guards are held"
        );
    }
    assert!(transport.try_acquire_outbound_emit_guard(PEER).is_some());
    assert!(gate.try_lock().is_ok());
    assert!(transport.try_session_status(PEER).is_some());
    drop(log);
    drop(deferred);
    let state = profiler.state.lock().unwrap();
    assert_eq!(state.stages.len(), 3);
    for stage in [
        CryptoProfileStage::SessionWait,
        CryptoProfileStage::Crypto,
        CryptoProfileStage::SessionHold,
    ] {
        let samples = &state.stages[&(stage.key(), ProfileUnit::Microseconds)];
        assert_eq!(samples.total, 1);
        assert_eq!(samples.values.len(), 1);
        assert_eq!(
            (samples.values[0].value, samples.values[0].observed_at_us),
            original[stage as usize].unwrap()
        );
    }
    assert_eq!(
        f.record.physical_publication.state(),
        crate::overlay_requests::PhysicalPublicationState::Idle
    );
}
