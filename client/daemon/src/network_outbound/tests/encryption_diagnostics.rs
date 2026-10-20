//! Original entry points, actual guards and actual ciphertext. No native credit.
use super::*;
use futures_util::FutureExt;
use std::sync::Mutex;
use tracing_subscriber::prelude::*;

const TARGET: &str = "p2pnet_daemon::transport::sessions::encryption";

#[derive(Default, Debug)]
struct Fields {
    event: String,
    message: String,
    peer: String,
    counter: String,
    fingerprint: String,
    bytes: u64,
    session: u64,
    business: bool,
}
impl tracing::field::Visit for Fields {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "event" {
            self.event = value.to_owned();
        }
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        match field.name() {
            "bytes" => self.bytes = value,
            "session_instance" => self.session = value,
            _ => {}
        }
    }
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        if field.name() == "is_business" {
            self.business = value;
        }
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let target = match field.name() {
            "message" => &mut self.message,
            "peer_id" => &mut self.peer,
            "counter" => &mut self.counter,
            "wire_fp" => &mut self.fingerprint,
            _ => return,
        };
        *target = format!("{value:?}");
    }
}

#[derive(Debug)]
struct Row {
    fields: Fields,
    emit_free: bool,
    epoch_free: bool,
    session_free: bool,
}
type Rows = Arc<Mutex<Vec<Row>>>;
struct Probe {
    transport: WireGuardTransport,
    peers: Arc<PeerManager>,
    rows: Rows,
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Probe {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        if fields.event == "wireguard_outbound_counter_allocated"
            || fields.message.starts_with("No WireGuard session for peer")
            || fields
                .message
                .starts_with("No usable WireGuard session for peer")
            || fields.message.starts_with("WireGuard session for peer")
        {
            assert_eq!(event.metadata().target(), TARGET);
            self.rows.lock().unwrap().push(Row {
                fields,
                emit_free: self
                    .transport
                    .try_acquire_outbound_emit_guard(PEER)
                    .is_some(),
                epoch_free: self.peers.network_epoch_gate().try_lock_owned().is_ok(),
                session_free: self
                    .transport
                    .hold_session_registry_for_test()
                    .now_or_never()
                    .is_some(),
            });
        }
    }
}
fn observe(
    transport: &WireGuardTransport,
    peers: &Arc<PeerManager>,
) -> (tracing::subscriber::DefaultGuard, Rows) {
    let rows = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(Probe {
        transport: transport.clone(),
        peers: peers.clone(),
        rows: rows.clone(),
    });
    (tracing::subscriber::set_default(subscriber), rows)
}
fn assert_released(rows: &Rows) {
    let rows = rows.lock().unwrap();
    assert_eq!(
        rows.len(),
        1,
        "one original crypto event is required: {rows:?}"
    );
    assert!(
        rows[0].emit_free,
        "crypto logger still owns actual emit mutex: {rows:?}"
    );
    assert!(
        rows[0].epoch_free,
        "crypto logger still owns actual epoch mutex: {rows:?}"
    );
    assert!(
        rows[0].session_free,
        "crypto logger still owns actual session mutex: {rows:?}"
    );
}
fn assert_counter(rows: &Rows, wire: &[u8], session: u64, fast: bool) {
    assert_released(rows);
    let rows = rows.lock().unwrap();
    let fields = &rows[0].fields;
    assert_eq!(fields.event, "wireguard_outbound_counter_allocated");
    assert_eq!(fields.peer, PEER);
    assert_eq!(fields.session, session);
    assert_eq!(fields.counter, "Some(0)");
    assert_eq!(fields.bytes, wire.len() as u64);
    assert!(fields.business);
    assert_eq!(
        fields.fingerprint,
        format!("{:016x}", crate::transport::wire_fingerprint(wire))
    );
    assert_eq!(
        fields.message,
        if fast {
            "WireGuard counter allocated under the LAN Direct fast-path ordering lock"
        } else {
            "WireGuard counter allocated under the per-peer emit ordering lock"
        }
    );
}
async fn receive(
    receiver: &tokio::net::UdpSocket,
    remote: &mut p2pnet_wireguard::TransportSession,
    f: &RoutedRequestFixture,
) -> Vec<u8> {
    let mut wire = [0; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut wire))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(crate::transport::wire_counter(&wire[..n]), Some(0));
    assert_eq!(
        remote.decrypt_from_bytes(&wire[..n]).unwrap(),
        f.record.original_packet()
    );
    assert!(
        matches!(receiver.try_recv_from(&mut [0; 2048]), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    );
    wire[..n].to_vec()
}

async fn actual_send_logs_after_guards(fast: bool, sourced: bool) {
    let (f, transport, udp, receiver, mut remote) = direct_fixture(fast).await;
    let session = transport
        .session_status(PEER)
        .await
        .active_session_instance
        .unwrap();
    if fast {
        let (_, socket) = udp
            .socket_for_peer_endpoint(Some(PEER), Some(receiver.local_addr().unwrap()))
            .await
            .unwrap();
        socket.writable().await.unwrap();
    }
    let (_subscriber, rows) = observe(&transport, &f.peers);
    let udps = RwLock::new(Some(udp));
    let relays = RwLock::new(None);
    let packet = if sourced {
        f.delivery.clone()
    } else {
        crate::dataplane::OutboundPacket {
            room_authorization: f.delivery.room_authorization.clone(),
            peer_id: f.delivery.peer_id.clone(),
            dst_ip: f.delivery.dst_ip.clone(),
            packet: f.delivery.packet.clone(),
            trace: None,
        }
        .into()
    };
    if fast {
        let mut paths = HashMap::new();
        let mut ineligible = HashMap::new();
        let result = super::super::super::fast_path::try_lan_direct_fast_path(
            packet,
            &transport,
            &f.peers,
            true,
            &udps,
            &mut paths,
            &mut ineligible,
        );
        assert!(matches!(
            result,
            super::super::super::fast_path::FastPathAttempt::Sent
        ));
    } else {
        let result = encrypt_then_send_with_deadline(
            packet,
            &transport,
            &f.peers,
            f.record.generation,
            true,
            &udps,
            &relays,
            false,
            Some(Instant::now() + Duration::from_secs(1)),
            None,
        )
        .await;
        assert!(matches!(result, EncryptSendOutcome::Sent));
    }
    let wire = receive(&receiver, &mut remote, &f).await;
    assert_counter(&rows, &wire, session, fast);
    if sourced {
        assert_eq!(
            f.record
                .physical_publication
                .record()
                .unwrap()
                .qualify(&f.record, Instant::now()),
            PhysicalInputQualification::UnknownUdpPublication
        );
    } else {
        assert_eq!(
            f.record.physical_publication.state(),
            PhysicalPublicationState::Idle
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn encryption_counter_log_sourced_slow_send_releases_all_actual_guards() {
    actual_send_logs_after_guards(false, true).await;
}
#[tokio::test(flavor = "current_thread")]
async fn encryption_counter_log_unsourced_slow_send_releases_all_actual_guards() {
    actual_send_logs_after_guards(false, false).await;
}
#[tokio::test(flavor = "current_thread")]
async fn encryption_counter_log_fast_send_releases_all_actual_guards() {
    actual_send_logs_after_guards(true, true).await;
}

async fn actual_pending_send_publishes_once(timeout: bool) {
    let (f, transport, udp, receiver, _remote) = direct_fixture(false).await;
    let _polls = udp.inject_udp_send_pending_for_test(PEER);
    let (_subscriber, rows) = observe(&transport, &f.peers);
    let udps = RwLock::new(Some(udp.clone()));
    let relays = RwLock::new(None);
    let deadline = Instant::now()
        + if timeout {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(1)
        };
    let mut send = Box::pin(encrypt_then_send_with_deadline(
        f.delivery.clone(),
        &transport,
        &f.peers,
        f.record.generation,
        true,
        &udps,
        &relays,
        false,
        Some(deadline),
        None,
    ));
    assert!(matches!(
        futures_util::poll!(send.as_mut()),
        std::task::Poll::Pending
    ));
    assert_eq!(
        f.record.physical_publication.state(),
        PhysicalPublicationState::Open
    );
    assert!(transport.try_acquire_outbound_emit_guard(PEER).is_none());
    assert!(
        rows.lock().unwrap().is_empty(),
        "counter log published before actual physical attempt ended"
    );
    if timeout {
        let outcome = send.await;
        assert!(!matches!(outcome, EncryptSendOutcome::Sent));
        assert!(Instant::now() >= deadline);
    } else {
        drop(send);
    }
    assert_released(&rows);
    let rows = rows.lock().unwrap();
    assert_eq!(rows[0].fields.counter, "Some(0)");
    drop(rows);
    assert_eq!(
        f.record.physical_publication.state(),
        PhysicalPublicationState::CancelledOrUncertain
    );
    assert!(f.record.physical_publication.record().is_none());
    assert!(
        matches!(receiver.try_recv_from(&mut [0;2048]), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    );
    udp.release_udp_send_pending_for_test(PEER);
}
#[tokio::test(flavor = "current_thread")]
async fn encryption_counter_log_cancelled_actual_handoff_releases_all_guards() {
    actual_pending_send_publishes_once(false).await;
}
#[tokio::test(flavor = "current_thread")]
async fn encryption_counter_log_original_handoff_timeout_releases_all_guards() {
    actual_pending_send_publishes_once(true).await;
}

async fn actual_unavailable_log_releases_guards(pending: bool) {
    let (f, transport, udp, receiver, _remote) = direct_fixture(false).await;
    transport.remove_session(PEER).await;
    if pending {
        let (session, _) = establish_sessions();
        transport
            .stage_responder_session(PEER, "pending-only".into(), session)
            .await;
    }
    let (_subscriber, rows) = observe(&transport, &f.peers);
    let udps = RwLock::new(Some(udp));
    let relays = RwLock::new(None);
    let outcome = encrypt_then_send_with_deadline(
        f.delivery.clone(),
        &transport,
        &f.peers,
        f.record.generation,
        true,
        &udps,
        &relays,
        false,
        Some(Instant::now() + Duration::from_secs(1)),
        None,
    )
    .await;
    assert!(matches!(
        outcome,
        EncryptSendOutcome::Retryable {
            reason_code: REASON_OUTBOUND_SESSION_NOT_READY,
            ..
        }
    ));
    assert_released(&rows);
    let rows = rows.lock().unwrap();
    let expected = if pending {
        format!("No usable WireGuard session for peer {PEER}; dropping {} byte packet until rekey completes", f.record.original_packet().len())
    } else {
        format!(
            "No WireGuard session for peer {PEER}; dropping {} byte packet",
            f.record.original_packet().len()
        )
    };
    assert_eq!(rows[0].fields.message, expected);
    assert!(rows[0].fields.event.is_empty());
    assert_eq!(
        f.record.physical_publication.state(),
        PhysicalPublicationState::Idle
    );
    assert!(
        matches!(receiver.try_recv_from(&mut [0;2048]), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    );
}
#[tokio::test(flavor = "current_thread")]
async fn encryption_missing_session_log_releases_original_epoch_and_emit() {
    actual_unavailable_log_releases_guards(false).await;
}
#[tokio::test(flavor = "current_thread")]
async fn encryption_inactive_session_log_releases_original_epoch_and_emit() {
    actual_unavailable_log_releases_guards(true).await;
}

struct EnableProbe {
    transport: WireGuardTransport,
    peers: Arc<PeerManager>,
    calls: Arc<std::sync::atomic::AtomicUsize>,
    free: Arc<std::sync::atomic::AtomicBool>,
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for EnableProbe {
    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if metadata.target() == TARGET {
            tracing::subscriber::Interest::sometimes()
        } else {
            tracing::subscriber::Interest::always()
        }
    }
    fn enabled(
        &self,
        metadata: &tracing::Metadata<'_>,
        _: tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        if metadata.target() == TARGET {
            use std::sync::atomic::Ordering::SeqCst;
            self.calls.fetch_add(1, SeqCst);
            let emit = self
                .transport
                .try_acquire_outbound_emit_guard(PEER)
                .is_some();
            let epoch = self.peers.network_epoch_gate().try_lock_owned().is_ok();
            let session = self
                .transport
                .hold_session_registry_for_test()
                .now_or_never()
                .is_some();
            self.free.fetch_and(emit && epoch && session, SeqCst);
        }
        true
    }
}

#[tokio::test(flavor = "current_thread")]
async fn encryption_level_gate_does_not_callback_inside_actual_crypto_guards() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
    let (f, transport, udp, receiver, mut remote) = direct_fixture(false).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let free = Arc::new(AtomicBool::new(true));
    let subscriber = tracing_subscriber::registry().with(EnableProbe {
        transport: transport.clone(),
        peers: f.peers.clone(),
        calls: calls.clone(),
        free: free.clone(),
    });
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let udps = RwLock::new(Some(udp));
    let relays = RwLock::new(None);
    let result = encrypt_then_send_with_deadline(
        f.delivery.clone(),
        &transport,
        &f.peers,
        f.record.generation,
        true,
        &udps,
        &relays,
        false,
        Some(Instant::now() + Duration::from_secs(1)),
        None,
    )
    .await;
    assert!(matches!(result, EncryptSendOutcome::Sent));
    receive(&receiver, &mut remote, &f).await;
    assert!(
        calls.load(SeqCst) > 0,
        "metadata eligibility must actually enter this subscriber"
    );
    assert!(
        free.load(SeqCst),
        "crypto level eligibility called a subscriber under original guards"
    );
    assert_eq!(
        f.record
            .physical_publication
            .record()
            .unwrap()
            .qualify(&f.record, Instant::now()),
        PhysicalInputQualification::UnknownUdpPublication
    );
}
