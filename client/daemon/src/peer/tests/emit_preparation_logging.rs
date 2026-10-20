//! Real preparation and real mutex probes; no native input/output is forged.
use super::*;
use std::sync::Mutex;
use tracing::{span, Event, Metadata, Subscriber};

const PEER: &str = "emit-preparation-peer";
type Observations = Arc<Mutex<Vec<(String, bool, bool)>>>;

struct Observer {
    peers: Arc<PeerManager>,
    transport: Arc<crate::transport::WireGuardTransport>,
    rows: Observations,
}

#[derive(Default)]
struct Name(String);
impl tracing::field::Visit for Name {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "event" {
            self.0 = value.to_owned();
        }
    }
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
}

impl Subscriber for Observer {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut name = Name::default();
        event.record(&mut name);
        if matches!(
            name.0.as_str(),
            "outbound_business_emit_lock_acquired"
                | "outbound_session_unavailable"
                | "outbound_counter_allocation_rejected"
        ) {
            assert_eq!(
                event.metadata().target(),
                "p2pnet_daemon::network_outbound::send"
            );
            self.rows.lock().unwrap().push((
                name.0,
                self.transport
                    .try_acquire_outbound_emit_guard(PEER)
                    .is_some(),
                self.peers.network_epoch_gate().try_lock_owned().is_ok(),
            ));
        }
    }
}

async fn fixture() -> (Arc<PeerManager>, Arc<crate::transport::WireGuardTransport>) {
    let mut config = test_config();
    config.relay.path_policy = crate::config::PathPolicy::RelayOnly;
    let peers = Arc::new(PeerManager::new(config));
    peers
        .add_peer(&test_peer(PEER, "192.0.2.4:41000".parse().unwrap()))
        .await;
    (
        peers,
        Arc::new(crate::transport::WireGuardTransport::new().0),
    )
}

fn observe(
    peers: Arc<PeerManager>,
    transport: Arc<crate::transport::WireGuardTransport>,
) -> (tracing::subscriber::DefaultGuard, Observations) {
    let rows = Arc::new(Mutex::new(Vec::new()));
    let guard = tracing::subscriber::set_default(Observer {
        peers,
        transport,
        rows: rows.clone(),
    });
    (guard, rows)
}

fn assert_released(rows: &Mutex<Vec<(String, bool, bool)>>, expected: &[&str]) {
    let rows = rows.lock().unwrap();
    assert!(
        rows.iter().all(|(_, emit, _)| *emit),
        "preparation logger still owns actual emit mutex: {rows:?}"
    );
    assert!(
        rows.iter().all(|(_, _, epoch)| *epoch),
        "preparation logger still owns actual epoch mutex: {rows:?}"
    );
    assert_eq!(
        rows.iter().map(|r| r.0.as_str()).collect::<Vec<_>>(),
        expected
    );
}

#[tokio::test(flavor = "current_thread")]
async fn outbound_emit_preparation_logs_release_real_guards_on_missing_session() {
    let (peers, transport) = fixture().await;
    let (_subscriber, rows) = observe(peers.clone(), transport.clone());
    assert!(
        crate::network_outbound::one_missing_session_send_for_path_log_test(
            &peers, &transport, PEER
        )
        .await
    );
    assert_released(
        &rows,
        &[
            "outbound_business_emit_lock_acquired",
            "outbound_session_unavailable",
        ],
    );
}

#[tokio::test(flavor = "current_thread")]
async fn outbound_emit_preparation_logs_release_real_guards_after_cancellation() {
    let (peers, transport) = fixture().await;
    let (_subscriber, rows) = observe(peers.clone(), transport.clone());
    let session = transport.hold_session_registry_for_test().await;
    let mut send = Box::pin(
        crate::network_outbound::one_missing_session_send_for_path_log_test(
            &peers, &transport, PEER,
        ),
    );
    assert!(matches!(
        futures_util::poll!(send.as_mut()),
        std::task::Poll::Pending
    ));
    assert!(transport.try_acquire_outbound_emit_guard(PEER).is_none());
    assert!(peers.network_epoch_gate().try_lock_owned().is_err());
    drop(send);
    assert_released(&rows, &["outbound_business_emit_lock_acquired"]);
    drop(session);
}

#[tokio::test(flavor = "current_thread")]
async fn outbound_emit_preparation_logs_release_real_guards_after_timeout() {
    let (peers, transport) = fixture().await;
    let (_subscriber, rows) = observe(peers.clone(), transport.clone());
    let session = transport.hold_session_registry_for_test().await;
    let deadline = Instant::now() + Duration::from_millis(100);
    let mut send = Box::pin(
        crate::network_outbound::one_expiring_session_send_for_path_log_test(
            &peers, &transport, PEER, deadline,
        ),
    );
    assert!(matches!(
        futures_util::poll!(send.as_mut()),
        std::task::Poll::Pending
    ));
    assert!(transport.try_acquire_outbound_emit_guard(PEER).is_none());
    assert!(peers.network_epoch_gate().try_lock_owned().is_err());
    assert!(send.await);
    assert!(Instant::now() >= deadline);
    assert_released(&rows, &["outbound_business_emit_lock_acquired"]);
    drop(session);
}

#[tokio::test(flavor = "current_thread")]
async fn outbound_emit_preparation_resource_wait_keeps_real_emit_mutex_free() {
    let (peers, transport) = fixture().await;
    let (_subscriber, rows) = observe(peers.clone(), transport.clone());
    let udp = tokio::sync::RwLock::new(None);
    let relay = tokio::sync::RwLock::new(None);
    let held = relay.write().await;
    let mut send = Box::pin(
        crate::network_outbound::one_emit_preparation_with_resources_for_test(
            &peers,
            &transport,
            PEER,
            peers.current_network_generation_sync(),
            &udp,
            &relay,
            None,
        ),
    );
    assert!(matches!(
        futures_util::poll!(send.as_mut()),
        std::task::Poll::Pending
    ));
    assert!(
        transport.try_acquire_outbound_emit_guard(PEER).is_some(),
        "resource snapshot wait owns actual emit mutex"
    );
    drop(send);
    assert!(rows.lock().unwrap().is_empty());
    drop(held);
}

#[tokio::test(flavor = "current_thread")]
async fn outbound_emit_preparation_resource_wait_rechecks_original_generation() {
    let (peers, transport) = fixture().await;
    let (_subscriber, rows) = observe(peers.clone(), transport.clone());
    let udp = tokio::sync::RwLock::new(None);
    let relay = tokio::sync::RwLock::new(None);
    let held = udp.write().await;
    let generation = peers.current_network_generation_sync();
    let mut send = Box::pin(
        crate::network_outbound::one_emit_preparation_with_resources_for_test(
            &peers, &transport, PEER, generation, &udp, &relay, None,
        ),
    );
    assert!(matches!(
        futures_util::poll!(send.as_mut()),
        std::task::Poll::Pending
    ));
    assert!(
        transport.try_acquire_outbound_emit_guard(PEER).is_some(),
        "resource snapshot wait owns actual emit mutex"
    );
    assert!(
        peers
            .advance_network_generation("emit-resource-wait-control")
            .await
            > generation
    );
    drop(held);
    assert_eq!(send.await, "outbound_generation_changed");
    assert_released(
        &rows,
        &[
            "outbound_business_emit_lock_acquired",
            "outbound_counter_allocation_rejected",
        ],
    );
}
