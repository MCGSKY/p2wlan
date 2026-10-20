//! Real synchronous tracing callbacks inspect the original locks. These
//! controls create no KernelRead, Full, system TUN or native success fact.
use super::*;
use std::sync::Mutex;
use tracing::{span, Event, Metadata, Subscriber};

const PEER: &str = "path-log-peer";

#[derive(Debug)]
struct Observation {
    event: String,
    target: String,
    generation: Option<u64>,
    path_id: Option<String>,
    epoch_free: bool,
    connections_free: bool,
    emit_free: bool,
}

struct LockObserver {
    peers: Arc<PeerManager>,
    transport: Option<Arc<crate::transport::WireGuardTransport>>,
    observations: Arc<Mutex<Vec<Observation>>>,
}

#[derive(Default)]
struct EventName {
    event: String,
    generation: Option<u64>,
    path_id: Option<String>,
}

impl tracing::field::Visit for EventName {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "event" {
            self.event = value.to_owned();
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "generation" {
            self.generation = Some(value);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "path_id" {
            self.path_id = Some(format!("{value:?}"));
        }
    }
}

impl Subscriber for LockObserver {
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
        let mut name = EventName::default();
        event.record(&mut name);
        if !matches!(
            name.event.as_str(),
            "path_state_snapshot" | "path_selection_log_overflow"
        ) {
            return;
        }
        let epoch_free = self.peers.network_epoch_gate().try_lock_owned().is_ok();
        let connections_free = self.peers.connections.try_write().is_ok();
        let emit_free = self
            .transport
            .as_ref()
            .is_none_or(|transport| transport.try_acquire_outbound_emit_guard(PEER).is_some());
        self.observations.lock().unwrap().push(Observation {
            event: name.event,
            target: event.metadata().target().to_owned(),
            generation: name.generation,
            path_id: name.path_id,
            epoch_free,
            connections_free,
            emit_free,
        });
    }
}

async fn fixture() -> Arc<PeerManager> {
    let mut config = test_config();
    config.relay.path_policy = crate::config::PathPolicy::RelayOnly;
    let peers = Arc::new(PeerManager::new(config));
    peers
        .add_peer(&test_peer(PEER, "192.0.2.4:41000".parse().unwrap()))
        .await;
    peers
}

fn observe(
    peers: Arc<PeerManager>,
    transport: Option<Arc<crate::transport::WireGuardTransport>>,
) -> (
    tracing::subscriber::DefaultGuard,
    Arc<Mutex<Vec<Observation>>>,
) {
    let observations = Arc::new(Mutex::new(Vec::new()));
    let guard = tracing::subscriber::set_default(LockObserver {
        peers,
        transport,
        observations: observations.clone(),
    });
    (guard, observations)
}

fn assert_released(observations: &Mutex<Vec<Observation>>, emit_expected: bool) {
    let rows = observations.lock().unwrap();
    assert_eq!(
        rows.len(),
        1,
        "exactly one real selector transition: {rows:?}"
    );
    assert!(
        rows[0].epoch_free,
        "callback still owns actual epoch: {rows:?}"
    );
    assert!(
        rows[0].connections_free,
        "callback still owns actual connections: {rows:?}"
    );
    if emit_expected {
        assert!(
            rows[0].emit_free,
            "callback still owns actual emit: {rows:?}"
        );
    }
    assert_eq!(rows[0].target, PATH_SELECTION_LOG_TARGET);
}

#[tokio::test(flavor = "current_thread")]
async fn owned_selector_logs_after_actual_epoch_and_connection_guards_release() {
    let peers = fixture().await;
    let (_subscriber, observations) = observe(peers.clone(), None);
    let selection = peers.select_path_for_data(PEER, false, true).await;
    assert_eq!(selection.path, Some(NetworkPath::Relay));
    assert_released(&observations, false);
}

#[tokio::test(flavor = "current_thread")]
async fn original_missing_session_preparation_logs_after_actual_emit_and_epoch_release() {
    let peers = fixture().await;
    let (transport, _receiver) = crate::transport::WireGuardTransport::new();
    let transport = Arc::new(transport);
    let (_subscriber, observations) = observe(peers.clone(), Some(transport.clone()));
    assert!(
        crate::network_outbound::one_missing_session_send_for_path_log_test(
            &peers, &transport, PEER,
        )
        .await
    );
    assert_released(&observations, true);
}

#[tokio::test(flavor = "current_thread")]
async fn original_preparation_cancellation_drops_actual_guards_before_selector_callback() {
    let peers = fixture().await;
    let (transport, _receiver) = crate::transport::WireGuardTransport::new();
    let transport = Arc::new(transport);
    let (_subscriber, observations) = observe(peers.clone(), Some(transport.clone()));
    let session_writer = transport.hold_session_registry_for_test().await;
    let mut send = Box::pin(
        crate::network_outbound::one_missing_session_send_for_path_log_test(
            &peers, &transport, PEER,
        ),
    );
    assert!(matches!(
        futures_util::poll!(send.as_mut()),
        std::task::Poll::Pending
    ));
    assert!(observations.lock().unwrap().is_empty());
    assert!(peers.network_epoch_gate().try_lock_owned().is_err());
    assert!(transport.try_acquire_outbound_emit_guard(PEER).is_none());
    assert_eq!(
        peers.connections.try_read().unwrap()[PEER]
            .path_events
            .len(),
        1
    );
    drop(send);
    assert_released(&observations, true);
    drop(session_writer);
}

#[tokio::test(flavor = "current_thread")]
async fn original_preparation_timeout_drops_actual_guards_before_selector_callback() {
    let peers = fixture().await;
    let (transport, _receiver) = crate::transport::WireGuardTransport::new();
    let transport = Arc::new(transport);
    let (_subscriber, observations) = observe(peers.clone(), Some(transport.clone()));
    let session_writer = transport.hold_session_registry_for_test().await;
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
    assert!(observations.lock().unwrap().is_empty());
    assert!(peers.network_epoch_gate().try_lock_owned().is_err());
    assert!(transport.try_acquire_outbound_emit_guard(PEER).is_none());
    assert!(send.await);
    assert!(Instant::now() >= deadline);
    assert_released(&observations, true);
    drop(session_writer);
}

#[tokio::test(flavor = "current_thread")]
async fn unchanged_canonical_selection_does_not_duplicate_history_or_callback() {
    let peers = fixture().await;
    let (_subscriber, observations) = observe(peers.clone(), None);
    let first = peers.select_path_for_data(PEER, false, true).await;
    let second = peers.select_path_for_data(PEER, false, true).await;
    assert_eq!(first, second);
    let connections = peers.connections.read().await;
    assert_eq!(connections[PEER].path_events.len(), 1);
    assert_eq!(
        connections[PEER].last_path_selection.as_ref(),
        Some(&second)
    );
    drop(connections);
    assert_released(&observations, false);
}

#[tokio::test(flavor = "current_thread")]
async fn missing_canonical_peer_creates_no_transition_or_callback() {
    let peers = fixture().await;
    let (_subscriber, observations) = observe(peers.clone(), None);
    assert_eq!(
        peers
            .select_path_for_data("missing", false, true)
            .await
            .path,
        Some(NetworkPath::Relay)
    );
    assert!(peers
        .select_path_for_data("missing", false, false)
        .await
        .path
        .is_none());
    assert!(observations.lock().unwrap().is_empty());
    assert!(peers.connections.read().await[PEER].path_events.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn deferred_snapshot_keeps_original_generation_and_relay_after_authoritative_change() {
    let peers = fixture().await;
    let (_subscriber, observations) = observe(peers.clone(), None);
    let generation = peers.current_network_generation_sync();
    let mut log = DeferredPathSelectionLog::default();
    {
        let (_epoch, mut connections) = peers.lock_epoch_and_connections_write().await;
        connections.get_mut(PEER).unwrap().relay_server = Some("relay.example:443".to_owned());
        let selected = peers.select_path_for_data_with_local_endpoint_in_epoch_with_conns(
            &mut connections,
            PEER,
            false,
            true,
            None,
            generation,
            true,
            Some(&mut log),
        );
        assert_eq!(
            connections[PEER].last_path_selection.as_ref(),
            Some(&selected)
        );
        assert_eq!(connections[PEER].path_events.len(), 1);
        assert!(observations.lock().unwrap().is_empty());
        connections.get_mut(PEER).unwrap().relay_server =
            Some("replacement.example:443".to_owned());
    }
    assert!(
        peers
            .advance_network_generation("path-log-generation-control")
            .await
            > generation
    );
    drop(log);
    assert_released(&observations, false);
    let rows = observations.lock().unwrap();
    assert_eq!(rows[0].generation, Some(generation));
    assert_eq!(
        rows[0].path_id.as_deref(),
        Some("Some(\"relay.example:443\")")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn deferred_diagnostic_does_not_extend_actual_manager_lifetime() {
    let peers = fixture().await;
    let weak = Arc::downgrade(&peers);
    let mut log = DeferredPathSelectionLog::default();
    {
        let (_epoch, mut connections) = peers.lock_epoch_and_connections_write().await;
        peers.select_path_for_data_with_local_endpoint_in_epoch_with_conns(
            &mut connections,
            PEER,
            false,
            true,
            None,
            peers.current_network_generation_sync(),
            false,
            Some(&mut log),
        );
    }
    drop(peers);
    assert!(weak.upgrade().is_none());
    drop(log);
}

#[tokio::test(flavor = "current_thread")]
async fn single_diagnostic_slot_preserves_first_and_reports_duplicate_after_actual_unlock() {
    let peers = fixture().await;
    let (_subscriber, observations) = observe(peers.clone(), None);
    let mut log = DeferredPathSelectionLog::default();
    {
        let (_epoch, mut connections) = peers.lock_epoch_and_connections_write().await;
        for relay in ["first.example:443", "second.example:443"] {
            connections.get_mut(PEER).unwrap().relay_server = Some(relay.to_owned());
            peers.select_path_for_data_with_local_endpoint_in_epoch_with_conns(
                &mut connections,
                PEER,
                false,
                true,
                None,
                peers.current_network_generation_sync(),
                true,
                Some(&mut log),
            );
        }
        assert_eq!(connections[PEER].path_events.len(), 2);
        assert_eq!(
            connections[PEER]
                .last_path_selection
                .as_ref()
                .unwrap()
                .relay_server
                .as_deref(),
            Some("second.example:443")
        );
        assert!(observations.lock().unwrap().is_empty());
    }
    drop(log);
    let rows = observations.lock().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].event, "path_state_snapshot");
    assert_eq!(
        rows[0].path_id.as_deref(),
        Some("Some(\"first.example:443\")")
    );
    assert_eq!(rows[1].event, "path_selection_log_overflow");
    assert!(rows
        .iter()
        .all(|row| row.epoch_free && row.connections_free));
}

#[tokio::test(flavor = "current_thread")]
async fn canonical_transition_history_keeps_original_cap_after_deferred_logging() {
    let peers = fixture().await;
    let (_subscriber, observations) = observe(peers.clone(), None);
    for i in 0..PATH_SELECTION_EVENT_LIMIT + 3 {
        peers.select_path_for_data(PEER, false, i % 2 == 0).await;
    }
    let connections = peers.connections.read().await;
    assert_eq!(
        connections[PEER].path_events.len(),
        PATH_SELECTION_EVENT_LIMIT
    );
    assert_eq!(
        connections[PEER].path_events.last().unwrap().selected_path,
        Some(NetworkPath::Relay)
    );
    let rows = observations.lock().unwrap();
    assert_eq!(rows.len(), PATH_SELECTION_EVENT_LIMIT + 3);
    assert!(rows
        .iter()
        .all(|row| row.epoch_free && row.connections_free));
}

#[tokio::test(flavor = "current_thread")]
async fn direct_first_forced_relay_refusal_creates_no_fabricated_transition_log() {
    let mut config = test_config();
    config.relay.path_policy = crate::config::PathPolicy::DirectFirst;
    let peers = Arc::new(PeerManager::new(config));
    peers
        .add_peer(&test_peer(PEER, "192.0.2.4:41000".parse().unwrap()))
        .await;
    let (_subscriber, observations) = observe(peers.clone(), None);
    let mut log = DeferredPathSelectionLog::default();
    {
        let (_epoch, mut connections) = peers.lock_epoch_and_connections_write().await;
        assert!(connections[PEER].direct_first_pending());
        let selection = peers.select_path_for_data_with_local_endpoint_in_epoch_with_conns(
            &mut connections,
            PEER,
            false,
            true,
            None,
            peers.current_network_generation_sync(),
            true,
            Some(&mut log),
        );
        assert_eq!(selection.reason_code, REASON_PATH_DIRECT_FIRST_WAIT);
        assert!(selection.path.is_none());
        assert!(connections[PEER].path_events.is_empty());
        assert!(connections[PEER].last_path_selection.is_none());
    }
    drop(log);
    assert!(observations.lock().unwrap().is_empty());
}
