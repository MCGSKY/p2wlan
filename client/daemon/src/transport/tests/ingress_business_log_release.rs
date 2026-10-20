// The production inbound worker decrypts a real handshake peer's packet.
// Synthetic ingress envelopes grant no original read, Full or native credit.
use tracing::instrument::WithSubscriber;

struct BusinessLogProbe {
    // Retain the exact original gate so callback reentry cannot create a
    // replacement mutex after its registry's weak entry expires.
    gate: Arc<crate::transport::emit_gate::EmitGate>,
    observations: Arc<std::sync::Mutex<Vec<(String, bool)>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for BusinessLogProbe {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
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
        let mut name = Name::default();
        event.record(&mut name);
        if matches!(
            name.0.as_str(),
            "business_ingress_observed" | "first_real_business_ingress"
        ) {
            let released = self.gate.clone().try_lock_owned().is_ok();
            self.observations.lock().unwrap().push((name.0, released));
        }
    }
}

async fn actual_ingress(relay_ingress: bool) {
    let (mut remote, local) = establish_sessions();
    let (transport, _outbound_rx) = WireGuardTransport::new();
    transport.add_session("peer-a", local).await;
    let original_gate = transport.outbound_emit_lock("peer-a").await;
    let mut config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    if relay_ingress {
        config.relay.path_policy = crate::config::PathPolicy::RelayOnly;
    }
    let peers = Arc::new(PeerManager::new(config));
    peers
        .add_peer(&PeerInfo {
            node_id: "peer-a".into(),
            virtual_ip: "10.20.0.1".into(),
            endpoint: "198.51.100.10:51820".into(),
            online: true,
            ..PeerInfo::default()
        })
        .await;
    let relay_endpoint = "tls://relay.test:443";
    let relay =
        crate::relay::RelayTransport::connect_for_test("test", relay_endpoint, peers.clone());
    let relay_id = relay.connection_id();
    peers
        .mark_relay_transport_ready_with_transport("peer-a", relay_endpoint, 0, Some(relay_id))
        .await;
    assert!(
        peers
            .confirm_relay_peer_with_transport("peer-a", relay_endpoint, 0, Some(relay_id))
            .await
    );
    let timeline = crate::connection_timeline::ConnectionTimeline::new("node-a", 1);
    peers.set_timeline(timeline.clone());
    let evidence = InboundEvidenceFeed {
        relay_transport: Arc::new(RwLock::new(Some(relay))),
        timeline: Some(timeline.clone()),
        overlay_ingress_tx: None,
    };
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    udp.set_inbound_publication_owner(1);
    let local_endpoint = udp.local_addr().unwrap();
    let (_updates_tx, udp_updates) = watch::channel(Some(udp));
    let observations = Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(BusinessLogProbe {
        gate: original_gate.clone(),
        observations: observations.clone(),
    });
    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        7,
        1,
        b"business-log-real-emit-boundary",
    );
    let wire_bytes = remote.encrypt_to_bytes(&packet).unwrap();
    let (encrypted_tx, encrypted_rx) = mpsc::channel(1);
    let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
    let worker = tokio::spawn({
        let transport = transport.clone();
        let peers = peers.clone();
        async move {
            transport
                .run_inbound_with_peers_live_udp_and_relay(
                    encrypted_rx,
                    inbound_tx,
                    Some(peers),
                    udp_updates,
                    Some(evidence),
                )
                .await
        }
        .with_subscriber(subscriber)
    });
    encrypted_tx
        .send(ReceivedEncryptedPacket {
            physical_ingress: None,
            original_relay_read: None,
            original_udp_read: None,
            source: (!relay_ingress).then(|| "198.51.100.10:51820".parse().unwrap()),
            local_endpoint: (!relay_ingress).then_some(local_endpoint),
            relay_endpoint: relay_ingress.then(|| relay_endpoint.to_string()),
            relay_connection_id: relay_ingress.then_some(relay_id),
            relay_peer_id: relay_ingress.then(|| "peer-a".into()),
            socket_index: (!relay_ingress).then_some(0),
            direct_socket: None,
            udp_transport_owner: (!relay_ingress).then_some(1),
            network_generation: Some(0),
            profile_sampled: false,
            udp_received: None,
            transport_queue_send_started: None,
            wire_bytes,
        })
        .await
        .unwrap();
    let inbound = timeout(Duration::from_secs(2), inbound_rx.recv())
        .await
        .unwrap()
        .unwrap();
    drop(encrypted_tx);
    worker.await.unwrap().unwrap(); // Join the real worker before any expected preimage failure.
    assert_eq!(inbound.packet, packet);
    let connection = peers.get_connection("peer-a").await.unwrap();
    let path = if relay_ingress { "relay" } else { "direct" };
    if relay_ingress {
        assert_eq!(connection.first_usable_path, Some(NetworkPath::Relay));
        assert_eq!(connection.first_usable_generation, Some(0));
    } else {
        assert_eq!(
            connection.first_usable_path, None,
            "DirectFirst gate is still authoritative"
        );
    }
    let events = timeline.snapshot().events;
    assert!(events.iter().any(|e| e.event == "business_ingress_observed"
        && e.path.as_deref() == Some(path)
        && e.reason_code.as_deref()
            == Some(if relay_ingress {
                "first_usable_recorded"
            } else {
                "first_usable_not_recorded"
            })));
    let rows = observations.lock().unwrap();
    assert_eq!(
        rows.len(),
        2,
        "both original business milestones remain visible: {rows:?}"
    );
    assert!(
        rows.iter().all(|(_, released)| *released),
        "business logger still owns the exact emit mutex: {rows:?}"
    );
}

#[tokio::test]
async fn relay_business_logs_release_emit_after_canonical_first_usable() {
    actual_ingress(true).await;
}

#[tokio::test]
async fn gated_direct_business_logs_release_emit_without_first_usable_credit() {
    actual_ingress(false).await;
}
