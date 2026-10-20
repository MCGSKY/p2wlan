#[tokio::test]
async fn relay_business_ingress_records_first_usable_even_before_probe_ack() {
    let (mut remote_session, local_session) = establish_sessions();
    let (transport, _encrypted_rx) = WireGuardTransport::new();
    transport.add_session("peer-a", local_session).await;

    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    peers
        .add_peer(&PeerInfo {
            capabilities: crate::control::PeerCapabilities::default(),
            registration_seq: 0,
            node_id: "peer-a".to_string(),
            virtual_ip: "10.20.0.1".to_string(),
            online: true,
            ..PeerInfo::default()
        })
        .await;

    let relay = crate::relay::RelayTransport::connect_for_test(
        "test",
        "tls://relay.test:443",
        peers.clone(),
    );
    let relay_connection_id = relay.connection_id();
    let timeline = crate::connection_timeline::ConnectionTimeline::new("node-a", 1);
    // The production daemon installs the same timeline on PeerManager and
    // on the inbound evidence feed.  Keep the test wired the same way so
    // the manager's first_usable_path milestone and the transport's
    // first_real_business_ingress event are asserted against one audit
    // stream.
    peers.set_timeline(timeline.clone());
    let evidence = InboundEvidenceFeed {
        relay_transport: Arc::new(RwLock::new(Some(relay))),
        timeline: Some(timeline.clone()),
        overlay_ingress_tx: None,
    };

    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        0x4321,
        7,
        b"business-before-relay-probe-ack",
    );
    let wire_bytes = remote_session.encrypt_to_bytes(&packet).unwrap();
    let (encrypted_tx, encrypted_rx) = mpsc::channel(1);
    let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
    let (_udp_tx, udp_updates) = watch::channel(None);
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
    });

    encrypted_tx
        .send(ReceivedEncryptedPacket {
            physical_ingress: None,
            original_relay_read: None,
            original_udp_read: None,
            source: None,
            local_endpoint: None,
            relay_endpoint: Some("tls://relay.test:443".to_string()),
            relay_connection_id: Some(relay_connection_id),
            relay_peer_id: Some("peer-a".to_string()),
            socket_index: None,
            direct_socket: None,
            udp_transport_owner: None,
            network_generation: Some(0),
            profile_sampled: false,
            udp_received: None,
            transport_queue_send_started: None,
            wire_bytes,
        })
        .await
        .unwrap();

    let inbound = inbound_rx.recv().await.unwrap();
    assert_eq!(inbound.peer_id, "peer-a");
    let connection = peers.get_connection("peer-a").await.unwrap();
    assert_eq!(connection.relay_confirmed_generation, Some(0));
    assert_eq!(
        connection.relay_confirmed_connection_id,
        Some(relay_connection_id)
    );
    assert_eq!(connection.relay_first.business_received_generation, Some(0));
    assert_eq!(connection.first_usable_generation, Some(0));
    assert_eq!(connection.first_usable_path, Some(NetworkPath::Relay));

    let events = timeline.snapshot().events;
    assert!(events.iter().any(|event| {
        event.event == "business_ingress_observed"
            && event.path.as_deref() == Some("relay")
            && event.reason_code.as_deref() == Some("first_usable_recorded")
            && event.connection_generation == Some(0)
            && event.relay_id.as_deref() == Some("tls://relay.test:443")
    }));
    assert!(events.iter().any(|event| {
        event.event == "first_real_business_ingress" && event.path.as_deref() == Some("relay")
    }));
    assert!(events
        .iter()
        .any(|event| event.event == "first_usable_path" && event.path.as_deref() == Some("relay")));

    drop(encrypted_tx);
    worker.await.unwrap().unwrap();
}

#[tokio::test]
async fn direct_first_gate_rejection_does_not_hide_later_relay_ingress() {
    let (mut remote_session, local_session) = establish_sessions();
    let (transport, _encrypted_rx) = WireGuardTransport::new();
    transport.add_session("peer-a", local_session).await;

    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&PeerInfo {
            capabilities: crate::control::PeerCapabilities::default(),
            registration_seq: 0,
            node_id: "peer-a".to_string(),
            virtual_ip: "10.20.0.1".to_string(),
            online: true,
            ..PeerInfo::default()
        })
        .await;

    let relay_endpoint = "tls://relay.test:443";
    let relay =
        crate::relay::RelayTransport::connect_for_test("test", relay_endpoint, peers.clone());
    let relay_connection_id = relay.connection_id();
    peers
        .mark_relay_transport_ready_with_transport(
            "peer-a",
            relay_endpoint,
            0,
            Some(relay_connection_id),
        )
        .await;
    assert!(
        peers
            .confirm_relay_peer_with_transport(
                "peer-a",
                relay_endpoint,
                0,
                Some(relay_connection_id),
            )
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
    let (_udp_updates_tx, udp_updates) = watch::channel(Some(udp));
    let (encrypted_tx, encrypted_rx) = mpsc::channel(2);
    let (inbound_tx, mut inbound_rx) = mpsc::channel(2);
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
    });

    let direct_packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        0x6101,
        1,
        b"direct-first-gated",
    );
    encrypted_tx
        .send(ReceivedEncryptedPacket {
            physical_ingress: None,
            original_relay_read: None,
            original_udp_read: None,
            source: Some("198.51.100.10:51820".parse().unwrap()),
            local_endpoint: Some(local_endpoint),
            relay_endpoint: None,
            relay_connection_id: None,
            relay_peer_id: None,
            socket_index: Some(0),
            direct_socket: None,
            udp_transport_owner: Some(1),
            network_generation: Some(0),
            profile_sampled: false,
            udp_received: None,
            transport_queue_send_started: None,
            wire_bytes: remote_session.encrypt_to_bytes(&direct_packet).unwrap(),
        })
        .await
        .unwrap();
    assert_eq!(inbound_rx.recv().await.unwrap().peer_id, "peer-a");
    assert_eq!(
        peers
            .get_connection("peer-a")
            .await
            .unwrap()
            .first_usable_path,
        None,
        "Direct business ingress before the relay-business gate is not first usable"
    );

    let relay_packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        0x6102,
        1,
        b"relay-later-usable",
    );
    encrypted_tx
        .send(ReceivedEncryptedPacket {
            physical_ingress: None,
            original_relay_read: None,
            original_udp_read: None,
            source: None,
            local_endpoint: None,
            relay_endpoint: Some(relay_endpoint.to_string()),
            relay_connection_id: Some(relay_connection_id),
            relay_peer_id: Some("peer-a".to_string()),
            socket_index: None,
            direct_socket: None,
            udp_transport_owner: None,
            network_generation: Some(0),
            profile_sampled: false,
            udp_received: None,
            transport_queue_send_started: None,
            wire_bytes: remote_session.encrypt_to_bytes(&relay_packet).unwrap(),
        })
        .await
        .unwrap();
    assert_eq!(inbound_rx.recv().await.unwrap().peer_id, "peer-a");

    let connection = peers.get_connection("peer-a").await.unwrap();
    assert_eq!(connection.first_usable_generation, Some(0));
    assert_eq!(connection.first_usable_path, Some(NetworkPath::Relay));

    let events = timeline.snapshot().events;
    assert!(events.iter().any(|event| {
        event.event == "business_ingress_observed"
            && event.path.as_deref() == Some("direct")
            && event.reason_code.as_deref() == Some("first_usable_not_recorded")
    }));
    assert!(events.iter().any(|event| {
        event.event == "business_ingress_observed"
            && event.path.as_deref() == Some("relay")
            && event.reason_code.as_deref() == Some("first_usable_recorded")
            && event.relay_id.as_deref() == Some(relay_endpoint)
    }));
    assert!(events.iter().any(|event| {
        event.event == "first_usable_path" && event.path.as_deref() == Some("relay")
    }));

    drop(encrypted_tx);
    worker.await.unwrap().unwrap();
}
