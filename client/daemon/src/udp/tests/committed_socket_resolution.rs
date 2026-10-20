// Real socket/registry contention controls; no native ACK or current-owner credit.
use super::*;

#[tokio::test]
async fn fixed_committed_registry_contention_pool_keeps_exact_arcs() {
    timeout(Duration::from_secs(1), async {
        let peers = peer_manager();
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_socket_pool(2)
            .await
            .unwrap();
        let epoch = peers.network_epoch_gate();
        let _epoch = epoch.lock().await;
        let _registry = udp.socket_state.lock().await;
        let generation = peers.current_network_generation_sync();
        for (index, socket) in udp.active_sockets().iter().enumerate() {
            let (actual, resolved, _lease) = udp
                .resolve_committed_direct_socket_with_lease(
                    "peer-b",
                    socket.local_addr().unwrap(),
                    generation,
                )
                .await
                .unwrap();
            assert_eq!(actual, index);
            assert!(Arc::ptr_eq(&resolved, socket));
            assert!(udp
                .resolve_committed_direct_socket_with_lease(
                    "peer-b",
                    socket.local_addr().unwrap(),
                    generation + 1,
                )
                .await
                .is_none());
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn fixed_committed_registry_contention_ipv6_keeps_exact_arc() {
    timeout(Duration::from_secs(1), async {
        let peers = peer_manager();
        let ipv6 = Arc::new(
            p2pnet_netbind::bind_udp("[::1]:0".parse().unwrap(), None)
                .await
                .unwrap(),
        );
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_ipv6_socket(ipv6.clone());
        let epoch = peers.network_epoch_gate();
        let _epoch = epoch.lock().await;
        let _registry = udp.socket_state.lock().await;
        let generation = peers.current_network_generation_sync();
        let (index, resolved, _lease) = udp
            .resolve_committed_direct_socket_with_lease(
                "peer-b",
                ipv6.local_addr().unwrap(),
                generation,
            )
            .await
            .unwrap();
        assert_eq!(index, IPV6_SOCKET_INDEX);
        assert!(Arc::ptr_eq(&resolved, &ipv6));
        assert!(udp
            .resolve_committed_direct_socket_with_lease(
                "peer-b",
                ipv6.local_addr().unwrap(),
                generation + 1,
            )
            .await
            .is_none());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn committed_dynamic_resolution_keeps_exact_peer_and_send_lease() {
    timeout(Duration::from_secs(1), async {
        let (peers, udp, _nat, index) = exact_send_report_fixture().await;
        let (socket, leases) = {
            let registry = udp.socket_state.lock().await;
            let entry = &registry.dynamic[&index];
            (entry.socket.clone(), entry.send_leases.clone())
        };
        let generation = peers.current_network_generation_sync();
        let (actual, resolved, lease) = udp
            .resolve_committed_direct_socket_with_lease(
                "peer-b",
                socket.local_addr().unwrap(),
                generation,
            )
            .await
            .unwrap();
        assert_eq!(actual, index);
        assert!(Arc::ptr_eq(&socket, &resolved));
        assert_eq!(leases.outstanding(), 1);
        assert!(udp
            .resolve_committed_direct_socket_with_lease(
                "other-peer",
                socket.local_addr().unwrap(),
                generation,
            )
            .await
            .is_none());
        drop(lease);
        assert_eq!(leases.outstanding(), 0);
        udp.detach_all_dynamic_punch_sockets("committed_resolution_control")
            .await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn committed_dynamic_wait_rechecks_generation_before_lease() {
    timeout(Duration::from_secs(1), async {
        let (peers, udp, _nat, index) = exact_send_report_fixture().await;
        let registry = udp.socket_state.lock().await;
        let entry = &registry.dynamic[&index];
        let address = entry.socket.local_addr().unwrap();
        let leases = entry.send_leases.clone();
        let generation = peers.current_network_generation_sync();
        let mut resolve =
            Box::pin(udp.resolve_committed_direct_socket_with_lease("peer-b", address, generation));
        assert!(matches!(
            futures_util::poll!(resolve.as_mut()),
            std::task::Poll::Pending
        ));
        assert_eq!(leases.outstanding(), 0);
        drop(registry);
        assert!(
            peers
                .advance_network_generation("committed_registry_wait")
                .await
                > generation
        );
        assert!(resolve.await.is_none());
        assert_eq!(leases.outstanding(), 0);
        udp.detach_all_dynamic_punch_sockets("committed_generation_control")
            .await;
    })
    .await
    .unwrap();
}
