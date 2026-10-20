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

#[tokio::test]
async fn prepared_fixed_resource_rechecks_exact_slot_peer_endpoint_and_generation() {
    let peers = peer_manager();
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_socket_pool(2)
        .await
        .unwrap();
    let other = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let generation = peers.current_network_generation_sync();
    let socket = udp.active_sockets()[1].clone();
    let address = socket.local_addr().unwrap();
    let mut resource = udp.try_prepare_committed_socket_resource("peer-b", address, generation);
    assert!(resource.is_some());
    assert!(udp
        .try_take_prepared_committed_socket("other-peer", address, generation, &mut resource)
        .is_none());
    assert!(udp
        .try_take_prepared_committed_socket("peer-b", address, generation + 1, &mut resource)
        .is_none());
    assert!(other
        .try_take_prepared_committed_socket("peer-b", address, generation, &mut resource)
        .is_none());
    let mut changed = address;
    changed.set_port(if address.port() == u16::MAX {
        1
    } else {
        address.port() + 1
    });
    assert!(udp
        .try_take_prepared_committed_socket("peer-b", changed, generation, &mut resource)
        .is_none());
    assert!(
        resource.is_some(),
        "rejected preparation remains with its original owner"
    );
    let (index, actual, lease) = udp
        .try_take_prepared_committed_socket("peer-b", address, generation, &mut resource)
        .unwrap();
    assert_eq!(index, 1);
    assert!(Arc::ptr_eq(&socket, &actual));
    assert!(resource.is_none());
    drop(lease);
    let ipv6 = Arc::new(
        p2pnet_netbind::bind_udp("[::]:0".parse().unwrap(), None)
            .await
            .unwrap(),
    );
    let udp6 = udp.clone().with_ipv6_socket(ipv6.clone());
    let original = ipv6.local_addr().unwrap();
    let mut resource = udp6.try_prepare_committed_socket_resource("peer-b", original, generation);
    assert!(resource.is_some());
    ipv6.connect("[::1]:32123").await.unwrap();
    assert_ne!(ipv6.local_addr().unwrap(), original);
    assert!(
        udp6.try_take_prepared_committed_socket("peer-b", original, generation, &mut resource)
            .is_none(),
        "even the same Arc cannot conceal an actual socket address change"
    );
}

#[tokio::test]
async fn prepared_dynamic_resource_rejects_actual_retirement_without_consuming_lease() {
    timeout(Duration::from_secs(1), async {
        let (peers, udp, _nat, index) = exact_send_report_fixture().await;
        let (socket, leases) = {
            let registry = udp.socket_state.lock().await;
            let entry = &registry.dynamic[&index];
            (entry.socket.clone(), entry.send_leases.clone())
        };
        let generation = peers.current_network_generation_sync();
        let address = socket.local_addr().unwrap();
        let mut resource = udp.try_prepare_committed_socket_resource("peer-b", address, generation);
        assert_eq!(leases.outstanding(), 1);
        let retired = udp.remove_original_dynamic_entry(index).await.unwrap();
        assert!(udp
            .try_take_prepared_committed_socket("peer-b", address, generation, &mut resource)
            .is_none());
        assert!(resource.is_some());
        assert_eq!(leases.outstanding(), 1);
        drop(resource);
        assert_eq!(leases.outstanding(), 0);
        udp.detach_dynamic_entry(retired, "prepared_resource_retirement_control")
            .await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn prepared_dynamic_resource_busy_registry_keeps_original_fallback_and_owner() {
    timeout(Duration::from_secs(1), async {
        let (peers, udp, _nat, index) = exact_send_report_fixture().await;
        let (socket, leases) = {
            let registry = udp.socket_state.lock().await;
            let entry = &registry.dynamic[&index];
            (entry.socket.clone(), entry.send_leases.clone())
        };
        let generation = peers.current_network_generation_sync();
        let address = socket.local_addr().unwrap();
        let mut resource = udp.try_prepare_committed_socket_resource("peer-b", address, generation);
        let registry = udp.socket_state.lock().await;
        assert!(udp
            .try_take_prepared_committed_socket("peer-b", address, generation, &mut resource)
            .is_none());
        assert_eq!(leases.outstanding(), 1);
        assert!(resource.is_some());
        drop(registry);
        let (actual, resolved, lease) = udp
            .try_take_prepared_committed_socket("peer-b", address, generation, &mut resource)
            .unwrap();
        assert_eq!(actual, index);
        assert!(Arc::ptr_eq(&socket, &resolved));
        assert!(resource.is_none());
        assert_eq!(leases.outstanding(), 1);
        drop(lease);
        assert_eq!(leases.outstanding(), 0);
        udp.detach_all_dynamic_punch_sockets("prepared_resource_busy_control")
            .await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn busy_prepared_dynamic_snapshot_adds_no_waiter_or_send_lease() {
    timeout(Duration::from_secs(1), async {
        let (_peers, udp, _nat, index) = exact_send_report_fixture().await;
        let registry = udp.socket_state.lock().await;
        let entry = &registry.dynamic[&index];
        let address = entry.socket.local_addr().unwrap();
        let leases = entry.send_leases.clone();
        let generation = entry.network_generation;
        assert!(udp
            .try_prepare_committed_socket_resource("peer-b", address, generation)
            .is_none());
        assert_eq!(leases.outstanding(), 0);
        drop(registry);
        assert!(udp.socket_state.try_lock().is_ok());
        assert_eq!(leases.outstanding(), 0);
        udp.detach_all_dynamic_punch_sockets("prepared_resource_busy_snapshot_control")
            .await;
    })
    .await
    .unwrap();
}
