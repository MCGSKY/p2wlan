//! Actual resource waits/cancellation, without constructing native observations.
use super::*;
use std::future::Future;
use std::task::Poll;

#[tokio::test(flavor = "current_thread")]
async fn stale_peer_update_rejects_before_waiting_for_original_ip_writer() {
    let manager = PeerManager::new(test_config());
    let mut current = test_peer("ip-writer-stale", "192.0.2.1:51820".parse().unwrap());
    current.registration_seq = 2;
    manager.add_peer(&current).await;
    let mut delayed = current.clone();
    delayed.registration_seq = 1;
    delayed.online = false;
    let ip_writer = manager.ip_to_node.write().await;
    let mut update = Box::pin(manager.add_peer(&delayed));
    let outcome = std::future::poll_fn(|cx| Poll::Ready(update.as_mut().poll(cx))).await;
    drop(update);
    assert!(manager.network_epoch_gate.try_lock().is_ok());
    let connection = manager.connections.try_read().unwrap();
    let retained = connection.get(&current.node_id).unwrap();
    assert!(retained.online);
    assert_eq!(retained.registration_seq, 2);
    assert_eq!(ip_writer.get(&current.virtual_ip), Some(&current.node_id));
    drop(connection);
    drop(ip_writer);
    match outcome {
        Poll::Ready(result) => assert!(result.last_seen_only),
        Poll::Pending => panic!("stale roster waited behind the unrelated IP writer"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn peer_update_waits_for_ip_writer_without_holding_epoch_or_connections() {
    let manager = PeerManager::new(test_config());
    let info = test_peer("ip-writer-wait", "192.0.2.1:51820".parse().unwrap());
    let ip_writer = manager.ip_to_node.write().await;
    let mut update = Box::pin(manager.add_peer(&info));
    std::future::poll_fn(|cx| {
        assert!(update.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(manager.network_epoch_gate.try_lock().is_ok());
    let connections = manager.connections.try_read().unwrap();
    assert!(!connections.contains_key(&info.node_id));
    drop(connections);
    drop(ip_writer);
    tokio::time::timeout(std::time::Duration::from_secs(1), update)
        .await
        .unwrap();
    let connection = manager.get_connection(&info.node_id).await.unwrap();
    assert!(connection.online);
    assert_eq!(connection.virtual_ip, info.virtual_ip);
    assert_eq!(
        manager.ip_to_node.read().await.get(&info.virtual_ip),
        Some(&info.node_id)
    );
    assert!(manager.network_epoch_gate.try_lock().is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_peer_update_ip_wait_releases_original_writer_and_partial_guards() {
    let manager = PeerManager::new(test_config());
    let info = test_peer("ip-writer-cancel", "192.0.2.1:51820".parse().unwrap());
    let ip_writer = manager.ip_to_node.write().await;
    let mut update = Box::pin(manager.add_peer(&info));
    std::future::poll_fn(|cx| {
        assert!(update.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(manager.network_epoch_gate.try_lock().is_ok());
    drop(update);
    assert!(manager.network_epoch_gate.try_lock().is_ok());
    assert!(!manager
        .connections
        .try_read()
        .unwrap()
        .contains_key(&info.node_id));
    assert!(!ip_writer.contains_key(&info.virtual_ip));
    drop(ip_writer);
    assert!(manager.ip_to_node.try_write().is_ok());
    tokio::time::timeout(std::time::Duration::from_secs(1), manager.add_peer(&info))
        .await
        .unwrap();
    assert!(manager.get_connection(&info.node_id).await.unwrap().online);
    assert_eq!(
        manager.ip_to_node.read().await.get(&info.virtual_ip),
        Some(&info.node_id)
    );
}
