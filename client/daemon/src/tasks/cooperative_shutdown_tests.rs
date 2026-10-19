use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{oneshot, Notify};
use tokio::time::timeout;

#[tokio::test]
async fn cooperative_owner_joins_original_udp_reader_before_shutdown_returns() {
    let manager = TaskManager::new(HealthState::new());
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let (ready_tx, ready_rx) = oneshot::channel();
    let joined = Arc::new(AtomicBool::new(false));
    let completed = joined.clone();
    let mut stop = manager.shutdown_rx();
    manager
        .spawn_result_with_shutdown(
            "udp-owner",
            false,
            TaskShutdownMode::Cooperative,
            async move {
                let reader = tokio::spawn(async move {
                    ready_tx.send(()).unwrap();
                    socket.recv_from(&mut [0; 1]).await
                });
                if !*stop.borrow_and_update() {
                    let _ = stop.changed().await;
                }
                reader.abort();
                assert!(reader.await.unwrap_err().is_cancelled());
                completed.store(true, Ordering::Release);
                Ok::<(), &'static str>(())
            },
        )
        .await;
    timeout(Duration::from_secs(1), ready_rx)
        .await
        .unwrap()
        .unwrap();
    manager.shutdown_all(Duration::from_secs(1)).await;
    assert!(joined.load(Ordering::Acquire));
    assert!(manager.task_statuses().await.is_empty());
    let rebound = std::net::UdpSocket::bind(address).unwrap();
    drop(rebound);
}

struct NotifyDrop(Arc<Notify>);
impl Drop for NotifyDrop {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

async fn pending_owner(manager: &Arc<TaskManager>) -> Arc<Notify> {
    let dropped = Arc::new(Notify::new());
    let observed = dropped.clone();
    let (ready_tx, ready_rx) = oneshot::channel();
    manager
        .spawn_result_with_shutdown(
            "unresponsive-owner",
            false,
            TaskShutdownMode::Cooperative,
            async move {
                let _guard = NotifyDrop(observed);
                ready_tx.send(()).unwrap();
                std::future::pending::<Result<(), &'static str>>().await
            },
        )
        .await;
    timeout(Duration::from_secs(1), ready_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(manager.task_statuses().await.len(), 1);
    dropped
}

#[tokio::test]
async fn cooperative_owner_is_cancelled_when_original_shutdown_budget_expires() {
    let manager = TaskManager::new(HealthState::new());
    let dropped = pending_owner(&manager).await;
    timeout(
        Duration::from_secs(1),
        manager.shutdown_all(Duration::from_millis(20)),
    )
    .await
    .unwrap();
    timeout(Duration::from_secs(1), dropped.notified())
        .await
        .unwrap();
    assert!(manager.is_shutdown());
    assert!(manager.task_statuses().await.is_empty());
}

#[tokio::test]
async fn cancelling_shutdown_cancels_original_cooperative_owner() {
    let manager = TaskManager::new(HealthState::new());
    let dropped = pending_owner(&manager).await;
    let owner = manager.clone();
    let shutdown = tokio::spawn(async move {
        owner.shutdown_all(Duration::from_secs(60)).await;
    });
    timeout(Duration::from_secs(1), async {
        while !manager.task_statuses().await.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    shutdown.abort();
    assert!(shutdown.await.unwrap_err().is_cancelled());
    timeout(Duration::from_secs(1), dropped.notified())
        .await
        .unwrap();
}
