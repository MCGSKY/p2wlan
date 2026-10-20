//! Test-only, bounded observations of the real registry mutex at construction.
//! This adds no production observer, delay, callback, owner or kernel credit.
use super::*;
use std::cell::RefCell;

#[derive(Default)]
struct Observations {
    count: usize,
    free: [bool; 4],
}
thread_local! {
    static ACTIVE: RefCell<Option<Observations>> = const { RefCell::new(None) };
}

pub(super) fn record(registry: &Arc<EmitRegistry>) {
    ACTIVE.with(|active| {
        if let Some(observed) = active.borrow_mut().as_mut() {
            assert!(observed.count < observed.free.len());
            observed.free[observed.count] = registry.try_lock().is_ok();
            observed.count += 1;
        }
    });
}

struct Probe;
impl Probe {
    fn start() -> Self {
        ACTIVE.with(|active| {
            assert!(active.borrow().is_none());
            *active.borrow_mut() = Some(Observations::default());
        });
        Self
    }

    fn finish(self) -> Observations {
        ACTIVE.with(|active| active.borrow_mut().take().unwrap())
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        ACTIVE.with(|active| *active.borrow_mut() = None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{OriginalKernelEmitFailure, WireGuardTransport};

    #[tokio::test(flavor = "current_thread")]
    async fn emit_index_try_construction_releases_actual_registry_for_allocation() {
        let (transport, _) = WireGuardTransport::new();
        let dead = Arc::new(EmitGate::new(&transport.outbound_emit_locks));
        transport
            .outbound_emit_locks
            .lock()
            .await
            .insert("dead-peer".into(), Arc::downgrade(&dead));
        drop(dead);
        let probe = Probe::start();
        let gate = transport.try_outbound_emit_lock("try-miss-peer").unwrap();
        let observed = probe.finish();
        assert_eq!(observed.count, 1);
        assert!(
            observed.free[0],
            "producer gate construction still owns the actual registry mutex"
        );
        let index = transport.outbound_emit_locks.try_lock().unwrap();
        assert!(!index.contains_key("dead-peer"));
        assert!(Arc::ptr_eq(
            &index["try-miss-peer"].upgrade().unwrap(),
            &gate
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn emit_index_try_prepared_candidate_cannot_replace_live_counter_gate() {
        let (transport, _) = WireGuardTransport::new();
        let first = transport.outbound_emit_lock("live-peer").await;
        let other = transport.outbound_emit_lock("other-peer").await;
        let weak_count = Arc::weak_count(&transport.outbound_emit_locks);
        let probe = Probe::start();
        let same = transport.try_outbound_emit_lock("live-peer").unwrap();
        let observed = probe.finish();
        assert_eq!(observed.count, 1);
        assert!(observed.free[0]);
        assert!(Arc::ptr_eq(&first, &same));
        assert_eq!(Arc::weak_count(&transport.outbound_emit_locks), weak_count);
        let held = first.clone().lock_owned().await;
        assert!(same.clone().try_lock_owned().is_err());
        let owner = transport
            .original_kernel_transport_owners()
            .upgrade()
            .unwrap();
        assert!(matches!(
            owner.try_emit_guard("live-peer", None),
            Err(OriginalKernelEmitFailure::Emit)
        ));
        drop(held);
        assert!(same.try_lock_owned().is_ok());
        drop(other);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn emit_index_try_busy_registry_cannot_publish_or_retain_candidate() {
        let (transport, _) = WireGuardTransport::new();
        let owner = transport
            .original_kernel_transport_owners()
            .upgrade()
            .unwrap();
        let held = transport.outbound_emit_locks.lock().await;
        let weak_count = Arc::weak_count(&transport.outbound_emit_locks);
        assert!(transport
            .try_outbound_emit_lock("busy-index-peer")
            .is_none());
        assert!(held.is_empty());
        assert_eq!(Arc::weak_count(&transport.outbound_emit_locks), weak_count);
        assert!(matches!(
            owner.try_emit_guard("busy-index-peer", None),
            Err(OriginalKernelEmitFailure::Registry)
        ));
        assert!(cache::lookup(&transport.outbound_emit_locks, "busy-index-peer").is_none());
        drop(held);
        assert!(transport
            .try_outbound_emit_lock("busy-index-peer")
            .is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn emit_index_try_long_key_keeps_original_canonical_and_idle_incarnations() {
        let (transport, _) = WireGuardTransport::new();
        let peer = "x".repeat(cache::MAX_CACHED_PEER_BYTES + 1);
        let gate = transport.try_outbound_emit_lock(&peer).unwrap();
        let weak = Arc::downgrade(&gate);
        let same = transport.try_outbound_emit_lock(&peer).unwrap();
        assert!(Arc::ptr_eq(&gate, &same));
        let owner = transport
            .original_kernel_transport_owners()
            .upgrade()
            .unwrap();
        let held = owner.try_emit_guard(&peer, None).unwrap();
        drop(gate);
        drop(same);
        assert!(weak.upgrade().is_some());
        drop(held);
        assert!(weak.upgrade().is_none());
        transport.remove_idle_outbound_emit_lock(&peer).await;
        assert!(!transport
            .outbound_emit_locks
            .lock()
            .await
            .contains_key(&peer));
        let next = transport.try_outbound_emit_lock(&peer).unwrap();
        assert!(!weak.ptr_eq(&Arc::downgrade(&next)));
        let index = transport.outbound_emit_locks.lock().await;
        assert!(transport.try_outbound_emit_lock(&peer).is_none());
        assert!(matches!(
            owner.try_emit_guard(&peer, None),
            Err(OriginalKernelEmitFailure::Registry)
        ));
        drop(index);
        assert!(next.try_lock_owned().is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn emit_index_async_preparation_preserves_original_free_registry() {
        let (transport, _) = WireGuardTransport::new();
        let probe = Probe::start();
        let gate = transport.outbound_emit_lock("async-index-peer").await;
        let observed = probe.finish();
        assert_eq!(observed.count, 1);
        assert!(observed.free[0]);
        let index = transport.outbound_emit_locks.try_lock().unwrap();
        assert!(Arc::ptr_eq(
            &index["async-index-peer"].upgrade().unwrap(),
            &gate
        ));
    }
}
