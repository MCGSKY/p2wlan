//! Producer access to the sole weak canonical counter-gate index. Resource
//! preparation does not publish a gate or change the native guard's tries.
use super::*;

impl WireGuardTransport {
    pub(in crate::transport) async fn outbound_emit_lock(
        &self,
        peer_id: &str,
    ) -> Arc<emit_gate::EmitGate> {
        if let Some(gate) = emit_gate::cache::lookup(&self.outbound_emit_locks, peer_id) {
            return gate;
        }
        // Construction and the owned key are prepared without the global
        // index guard. Nothing is published until its original acquisition.
        let candidate = Arc::new(emit_gate::EmitGate::new(&self.outbound_emit_locks));
        let key = peer_id.to_string();
        let mut locks = self.outbound_emit_locks.lock().await;
        let gate = if let Some(gate) = locks.get(peer_id).and_then(Weak::upgrade) {
            gate
        } else {
            // Preserve the sole canonical live incarnation and original GC.
            locks.retain(|_, lock| lock.strong_count() > 0);
            locks.insert(key, Arc::downgrade(&candidate));
            candidate
        };
        drop(locks);
        emit_gate::cache::remember(&self.outbound_emit_locks, peer_id, &gate);
        gate
    }

    pub(in crate::transport) fn try_outbound_emit_lock(
        &self,
        peer_id: &str,
    ) -> Option<Arc<emit_gate::EmitGate>> {
        if let Some(gate) = emit_gate::cache::lookup(&self.outbound_emit_locks, peer_id) {
            return Some(gate);
        }
        // Prepare the same resources before the producer's single index try.
        // The native guard still uses its original independent registry try.
        let candidate = Arc::new(emit_gate::EmitGate::new(&self.outbound_emit_locks));
        let key = peer_id.to_string();
        let mut locks = self.outbound_emit_locks.try_lock().ok()?;
        let gate = if let Some(gate) = locks.get(peer_id).and_then(Weak::upgrade) {
            gate
        } else {
            locks.retain(|_, lock| lock.strong_count() > 0);
            locks.insert(key, Arc::downgrade(&candidate));
            candidate
        };
        drop(locks);
        emit_gate::cache::remember(&self.outbound_emit_locks, peer_id, &gate);
        Some(gate)
    }
}
