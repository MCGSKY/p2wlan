//! A producer-only weak alias of a live canonical counter gate. It grants no
//! permission and never replaces the native guard's real registry/emit tries.
//! All registry writers remove dead weak entries only. A successful upgrade
//! therefore names the same gate that the canonical index must still contain.
use super::{EmitGate, EmitRegistry};
use std::cell::RefCell;
use std::sync::{Arc, Weak};

pub(in crate::transport) const MAX_CACHED_PEER_BYTES: usize = 256;
struct Entry {
    registry: Weak<EmitRegistry>,
    gate: Weak<EmitGate>,
    key: [u8; MAX_CACHED_PEER_BYTES],
    length: usize,
}
thread_local! {
    // At most one fixed-size entry per existing thread, with no allocation,
    // strong gate/registry/worker owner, task, timer or independent state.
    static LAST: RefCell<Option<Entry>> = const { RefCell::new(None) };
}

pub(in crate::transport) fn lookup(
    registry: &Arc<EmitRegistry>,
    peer: &str,
) -> Option<Arc<EmitGate>> {
    LAST.try_with(|last| {
        let mut last = last.try_borrow_mut().ok()?;
        let entry = last.as_ref()?;
        if entry.length != peer.len()
            || entry.key[..entry.length] != *peer.as_bytes()
            || !entry.registry.ptr_eq(&Arc::downgrade(registry))
        {
            *last = None;
            return None;
        }
        let gate = entry.gate.upgrade();
        if gate.is_none() {
            *last = None;
        }
        gate
    })
    .ok()
    .flatten()
}

pub(in crate::transport) fn remember(
    registry: &Arc<EmitRegistry>,
    peer: &str,
    gate: &Arc<EmitGate>,
) {
    let entry = if peer.len() <= MAX_CACHED_PEER_BYTES {
        let mut key = [0; MAX_CACHED_PEER_BYTES];
        key[..peer.len()].copy_from_slice(peer.as_bytes());
        Some(Entry {
            registry: Arc::downgrade(registry),
            gate: Arc::downgrade(gate),
            key,
            length: peer.len(),
        })
    } else {
        None
    };
    // Reentrancy or thread teardown only skips an optional hint. The caller
    // has already resolved its actual canonical resource through the registry.
    let _ = LAST.try_with(|last| {
        if let Ok(mut last) = last.try_borrow_mut() {
            *last = entry;
        }
    });
}
