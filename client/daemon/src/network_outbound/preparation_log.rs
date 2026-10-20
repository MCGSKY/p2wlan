//! Bounded diagnostic fields owned outside preparation and physical sending.
use super::{
    REASON_OUTBOUND_ENCRYPT_FAILED, REASON_OUTBOUND_GENERATION_CHANGED,
    REASON_OUTBOUND_SESSION_NOT_READY,
};
use tracing::{debug, warn};

enum Rejection {
    Generation(u64),
    MissingSession(usize),
    Encryption(usize, String),
}

pub(super) struct DeferredPreparationLog {
    peer: String,
    generation: u64,
    acquired: Option<u64>,
    rejection: Option<Rejection>,
}

impl DeferredPreparationLog {
    pub(super) fn new(peer: String, generation: u64) -> Self {
        Self {
            peer,
            generation,
            acquired: None,
            rejection: None,
        }
    }

    pub(super) fn acquired(&mut self, wait_ms: u64) {
        self.acquired = Some(wait_ms);
    }

    pub(super) fn generation_rejected(&mut self, current: u64) {
        self.rejection = Some(Rejection::Generation(current));
    }

    pub(super) fn missing_session(&mut self, bytes: usize) {
        self.rejection = Some(Rejection::MissingSession(bytes));
    }

    pub(super) fn encryption_failed(&mut self, bytes: usize, error: String) {
        self.rejection = Some(Rejection::Encryption(bytes, error));
    }
}

impl Drop for DeferredPreparationLog {
    fn drop(&mut self) {
        if let Some(lock_wait_ms) = self.acquired {
            debug!(
                target: "p2pnet_daemon::network_outbound::send",
                event = "outbound_business_emit_lock_acquired",
                peer_id = %self.peer,
                generation = self.generation,
                lock_wait_ms,
                "business packet acquired its per-peer WireGuard counter-ordering lock"
            );
        }
        match self.rejection.as_ref() {
            Some(Rejection::Generation(current_generation)) => debug!(
                target: "p2pnet_daemon::network_outbound::send",
                event = "outbound_counter_allocation_rejected",
                peer_id = %self.peer,
                expected_generation = self.generation,
                current_generation,
                reason_code = REASON_OUTBOUND_GENERATION_CHANGED,
                "business packet was not encrypted because its network generation is stale"
            ),
            Some(Rejection::MissingSession(bytes)) => debug!(
                target: "p2pnet_daemon::network_outbound::send",
                event = "outbound_session_unavailable",
                peer_id = %self.peer,
                generation = self.generation,
                bytes,
                reason_code = REASON_OUTBOUND_SESSION_NOT_READY,
                "business packet remained plaintext because no usable WireGuard session exists"
            ),
            Some(Rejection::Encryption(bytes, error)) => warn!(
                target: "p2pnet_daemon::network_outbound::send",
                event = "outbound_encrypt_failed",
                peer_id = %self.peer,
                generation = self.generation,
                bytes,
                reason_code = REASON_OUTBOUND_ENCRYPT_FAILED,
                error = %error,
                "business packet encryption failed before a transport handoff"
            ),
            None => {}
        }
    }
}
