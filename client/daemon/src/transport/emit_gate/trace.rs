//! One fixed negative record per original capture, independent of peer churn.
//! Only metadata survives a guard: no transport, real mutex, source or IO fact.
use crate::peer::EpochTryContext;
use serde::Serialize;
use std::panic::Location;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Instant;

pub(super) fn now_ns() -> Option<u64> {
    crate::os_request_capture::original_kernel_monotonic_ns()
}

#[derive(Clone, Copy)]
pub(in crate::transport) struct Site {
    code: u8,
    line: u32,
}
impl Site {
    #[track_caller]
    pub(super) fn caller() -> Self {
        let location = Location::caller();
        let file = location.file();
        let code = SOURCES
            .iter()
            .position(|source| file.ends_with(source))
            .map_or(0, |i| (i + 1) as u8);
        Self {
            code,
            line: location.line(),
        }
    }
    fn name(self) -> &'static str {
        self.code
            .checked_sub(1)
            .and_then(|i| SOURCES.get(i as usize))
            .copied()
            .unwrap_or("unclassified")
    }
}
// Stable repository-relative names; never serialize compiler/host paths.
const SOURCES: &[&str] = &[
    "transport/sessions.rs",
    "transport/sessions/encryption.rs",
    "transport/direct_validation.rs",
    "network_outbound/send.rs",
    "network_outbound/fast_path.rs",
    "udp/inbound.rs",
    "relay/send_origin.rs",
    "peer/manager/echo_origin.rs",
    "peer/manager/overlay_credit.rs",
    "peer/manager/kernel_credit.rs",
    "lib/daemon/handshake/initiate.rs",
    "lib/daemon/handshake/offer.rs",
    "lib/daemon/handshake/answer.rs",
];

#[derive(Clone, Copy)]
struct Holder {
    token: u64,
    site: Site,
    started: Option<u64>,
}

pub(super) struct HolderState {
    next: AtomicU64,
    current: AtomicU64,
    site: AtomicU8,
    line: AtomicU32,
    started: AtomicU64,
    first: OnceLock<Weak<Refusal>>,
}
impl HolderState {
    pub(super) fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
            current: AtomicU64::new(0),
            site: AtomicU8::new(0),
            line: AtomicU32::new(0),
            started: AtomicU64::new(0),
            first: OnceLock::new(),
        }
    }
    pub(super) fn acquired(&self, observer: &EmitTrace, site: Site) -> Option<u64> {
        if !observer.live() {
            return None;
        }
        self.current.store(0, Ordering::SeqCst);
        // All acquisitions are serialized by this same actual peer mutex.
        let token = self.next.load(Ordering::Relaxed);
        self.next.store(token.checked_add(1)?, Ordering::Relaxed);
        self.site.store(site.code, Ordering::SeqCst);
        self.line.store(site.line, Ordering::SeqCst);
        self.started.store(now_ns().unwrap_or(0), Ordering::SeqCst);
        self.current.store(token, Ordering::SeqCst);
        Some(token)
    }
    fn snapshot(&self) -> Option<Holder> {
        let token = self.current.load(Ordering::SeqCst);
        let holder = Holder {
            token,
            site: Site {
                code: self.site.load(Ordering::SeqCst),
                line: self.line.load(Ordering::SeqCst),
            },
            started: nonzero(self.started.load(Ordering::SeqCst)),
        };
        (token != 0 && token == self.current.load(Ordering::SeqCst)).then_some(holder)
    }
    pub(super) fn released(&self, token: u64, ended: Option<u64>) {
        let _ = self
            .current
            .compare_exchange(token, 0, Ordering::SeqCst, Ordering::SeqCst);
        if let Some(first) = self.first.get().and_then(Weak::upgrade) {
            if first.holder.is_some_and(|holder| holder.token == token)
                && first
                    .completion_claimed
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                first.ended.store(ended.unwrap_or(0), Ordering::Release);
                first.completed.store(true, Ordering::Release);
            }
        }
    }
}

struct Refusal {
    context: EpochTryContext,
    started: Option<u64>,
    returned: Option<u64>,
    holder: Option<Holder>,
    // Metadata only: keep this allocation's identity, not the actual gate.
    _holder_identity: Option<Arc<HolderState>>,
    completion_claimed: AtomicBool,
    completed: AtomicBool,
    ended: AtomicU64,
}

pub(crate) struct EmitTrace {
    owner: u64,
    capture_id: [u8; 16],
    expires: Instant,
    active: AtomicBool,
    claimed: AtomicBool,
    first: OnceLock<Arc<Refusal>>,
}

pub(crate) struct EmitTryContext {
    pub(super) trace: Arc<EmitTrace>,
    labels: EpochTryContext,
}

impl EmitTrace {
    pub(crate) fn new(owner: u64, capture_id: [u8; 16], expires: Instant) -> Arc<Self> {
        Arc::new(Self {
            owner,
            capture_id,
            expires,
            active: AtomicBool::new(true),
            claimed: AtomicBool::new(false),
            first: OnceLock::new(),
        })
    }
    pub(super) fn live(&self) -> bool {
        self.owner != 0 && self.active.load(Ordering::Acquire) && Instant::now() < self.expires
    }
    pub(crate) fn deactivate(&self) {
        self.active.store(false, Ordering::Release);
    }
    pub(crate) fn context(self: &Arc<Self>, labels: EpochTryContext) -> Option<EmitTryContext> {
        let context = EmitTryContext {
            trace: self.clone(),
            labels,
        };
        context.accepted().then_some(context)
    }
    pub(crate) fn snapshot(&self) -> Option<EmitRefusalSnapshot> {
        let first = self.first.get()?;
        let completed = first.completed.load(Ordering::Acquire);
        let ended = completed
            .then(|| first.ended.load(Ordering::Acquire))
            .and_then(nonzero);
        let holder = first.holder.map(|holder| EmitHolderSnapshot {
            token: holder.token,
            source: holder.site.name(),
            source_line: holder.site.line,
            acquired_observed_monotonic_ns: holder.started,
            ended_before_unlock_monotonic_ns: ended,
            release_completion_observed: completed,
        });
        let labels = first.context;
        Some(EmitRefusalSnapshot {
            scope: "actual_final_kernel_peer_emit_try_refusal_only",
            capture_owner: self.owner,
            capture_id: hex::encode(labels.capture_id),
            run_nonce: hex::encode(labels.run),
            round_nonce: hex::encode(labels.round),
            request_nonce: hex::encode(labels.request_nonce),
            sequence: labels.sequence,
            protocol: labels.protocol,
            kind: labels.kind,
            first_read_ordinal: labels.first_read_ordinal,
            failed_try_started_monotonic_ns: first.started,
            failed_try_returned_monotonic_ns: first.returned,
            holder,
            holder_interval_covers_failed_try: covers(
                first.holder.and_then(|holder| holder.started),
                first.started,
                first.returned,
                ended,
            ),
            native_os_write_verified: false,
            physical_send_verified: false,
            canonical_current_owner_verified: false,
        })
    }
}

impl EmitTryContext {
    pub(super) fn accepted(&self) -> bool {
        self.trace.live()
            && self.labels.capture_owner == self.trace.owner
            && self.labels.capture_id == self.trace.capture_id
            && self.labels.first_read_ordinal != 0
            && self.labels.read_peer_input_ordinal.is_none()
    }
    pub(super) fn refused(
        self,
        state: Option<&Arc<HolderState>>,
        started: Option<u64>,
        returned: Option<u64>,
    ) {
        if !self.accepted()
            || self
                .trace
                .claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        let holder = state.and_then(|state| state.snapshot());
        let first = Arc::new(Refusal {
            context: self.labels,
            started: started.filter(|n| *n != 0),
            returned: returned.filter(|n| *n != 0),
            holder,
            _holder_identity: state.cloned(),
            completion_claimed: AtomicBool::new(false),
            completed: AtomicBool::new(false),
            ended: AtomicU64::new(0),
        });
        if let Some(state) = state.filter(|_| holder.is_some()) {
            // A release that already happened remains unknown. Never backfill
            // from a later holder, incarnation, peer or capture.
            let _ = state.first.set(Arc::downgrade(&first));
        }
        let _ = self.trace.first.set(first);
    }
}

fn nonzero(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}
fn covers(a: Option<u64>, b: Option<u64>, c: Option<u64>, d: Option<u64>) -> bool {
    match (a, b, c, d) {
        (Some(a), Some(b), Some(c), Some(d)) => a < b && b <= c && c < d,
        _ => false,
    }
}

#[derive(Serialize)]
struct EmitHolderSnapshot {
    token: u64,
    source: &'static str,
    source_line: u32,
    acquired_observed_monotonic_ns: Option<u64>,
    ended_before_unlock_monotonic_ns: Option<u64>,
    release_completion_observed: bool,
}
#[derive(Serialize)]
pub(crate) struct EmitRefusalSnapshot {
    scope: &'static str,
    capture_owner: u64,
    capture_id: String,
    run_nonce: String,
    round_nonce: String,
    request_nonce: String,
    sequence: u32,
    protocol: &'static str,
    kind: &'static str,
    first_read_ordinal: u64,
    failed_try_started_monotonic_ns: Option<u64>,
    failed_try_returned_monotonic_ns: Option<u64>,
    holder: Option<EmitHolderSnapshot>,
    holder_interval_covers_failed_try: bool,
    native_os_write_verified: bool,
    physical_send_verified: bool,
    canonical_current_owner_verified: bool,
}

#[cfg(test)]
mod tests {
    use super::covers;
    #[test]
    fn emit_metadata_interval_requires_all_four_strict_original_clock_bounds() {
        assert!(covers(Some(10), Some(11), Some(11), Some(12)));
        for bounds in [
            (None, Some(11), Some(11), Some(12)),
            (Some(10), None, Some(11), Some(12)),
            (Some(10), Some(11), None, Some(12)),
            (Some(10), Some(11), Some(11), None),
            (Some(11), Some(11), Some(11), Some(12)),
            (Some(10), Some(11), Some(11), Some(11)),
            (Some(10), Some(12), Some(11), Some(13)),
        ] {
            assert!(!covers(bounds.0, bounds.1, bounds.2, bounds.3));
        }
    }
}
