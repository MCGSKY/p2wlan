//! Fixed-size observation of the actual exclusive gate; never an owner permit.
use super::OutboundEpochPhase;
use serde::Serialize;
use std::panic::Location;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

pub(super) fn now_ns() -> Option<u64> {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    {
        crate::os_request_capture::original_kernel_monotonic_ns()
    }
    #[cfg(not(any(target_os = "linux", all(unix, test))))]
    {
        None
    }
}

#[derive(Clone, Copy)]
pub(crate) struct EpochTryContext {
    pub(crate) capture_owner: u64,
    pub(crate) capture_id: [u8; 16],
    pub(crate) run: [u8; 16],
    pub(crate) round: [u8; 16],
    pub(crate) request_nonce: [u8; 16],
    pub(crate) sequence: u32,
    pub(crate) protocol: &'static str,
    pub(crate) kind: &'static str,
    pub(crate) first_read_ordinal: u64,
    pub(crate) read_peer_input_ordinal: Option<u64>,
}

#[derive(Clone, Copy)]
pub(super) struct Site {
    code: u8,
    line: u32,
}
impl Site {
    #[track_caller]
    pub(super) fn caller() -> Self {
        let location = Location::caller();
        let file = location.file();
        let code = if file.ends_with("network_outbound/send.rs") {
            1
        } else if file.ends_with("network_outbound/fast_path.rs") {
            2
        } else if file.ends_with("peer/manager/core.rs") {
            3
        } else if file.ends_with("peer/manager/echo_origin.rs") {
            4
        } else if file.ends_with("peer/manager/kernel_credit.rs") {
            5
        } else if file.ends_with("peer/manager/kernel_read.rs") {
            6
        } else if file.ends_with("peer/manager/peers/lifecycle.rs") {
            7
        } else if file.ends_with("peer/manager/peers/membership.rs") {
            8
        } else if file.ends_with("peer/manager/quarantine.rs") {
            9
        } else if file.ends_with("peer/manager/recovery_epoch.rs") {
            10
        } else if file.ends_with("peer/manager/relay/confirmation.rs") {
            11
        } else if file.ends_with("peer/manager/relay/business_evidence.rs") {
            12
        } else if file.ends_with("peer/manager/relay/readiness.rs") {
            13
        } else if file.ends_with("peer/manager/relay/probe_expectations.rs") {
            14
        } else if file.ends_with("peer/manager/path.rs") {
            15
        } else if file.contains("/udp/") {
            16
        } else {
            0
        };
        Self {
            code,
            line: location.line(),
        }
    }
    fn name(self) -> &'static str {
        match self.code {
            1 => "outbound_prepare",
            2 => "outbound_fast_path",
            3 => "peer_core",
            4 => "original_echo",
            5 => "original_kernel_final",
            6 => "original_read_peer",
            7 => "peer_lifecycle",
            8 => "peer_membership",
            9 => "quarantine",
            10 => "recovery_epoch",
            11 => "relay_confirmation",
            12 => "relay_business",
            13 => "relay_readiness",
            14 => "relay_probe",
            15 => "peer_path",
            16 => "udp_epoch",
            _ => "unclassified",
        }
    }
}

#[derive(Clone, Copy)]
struct Holder {
    token: u64,
    site: Site,
    started: Option<u64>,
    phase: Option<Phase>,
}
#[derive(Clone, Copy)]
struct Phase {
    version: u64,
    code: u8,
    started: Option<u64>,
}
struct Refusal {
    context: EpochTryContext,
    started: Option<u64>,
    returned: Option<u64>,
    holder: Option<Holder>,
    completion_claimed: AtomicBool,
    completion_observed: AtomicBool,
    ended: AtomicU64,
}
pub(super) struct Trace {
    owner: u64,
    capture_id: [u8; 16],
    expires: Instant,
    active: AtomicBool,
    next: AtomicU64,
    current: AtomicU64,
    site: AtomicU8,
    line: AtomicU32,
    started: AtomicU64,
    phase_next: AtomicU64,
    phase_current: AtomicU64,
    phase_code: AtomicU8,
    phase_started: AtomicU64,
    first_claimed: AtomicBool,
    first: OnceLock<Refusal>,
    read_peer_claimed: AtomicBool,
    read_peer_first: OnceLock<Refusal>,
}

impl Trace {
    pub(super) fn new(owner: u64, capture_id: [u8; 16], expires: Instant) -> Self {
        Self {
            owner,
            capture_id,
            expires,
            active: AtomicBool::new(true),
            next: AtomicU64::new(1),
            current: AtomicU64::new(0),
            site: AtomicU8::new(0),
            line: AtomicU32::new(0),
            started: AtomicU64::new(0),
            phase_next: AtomicU64::new(1),
            phase_current: AtomicU64::new(0),
            phase_code: AtomicU8::new(0),
            phase_started: AtomicU64::new(0),
            first_claimed: AtomicBool::new(false),
            first: OnceLock::new(),
            read_peer_claimed: AtomicBool::new(false),
            read_peer_first: OnceLock::new(),
        }
    }
    fn live(&self) -> bool {
        self.active.load(Ordering::Acquire) && Instant::now() < self.expires
    }
    pub(super) fn accepts(&self, context: &EpochTryContext) -> bool {
        self.live() && context.capture_owner == self.owner && context.capture_id == self.capture_id
    }
    pub(super) fn acquired(&self, site: Site) -> Option<u64> {
        if !self.live() {
            return None;
        }
        self.current.store(0, Ordering::SeqCst);
        self.phase_current.store(0, Ordering::SeqCst);
        self.phase_next.store(1, Ordering::Relaxed);
        // The actual epoch mutex serializes acquisitions; no CAS loop or retry.
        let token = self.next.load(Ordering::Relaxed);
        let next = token.checked_add(1)?;
        self.next.store(next, Ordering::Relaxed);
        self.site.store(site.code, Ordering::SeqCst);
        self.line.store(site.line, Ordering::SeqCst);
        self.started.store(now_ns().unwrap_or(0), Ordering::SeqCst);
        self.current.store(token, Ordering::SeqCst);
        Some(token)
    }
    pub(super) fn phase(&self, token: u64, phase: OutboundEpochPhase) {
        if !self.live() || token == 0 || self.current.load(Ordering::SeqCst) != token {
            return;
        }
        self.phase_current.store(0, Ordering::SeqCst);
        // Only the actual borrowed holder writes phases. No wait or retry;
        // exhaustion stays unknown until a different actual holder acquires.
        let version = self.phase_next.load(Ordering::Relaxed);
        let Some(next) = version.checked_add(1) else {
            return;
        };
        self.phase_next.store(next, Ordering::Relaxed);
        self.phase_code.store(phase as u8, Ordering::SeqCst);
        self.phase_started
            .store(now_ns().unwrap_or(0), Ordering::SeqCst);
        self.phase_current.store(version, Ordering::SeqCst);
    }
    fn observed_phase(&self) -> Option<Phase> {
        let version = self.phase_current.load(Ordering::SeqCst);
        let phase = Phase {
            version,
            code: self.phase_code.load(Ordering::SeqCst),
            started: nonzero(self.phase_started.load(Ordering::SeqCst)),
        };
        (version != 0 && version == self.phase_current.load(Ordering::SeqCst)).then_some(phase)
    }
    pub(super) fn refused(
        &self,
        context: EpochTryContext,
        started: Option<u64>,
        returned: Option<u64>,
    ) {
        let (claimed, first) = if let Some(ordinal) = context.read_peer_input_ordinal {
            if ordinal == 0 || context.first_read_ordinal != 0 {
                return;
            }
            (&self.read_peer_claimed, &self.read_peer_first)
        } else {
            (&self.first_claimed, &self.first)
        };
        if !self.accepts(&context)
            || claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        let token = self.current.load(Ordering::SeqCst);
        let holder = Holder {
            token,
            site: Site {
                code: self.site.load(Ordering::SeqCst),
                line: self.line.load(Ordering::SeqCst),
            },
            started: nonzero(self.started.load(Ordering::SeqCst)),
            phase: self.observed_phase(),
        };
        let stable = token != 0 && token == self.current.load(Ordering::SeqCst);
        // Only one claimant sets the first slot. An unstable/missing holder
        // remains unknown; no initializer wait or later replacement is allowed.
        let _ = first.set(Refusal {
            context,
            started: started.filter(|n| *n != 0),
            returned: returned.filter(|n| *n != 0),
            holder: stable.then_some(holder),
            completion_claimed: AtomicBool::new(false),
            completion_observed: AtomicBool::new(false),
            ended: AtomicU64::new(0),
        });
    }
    pub(super) fn released(&self, token: u64, ended: Option<u64>) {
        let _ = self
            .current
            .compare_exchange(token, 0, Ordering::SeqCst, Ordering::SeqCst);
        for first in [self.first.get(), self.read_peer_first.get()]
            .into_iter()
            .flatten()
        {
            if first.holder.is_some_and(|holder| holder.token == token)
                && first
                    .completion_claimed
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                first.ended.store(ended.unwrap_or(0), Ordering::Release);
                first.completion_observed.store(true, Ordering::Release);
            }
        }
    }
    pub(super) fn deactivate(&self, owner: u64) {
        if owner == self.owner {
            self.active.store(false, Ordering::Release);
        }
    }
    #[cfg(test)]
    pub(super) fn exhaust_tokens(&self) {
        self.next.store(u64::MAX, Ordering::Relaxed);
    }
    pub(super) fn snapshot(&self, owner: u64) -> Option<EpochRefusalSnapshot> {
        self.snapshot_slot(
            owner,
            self.first.get(),
            "actual_final_kernel_epoch_try_refusal_only",
        )
    }
    pub(super) fn read_peer_snapshot(&self, owner: u64) -> Option<EpochRefusalSnapshot> {
        self.snapshot_slot(
            owner,
            self.read_peer_first.get(),
            "actual_original_read_peer_epoch_try_refusal_only",
        )
    }
    fn snapshot_slot(
        &self,
        owner: u64,
        first: Option<&Refusal>,
        scope: &'static str,
    ) -> Option<EpochRefusalSnapshot> {
        if owner != self.owner {
            return None;
        }
        let first = first?;
        let completed = first.completion_observed.load(Ordering::Acquire);
        let ended = completed
            .then(|| first.ended.load(Ordering::Acquire))
            .and_then(nonzero);
        let covers = match (
            first.holder.and_then(|h| h.started),
            first.started,
            first.returned,
            ended,
        ) {
            (Some(a), Some(b), Some(c), Some(d)) => a < b && b <= c && c < d,
            _ => false,
        };
        let holder = first.holder.map(|holder| EpochHolderSnapshot {
            token: holder.token,
            source: holder.site.name(),
            source_line: holder.site.line,
            acquired_observed_monotonic_ns: holder.started,
            ended_before_unlock_monotonic_ns: ended,
            release_completion_observed: completed,
            phase: holder.phase.map(|phase| EpochPhaseSnapshot {
                version: phase.version,
                source: phase_name(phase.code),
                started_observed_monotonic_ns: phase.started,
                // A phase is sampled after the actual try returned. A stable
                // version alone cannot prove its mutex was still held then.
                interval_covers_failed_try: phase_covers(covers, phase.started, first.started),
            }),
        });
        let context = first.context;
        Some(EpochRefusalSnapshot {
            scope,
            capture_owner: self.owner,
            capture_id: hex::encode(context.capture_id),
            run_nonce: hex::encode(context.run),
            round_nonce: hex::encode(context.round),
            request_nonce: hex::encode(context.request_nonce),
            sequence: context.sequence,
            protocol: context.protocol,
            kind: context.kind,
            first_read_ordinal: context
                .read_peer_input_ordinal
                .is_none()
                .then_some(context.first_read_ordinal),
            original_input_read_ordinal: context.read_peer_input_ordinal,
            failed_try_started_monotonic_ns: first.started,
            failed_try_returned_monotonic_ns: first.returned,
            holder,
            holder_interval_covers_failed_try: covers,
            native_os_write_verified: false,
            physical_send_verified: false,
            canonical_current_owner_verified: false,
        })
    }
}
fn nonzero(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}
fn phase_covers(holder_covers: bool, phase_started: Option<u64>, try_started: Option<u64>) -> bool {
    holder_covers && matches!((phase_started, try_started), (Some(a), Some(b)) if a != 0 && a < b)
}
fn phase_name(code: u8) -> &'static str {
    match code {
        1 => "generation",
        2 => "path_selection",
        3 => "direct_budget",
        4 => "original_echo",
        5 => "encryption",
        6 => "physical_metadata",
        7 => "direct_first",
        _ => "unclassified",
    }
}

#[derive(Serialize)]
struct EpochPhaseSnapshot {
    version: u64,
    source: &'static str,
    started_observed_monotonic_ns: Option<u64>,
    interval_covers_failed_try: bool,
}

#[derive(Serialize)]
struct EpochHolderSnapshot {
    token: u64,
    source: &'static str,
    source_line: u32,
    acquired_observed_monotonic_ns: Option<u64>,
    ended_before_unlock_monotonic_ns: Option<u64>,
    release_completion_observed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    phase: Option<EpochPhaseSnapshot>,
}
#[derive(Serialize)]
pub(crate) struct EpochRefusalSnapshot {
    scope: &'static str,
    capture_owner: u64,
    capture_id: String,
    run_nonce: String,
    round_nonce: String,
    request_nonce: String,
    sequence: u32,
    protocol: &'static str,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_read_ordinal: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    original_input_read_ordinal: Option<u64>,
    failed_try_started_monotonic_ns: Option<u64>,
    failed_try_returned_monotonic_ns: Option<u64>,
    holder: Option<EpochHolderSnapshot>,
    holder_interval_covers_failed_try: bool,
    native_os_write_verified: bool,
    physical_send_verified: bool,
    canonical_current_owner_verified: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_phase_strict_coverage_requires_actual_completed_holder_and_original_clocks() {
        assert!(phase_covers(true, Some(10), Some(11)));
        for (holder, phase, started) in [
            (false, Some(10), Some(11)),
            (true, None, Some(11)),
            (true, Some(10), None),
            (true, Some(0), Some(11)),
            (true, Some(11), Some(11)),
            (true, Some(12), Some(11)),
        ] {
            assert!(!phase_covers(holder, phase, started));
        }
        let trace = Trace::new(
            7,
            [1; 16],
            Instant::now() + std::time::Duration::from_secs(1),
        );
        let token = trace.acquired(Site { code: 1, line: 10 }).unwrap();
        assert!(trace.observed_phase().is_none());
        trace.phase(token, OutboundEpochPhase::Encryption);
        let first = trace.observed_phase().unwrap();
        trace.phase(token, OutboundEpochPhase::PhysicalMetadata);
        assert!(trace.observed_phase().unwrap().version > first.version);
        trace.phase_next.store(u64::MAX, Ordering::Relaxed);
        trace.phase(token, OutboundEpochPhase::DirectFirst);
        assert!(trace.observed_phase().is_none());
        trace.phase(token, OutboundEpochPhase::Path);
        assert!(trace.observed_phase().is_none());
    }
}
