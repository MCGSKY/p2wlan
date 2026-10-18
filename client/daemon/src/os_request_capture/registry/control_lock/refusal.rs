//! Fixed first-refusal metadata. No owner, packet, Full or admission is created.
use crate::os_request_capture::clock::monotonic_ns;
use serde::Serialize;
use std::panic::Location;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::OnceLock;

#[derive(Clone, Copy)]
pub(super) struct Site {
    code: u8,
    line: u32,
}

impl Site {
    #[track_caller]
    pub(super) fn caller() -> Self {
        let location = Location::caller();
        let code = match location.file().rsplit('/').next() {
            Some("registry.rs") => 1,
            Some("ingress.rs") => 2,
            Some("write_window.rs") => 3,
            Some("full_completion.rs") => 4,
            Some("control_lock.rs") => 5,
            Some("tests.rs") => 6,
            _ => 0,
        };
        Self {
            code,
            line: location.line(),
        }
    }

    fn source(self) -> &'static str {
        match self.code {
            1 => "registry",
            2 => "ingress",
            3 => "write_window",
            4 => "full_completion",
            5 => "control_wait",
            6 => "test_metadata_only",
            _ => "unclassified",
        }
    }
}

#[derive(Clone, Copy)]
struct Holder {
    token: u64,
    site: Site,
    started: Option<u64>,
}

struct Refusal {
    read_ordinal: u64,
    started: Option<u64>,
    returned: Option<u64>,
    holder: Option<Holder>,
    completion_claimed: AtomicBool,
    completion_observed: AtomicBool,
    holder_ended: AtomicU64,
}

pub(super) struct RefusalDiagnostics {
    next: AtomicU64,
    current: AtomicU64,
    site: AtomicU8,
    line: AtomicU32,
    started: AtomicU64,
    first_claimed: AtomicBool,
    first: OnceLock<Refusal>,
}

impl RefusalDiagnostics {
    #[cfg(any(target_os = "linux", test))]
    pub(super) fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
            current: AtomicU64::new(0),
            site: AtomicU8::new(0),
            line: AtomicU32::new(0),
            started: AtomicU64::new(0),
            first_claimed: AtomicBool::new(false),
            first: OnceLock::new(),
        }
    }

    // Called only after acquiring the actual original mutex. One actual
    // holder serializes these stores; zero and unstable tokens stay unknown.
    pub(super) fn acquired(&self, site: Site) -> u64 {
        self.acquired_at(site, monotonic_ns())
    }

    fn acquired_at(&self, site: Site, started: Option<u64>) -> u64 {
        self.current.store(0, Ordering::SeqCst);
        // The actual mutex serializes acquisition; this diagnostic counter
        // needs neither a CAS loop nor a retry. Exhaustion changes no admission.
        let token = self.next.load(Ordering::Relaxed);
        let Some(next) = token.checked_add(1) else {
            return 0;
        };
        self.next.store(next, Ordering::Relaxed);
        self.site.store(site.code, Ordering::SeqCst);
        self.line.store(site.line, Ordering::SeqCst);
        self.started.store(started.unwrap_or(0), Ordering::SeqCst);
        self.current.store(token, Ordering::SeqCst);
        token
    }

    // Only the actual input's WouldBlock calls this, after its single try.
    // The first slot never reopens, including when clocks or a holder are absent.
    pub(super) fn refused(&self, read_ordinal: u64, started: Option<u64>, returned: Option<u64>) {
        if read_ordinal == 0
            || self
                .first_claimed
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
        };
        let stable = token != 0 && self.current.load(Ordering::SeqCst) == token;
        // Exactly one claimant can call set, so no competing initializer can
        // make this packet callback wait. Missing metadata never reopens it.
        let _ = self.first.set(Refusal {
            read_ordinal,
            started: started.filter(|value| *value != 0),
            returned: returned.filter(|value| *value != 0),
            holder: stable.then_some(holder),
            completion_claimed: AtomicBool::new(false),
            completion_observed: AtomicBool::new(false),
            holder_ended: AtomicU64::new(0),
        });
    }

    // The caller captures this upper endpoint while still holding the mutex,
    // releases the actual guard first, then completes only fixed metadata.
    pub(super) fn released(&self, token: u64, ended: Option<u64>) {
        let _ = self
            .current
            .compare_exchange(token, 0, Ordering::SeqCst, Ordering::SeqCst);
        let Some(first) = self.first.get() else {
            return;
        };
        if token == 0
            || first.holder.is_none_or(|holder| holder.token != token)
            || first
                .completion_claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        first
            .holder_ended
            .store(ended.unwrap_or(0), Ordering::Relaxed);
        first.completion_observed.store(true, Ordering::Release);
    }

    pub(super) fn snapshot(&self) -> Option<InputRefusalSnapshot> {
        let first = self.first.get()?;
        let completed = first.completion_observed.load(Ordering::Acquire);
        let ended = completed
            .then(|| nonzero(first.holder_ended.load(Ordering::Relaxed)))
            .flatten();
        let holder = first.holder.map(|holder| HolderSnapshot {
            token: holder.token,
            source: holder.site.source(),
            source_line: holder.site.line,
            acquired_observed_monotonic_ns: holder.started,
            ended_before_unlock_monotonic_ns: ended,
            release_completion_observed: completed,
        });
        let covers = holder.as_ref().is_some_and(|holder| {
            match (
                holder.acquired_observed_monotonic_ns,
                first.started,
                first.returned,
                ended,
            ) {
                (Some(a), Some(b), Some(c), Some(d)) => a < b && b <= c && c < d,
                _ => false,
            }
        });
        Some(InputRefusalSnapshot {
            scope: "actual_input_registry_try_lock_refusal_only",
            read_ordinal: first.read_ordinal,
            failed_try_started_monotonic_ns: first.started,
            failed_try_returned_monotonic_ns: first.returned,
            holder,
            holder_interval_covers_failed_try: covers,
        })
    }
}

fn nonzero(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}

#[derive(Serialize)]
pub(in crate::os_request_capture) struct InputRefusalSnapshot {
    scope: &'static str,
    read_ordinal: u64,
    failed_try_started_monotonic_ns: Option<u64>,
    failed_try_returned_monotonic_ns: Option<u64>,
    holder: Option<HolderSnapshot>,
    holder_interval_covers_failed_try: bool,
}

#[derive(Serialize)]
struct HolderSnapshot {
    token: u64,
    source: &'static str,
    source_line: u32,
    acquired_observed_monotonic_ns: Option<u64>,
    ended_before_unlock_monotonic_ns: Option<u64>,
    release_completion_observed: bool,
}

#[cfg(test)]
mod tests;
