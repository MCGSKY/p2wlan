//! One completed diagnostic interval, copied into the first refusal only.
//! Missing clocks or incomplete coverage never establish a causal holder.
//! No allocation, strong owner, queue, wait or replacement of original facts.
use super::*;

pub(super) struct LastInterval {
    token: AtomicU64,
    completed: AtomicU64,
    site: AtomicU8,
    line: AtomicU32,
    started: AtomicU64,
    ended: AtomicU64,
    phase_version: AtomicU64,
    phase_code: AtomicU8,
    phase_started: AtomicU64,
}
#[derive(Clone, Copy)]
pub(super) struct CompletedInterval {
    holder: Holder,
    ended: Option<u64>,
}
impl LastInterval {
    pub(super) fn new() -> Self {
        Self {
            token: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            site: AtomicU8::new(0),
            line: AtomicU32::new(0),
            started: AtomicU64::new(0),
            ended: AtomicU64::new(0),
            phase_version: AtomicU64::new(0),
            phase_code: AtomicU8::new(0),
            phase_started: AtomicU64::new(0),
        }
    }
    // Only the same actual mutex holder writes, before its original unlock.
    // Token invalidation and double reads keep a concurrent observer unknown.
    pub(super) fn ending(&self, holder: Holder, ended: Option<u64>) {
        self.token.store(0, Ordering::SeqCst);
        self.completed.store(0, Ordering::SeqCst);
        self.site.store(holder.site.code, Ordering::SeqCst);
        self.line.store(holder.site.line, Ordering::SeqCst);
        self.started
            .store(holder.started.unwrap_or(0), Ordering::SeqCst);
        self.ended.store(ended.unwrap_or(0), Ordering::SeqCst);
        self.phase_version
            .store(holder.phase.map_or(0, |p| p.version), Ordering::SeqCst);
        self.phase_code
            .store(holder.phase.map_or(0, |p| p.code), Ordering::SeqCst);
        self.phase_started.store(
            holder.phase.and_then(|p| p.started).unwrap_or(0),
            Ordering::SeqCst,
        );
        self.token.store(holder.token, Ordering::SeqCst);
    }
    // This notification occurs only AFTER dropping the original actual guard.
    // A release racing a newer interval can lose metadata, never create credit.
    pub(super) fn complete(&self, token: u64) {
        if token != 0 && self.token.load(Ordering::SeqCst) == token {
            self.completed.store(token, Ordering::SeqCst);
        }
    }
    pub(super) fn observed_completed(&self) -> Option<CompletedInterval> {
        let token = self.token.load(Ordering::SeqCst);
        if token == 0 || self.completed.load(Ordering::SeqCst) != token {
            return None;
        }
        let version = self.phase_version.load(Ordering::SeqCst);
        let interval = CompletedInterval {
            holder: Holder {
                token,
                site: Site {
                    code: self.site.load(Ordering::SeqCst),
                    line: self.line.load(Ordering::SeqCst),
                },
                started: nonzero(self.started.load(Ordering::SeqCst)),
                phase: (version != 0).then(|| Phase {
                    version,
                    code: self.phase_code.load(Ordering::SeqCst),
                    started: nonzero(self.phase_started.load(Ordering::SeqCst)),
                }),
            },
            ended: nonzero(self.ended.load(Ordering::SeqCst)),
        };
        (self.token.load(Ordering::SeqCst) == token
            && self.completed.load(Ordering::SeqCst) == token)
            .then_some(interval)
    }
}
impl CompletedInterval {
    pub(super) fn snapshot(
        self,
        started: Option<u64>,
        returned: Option<u64>,
    ) -> (EpochHolderSnapshot, bool) {
        let covers = matches!((self.holder.started, started, returned, self.ended),
            (Some(a), Some(b), Some(c), Some(d)) if a < b && b <= c && c < d);
        let h = self.holder;
        (
            EpochHolderSnapshot {
                token: h.token,
                source: h.site.name(),
                source_line: h.site.line,
                acquired_observed_monotonic_ns: h.started,
                ended_before_unlock_monotonic_ns: self.ended,
                release_completion_observed: true,
                phase: h.phase.map(|p| EpochPhaseSnapshot {
                    version: p.version,
                    source: phase_name(p.code),
                    started_observed_monotonic_ns: p.started,
                    interval_covers_failed_try: phase_covers(covers, p.started, started),
                }),
            },
            covers,
        )
    }
}
impl Trace {
    pub(super) fn observed_holder(&self) -> Option<Holder> {
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
        (token != 0 && token == self.current.load(Ordering::SeqCst)).then_some(holder)
    }
}
