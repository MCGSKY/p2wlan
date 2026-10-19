//! Fixed diagnostic samples; no packet, session or network authority is retained.
use super::{duration_us, DataplaneProfiler, ProfileUnit};
use std::time::Duration;

#[derive(Clone, Copy)]
pub(crate) enum CryptoProfileStage {
    SessionWait,
    Crypto,
    SessionHold,
}

impl CryptoProfileStage {
    fn key(self) -> &'static str {
        match self {
            Self::SessionWait => "tx_session_lock_wait_us",
            Self::Crypto => "tx_crypto_exec_us",
            Self::SessionHold => "tx_session_lock_hold_us",
        }
    }
}

/// The preparation future declares this before acquiring epoch. Original
/// observation sites retain values and timestamps without taking the histogram
/// mutex. Dropping after the actual guards publishes at most three samples,
/// including samples already captured before cancellation or an early return.
pub(crate) struct DeferredCryptoProfile<'a> {
    profiler: &'a DataplaneProfiler,
    samples: [Option<(u64, u64)>; 3],
}

impl<'a> DeferredCryptoProfile<'a> {
    pub(crate) fn new(profiler: &'a DataplaneProfiler) -> Self {
        Self {
            profiler,
            samples: [None; 3],
        }
    }

    fn record(&mut self, stage: CryptoProfileStage, duration: Duration) {
        self.samples[stage as usize].get_or_insert_with(|| {
            (
                duration_us(duration),
                duration_us(self.profiler.started_at.elapsed()),
            )
        });
    }
}

pub(crate) fn record_crypto_profile(
    profiler: &DataplaneProfiler,
    deferred: Option<&mut DeferredCryptoProfile<'_>>,
    sampled: bool,
    stage: CryptoProfileStage,
    duration: Duration,
) {
    if !sampled {
        return;
    }
    if let Some(deferred) = deferred {
        deferred.record(stage, duration);
    } else {
        profiler.record(true, stage.key(), duration);
    }
}

impl Drop for DeferredCryptoProfile<'_> {
    fn drop(&mut self) {
        for stage in [
            CryptoProfileStage::SessionWait,
            CryptoProfileStage::Crypto,
            CryptoProfileStage::SessionHold,
        ] {
            if let Some((value, observed_at_us)) = self.samples[stage as usize] {
                self.profiler.record_value_at(
                    stage.key(),
                    value,
                    ProfileUnit::Microseconds,
                    observed_at_us,
                );
            }
        }
    }
}

#[cfg(test)]
#[path = "crypto_profile_tests.rs"]
mod tests;
