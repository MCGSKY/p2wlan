//! Five fixed samples from the original outbound preparation observation sites.
use super::{duration_us, DataplaneProfiler, ProfileUnit};
use std::time::Duration;

#[derive(Clone, Copy)]
pub(crate) enum OutboundPreparationStage {
    EmitWait,
    TunToEncrypt,
    RouteToEncrypt,
    Encrypt,
    SlowEncrypt,
}

const KEYS: [&str; 5] = [
    "tx_emit_guard_wait_us",
    "tun_read_to_encrypt_us",
    "route_to_encrypt_us",
    "encrypt_us",
    "tx_slow_path_encrypt_us",
];

/// Declare outside preparation and the physical attempt. Only values and
/// original observation times are retained; no packet, lock or owner is kept.
pub(crate) struct DeferredOutboundPreparationProfile<'a> {
    profiler: &'a DataplaneProfiler,
    samples: [Option<(u64, u64)>; 5],
}

impl<'a> DeferredOutboundPreparationProfile<'a> {
    pub(crate) fn new(profiler: &'a DataplaneProfiler) -> Self {
        Self {
            profiler,
            samples: [None; 5],
        }
    }

    // Each stage has exactly one original call site per preparation attempt.
    pub(crate) fn record(
        &mut self,
        sampled: bool,
        stage: OutboundPreparationStage,
        duration: Duration,
    ) {
        if sampled {
            self.samples[stage as usize] = Some((
                duration_us(duration),
                duration_us(self.profiler.started_at.elapsed()),
            ));
        }
    }
}

impl Drop for DeferredOutboundPreparationProfile<'_> {
    fn drop(&mut self) {
        for (key, sample) in KEYS.into_iter().zip(self.samples) {
            if let Some((value, observed_at_us)) = sample {
                self.profiler.record_value_at(
                    key,
                    value,
                    ProfileUnit::Microseconds,
                    observed_at_us,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preparation_profile_preserves_five_original_values_times_and_units() {
        let profiler = DataplaneProfiler::new();
        let mut profile = DeferredOutboundPreparationProfile::new(&profiler);
        let held = profiler.state.lock().unwrap();
        for (index, stage) in [
            OutboundPreparationStage::EmitWait,
            OutboundPreparationStage::TunToEncrypt,
            OutboundPreparationStage::RouteToEncrypt,
            OutboundPreparationStage::Encrypt,
            OutboundPreparationStage::SlowEncrypt,
        ]
        .into_iter()
        .enumerate()
        {
            profile.record(true, stage, Duration::from_micros(index as u64 + 7));
        }
        assert!(held.stages.is_empty());
        let original = profile.samples;
        drop(held);
        drop(profile);
        let state = profiler.state.lock().unwrap();
        assert_eq!(state.stages.len(), 5);
        for (index, key) in KEYS.into_iter().enumerate() {
            let sample = &state.stages[&(key, ProfileUnit::Microseconds)];
            assert_eq!(sample.total, 1);
            assert_eq!(sample.values.len(), 1);
            assert_eq!(
                (sample.values[0].value, sample.values[0].observed_at_us),
                original[index].unwrap()
            );
        }
    }

    #[test]
    fn preparation_profile_unsampled_empty_and_partial_keep_original_counts() {
        let profiler = DataplaneProfiler::new();
        drop(DeferredOutboundPreparationProfile::new(&profiler));
        let mut profile = DeferredOutboundPreparationProfile::new(&profiler);
        profile.record(false, OutboundPreparationStage::EmitWait, Duration::ZERO);
        drop(profile);
        assert!(profiler.state.lock().unwrap().stages.is_empty());
        let mut profile = DeferredOutboundPreparationProfile::new(&profiler);
        profile.record(
            true,
            OutboundPreparationStage::EmitWait,
            Duration::from_micros(13),
        );
        drop(profile);
        let state = profiler.state.lock().unwrap();
        assert_eq!(state.stages.len(), 1);
        let sample = &state.stages[&(KEYS[0], ProfileUnit::Microseconds)];
        assert_eq!(sample.total, 1);
        assert_eq!(sample.values[0].value, 13);
    }
}
