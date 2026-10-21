//! One copied observation after actual epoch unlock. This is not a fence,
//! owner, permission, native fact, retry queue or replacement clock.
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ReleaseObservation {
    pub(super) token: u64,
    pub(super) observed_after_unlock_ns: u64,
}

impl ReleaseObservation {
    pub(super) fn definitely_before(self, token: u64, try_started: Option<u64>) -> bool {
        self.token == token
            && self.token != 0
            && self.observed_after_unlock_ns != 0
            && try_started.is_some_and(|start| self.observed_after_unlock_ns < start)
    }
}

pub(super) struct ReleaseObservationSlot(Mutex<Option<ReleaseObservation>>);

impl ReleaseObservationSlot {
    pub(super) fn new() -> Self {
        Self(Mutex::new(None))
    }

    // Called after the original actual guard is dropped. A busy/poisoned
    // diagnostic slot stays unavailable; it never delays an original caller.
    pub(super) fn record(&self, token: u64, observed_after_unlock_ns: Option<u64>) {
        let Some(time) = observed_after_unlock_ns.filter(|time| *time != 0) else {
            return;
        };
        if token == 0 {
            return;
        }
        if let Ok(mut slot) = self.0.try_lock() {
            *slot = Some(ReleaseObservation {
                token,
                observed_after_unlock_ns: time,
            });
        }
    }

    // A first-refusal copy cannot observe a later replacement or refill.
    pub(super) fn try_snapshot(&self) -> Option<ReleaseObservation> {
        self.0.try_lock().ok().and_then(|slot| *slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn release_observation_requires_same_token_and_strictly_before_try() {
        let slot = ReleaseObservationSlot::new();
        slot.record(7, Some(41));
        let value = slot.try_snapshot().unwrap();
        assert!(value.definitely_before(7, Some(42)));
        assert!(!value.definitely_before(8, Some(42)));
        assert!(!value.definitely_before(7, Some(41)));
        assert!(!value.definitely_before(7, Some(40)));
        assert!(!value.definitely_before(7, None));
    }

    #[test]
    fn release_observation_missing_clock_and_zero_token_supply_no_new_record() {
        let slot = ReleaseObservationSlot::new();
        slot.record(0, Some(1));
        slot.record(7, None);
        slot.record(7, Some(0));
        assert!(slot.try_snapshot().is_none());
        slot.record(7, Some(11));
        let first = slot.try_snapshot();
        slot.record(8, None);
        assert_eq!(slot.try_snapshot(), first);
    }

    #[test]
    fn release_observation_busy_slot_never_waits_or_changes_its_record() {
        let slot = ReleaseObservationSlot::new();
        slot.record(7, Some(11));
        let held = slot.0.lock().unwrap();
        slot.record(8, Some(12));
        assert!(slot.try_snapshot().is_none());
        drop(held);
        assert_eq!(slot.try_snapshot().unwrap().token, 7);
    }

    #[test]
    fn release_observation_first_missing_copy_is_not_refilled() {
        let slot = ReleaseObservationSlot::new();
        let held = slot.0.lock().unwrap();
        let first = slot.try_snapshot();
        drop(held);
        slot.record(7, Some(11));
        assert!(first.is_none());
        assert!(slot.try_snapshot().is_some());
    }

    #[test]
    fn release_observation_copied_token_cannot_borrow_later_release() {
        let slot = ReleaseObservationSlot::new();
        slot.record(7, Some(11));
        let first = slot.try_snapshot().unwrap();
        slot.record(8, Some(12));
        assert_eq!(first.token, 7);
        assert_eq!(first.observed_after_unlock_ns, 11);
        assert!(!first.definitely_before(8, Some(13)));
        assert_eq!(slot.try_snapshot().unwrap().token, 8);
    }

    #[test]
    fn release_observation_concurrent_copies_never_mix_token_and_time() {
        let slot = Arc::new(ReleaseObservationSlot::new());
        let writer = slot.clone();
        let child = std::thread::spawn(move || {
            for token in 1..=2_000 {
                writer.record(token, Some(token * 1_000));
            }
        });
        for _ in 0..2_000 {
            if let Some(value) = slot.try_snapshot() {
                assert_eq!(value.observed_after_unlock_ns, value.token * 1_000);
            }
        }
        child.join().unwrap();
    }
}
