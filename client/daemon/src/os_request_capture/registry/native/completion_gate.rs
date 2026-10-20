//! The sole synchronous native-completion executor for one capture scope.
//! It never holds the input registry and never crosses an IO/async wait.
use super::super::full_completion::CompletionSignal;
use std::sync::{Mutex, MutexGuard, TryLockError};

pub(in crate::os_request_capture::registry) struct NativeCompletionGate(Mutex<()>);
pub(in crate::os_request_capture::registry) enum EnterError {
    Busy,
    Poisoned,
}
pub(in crate::os_request_capture::registry) struct CompletionGuard<'a> {
    held: Option<MutexGuard<'a, ()>>,
    signal: &'a CompletionSignal,
}

impl NativeCompletionGate {
    pub(in crate::os_request_capture::registry) fn new() -> Self {
        Self(Mutex::new(()))
    }
    pub(in crate::os_request_capture::registry) fn try_enter<'a>(
        &'a self,
        signal: &'a CompletionSignal,
    ) -> Result<CompletionGuard<'a>, EnterError> {
        match self.0.try_lock() {
            Ok(held) => Ok(CompletionGuard {
                held: Some(held),
                signal,
            }),
            Err(TryLockError::WouldBlock) => Err(EnterError::Busy),
            Err(TryLockError::Poisoned(_)) => Err(EnterError::Poisoned),
        }
    }
    pub(in crate::os_request_capture::registry) fn probe_released_after_defer(
        &self,
        signal: &CompletionSignal,
    ) {
        // If release preceded the deferred marker, this nonblocking metadata
        // probe supplies its missed wake. If still busy, that owner's drop
        // supplies it. No native owner/once transaction runs in this probe.
        match self.try_enter(signal) {
            Ok(guard) => drop(guard),
            Err(EnterError::Poisoned) => signal.notify_ready(),
            Err(EnterError::Busy) => {}
        }
    }
    #[cfg(all(unix, test))]
    pub(in crate::os_request_capture::registry) fn hold_for_test<'a>(
        &'a self,
        signal: &'a CompletionSignal,
    ) -> CompletionGuard<'a> {
        CompletionGuard {
            held: Some(self.0.lock().unwrap()),
            signal,
        }
    }
}

impl Drop for CompletionGuard<'_> {
    fn drop(&mut self) {
        drop(self.held.take());
        self.signal.notify_ready();
    }
}
