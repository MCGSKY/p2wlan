//! Resume bounded completion metadata on the existing descriptor actor.
//! No task, packet retry, fresh deadline or replacement native fact is created.
use super::{CaptureSession, FullRetentionLossReason, KernelReadBinding, RegistryState};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, TryLockError};
use tokio::sync::Notify;

pub(super) struct CompletionSignal {
    pending: AtomicBool,
    window_pending: AtomicBool,
    terminal_pending: AtomicBool,
    ready: Notify,
}

impl CompletionSignal {
    pub(super) fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            window_pending: AtomicBool::new(false),
            terminal_pending: AtomicBool::new(false),
            ready: Notify::new(),
        }
    }

    fn request(&self) {
        self.pending.store(true, Ordering::Release);
        self.ready.notify_one();
    }

    pub(super) fn notify_ready(&self) {
        // A readiness wake only. The sole metadata rows and pending markers
        // remain authoritative; this cannot create a native observation.
        self.ready.notify_one();
    }

    pub(super) fn defer_window_until_unlock(&self) {
        // A busy metadata executor will wake after releasing its own mutex.
        // Do not spin the descriptor actor by immediately notifying it here.
        self.window_pending.store(true, Ordering::Release);
    }

    pub(super) fn request_window(&self) {
        // A bounded metadata wakeup, never a real Full marker or I/O fact.
        self.window_pending.store(true, Ordering::Release);
        self.ready.notify_one();
    }

    fn request_terminal(&self) {
        self.terminal_pending.store(true, Ordering::Release);
        self.ready.notify_one();
    }

    fn metadata_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
            || self.window_pending.load(Ordering::Acquire)
            || self.terminal_pending.load(Ordering::Acquire)
    }

    fn clear(&self) {
        self.pending.store(false, Ordering::Release);
        self.window_pending.store(false, Ordering::Release);
        self.terminal_pending.store(false, Ordering::Release);
    }
}

impl KernelReadBinding {
    pub(super) fn complete_original_full_or_notify(self: &Arc<Self>, scope: &Arc<CaptureSession>) {
        let completion = match scope.state.try_lock() {
            Ok(state) => {
                let mut completion = super::native::completion::NativeCompletionBatch::new();
                scope.prepare_original_frames_in(&state, self.flow, &self.slots, &mut completion);
                drop(state);
                completion
            }
            Err(TryLockError::WouldBlock) => {
                self.full_completion_pending.store(true, Ordering::Release);
                scope.pending_full.request();
                return;
            }
            Err(TryLockError::Poisoned(_)) => {
                scope.original_full_retention_lost(FullRetentionLossReason::HistoryContended);
                return;
            }
        };
        completion.finish(scope);
    }
}

impl CaptureSession {
    pub(super) fn wake_original_terminal_loss(&self) {
        // Only a wakeup for the existing metadata actor. A lost observation
        // is never a real-Full pending marker or a replacement native fact.
        self.pending_full.request_terminal();
    }

    pub(in crate::os_request_capture) async fn full_completion_ready(&self) {
        self.pending_full.ready.notified().await;
    }

    pub(in crate::os_request_capture) async fn full_metadata_released(&self) {
        self.state.completion_released().await;
    }

    pub(in crate::os_request_capture) fn full_completion_pending(&self) -> bool {
        self.pending_full.pending.load(Ordering::Acquire)
    }

    pub(in crate::os_request_capture) fn metadata_completion_pending(&self) -> bool {
        self.pending_full.metadata_pending()
    }

    pub(in crate::os_request_capture) fn complete_pending_fulls(self: &Arc<Self>) {
        if !self.metadata_completion_pending() || !self.is_live(std::time::Instant::now()) {
            return;
        }
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return,
            Err(TryLockError::Poisoned(_)) => {
                self.original_full_retention_lost(FullRetentionLossReason::HistoryContended);
                self.pending_full.clear();
                return;
            }
        };
        let completion = self.prepare_pending_fulls_in(&mut state);
        drop(state);
        completion.finish(self);
    }

    pub(super) fn prepare_pending_fulls_in(
        self: &Arc<Self>,
        state: &mut RegistryState,
    ) -> super::native::completion::NativeCompletionBatch {
        let mut completion = super::native::completion::NativeCompletionBatch::new();
        if !self.metadata_completion_pending() || !self.is_live(std::time::Instant::now()) {
            return completion;
        }
        // Clear only after acquisition. A contended attempt keeps its marker
        // and waits for an unlock, rather than polling or losing the event.
        if self.full_completion_pending() {
            self.pending_full.pending.store(false, Ordering::Release);
            for index in 0..state.read_history.len() {
                let read = &state.read_history[index];
                if !read.full_completion_pending.swap(false, Ordering::AcqRel) {
                    continue;
                }
                let read = read.clone();
                // The original transaction still checks its original window and
                // current owners try-only. Existing terminal outcomes are skipped.
                self.prepare_original_frames_in(state, read.flow, &read.slots, &mut completion);
            }
        }
        let window_pending = self
            .pending_full
            .window_pending
            .swap(false, Ordering::AcqRel);
        let terminal_pending = self
            .pending_full
            .terminal_pending
            .swap(false, Ordering::AcqRel);
        if window_pending || terminal_pending {
            let missing = !self.read_complete.load(Ordering::Acquire)
                || !self.full_complete.load(Ordering::Acquire)
                || !self.inbound_complete.load(Ordering::Acquire);
            // Registration already bounds both dimensions. These signals
            // carry no observations: the unchanged capture predicate decides
            // eligibility and rejects missing provenance before owner/once.
            for flow in 0..state.flows.len() {
                for slot in 0..state.flows[flow].requests.len() {
                    if missing
                        || (window_pending
                            && state.flows[flow].requests[slot]
                                .original_write_window
                                .is_some())
                    {
                        self.prepare_original_frames_in(state, flow, &[slot], &mut completion);
                    }
                }
            }
        }
        completion
    }
}

#[cfg(test)]
mod tests;
