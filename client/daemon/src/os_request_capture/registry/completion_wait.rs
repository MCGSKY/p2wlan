//! Metadata completion only: a refusal releases the TCP lifecycle just as a
//! commit does. It never retries a terminal owner check or grants native facts.
use super::{CaptureFailure, CaptureSession, Protocol};
use serde::Serialize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

mod failure;

#[derive(Serialize)]
pub(in crate::os_request_capture) struct TerminalMetadataReceipt {
    scope: &'static str,
    owner: u64,
    capture_id: String,
    producer_scope: String,
    completed_requests: usize,
    native_os_write_verified: bool,
    physical_send_verified: bool,
    canonical_current_owner_verified: bool,
}

impl CaptureSession {
    // Results are immutable before this release/wake. Concurrent completion
    // owners publish revisions atomically; readiness reads the sole slots.
    pub(super) fn record_native_terminal_progress(&self) {
        let _ = self.native_terminal_revision.try_update(
            Ordering::Release,
            Ordering::Relaxed,
            |value| value.checked_add(1),
        );
        self.pending_full.notify_ready();
    }

    pub(in crate::os_request_capture) async fn wait_original_outcomes(
        self: &Arc<Self>,
        producer: [u8; 16],
        end: tokio::time::Instant,
    ) -> Result<TerminalMetadataReceipt, CaptureFailure> {
        let mut observed = self.native_terminal_revision.load(Ordering::Acquire);
        loop {
            if tokio::time::Instant::now() >= end {
                return Err(CaptureFailure::ControlNotReady);
            }
            if !self.is_live(Instant::now()) {
                return Err(CaptureFailure::Expired);
            }
            let ready = {
                let state = self.state.lock_until(end).await?;
                let index = {
                    let mut matches = state
                        .flows
                        .iter()
                        .enumerate()
                        .filter(|(_, flow)| flow.producer_scope == producer);
                    let (index, _) = matches.next().ok_or(CaptureFailure::InvalidPlan)?;
                    if matches.next().is_some() {
                        return Err(CaptureFailure::InvalidPlan);
                    }
                    index
                };
                if state.flows[index].plan.protocol != Protocol::Tcp
                    || state.flows[index].requests.len() != 8
                {
                    return Err(CaptureFailure::InvalidPlan);
                }
                // Eight metadata handles only, never a scope/descriptor or
                // daemon owner. No terminal/native work holds the input lock.
                let outcomes = std::array::from_fn::<_, 8, _>(|slot| {
                    state.flows[index].requests[slot].native_credit.shared()
                });
                drop(state);
                // Only the existing bounded real-Full markers are drained.
                // Some terminal outcome, including every refusal, is enough.
                let mut completion = self.prepare_pending_fulls();
                if !self.read_complete.load(Ordering::Acquire)
                    || !self.full_complete.load(Ordering::Acquire)
                    || !self.inbound_complete.load(Ordering::Acquire)
                {
                    // These flags never recover. The existing capture
                    // predicate returns Unknown(OriginalPublication) before
                    // any native owner/once check. Preserve recorded rows;
                    // a lost input need not have a real-Full marker to wake us.
                    self.prepare_original_frames(index, &[0, 1, 2, 3, 4, 5, 6, 7], &mut completion);
                }
                completion.finish(self);
                outcomes.iter().all(|outcome| outcome.is_some())
            };
            if ready {
                if tokio::time::Instant::now() >= end {
                    return Err(CaptureFailure::ControlNotReady);
                }
                return Ok(TerminalMetadataReceipt {
                    scope: "original_window_terminal_metadata_only",
                    owner: self.owner,
                    capture_id: hex::encode(self.capture_id),
                    producer_scope: hex::encode(producer),
                    completed_requests: 8,
                    native_os_write_verified: false,
                    physical_send_verified: false,
                    canonical_current_owner_verified: false,
                });
            }
            loop {
                if tokio::time::Instant::now() >= end {
                    return Err(CaptureFailure::ControlNotReady);
                }
                let current = self.native_terminal_revision.load(Ordering::Acquire);
                if current != observed || self.full_completion_pending() {
                    observed = current;
                    break;
                }
                // A metadata reader's own unlock may wake this once. Without
                // new terminal rows it waits again, without reacquiring/spinning.
                tokio::select! {
                    _ = self.full_completion_ready() => break,
                    _ = self.full_metadata_released() => {},
                    _ = tokio::time::sleep_until(end) => return Err(CaptureFailure::ControlNotReady),
                }
            }
        }
    }
}
