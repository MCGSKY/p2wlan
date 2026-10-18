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
    // Called only under the existing registry guard after new terminal rows
    // were stored. Its ordinary drop already releases before waking the actor.
    // This revision is a wakeup hint; readiness always reads the sole rows.
    pub(super) fn record_native_terminal_progress(&self) {
        if let Some(next) = self
            .native_terminal_revision
            .load(Ordering::Relaxed)
            .checked_add(1)
        {
            self.native_terminal_revision.store(next, Ordering::Release);
        }
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
                let mut state = self.state.lock_until(end).await?;
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
                // Only the existing bounded real-Full markers are drained.
                // Some terminal outcome, including every refusal, is enough.
                self.complete_pending_fulls_in(&mut state);
                state.flows[index]
                    .requests
                    .iter()
                    .all(|row| row.native_credit.is_some())
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
