//! Bounded expected input lookup through the sole published registration cells.
//! A copied producer label and plan Arc grant no IO or current-owner fact.
use super::*;

pub(super) fn prepare(
    scope: &CaptureSession,
    producer: [u8; 16],
) -> Result<OriginalWindowPlan, CaptureFailure> {
    let mut flows = scope
        .sources
        .flows
        .iter()
        .enumerate()
        .filter(|(_, flow)| flow.producer_scope == producer);
    let (index, flow) = flows.next().ok_or(CaptureFailure::InvalidPlan)?;
    if flows.next().is_some() || flow.requests.len() != 8 || flow.plan.payload_bytes != 128 {
        return Err(CaptureFailure::InvalidPlan);
    }
    Ok(OriginalWindowPlan {
        producer,
        flow: index,
        plan: flow.plan.clone(),
    })
}
