//! Temporary diagnostic storage, prepared before taking the input registry.
//! These empty vectors contain no sampled facts, live scope or IO authority.
use super::*;

pub(in crate::os_request_capture::registry) struct SnapshotBuffers {
    pub(super) requests: Vec<RequestSnapshot>,
    pub(super) plans: Vec<Arc<RegisteredFlowPlan>>,
    pub(super) full_coverage: Vec<(usize, Vec<full::ReadFrameSpan>)>,
    pub(super) inbound_coverage: Vec<(usize, Vec<full::ReadFrameSpan>)>,
    pub(super) full_packets: Vec<full::FullPacketSnapshot>,
    pub(super) system_writes: Vec<ingress::WriteSnapshot>,
}

impl SnapshotBuffers {
    pub(in crate::os_request_capture::registry) fn prepare() -> Self {
        // Each registration contributes at least one of the existing 1000
        // requests. Packet histories retain their independent 1024-fact caps.
        // Reserve only outer storage; nested spans are copied at the original
        // frozen observation sites, without a requests*history reservation.
        Self {
            requests: Vec::with_capacity(crate::business_evidence::MAX_REQUESTS),
            plans: Vec::with_capacity(crate::business_evidence::MAX_REQUESTS),
            full_coverage: Vec::with_capacity(full::MAX_FULL_PACKETS),
            inbound_coverage: Vec::with_capacity(ingress::MAX_SYSTEM_WRITES),
            full_packets: Vec::with_capacity(full::MAX_FULL_PACKETS),
            system_writes: Vec::with_capacity(ingress::MAX_SYSTEM_WRITES),
        }
    }
}
