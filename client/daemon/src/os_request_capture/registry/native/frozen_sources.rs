//! Bounded, ordered copies of already-retained source membership. These
//! handles keep data alive, never the scope, descriptor or daemon owners.
use super::*;

pub(super) struct FrozenFlowSources {
    pub(super) plan: Arc<RegisteredFlowPlan>,
    pub(super) invalid: Arc<AtomicBool>,
    pub(super) inbound_invalid: Arc<AtomicBool>,
    pub(super) device: Option<Weak<DeviceLease>>,
    pub(super) owners: Option<Arc<owners::OriginalKernelOwners>>,
    pub(super) reads: Vec<Arc<KernelReadBinding>>,
    pub(super) writes: Vec<Arc<KernelIngressBinding>>,
}

impl FrozenFlowSources {
    pub(super) fn capture(index: &source_index::SourceIndex, flow: usize) -> Option<Self> {
        #[cfg(all(unix, test))]
        preparation_probe_for_test();
        let original = index.flows.get(flow)?;
        let mut reads = Vec::new();
        let mut writes = Vec::new();
        for read in index.reads.iter().filter(|read| read.flow == flow) {
            reads.try_reserve(1).ok()?;
            reads.push(read.clone());
        }
        for write in index
            .writes
            .iter()
            .filter(|write| write.frame_flow() == flow)
        {
            writes.try_reserve(1).ok()?;
            writes.push(write.clone());
        }
        Some(Self {
            plan: original.plan.clone(),
            invalid: original.invalid.clone(),
            inbound_invalid: original.inbound_invalid.clone(),
            device: index.device.as_ref().cloned(),
            owners: index.owners.as_ref().cloned(),
            reads,
            writes,
        })
    }
}

pub(super) struct FrozenRequestSources {
    pub(super) flow: Arc<FrozenFlowSources>,
    pub(super) flow_index: usize,
    pub(super) slot: usize,
    pub(super) window: Option<write_window::WriteWindow>,
    pub(super) first_peer: Option<Arc<read_peer::FirstReadPeer>>,
    pub(super) first_response: Option<Arc<ingress::ResponseCapture>>,
}

impl FrozenRequestSources {
    pub(super) fn capture(
        original: &source_index::RequestSources,
        flow: usize,
        slot: usize,
        sources: Arc<FrozenFlowSources>,
    ) -> Self {
        Self {
            flow: sources,
            flow_index: flow,
            slot,
            window: original.window.as_ref().cloned(),
            first_peer: original.peer.as_ref().cloned(),
            first_response: original.response.as_ref().cloned(),
        }
    }
}

#[cfg(all(unix, test))]
thread_local! {
    pub(super) static PREPARATION_PROBE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(unix, test))]
fn preparation_probe_for_test() {
    let probe = PREPARATION_PROBE.with(|slot| slot.borrow_mut().take());
    if let Some(probe) = probe {
        probe();
    }
}
