//! Private, bounded registration preparation; the original input mutex remains
//! the sole append authority. Empty shared cells contain no observed IO facts.
use super::*;

mod conflicts;

pub(super) struct PreparedRegistration {
    capture_id: [u8; 16],
    producer: [u8; 16],
    added: usize,
    incoming: Vec<FlowState>,
    sources: Result<Vec<Arc<native::source_index::FlowSources>>, CaptureFailure>,
    capture_label: String,
    producer_label: String,
    conflicts: conflicts::Prechecked,
}

impl PreparedRegistration {
    pub(super) fn new(plan: RegistrationPlan, scope: &CaptureSession) -> Self {
        let producer = plan.producer_scope;
        let added = plan.flows.iter().map(|flow| flow.requests.len()).sum();
        #[cfg(all(unix, test))]
        registration_tests::preparing();
        let incoming: Vec<_> = plan
            .flows
            .into_iter()
            .map(|plan| {
                let requests = plan
                    .requests
                    .iter()
                    .map(|_| RequestReadState {
                        native_credit: native::completion::NativeFrameSlot::new(),
                        first_request_room: None,
                        original_write_window: First::new(),
                        first_peer: First::new(),
                        first_response: First::new(),
                        read_events: 0,
                        first_read: None,
                        last_read: None,
                        tcp: None,
                        udp_complete: false,
                    })
                    .collect();
                FlowState {
                    inbound: ingress::InboundFlow::new(plan.requests.len()),
                    plan: Arc::new(plan),
                    producer_scope: producer,
                    tcp_open: None,
                    invalid: Arc::new(AtomicBool::new(false)),
                    requests,
                }
            })
            .collect();
        let sources = Self::sources(&incoming);
        let conflicts = conflicts::Prechecked::capture(scope, &incoming);
        Self {
            capture_id: plan.capture_id,
            producer,
            added,
            incoming,
            sources,
            capture_label: hex::encode(plan.capture_id),
            producer_label: hex::encode(producer),
            conflicts,
        }
    }

    fn sources(
        incoming: &[FlowState],
    ) -> Result<Vec<Arc<native::source_index::FlowSources>>, CaptureFailure> {
        let mut sources = Vec::new();
        sources
            .try_reserve_exact(incoming.len())
            .map_err(|_| CaptureFailure::Capacity)?;
        for flow in incoming {
            sources.push(native::source_index::FlowSources::capture(flow)?);
        }
        Ok(sources)
    }

    // Borrow preparation so any rejected bulk resources are dropped only after
    // the caller releases its actual guard. Authoritative checks stay here and
    // retain their original order, including before a preparation error.
    pub(super) fn append(
        &mut self,
        scope: &CaptureSession,
        state: &mut RegistryState,
    ) -> Result<RegistrationReceipt, CaptureFailure> {
        if self.capture_id != scope.capture_id || self.incoming.is_empty() {
            return Err(CaptureFailure::InvalidPlan);
        }
        if !scope.is_live(Instant::now()) {
            return Err(CaptureFailure::Expired);
        }
        let total = state
            .requests
            .checked_add(self.added)
            .filter(|n| *n <= MAX_REQUESTS)
            .ok_or(CaptureFailure::Capacity)?;
        if state.producers.contains(&self.producer) || self.conflicts.recheck(state, &self.incoming)
        {
            return Err(CaptureFailure::RegistrationConflict);
        }
        let revision = state
            .revision
            .checked_add(1)
            .ok_or(CaptureFailure::CounterExhausted)?;
        let sources = self.sources.as_mut().map_err(|error| *error)?;
        state.native_flows.try_reserve(sources.len())?;
        for source in sources.drain(..) {
            state.native_flows.push(source)?;
        }
        state.flows.append(&mut self.incoming);
        state.producers.insert(self.producer);
        state.requests = total;
        state.revision = revision;
        Ok(RegistrationReceipt {
            scope: "registered_expected_inputs_only",
            owner: scope.owner,
            capture_id: std::mem::take(&mut self.capture_label),
            producer_scope: std::mem::take(&mut self.producer_label),
            registration_revision: revision,
            added_requests: self.added,
            total_requests: total,
        })
    }
}
