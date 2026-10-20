//! Owned selector diagnostics only. Capture reads the canonical connection;
//! publication cannot route, authorize, publish Full, or consume native credit.
//! There is one inline slot per original selection attempt: no queue or task.
use super::*;

pub(super) struct PathSelectionLog {
    node_id: String,
    local_generation: u64,
    selection: PathSelection,
    pub(super) previous_path: Option<NetworkPath>,
    local_endpoint: Option<SocketAddr>,
    candidate_source: Option<CandidatePairSource>,
    rtt_ms: Option<u64>,
    direct_type: DirectPathType,
    state: ConnectionState,
    relay_server: Option<String>,
    relay_ready_generation: Option<u64>,
    relay_confirmed_generation: Option<u64>,
    relay_confirmed_connection_id: Option<u64>,
    relay_first_gate_generation: Option<u64>,
    relay_first_business_sent_generation: Option<u64>,
    relay_first_business_received_generation: Option<u64>,
    relay_first_business_exchange_generation: Option<u64>,
    relay_first_business_gate_completed_generation: Option<u64>,
    first_usable_generation: Option<u64>,
    first_usable_path: Option<NetworkPath>,
}

impl PathSelectionLog {
    pub(super) fn capture(
        conn: &PeerConnection,
        local_generation: u64,
        selection: &PathSelection,
        local_endpoint: Option<SocketAddr>,
    ) -> Option<Self> {
        let previous = conn.last_path_selection.as_ref();
        let changed = previous
            .map(|previous| {
                previous.path != selection.path
                    || previous.reason_code != selection.reason_code
                    || previous.direct_endpoint != selection.direct_endpoint
                    || previous.relay_hedged != selection.relay_hedged
                    || (selection.path == Some(NetworkPath::Relay)
                        && previous.relay_server != selection.relay_server)
            })
            .unwrap_or(true);
        if !changed {
            return None;
        }

        let previous_path = previous.and_then(|selection| selection.path);
        let pair = selection.direct_endpoint.and_then(|endpoint| {
            conn.candidate_pairs.iter().find(|pair| {
                pair.local_generation == local_generation
                    && pair.remote_endpoint == endpoint
                    && conn.pair_belongs_to_current_remote_epoch(pair)
            })
        });
        let captured_local_endpoint =
            local_endpoint.or_else(|| pair.and_then(|pair| pair.local_endpoint));
        let candidate_source = pair.map(|pair| pair.source);
        let rtt_ms = pair.and_then(|pair| pair.rtt_ewma_ms.or(pair.rtt_ms));
        let direct_type = classify_candidate_pair_path_with_on_link_host(
            selection.path,
            pair,
            selection.direct_confirmed,
            pair.is_some_and(|pair| conn.is_on_link_host_candidate(pair.remote_endpoint)),
        );

        Some(Self {
            node_id: conn.node_id.clone(),
            local_generation,
            selection: selection.clone(),
            previous_path,
            local_endpoint: captured_local_endpoint,
            candidate_source,
            rtt_ms,
            direct_type,
            state: conn.state,
            relay_server: conn.relay_server.clone(),
            relay_ready_generation: conn.relay_ready_generation,
            relay_confirmed_generation: conn.relay_confirmed_generation,
            relay_confirmed_connection_id: conn.relay_confirmed_connection_id,
            relay_first_gate_generation: conn.relay_first.gate_generation,
            relay_first_business_sent_generation: conn.relay_first.business_sent_generation,
            relay_first_business_received_generation: conn.relay_first.business_received_generation,
            relay_first_business_exchange_generation: conn.relay_first.business_exchange_generation,
            relay_first_business_gate_completed_generation: conn
                .relay_first
                .business_gate_completed_generation,
            first_usable_generation: conn.first_usable_generation,
            first_usable_path: conn.first_usable_path,
        })
    }

    pub(super) fn emit(self) {
        let selection = &self.selection;
        let local_generation = self.local_generation;
        let previous_path = self.previous_path;
        let remote_endpoint = selection.direct_endpoint;
        let remote_endpoint_text = match selection.path {
            Some(NetworkPath::Relay) => self
                .relay_server
                .clone()
                .unwrap_or_else(|| "unknown".to_owned()),
            _ => remote_endpoint
                .map(|endpoint| endpoint.to_string())
                .unwrap_or_else(|| "unknown".to_owned()),
        };
        let local_endpoint_text = format_log_endpoint(self.local_endpoint);
        let candidate_source = self.candidate_source;
        let rtt_ms = self.rtt_ms;
        let direct_type = self.direct_type;
        // Emit one compact state snapshot for every selector transition.  The
        // individual path events below describe the user-visible transition;
        // this snapshot explains why a transition was admitted or withheld
        // when relay setup, Direct validation, and the two-direction relay
        // business gate race each other.  It intentionally contains only
        // bounded diagnostic state (no ticket, key, or validation owner).
        debug!(
            target: PATH_SELECTION_LOG_TARGET,
            event = "path_state_snapshot",
            peer_id = %self.node_id,
            generation = local_generation,
            connection_state = ?self.state,
            previous_path = ?previous_path,
            selected_path = ?selection.path,
            path_id = ?selection.direct_endpoint
                .map(|endpoint| endpoint.to_string())
                .or_else(|| selection.relay_server.clone()),
            reason_code = selection.reason_code,
            direct_confirmed = selection.direct_confirmed,
            relay_hedged = selection.relay_hedged,
            relay_ready_generation = ?self.relay_ready_generation,
            relay_confirmed_generation = ?self.relay_confirmed_generation,
            relay_confirmed_connection_id = ?self.relay_confirmed_connection_id,
            relay_first_gate_generation = ?self.relay_first_gate_generation,
            relay_first_business_sent_generation = ?self.relay_first_business_sent_generation,
            relay_first_business_received_generation = ?self.relay_first_business_received_generation,
            relay_first_business_exchange_generation = ?self.relay_first_business_exchange_generation,
            relay_first_business_gate_completed_generation = ?self.relay_first_business_gate_completed_generation,
            first_usable_generation = ?self.first_usable_generation,
            first_usable_path = ?self.first_usable_path,
            "path selector state changed: path={:?} reason_code={} reason={}",
            selection.path,
            selection.reason_code,
            selection.reason,
        );

        if selection.path == Some(NetworkPath::Direct) && selection.direct_confirmed {
            info!(
                target: PATH_SELECTION_LOG_TARGET,
                event = "candidate_pair_selected",
                peer_id = %self.node_id,
                local_endpoint = %local_endpoint_text,
                remote_endpoint = %remote_endpoint_text,
                candidate_source = ?candidate_source,
                rtt_ms = ?rtt_ms,
                reason = %selection.reason,
                "candidate_pair_selected peer_id={} remote_endpoint={:?} reason={}",
                self.node_id,
                remote_endpoint,
                selection.reason
            );
            match direct_type {
                DirectPathType::PublicUdp => info!(
                target: PATH_SELECTION_LOG_TARGET,
                    event = "public_udp_direct_selected",
                    peer_id = %self.node_id,
                    local_endpoint = %local_endpoint_text,
                    remote_endpoint = %remote_endpoint_text,
                    candidate_source = ?candidate_source,
                    rtt_ms = ?rtt_ms,
                    reason = %selection.reason,
                    "public_udp_direct_selected peer_id={} remote_endpoint={:?} reason={}",
                    self.node_id,
                    remote_endpoint,
                    selection.reason
                ),
                DirectPathType::PeerReflexive => info!(
                target: PATH_SELECTION_LOG_TARGET,
                    event = "peer_reflexive_direct_selected",
                    peer_id = %self.node_id,
                    local_endpoint = %local_endpoint_text,
                    remote_endpoint = %remote_endpoint_text,
                    candidate_source = ?candidate_source,
                    rtt_ms = ?rtt_ms,
                    reason = %selection.reason,
                    "peer_reflexive_direct_selected peer_id={} remote_endpoint={:?} reason={}",
                    self.node_id,
                    remote_endpoint,
                    selection.reason
                ),
                DirectPathType::Overlay => info!(
                target: PATH_SELECTION_LOG_TARGET,
                    event = "overlay_direct_selected",
                    peer_id = %self.node_id,
                    local_endpoint = %local_endpoint_text,
                    remote_endpoint = %remote_endpoint_text,
                    candidate_source = ?candidate_source,
                    rtt_ms = ?rtt_ms,
                    reason = %selection.reason,
                    "overlay_direct_selected peer_id={} remote_endpoint={:?} reason={}",
                    self.node_id,
                    remote_endpoint,
                    selection.reason
                ),
                DirectPathType::Lan => info!(
                target: PATH_SELECTION_LOG_TARGET,
                    event = "lan_direct_selected",
                    peer_id = %self.node_id,
                    local_endpoint = %local_endpoint_text,
                    remote_endpoint = %remote_endpoint_text,
                    candidate_source = ?candidate_source,
                    rtt_ms = ?rtt_ms,
                    reason = %selection.reason,
                    "lan_direct_selected peer_id={} remote_endpoint={:?} reason={}",
                    self.node_id,
                    remote_endpoint,
                    selection.reason
                ),
                _ => {}
            }
        }

        if should_record_direct_promotion(previous_path, selection) {
            info!(
                target: PATH_SELECTION_LOG_TARGET,
                event = "direct_path_promoted",
                peer_id = %self.node_id,
                local_endpoint = %local_endpoint_text,
                remote_endpoint = %remote_endpoint_text,
                candidate_source = ?candidate_source,
                rtt_ms = ?rtt_ms,
                reason = %selection.reason,
                "direct_path_promoted peer_id={} remote_endpoint={:?} reason={}",
                self.node_id,
                remote_endpoint,
                selection.reason
            );
        }

        if selection.reason_code == REASON_PATH_DIRECT_DEGRADED {
            info!(
                target: PATH_SELECTION_LOG_TARGET,
                event = "direct_path_degraded",
                peer_id = %self.node_id,
                local_endpoint = %local_endpoint_text,
                remote_endpoint = %remote_endpoint_text,
                candidate_source = ?candidate_source,
                rtt_ms = ?rtt_ms,
                reason = %selection.reason,
                "direct_path_degraded peer_id={} remote_endpoint={:?} reason={}",
                self.node_id,
                remote_endpoint,
                selection.reason
            );
        }

        if selection.path == Some(NetworkPath::Relay) {
            info!(
                target: PATH_SELECTION_LOG_TARGET,
                event = "relay_fallback_selected",
                peer_id = %self.node_id,
                local_endpoint = %local_endpoint_text,
                remote_endpoint = %remote_endpoint_text,
                relay_server = ?self.relay_server,
                candidate_source = ?candidate_source,
                rtt_ms = ?rtt_ms,
                reason = %selection.reason,
                "relay_fallback_selected peer_id={} reason={}",
                self.node_id,
                selection.reason
            );
        }
    }
}

/// Declare before every actual epoch/connection/emit or physical-attempt
/// owner in the enclosing operation. Reverse local drop order then publishes
/// only after those original guards end, including error and cancellation.
/// The frozen metadata holds no owner Arc, permission, or protocol authority.
#[derive(Default)]
pub(crate) struct DeferredPathSelectionLog {
    log: Option<PathSelectionLog>,
    overflow: usize,
}

impl DeferredPathSelectionLog {
    pub(super) fn record(&mut self, log: Option<PathSelectionLog>) {
        let Some(log) = log else { return };
        if self.log.is_none() {
            self.log = Some(log);
        } else {
            // Keep the first diagnostic unchanged. This single-attempt caller
            // selects once; any future duplicate is bounded and observable.
            self.overflow = self.overflow.saturating_add(1);
        }
    }
}

impl Drop for DeferredPathSelectionLog {
    fn drop(&mut self) {
        if let Some(log) = self.log.take() {
            log.emit();
        }
        if self.overflow != 0 {
            warn!(
                target: PATH_SELECTION_LOG_TARGET,
                event = "path_selection_log_overflow",
                capacity = 1,
                dropped = self.overflow,
                "additional selector diagnostics exceeded the inline attempt slot"
            );
        }
    }
}
