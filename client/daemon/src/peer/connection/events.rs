impl PeerConnection {
    pub(super) fn record_path_selection_event(
        &mut self,
        local_generation: u64,
        selection: &PathSelection,
        local_endpoint: Option<SocketAddr>,
    ) {
        let Some(log) =
            PathSelectionLog::capture(self, local_generation, selection, local_endpoint)
        else {
            return;
        };
        let previous_path = log.previous_path;
        // Existing caller-owned epoch paths retain their original emission order.
        log.emit();
        self.record_path_selection_history(local_generation, selection, previous_path);
    }

    fn capture_path_selection_event(
        &mut self,
        local_generation: u64,
        selection: &PathSelection,
        local_endpoint: Option<SocketAddr>,
    ) -> Option<PathSelectionLog> {
        let log = PathSelectionLog::capture(self, local_generation, selection, local_endpoint)?;
        self.record_path_selection_history(local_generation, selection, log.previous_path);
        Some(log)
    }

    fn record_path_selection_history(
        &mut self,
        local_generation: u64,
        selection: &PathSelection,
        previous_path: Option<NetworkPath>,
    ) {
        self.path_events.push(PathSelectionEvent {
            selected_at: Instant::now(),
            network_generation: local_generation,
            previous_path,
            selected_path: selection.path,
            direct_endpoint: selection.direct_endpoint,
            relay_server: selection.relay_server.clone(),
            reason_code: selection.reason_code.to_string(),
            reason: selection.reason.clone(),
            direct_confirmed: selection.direct_confirmed,
            relay_hedged: selection.relay_hedged,
            direct_score: selection.direct_score.clone(),
            relay_score: selection.relay_score.clone(),
        });

        if self.path_events.len() > PATH_SELECTION_EVENT_LIMIT {
            let excess = self.path_events.len() - PATH_SELECTION_EVENT_LIMIT;
            self.path_events.drain(0..excess);
        }
    }

    fn record_direct_event(
        &mut self,
        local_generation: u64,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        self.push_direct_event(DirectTraversalEvent::new(
            local_generation,
            stage,
            endpoint,
            candidate_count,
            sent_probes,
            detail,
        ));
    }

    #[allow(clippy::too_many_arguments)]
    fn record_direct_event_with_socket(
        &mut self,
        local_generation: u64,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        self.push_direct_event(
            DirectTraversalEvent::new(
                local_generation,
                stage,
                endpoint,
                candidate_count,
                sent_probes,
                detail,
            )
            .with_socket_index(socket_index),
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_direct_validation_event_with_metadata(
        &mut self,
        generation: u64,
        metadata: DirectValidationEventMetadata,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        let mut event = DirectTraversalEvent::new(
            generation,
            stage,
            endpoint,
            candidate_count,
            sent_probes,
            detail,
        );
        event.validation_session_id = metadata.local_validation_session_id;
        event.remote_validation_owner = metadata.remote_validation_owner;
        event.request_id = metadata.request_id;
        event.expected_endpoint = metadata.expected_endpoint;
        event.observed_ack_endpoint = metadata.observed_ack_endpoint;
        event.selected_endpoint = metadata.selected_endpoint;
        event.ack_endpoint_authenticated = metadata.ack_endpoint_authenticated;
        event.validation_rtt_ms = metadata.validation_rtt_ms;
        event.socket_index = socket_index;
        self.push_direct_event(event);
    }

    #[allow(clippy::too_many_arguments)]
    fn record_direct_event_with_probe_coverage(
        &mut self,
        local_generation: u64,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
        socket0_count: u32,
        alt_socket_count: u32,
        unique_target_ports: u32,
        repeated_target_ports: u32,
    ) {
        self.push_direct_event(
            DirectTraversalEvent::new(
                local_generation,
                stage,
                endpoint,
                candidate_count,
                sent_probes,
                detail,
            )
            .with_probe_coverage(
                socket0_count,
                alt_socket_count,
                unique_target_ports,
                repeated_target_ports,
            ),
        );
    }

    fn record_hard_hard_attempt_report(
        &mut self,
        report: HardHardAttemptReport,
        detail: impl Into<String>,
    ) {
        let generation = report.network_generation;
        let socket_index = report.socket_index;
        let candidate_count = report.counts.planned_targets as usize;
        let sent_datagrams = report.counts.send_success_datagrams;
        self.push_direct_event(
            DirectTraversalEvent::new(
                generation,
                "hard_hard_attempt_report",
                None,
                Some(candidate_count),
                Some(sent_datagrams),
                detail,
            )
            .with_socket_index(socket_index)
            .with_hard_hard_attempt(report),
        );
    }

    /// Push one direct-traversal event into the bounded ring.
    ///
    /// The strict acceptance lifecycle (owned validation request -> ACK ->
    /// promoted -> path) and the bounded Hard↔Hard lifecycle markers are
    /// authoritative traversal evidence, so those stages are protected from
    /// eviction: a post-promotion burst of ordinary traversal events (scan
    /// completions, inbound probes, maintainer stops) must never push the
    /// evidence chain out of the ring before the harness snapshot captures it
    /// (field evidence: the v0.1.116 acceptance rounds that converged in
    /// ~1 s produced enough post-promotion events to evict
    /// `direct_validation_request_sent`, so the strict parser could not
    /// reconstruct the owned chain).
    fn push_direct_event(&mut self, event: DirectTraversalEvent) {
        self.direct_events.push(event);
        if self.direct_events.len() <= DIRECT_TRAVERSAL_EVENT_LIMIT {
            return;
        }
        // Evict ordinary events first so the owned request -> ACK -> promoted
        // -> path chain survives the ring no matter which side pushed the
        // overflow.
        let mut evicted = 0usize;
        let excess = self.direct_events.len() - DIRECT_TRAVERSAL_EVENT_LIMIT;
        self.direct_events.retain(|candidate| {
            if evicted >= excess {
                return true;
            }
            if is_protected_direct_event_stage(&candidate.stage) {
                true
            } else {
                evicted += 1;
                false
            }
        });
        // A miss can produce more than 32 protected validation request/ACK
        // records while the final experiment snapshot is still pending. Keep
        // typed attempt reports ahead of that repeatable lifecycle traffic;
        // when only protected entries remain, evict the oldest non-report and
        // retain the newest validation chain. The hard cap remains absolute.
        while self.direct_events.len() > DIRECT_TRAVERSAL_EVENT_LIMIT {
            let evict = self
                .direct_events
                .iter()
                .position(|candidate| candidate.stage != "hard_hard_attempt_report")
                .unwrap_or(0);
            self.direct_events.remove(evict);
        }
    }
}

/// Direct-validation and bounded Hard↔Hard lifecycle stages that acceptance
/// diagnostics need as one evidence chain. These events are never evicted
/// from the bounded event ring by ordinary traversal noise; a typed attempt
/// report also survives a ring made entirely of repeated protected traffic.
fn is_protected_direct_event_stage(stage: &str) -> bool {
    matches!(
        stage,
        "direct_validation_request_sent"
            | "direct_validation_request_received"
            | "direct_validation_ack_sent"
            | "direct_validation_ack_received"
            | "direct_validation_emit_lock_timeout"
            | "direct_validation_promoted"
            | "direct_path_promoted"
            | "hard_hard_sweep_started"
            | "hard_hard_direct_validation_started"
            | "hard_hard_probe_summary"
            | "hard_hard_birthday_sweep_summary"
            | "hard_hard_attempt_report"
            | "hard_hard_sweep_completed"
            | "hard_hard_sweep_failed"
            | "hard_hard_failed"
    )
}

/// A Direct path is promoted only after the encrypted data-plane confirmation
/// transaction has committed.  Candidate nomination and trial-window sends
/// may still be recorded in `PathSelectionEvent`, but they are not a user
/// visible path transition and must never emit `direct_path_promoted`.
fn should_record_direct_promotion(
    previous_path: Option<NetworkPath>,
    selection: &PathSelection,
) -> bool {
    selection.path == Some(NetworkPath::Direct)
        && selection.direct_confirmed
        && previous_path != Some(NetworkPath::Direct)
}

#[cfg(test)]
mod path_promotion_tests {
    use super::*;

    #[test]
    fn trial_direct_selection_cannot_emit_promotion() {
        let selection = PathSelection::direct(
            "192.0.2.10:40000".parse().unwrap(),
            "direct_trial",
            "candidate probe only",
            false,
        );
        assert!(!should_record_direct_promotion(None, &selection));
    }

    #[test]
    fn encrypted_direct_selection_emits_promotion_once() {
        let selection = PathSelection::direct(
            "192.0.2.10:40000".parse().unwrap(),
            "direct_confirmed",
            "encrypted data path confirmed",
            true,
        );
        assert!(should_record_direct_promotion(None, &selection));
        assert!(!should_record_direct_promotion(
            Some(NetworkPath::Direct),
            &selection
        ));
    }
}
