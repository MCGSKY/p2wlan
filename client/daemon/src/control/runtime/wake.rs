// Reconcile only the work named by the bounded authenticated wake. Roster
// hints use the existing authoritative HTTP/command path before signal I/O.
#[allow(clippy::too_many_arguments)]
async fn handle_control_wake(
    wake: wake::Wake,
    http: &RouteAwareControlHttpClient,
    base_url: &str,
    token: &str,
    config: &Config,
    self_node_id: &str,
    registration_seq: Option<u64>,
    state: &Arc<RwLock<ClientState>>,
    event_tx: &mpsc::UnboundedSender<ControlEvent>,
    health: Option<&Arc<crate::tasks::HealthState>>,
    relay_selection: Option<&Arc<RwLock<RelaySelectionDiagnostics>>>,
    advertised_snapshot: &Arc<std::sync::Mutex<AdvertisedEndpointSnapshot>>,
    peer_roster_tick: &mut time::Interval,
    signal_ws_task: Option<&websocket::SignalWebSocketTask>,
    poll_failures: &mut u32,
    signal_failures: &mut u32,
    recent_signal_ids: &Arc<tokio::sync::Mutex<SignalDeliveryTracker>>,
    server_clock: &Arc<ServerClockEstimate>,
    critical_auth_tx: &watch::Sender<Option<CriticalControlAuth>>,
) -> ControlCommandDisposition {
    if wake.roster() {
        let disposition = handle_control_command(
            ControlCommand::PollPeersNow,
            http,
            base_url,
            token,
            config,
            self_node_id,
            registration_seq,
            state,
            event_tx,
            health,
            relay_selection,
            advertised_snapshot,
            peer_roster_tick,
            signal_ws_task,
            poll_failures,
        )
        .await;
        if disposition != ControlCommandDisposition::Continue {
            return disposition;
        }
    }
    if !wake.signals() {
        return ControlCommandDisposition::Continue;
    }

    let signal_result = async {
        let current_http = http.current()?;
        poll_signals(
            &current_http,
            base_url,
            token,
            self_node_id,
            registration_seq,
            event_tx,
            0,
            recent_signal_ids,
            server_clock,
            critical_auth_tx.subscribe(),
            http,
        )
        .await
    }
    .await;
    match signal_result {
        Ok(()) => {
            *signal_failures = 0;
            if let Some(health) = health {
                health.mark_control_success().await;
            }
            let _ = event_tx.send(ControlEvent::ControlHealthy);
        }
        Err(e) => {
            let err_str = e.to_string();
            if is_registration_conflict_error(&err_str) {
                emit_registration_lifecycle_conflict(health, event_tx, err_str).await;
                return ControlCommandDisposition::Exit;
            }
            if is_permanent_auth_error(&err_str) {
                error!("Permanent auth failure after WebSocket signal wake: {err_str}");
                if let Some(health) = health {
                    health.set_reauth_required(true);
                }
                let _ = event_tx.send(ControlEvent::ReauthRequired { message: err_str });
                return ControlCommandDisposition::Reregister;
            }
            *signal_failures = signal_failures.saturating_add(1);
            warn!("Signal fetch after WebSocket wake failed: {err_str}");
            if let Some(health) = health {
                health.set_control_connected(false);
            }
            let _ = event_tx.send(ControlEvent::Disconnected);
        }
    }

    ControlCommandDisposition::Continue
}
