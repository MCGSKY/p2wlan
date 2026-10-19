//! Diagnostic labels and actual epoch contention only; no kernel facts.
use super::*;
use crate::peer::EpochTryContext;

fn context(scope: &CaptureSession) -> EpochTryContext {
    let key = scope.state.lock().unwrap().flows[0].plan.requests[0];
    EpochTryContext {
        capture_owner: scope.owner,
        capture_id: scope.capture_id,
        run: key.run,
        round: key.round,
        request_nonce: key.request_nonce,
        sequence: key.sequence,
        protocol: "udp",
        kind: "request",
        first_read_ordinal: 0,
        // A metadata label in this control, never a constructed KernelRead.
        read_peer_input_ordinal: Some(19),
    }
}

fn negative(value: &serde_json::Value) {
    for key in [
        "native_os_write_verified",
        "physical_send_verified",
        "canonical_current_owner_verified",
    ] {
        assert_eq!(value[key], false);
    }
}

#[tokio::test]
async fn read_peer_epoch_metadata_records_the_original_try_and_no_first_read_claim() {
    let (setup, _parent, peers) = setup().await;
    let captured = collect(&setup.session);
    let context = context(&setup.session);
    let gate = peers.network_epoch_gate();
    let held = gate.lock().await;
    assert_eq!(
        captured.original().unwrap().try_identity_at_observed(
            &peers,
            Instant::now(),
            Some(context)
        ),
        Err(OverlayCreditOutcome::Contended(
            OverlayCreditLockSite::Epoch
        ))
    );
    assert!(setup.session.epoch_trace.snapshot().is_none());
    let before =
        serde_json::to_value(setup.session.epoch_trace.read_peer_snapshot().unwrap()).unwrap();
    assert_eq!(
        before["scope"],
        "actual_original_read_peer_epoch_try_refusal_only"
    );
    assert_eq!(before["original_input_read_ordinal"], 19);
    assert!(before.get("first_read_ordinal").is_none());
    negative(&before);
    drop(held);
    let after =
        serde_json::to_value(setup.session.epoch_trace.read_peer_snapshot().unwrap()).unwrap();
    assert_eq!(after["holder"]["release_completion_observed"], true);
    let times = (
        after["holder"]["acquired_observed_monotonic_ns"].as_u64(),
        after["failed_try_started_monotonic_ns"].as_u64(),
        after["failed_try_returned_monotonic_ns"].as_u64(),
        after["holder"]["ended_before_unlock_monotonic_ns"].as_u64(),
    );
    let covers = match times {
        (Some(a), Some(b), Some(c), Some(d)) => a < b && b <= c && c < d,
        _ => false,
    };
    assert_eq!(after["holder_interval_covers_failed_try"], covers);
    #[cfg(not(target_os = "linux"))]
    {
        // This capture clock deliberately has no non-Linux substitute.
        assert_eq!(times, (None, None, None, None));
        assert!(!covers);
    }
    no_kernel_credit(&setup.session);
}

#[tokio::test]
async fn read_peer_and_final_epoch_first_refusals_are_separate_and_never_replaced() {
    let (setup, _parent, peers) = setup().await;
    let captured = collect(&setup.session);
    let read_context = context(&setup.session);
    let mut final_context = read_context;
    final_context.first_read_ordinal = 9;
    final_context.read_peer_input_ordinal = None;
    let gate = peers.network_epoch_gate();
    let held = gate.lock().await;
    assert!(gate.try_lock_original(Some(final_context)).is_err());
    assert_eq!(
        captured.original().unwrap().try_identity_at_observed(
            &peers,
            Instant::now(),
            Some(read_context)
        ),
        Err(OverlayCreditOutcome::Contended(
            OverlayCreditLockSite::Epoch
        ))
    );
    drop(held);
    let final_value = serde_json::to_value(setup.session.epoch_trace.snapshot().unwrap()).unwrap();
    let read_value =
        serde_json::to_value(setup.session.epoch_trace.read_peer_snapshot().unwrap()).unwrap();
    assert_eq!(
        final_value["scope"],
        "actual_final_kernel_epoch_try_refusal_only"
    );
    assert_eq!(final_value["first_read_ordinal"], 9);
    assert!(final_value.get("original_input_read_ordinal").is_none());
    assert_eq!(read_value["original_input_read_ordinal"], 19);
    negative(&final_value);
    negative(&read_value);
    let held = gate.lock().await;
    let mut later = read_context;
    later.read_peer_input_ordinal = Some(20);
    assert!(captured
        .original()
        .unwrap()
        .try_identity_at_observed(&peers, Instant::now(), Some(later))
        .is_err());
    final_context.sequence += 1;
    assert!(gate.try_lock_original(Some(final_context)).is_err());
    drop(held);
    assert_eq!(
        serde_json::to_value(setup.session.epoch_trace.snapshot().unwrap()).unwrap(),
        final_value
    );
    assert_eq!(
        serde_json::to_value(setup.session.epoch_trace.read_peer_snapshot().unwrap()).unwrap(),
        read_value
    );
    no_kernel_credit(&setup.session);
}

#[tokio::test]
async fn read_peer_epoch_metadata_wrong_scope_owner_and_retirement_stay_unknown() {
    let (setup, _parent, peers) = setup().await;
    let captured = collect(&setup.session);
    let context = context(&setup.session);
    let foreign =
        PeerManager::new(crate::Config::generate_default("http://ctrl.test", "default").unwrap());
    assert_eq!(
        captured.original().unwrap().try_identity_at_observed(
            &foreign,
            Instant::now(),
            Some(context)
        ),
        Err(OverlayCreditOutcome::Stale(OverlayCreditStale::Identity))
    );
    let gate = peers.network_epoch_gate();
    let held = gate.lock().await;
    let mut wrong = context;
    wrong.capture_id[0] ^= 1;
    assert_eq!(
        captured
            .original()
            .unwrap()
            .try_identity_at_observed(&peers, Instant::now(), Some(wrong)),
        Err(OverlayCreditOutcome::Contended(
            OverlayCreditLockSite::Epoch
        ))
    );
    assert!(setup.session.epoch_trace.read_peer_snapshot().is_none());
    setup.session.retire();
    assert_eq!(
        captured.original().unwrap().try_identity_at_observed(
            &peers,
            Instant::now(),
            Some(context)
        ),
        Err(OverlayCreditOutcome::Contended(
            OverlayCreditLockSite::Epoch
        ))
    );
    drop(held);
    assert!(setup.session.epoch_trace.read_peer_snapshot().is_none());
    assert!(setup.session.epoch_trace.snapshot().is_none());
    no_kernel_credit(&setup.session);
}

#[tokio::test]
async fn first_capture_metadata_records_actual_epoch_try_without_creating_a_read() {
    let (setup, _parent, peers) = setup().await;
    let plan = setup.session.state.lock().unwrap().flows[0].plan.clone();
    // A diagnostic label in this control, never a constructed KernelRead.
    let context = context(&setup.session);
    let gate = peers.network_epoch_gate();
    let held = gate.lock().await;
    let first = FirstReadPeer::capture(&setup.session, &plan, Some(context));
    assert!(matches!(
        first.original,
        Err(OverlayCreditOutcome::Contended(
            OverlayCreditLockSite::Epoch
        ))
    ));
    let before =
        serde_json::to_value(setup.session.epoch_trace.read_peer_snapshot().unwrap()).unwrap();
    assert_eq!(before["original_input_read_ordinal"], 19);
    assert!(before.get("first_read_ordinal").is_none());
    assert_eq!(before["holder"]["release_completion_observed"], false);
    negative(&before);
    drop(held);
    let after =
        serde_json::to_value(setup.session.epoch_trace.read_peer_snapshot().unwrap()).unwrap();
    assert_eq!(after["holder"]["release_completion_observed"], true);
    assert_eq!(after["original_input_read_ordinal"], 19);
    assert!(setup.session.epoch_trace.snapshot().is_none());
    no_kernel_credit(&setup.session);
}

#[tokio::test]
async fn first_capture_metadata_cached_positive_never_resamples_contended_epoch() {
    let (setup, _parent, peers) = setup().await;
    let first = collect(&setup.session);
    assert!(first.original.is_ok());
    let before = setup.session.gaps.load(Ordering::Acquire);
    let gate = peers.network_epoch_gate();
    let held = gate.lock().await;
    let duplicate = collect(&setup.session);
    assert!(Arc::ptr_eq(&first, &duplicate));
    assert!(duplicate.original.is_ok());
    assert_eq!(setup.session.gaps.load(Ordering::Acquire), before);
    assert!(setup.session.epoch_trace.read_peer_snapshot().is_none());
    drop(held);
    no_kernel_credit(&setup.session);
}

#[tokio::test]
async fn first_capture_metadata_cached_negative_never_retries_or_refills_after_unlock() {
    let (setup, _parent, peers) = setup().await;
    let gate = peers.network_epoch_gate();
    let held = gate.lock().await;
    let first = collect(&setup.session);
    assert!(first.original.is_err());
    let before = setup.session.gaps.load(Ordering::Acquire);
    assert_eq!(before, 1);
    let still_held = collect(&setup.session);
    assert!(Arc::ptr_eq(&first, &still_held));
    assert_eq!(setup.session.gaps.load(Ordering::Acquire), before);
    drop(held);
    let after_unlock = collect(&setup.session);
    assert!(Arc::ptr_eq(&first, &after_unlock));
    assert!(matches!(
        after_unlock.original,
        Err(OverlayCreditOutcome::Contended(
            OverlayCreditLockSite::Epoch
        ))
    ));
    assert_eq!(setup.session.gaps.load(Ordering::Acquire), before);
    no_kernel_credit(&setup.session);
}

#[tokio::test]
async fn first_capture_metadata_wrong_context_and_retirement_cannot_enable_observation() {
    let (setup, _parent, peers) = setup().await;
    let plan = setup.session.state.lock().unwrap().flows[0].plan.clone();
    let mut context = context(&setup.session);
    let gate = peers.network_epoch_gate();
    let held = gate.lock().await;
    context.capture_id[0] ^= 1;
    assert!(FirstReadPeer::capture(&setup.session, &plan, Some(context))
        .original
        .is_err());
    assert!(setup.session.epoch_trace.read_peer_snapshot().is_none());
    context.capture_id[0] ^= 1;
    setup.session.retire();
    assert!(FirstReadPeer::capture(&setup.session, &plan, Some(context))
        .original
        .is_err());
    drop(held);
    assert!(setup.session.epoch_trace.read_peer_snapshot().is_none());
    assert!(setup.session.epoch_trace.snapshot().is_none());
    no_kernel_credit(&setup.session);
}
