use super::*;

#[tokio::test]
async fn actual_scope_weak_active_flag_controls_only_metadata_expectation() {
    let (setup, _parent, peers) = setup().await;
    let prepared = peers
        .prepare_original_kernel_read_view(PEER, TARGET)
        .unwrap();
    let gate = peers.network_epoch_gate();
    let mut epoch = gate.lock().await;
    let phase = peers
        .publish_original_kernel_read_view(&mut epoch, &prepared)
        .unwrap();
    let first = collect(&setup.session);
    assert!(first.is_known());
    no_kernel_credit(&setup.session);
    setup.session.retire();
    assert!(peers
        .prepare_original_kernel_read_view(PEER, TARGET)
        .is_none());
    assert!(peers
        .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
        .is_err());
    // A cached expectation creates no actual read and still needs the original
    // fresh identity/owner/once transaction.
    assert!(first
        .original
        .as_ref()
        .unwrap()
        .try_identity_at(&peers, Instant::now())
        .is_err());
    no_kernel_credit(&setup.session);
    drop(phase);
}

#[tokio::test]
async fn cached_first_refusal_cannot_be_refilled_by_a_later_live_phase() {
    let (setup, _parent, peers) = setup().await;
    let prepared = peers
        .prepare_original_kernel_read_view(PEER, TARGET)
        .unwrap();
    let gate = peers.network_epoch_gate();
    let mut epoch = gate.lock().await;
    let refused = collect(&setup.session);
    assert!(!refused.is_known());
    let phase = peers
        .publish_original_kernel_read_view(&mut epoch, &prepared)
        .unwrap();
    let cached = collect(&setup.session);
    assert!(Arc::ptr_eq(&refused, &cached));
    assert!(!cached.is_known());
    let plan = setup.session.state.lock().unwrap().flows[0].plan.clone();
    let fresh = FirstReadPeer::capture(&setup.session, &plan, None);
    assert!(fresh.is_known());
    no_kernel_credit(&setup.session);
    drop(phase);
}
