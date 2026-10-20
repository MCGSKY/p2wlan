//! Real descriptor/registration guards, with no KernelRead or native IO credit.
use super::super::selection::{begin_scans, finish_scans};
use super::*;

fn append_other(scope: &CaptureSession, tag: u8) {
    let mut plan = registered("udp", "response");
    plan.flow.src_port = 50000 + u16::from(tag);
    for key in &mut plan.requests {
        key.run[0] = tag;
        key.run[1] = tag ^ 0xff;
    }
    scope
        .register(super::super::super::super::plan::RegistrationPlan {
            capture_id: scope.capture_id,
            producer_scope: [tag; 16],
            flows: vec![plan],
        })
        .unwrap();
}

#[tokio::test]
async fn write_window_same_registration_at_original_capacity_needs_no_final_producer_scan() {
    let (setup, _parent) = digest_scope().await;
    for tag in (1..=125).filter(|tag| *tag != 0x22) {
        append_other(&setup.session, tag);
    }
    let end = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    let (prepared, prefix) = setup
        .session
        .original_window_plan_with_prefix([0x22; 16], end)
        .await
        .unwrap();
    {
        let state = setup.session.state.lock().unwrap();
        assert_eq!(state.requests, MAX_REQUESTS);
        assert_eq!(state.flows.len(), 125);
        begin_scans();
        assert_eq!(prefix.current_index(&prepared, &state), Ok(0));
        assert_eq!(finish_scans(), 0);
    }
    digest_no_credit(&setup.session);
}

#[tokio::test]
async fn write_window_same_prefix_selects_under_the_real_existing_metadata_guard() {
    let (setup, _parent) = digest_scope().await;
    let end = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    let (prepared, prefix) = setup
        .session
        .original_window_plan_with_prefix([0x22; 16], end)
        .await
        .unwrap();
    {
        let state = setup.session.state.try_lock().unwrap();
        begin_scans();
        assert_eq!(prefix.current_index(&prepared, &state), Ok(0));
        assert_eq!(finish_scans(), 0);
        assert!(matches!(
            setup.session.state.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
    }
    digest_no_credit(&setup.session);
}

#[tokio::test]
async fn write_window_intervening_real_registration_keeps_original_unique_scan_and_plan_fence() {
    let (setup, _parent) = digest_scope().await;
    let end = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    let (prepared, prefix) = setup
        .session
        .original_window_plan_with_prefix([0x22; 16], end)
        .await
        .unwrap();
    append_other(&setup.session, 1);
    {
        let state = setup.session.state.lock().unwrap();
        begin_scans();
        assert_eq!(prefix.current_index(&prepared, &state), Ok(0));
        assert_eq!(finish_scans(), 2);
        assert!(Arc::ptr_eq(&prepared.plan, &state.flows[0].plan));
        assert_eq!(state.revision, 2);
    }
    digest_no_credit(&setup.session);
}

#[tokio::test]
async fn write_window_same_prefix_rejects_wrong_producer_and_equal_bytes_replacement() {
    let (setup, _parent) = digest_scope().await;
    let end = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    let (prepared, prefix) = setup
        .session
        .original_window_plan_with_prefix([0x22; 16], end)
        .await
        .unwrap();
    {
        let mut state = setup.session.state.lock().unwrap();
        state.flows[0].producer_scope = [0x23; 16];
        assert_eq!(
            prefix.current_index(&prepared, &state),
            Err(CaptureFailure::InvalidPlan)
        );
        state.flows[0].producer_scope = [0x22; 16];
        state.flows[0].plan = Arc::new(registered("udp", "response"));
        assert_eq!(
            prefix.current_index(&prepared, &state),
            Err(CaptureFailure::InvalidPlan)
        );
    }
    digest_no_credit(&setup.session);
}

#[tokio::test]
async fn write_window_prefix_preserves_original_shape_checks_and_exhausted_revision_read() {
    let (setup, _parent) = digest_scope().await;
    let end = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    let (prepared, prefix) = setup
        .session
        .original_window_plan_with_prefix([0x22; 16], end)
        .await
        .unwrap();
    {
        let mut state = setup.session.state.lock().unwrap();
        state.revision = u64::MAX;
        begin_scans();
        assert_eq!(prefix.current_index(&prepared, &state), Ok(0));
        assert_eq!(finish_scans(), 1);
        state.flows[0].requests.pop();
        assert_eq!(
            prefix.current_index(&prepared, &state),
            Err(CaptureFailure::InvalidPlan)
        );
    }
    digest_no_credit(&setup.session);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn write_window_actual_control_entry_uses_real_boot_clock_and_keeps_metadata_only() {
    let (setup, _parent) = digest_scope().await;
    let now = monotonic_ns().unwrap();
    let clock = serde_json::to_value(setup.session.clock_scope.as_ref().unwrap()).unwrap();
    let mut wire = labels();
    wire.producer_scope = hex::encode([0x22; 16]);
    wire.request_nonce = hex::encode(registered("udp", "response").requests[0].request_nonce);
    wire.boot_id = clock["boot_id"].as_str().unwrap().to_owned();
    wire.frame_sha256 = UDP_REQUESTS[0].to_owned();
    wire.original_started_ns = now;
    wire.original_sent_ns = now;
    wire.original_deadline_ns = now.checked_add(1_000_000_000).unwrap();
    wire.complete_returned_ns = now;
    begin_scans();
    setup
        .session
        .observe_original_write_window(wire)
        .await
        .unwrap();
    assert_eq!(finish_scans(), 0);
    {
        let state = setup.session.state.lock().unwrap();
        assert!(state.flows[0].requests[0].original_write_window.is_some());
        assert_eq!(state.flows[0].requests.len(), 8);
    }
    digest_no_credit(&setup.session);
}
