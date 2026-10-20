//! Exercise the real registration writer and the exact original input mutex.
use super::*;

thread_local! {
    static COMPARING: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const {
        std::cell::RefCell::new(None)
    };
    static CHECKED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const {
        std::cell::RefCell::new(None)
    };
}
pub(in crate::os_request_capture::registry) fn comparing() {
    let probe = COMPARING.with(|slot| slot.borrow_mut().take());
    if let Some(probe) = probe {
        probe();
    }
}
pub(in crate::os_request_capture::registry) fn checked() {
    let probe = CHECKED.with(|slot| slot.borrow_mut().take());
    if let Some(probe) = probe {
        probe();
    }
}
fn after_checked(probe: impl FnOnce() + 'static) {
    CHECKED.with(|slot| assert!(slot.borrow_mut().replace(Box::new(probe)).is_none()));
}
fn distinct(n: u8) -> RegistrationPlan {
    let mut value = plan();
    value.producer_scope = [n; 16];
    value.flows[0].flow.src_port += u16::from(n);
    value.flows[0].requests[0].request_nonce = [n; 16];
    value
}
fn observe_comparison(scope: &Arc<CaptureSession>) -> Arc<AtomicBool> {
    let scope = scope.clone();
    let available = Arc::new(AtomicBool::new(false));
    let observed = available.clone();
    COMPARING.with(|slot| {
        assert!(slot
            .borrow_mut()
            .replace(Box::new(move || {
                // The same single try used by original read observation. This is
                // only a contention control, never a manufactured KernelRead.
                observed.store(
                    scope.state.try_original_read_lock(13).is_ok(),
                    Ordering::Release,
                );
            }))
            .is_none());
    });
    available
}
fn assert_two_label_sets(scope: &CaptureSession) {
    let value = snapshot(scope);
    assert_eq!(value["registration_revision"], 2);
    assert_eq!(value["registration_sets"], 2);
    assert_eq!(value["requests"].as_array().unwrap().len(), 2);
    assert!(value["requests"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| { row["native_credit"].is_null() && row["read_events"] == 0 }));
    assert_eq!(value["historical_full_packets"], json!([]));
    assert_eq!(value["system_tun_full_writes"], json!([]));
}

#[tokio::test]
async fn sync_conflict_comparison_releases_actual_original_read_mutex() {
    let (setup, _parent) = full::tests::descriptor_scope().await;
    setup.session.register(plan()).unwrap();
    let available = observe_comparison(&setup.session);
    setup.session.register(distinct(0x68)).unwrap();
    assert_two_label_sets(&setup.session);
    assert!(
        available.load(Ordering::Acquire),
        "conflict comparison owns original read mutex"
    );
    assert!(setup
        .session
        .state
        .original_read_refusal_snapshot()
        .is_none());
}

#[tokio::test]
async fn control_conflict_comparison_releases_actual_original_read_mutex() {
    let (setup, _parent) = full::tests::descriptor_scope().await;
    setup.session.register(plan()).unwrap();
    let available = observe_comparison(&setup.session);
    setup
        .session
        .register_control(
            distinct(0x68),
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
    assert_two_label_sets(&setup.session);
    assert!(
        available.load(Ordering::Acquire),
        "conflict comparison owns original read mutex"
    );
    assert!(setup
        .session
        .state
        .original_read_refusal_snapshot()
        .is_none());
}

#[tokio::test]
async fn intervening_append_cannot_hide_request_conflict_in_unchecked_suffix() {
    let (setup, _parent) = full::tests::descriptor_scope().await;
    setup.session.register(plan()).unwrap();
    let scope = setup.session.clone();
    after_checked(move || {
        scope.register(distinct(0x68)).unwrap();
    });
    let mut incoming = distinct(0x69);
    incoming.flows[0].requests[0].request_nonce = [0x68; 16];
    assert!(matches!(
        setup.session.register(incoming),
        Err(CaptureFailure::RegistrationConflict)
    ));
    assert_two_label_sets(&setup.session);
}

#[tokio::test]
async fn intervening_distinct_append_retains_both_original_plans_and_next_revision() {
    let (setup, _parent) = full::tests::descriptor_scope().await;
    setup.session.register(plan()).unwrap();
    let original = setup.session.state.lock().unwrap().flows[0].plan.clone();
    let scope = setup.session.clone();
    after_checked(move || {
        scope.register(distinct(0x68)).unwrap();
    });
    let result = setup.session.register(distinct(0x69)).unwrap();
    assert_eq!(result.registration_revision, 3);
    assert_eq!(result.total_requests, 3);
    let state = setup.session.state.lock().unwrap();
    assert!(Arc::ptr_eq(&original, &state.flows[0].plan));
    assert_eq!(state.flows.len(), 3);
    assert_eq!(state.native_flows.len(), 3);
    drop(state);
    assert!(snapshot(&setup.session)["requests"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["native_credit"].is_null()));
}

#[tokio::test]
async fn mismatched_source_prefix_rechecks_authoritative_conflict() {
    let (setup, _parent) = full::tests::descriptor_scope().await;
    setup.session.register(plan()).unwrap();
    // Inject a stale shared handle only in this control. The actual writer
    // must reject using its canonical plan, even if a prepared prefix differs.
    let scope = setup.session.clone();
    after_checked(move || {
        scope.state.lock().unwrap().flows[0].plan = Arc::new(distinct(0x68).flows.remove(0));
    });
    assert!(matches!(
        setup.session.register(distinct(0x68)),
        Err(CaptureFailure::RegistrationConflict)
    ));
    let state = setup.session.state.lock().unwrap();
    assert_eq!(state.revision, 1);
    assert_eq!(state.flows.len(), 1);
}
