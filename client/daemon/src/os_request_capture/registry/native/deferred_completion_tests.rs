//! Actual descriptor and real input mutex, negative metadata only.
//! No KernelRead, Full, SystemTun or current-owner permission is fabricated.
use super::*;
use crate::os_request_capture::plan::RegistrationPlan;
use serde_json::json;

async fn scope(
    protocol: &str,
) -> (
    crate::os_request_capture::control::CaptureSetup,
    std::os::unix::net::UnixStream,
) {
    let (setup, parent) = super::super::full::tests::descriptor_scope().await;
    let document = json!({"schema_version":1,"capture_id":"11".repeat(16),
        "producer_scope":"33".repeat(16),"flows":[{
            "protocol":protocol,"kind":"request","peer_id":"native-completion-peer",
            "run_nonce":"44".repeat(16),"round_nonce":"55".repeat(16),
            "bind_ip":"10.21.1.2","bind_port":32123,"target_ip":"10.21.1.3","target_port":43210,
            "payload_bytes":128,"request_nonces":(1..=8).map(|i|format!("{i:032x}")).collect::<Vec<_>>()}]});
    setup
        .session
        .register(RegistrationPlan::decode(&serde_json::to_vec(&document).unwrap()).unwrap())
        .unwrap();
    (setup, parent)
}
fn install_actual_input_mutex_probe(
    scope: &Arc<CaptureSession>,
) -> Arc<std::sync::atomic::AtomicBool> {
    let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = released.clone();
    let scope = Arc::downgrade(scope);
    NATIVE_CAPTURE_PROBE.with(|slot| {
        assert!(slot.borrow().is_none());
        *slot.borrow_mut() = Some(Box::new(move || {
            observed.store(
                scope
                    .upgrade()
                    .is_some_and(|scope| scope.state.try_lock().is_ok()),
                Ordering::SeqCst,
            );
        }));
    });
    released
}
fn assert_original_negative(scope: &CaptureSession) {
    let value = serde_json::to_value(scope.snapshot().unwrap()).unwrap();
    assert_eq!(value["requests"].as_array().unwrap().len(), 8);
    for r in value["requests"].as_array().unwrap() {
        assert_eq!(
            r["native_credit"]["outcome"],
            "Unknown(OriginalPublication)"
        );
        assert_eq!(r["native_credit"]["owner_check"], "not_entered");
        assert_eq!(r["native_credit"]["once_committed"], false);
        assert!(r["native_credit"]["commit_monotonic_ns"].is_null());
    }
    assert_eq!(value["historical_full_packets"], json!([]));
    assert_eq!(value["system_tun_full_writes"], json!([]));
    assert_eq!(value["physical_send_verified"], false);
}
#[tokio::test]
async fn native_completion_metadata_actor_releases_actual_input_mutex_before_capture() {
    let (setup, _parent) = scope("udp").await;
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::ObservationDropped);
    let released = install_actual_input_mutex_probe(&setup.session);
    setup.session.complete_pending_fulls();
    assert_original_negative(&setup.session);
    assert!(
        released.load(Ordering::SeqCst),
        "native capture must not hold the actual input registry mutex"
    );
}
#[tokio::test]
async fn native_completion_terminal_handoff_releases_actual_input_mutex_before_capture() {
    let (setup, _parent) = scope("tcp").await;
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::ObservationDropped);
    let released = install_actual_input_mutex_probe(&setup.session);
    setup
        .session
        .wait_original_outcomes(
            [0x33; 16],
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
    assert_original_negative(&setup.session);
    assert!(
        released.load(Ordering::SeqCst),
        "native completion must run after the original metadata reader unlocks"
    );
}

#[tokio::test]
async fn native_completion_one_inflight_slot_resumes_only_missing_metadata() {
    let (setup, _parent) = scope("udp").await;
    let state = setup.session.state.try_lock().unwrap();
    let slot = state.flows[0].requests[0].native_credit.shared();
    drop(state);
    let mut first = completion::NativeCompletionBatch::new();
    let mut concurrent = completion::NativeCompletionBatch::new();
    setup.session.prepare_original_frames(0, &[0], &mut first);
    setup
        .session
        .prepare_original_frames(0, &[0], &mut concurrent);
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = count.clone();
    NATIVE_CAPTURE_PROBE.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            observed.fetch_add(1, Ordering::SeqCst);
        }))
    });
    concurrent.finish(&setup.session);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    first.finish(&setup.session);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(slot.is_none());
    assert!(setup.session.metadata_completion_pending());
    setup.session.complete_pending_fulls();
    assert!(!setup.session.metadata_completion_pending());
    assert!(slot.is_none());
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::ObservationDropped);
    setup.session.complete_pending_fulls();
    assert_original_negative(&setup.session);
    let first = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    setup.session.pending_full.request_window();
    setup.session.complete_pending_fulls();
    assert_eq!(
        serde_json::to_value(setup.session.snapshot().unwrap()).unwrap()["requests"],
        first["requests"]
    );
}

#[tokio::test]
async fn native_completion_dropped_preparation_is_not_a_terminal_owner_retry() {
    let (setup, _parent) = scope("udp").await;
    let state = setup.session.state.try_lock().unwrap();
    let slot = state.flows[0].requests[0].native_credit.shared();
    drop(state);
    let mut prepared = completion::NativeCompletionBatch::new();
    setup
        .session
        .prepare_original_frames(0, &[0], &mut prepared);
    drop(prepared);
    assert!(slot.is_none());
    assert!(setup.session.metadata_completion_pending());
    setup.session.complete_pending_fulls();
    assert!(!setup.session.metadata_completion_pending());
    assert!(slot.is_none());
    assert!(setup.session.full_complete.load(Ordering::Acquire));
    assert_eq!(
        serde_json::to_value(setup.session.snapshot().unwrap()).unwrap()["physical_send_verified"],
        false
    );
}

#[tokio::test]
async fn native_completion_frozen_sources_keep_actual_invalidation_but_no_scope_owner() {
    let (setup, parent) = scope("udp").await;
    let state = setup.session.state.try_lock().unwrap();
    let invalid = state.flows[0].invalid.clone();
    drop(state);
    let mut prepared = completion::NativeCompletionBatch::new();
    setup
        .session
        .prepare_original_frames(0, &[0], &mut prepared);
    invalid.store(true, Ordering::Release);
    prepared.finish(&setup.session);
    let value = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    assert_eq!(
        value["requests"][0]["native_credit"]["outcome"],
        "Stale(Identity)"
    );
    assert_eq!(
        value["requests"][0]["native_credit"]["owner_check"],
        "not_entered"
    );
    assert_eq!(
        value["requests"][0]["native_credit"]["once_committed"],
        false
    );
    assert_eq!(value["requests"][0]["flow_invalid"], true);
    drop(parent);
    drop(setup);

    let (setup, parent) = scope("udp").await;
    let weak = Arc::downgrade(&setup.session);
    let state = setup.session.state.try_lock().unwrap();
    drop(state);
    let mut prepared = completion::NativeCompletionBatch::new();
    setup
        .session
        .prepare_original_frames(0, &[0], &mut prepared);
    drop(parent);
    drop(setup);
    assert!(
        weak.upgrade().is_none(),
        "pending native metadata must not keep scope, descriptor or daemon owners alive"
    );
    drop(prepared);
}

#[tokio::test]
async fn native_completion_new_terminal_result_cannot_refill_captured_snapshot() {
    let (setup, _parent) = scope("udp").await;
    let state = setup.session.state.try_lock().unwrap();
    let frozen = setup.session.capture_snapshot_in(&state).unwrap();
    drop(state);
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::ObservationDropped);
    setup.session.complete_pending_fulls();
    assert_original_negative(&setup.session);
    let first = serde_json::to_value(frozen.finish()).unwrap();
    assert!(first["requests"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["native_credit"].is_null()));
    assert_eq!(first["daemon_registration_verified"], false);
    assert_eq!(first["physical_send_verified"], false);
    assert_eq!(first["canonical_current_owner_verified"], false);
}

#[tokio::test]
async fn native_completion_busy_executor_keeps_input_unlocked_and_wakes_only_on_release() {
    let (setup, _parent) = scope("udp").await;
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::ObservationDropped);
    setup.session.full_completion_ready().await;
    let held = setup
        .session
        .native_completion
        .hold_for_test(&setup.session.pending_full);
    let released = install_actual_input_mutex_probe(&setup.session);
    setup.session.complete_pending_fulls();
    assert!(setup.session.metadata_completion_pending());
    assert!(!released.load(Ordering::SeqCst));
    assert!(setup.session.state.try_lock().is_ok());
    assert!(
        serde_json::to_value(setup.session.snapshot().unwrap()).unwrap()["requests"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["native_credit"].is_null())
    );
    let mut ready = Box::pin(setup.session.full_completion_ready());
    assert!(
        matches!(
            futures_util::poll!(ready.as_mut()),
            std::task::Poll::Pending
        ),
        "busy completion must not spin the existing metadata actor"
    );
    drop(held);
    ready.await;
    setup.session.complete_pending_fulls();
    assert!(released.load(Ordering::SeqCst));
    assert_original_negative(&setup.session);
}

#[tokio::test]
async fn native_completion_executor_poison_keeps_first_negative_and_once_false() {
    let (setup, _parent) = scope("udp").await;
    {
        let mut state = setup.session.state.try_lock().unwrap();
        state.flows[0].requests[0]
            .native_credit
            .get_or_insert_with(|| {
                NativeFrameOutcome::failure(Outcome::Unknown(Unknown::OriginalSource))
            });
    }
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::ObservationDropped);
    let poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = setup
            .session
            .native_completion
            .hold_for_test(&setup.session.pending_full);
        panic!("intentional native metadata executor poison control");
    }));
    assert!(poison.is_err());
    assert!(setup.session.state.try_lock().is_ok());
    setup.session.complete_pending_fulls();
    let first = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    for (i, row) in first["requests"].as_array().unwrap().iter().enumerate() {
        assert_eq!(
            row["native_credit"]["outcome"],
            if i == 0 {
                "Unknown(OriginalSource)"
            } else {
                "Unknown(OriginalPublication)"
            }
        );
        assert_eq!(row["native_credit"]["owner_check"], "not_entered");
        assert_eq!(row["native_credit"]["once_committed"], false);
        assert!(row["native_credit"]["commit_monotonic_ns"].is_null());
    }
    setup.session.pending_full.request_window();
    setup.session.complete_pending_fulls();
    assert_eq!(
        serde_json::to_value(setup.session.snapshot().unwrap()).unwrap()["requests"],
        first["requests"]
    );
    assert_eq!(
        setup.session.full_loss.snapshot(),
        Some(FullRetentionLossReason::ObservationDropped)
    );
    assert_eq!(first["physical_send_verified"], false);
    assert_eq!(first["historical_full_packets"], json!([]));
    assert_eq!(first["system_tun_full_writes"], json!([]));
}

#[tokio::test]
async fn native_completion_preparation_never_owns_the_actual_input_mutex() {
    let (setup, _parent) = scope("udp").await;
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::ObservationDropped);
    let scope = Arc::downgrade(&setup.session);
    let observed = Arc::new(AtomicBool::new(false));
    let probe = observed.clone();
    frozen_sources::PREPARATION_PROBE.with(|slot| {
        assert!(slot
            .borrow_mut()
            .replace(Box::new(move || {
                let scope = scope.upgrade().unwrap();
                probe.store(
                    scope.state.actual_mutex_is_available_for_test(),
                    Ordering::SeqCst,
                );
            }))
            .is_none());
    });
    setup.session.complete_pending_fulls();
    assert_original_negative(&setup.session);
    assert!(observed.load(Ordering::SeqCst), "native metadata preparation must release the actual input mutex before traversing original sources");
}

#[tokio::test]
async fn native_preparation_changed_input_version_defers_before_native_capture() {
    let (setup, _parent) = scope("udp").await;
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::ObservationDropped);
    let native_called = Arc::new(AtomicBool::new(false));
    let called = native_called.clone();
    NATIVE_CAPTURE_PROBE.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            called.store(true, Ordering::SeqCst);
        }))
    });
    let original = Arc::downgrade(&setup.session);
    frozen_sources::PREPARATION_PROBE.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            let scope = original.upgrade().unwrap();
            let _actual = scope.state.try_lock().unwrap();
        }))
    });
    setup.session.complete_pending_fulls();
    assert!(!native_called.load(Ordering::SeqCst));
    assert!(setup.session.metadata_completion_pending());
    assert!(setup.session.state.try_lock().unwrap().flows[0]
        .requests
        .iter()
        .all(|r| r.native_credit.is_none()));
    setup.session.complete_pending_fulls();
    assert!(native_called.load(Ordering::SeqCst));
    assert_original_negative(&setup.session);
}
