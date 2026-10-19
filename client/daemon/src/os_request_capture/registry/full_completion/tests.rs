//! Scheduler/descriptor negatives; no KernelRead, Full or owner is minted.
use super::super::full::tests::descriptor_scope;
use super::*;
use serde_json::json;

fn assert_no_credit(scope: &CaptureSession) {
    let value = serde_json::to_value(scope.snapshot().unwrap()).unwrap();
    assert_eq!(value["historical_full_packets"], json!([]));
    assert_eq!(value["system_tun_full_writes"], json!([]));
    assert_eq!(value["physical_send_verified"], false);
    assert_eq!(value["canonical_current_owner_verified"], false);
}

fn register_udp_requests(scope: &Arc<CaptureSession>) {
    let plan = json!({"schema_version":1,"capture_id":"11".repeat(16),
        "producer_scope":"33".repeat(16),"flows":[{
            "protocol":"udp","kind":"request","peer_id":"completion-metadata-peer",
            "run_nonce":"44".repeat(16),"round_nonce":"55".repeat(16),
            "bind_ip":"10.21.1.2","bind_port":32123,"target_ip":"10.21.1.3","target_port":43210,
            "payload_bytes":128,"request_nonces":(1..=8).map(|i|format!("{i:032x}")).collect::<Vec<_>>()}]});
    let plan = crate::os_request_capture::plan::RegistrationPlan::decode(
        &serde_json::to_vec(&plan).unwrap(),
    )
    .unwrap();
    scope.register(plan).unwrap();
}

fn assert_unentered_unknown(value: &serde_json::Value) {
    let requests = value["requests"].as_array().unwrap();
    assert_eq!(requests.len(), 8);
    for row in requests {
        let credit = &row["native_credit"];
        assert_eq!(credit["outcome"], "Unknown(OriginalPublication)");
        assert_eq!(credit["owner_check"], "not_entered");
        assert_eq!(credit["once_committed"], false);
        assert!(credit["commit_monotonic_ns"].is_null());
        assert_eq!(credit["original_kernel_read_ordinals"], json!([]));
        assert_eq!(credit["original_system_write_ordinals"], json!([]));
        assert_eq!(credit["native_os_write_verified"], false);
        assert_eq!(credit["physical_send_verified"], false);
        assert_eq!(credit["canonical_current_owner_verified"], false);
    }
}

#[tokio::test]
async fn metadata_completion_window_notification_is_not_full_or_native_eligibility() {
    let (setup, _parent) = descriptor_scope().await;
    register_udp_requests(&setup.session);
    setup.session.pending_full.request_window();
    assert!(setup.session.metadata_completion_pending());
    assert!(!setup.session.full_completion_pending());
    setup.session.complete_pending_fulls();
    assert!(!setup.session.metadata_completion_pending());
    let state = setup.session.state.try_lock().unwrap();
    assert!(state.flows[0]
        .requests
        .iter()
        .all(|request| request.native_credit.is_none()));
    drop(state);
    assert_no_credit(&setup.session);
}

#[tokio::test]
async fn metadata_completion_window_keeps_work_until_actual_registry_unlock() {
    let (setup, _parent) = descriptor_scope().await;
    register_udp_requests(&setup.session);
    let held = setup.session.state.try_lock().unwrap();
    setup.session.pending_full.request_window();
    setup.session.complete_pending_fulls();
    assert!(setup.session.metadata_completion_pending());
    assert!(!setup.session.full_completion_pending());
    assert!(setup.session.full_complete.load(Ordering::Acquire));
    drop(held);
    setup.session.full_metadata_released().await;
    setup.session.complete_pending_fulls();
    assert!(!setup.session.metadata_completion_pending());
    assert_no_credit(&setup.session);
}

#[tokio::test]
async fn metadata_completion_each_original_loss_closes_udp_rows_without_full() {
    for variant in 0..3 {
        let (setup, _parent) = descriptor_scope().await;
        let scope = &setup.session;
        register_udp_requests(scope);
        match variant {
            0 => scope.original_observation_lost(&scope.read_complete),
            1 => scope.original_full_retention_lost(FullRetentionLossReason::ObservationDropped),
            _ => scope.original_observation_lost(&scope.inbound_complete),
        }
        assert!(scope.metadata_completion_pending());
        assert!(!scope.full_completion_pending());
        scope.complete_pending_fulls();
        assert!(!scope.metadata_completion_pending());
        assert_unentered_unknown(&serde_json::to_value(scope.snapshot().unwrap()).unwrap());
        assert_no_credit(scope);
        assert_eq!(scope.gaps.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn metadata_completion_actor_preserves_partial_command_through_loss_and_unlock() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (setup, parent) = descriptor_scope().await;
    register_udp_requests(&setup.session);
    parent.set_nonblocking(true).unwrap();
    let mut parent = BufReader::new(tokio::net::UnixStream::from_std(parent).unwrap());
    let session = setup.session.clone();
    let actor = tokio::spawn(setup.channel.run());
    parent.get_mut().write_all(b"{\"op\":\"snap").await.unwrap();
    tokio::task::yield_now().await;
    let held = session.state.try_lock().unwrap();
    session.original_full_retention_lost(FullRetentionLossReason::ObservationDropped);
    tokio::task::yield_now().await;
    assert!(session.metadata_completion_pending());
    assert!(!session.full_completion_pending());
    drop(held);
    tokio::task::yield_now().await;
    parent.get_mut().write_all(b"shot\"}\n").await.unwrap();
    let mut reply = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        parent.read_line(&mut reply),
    )
    .await
    .unwrap()
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    assert_unentered_unknown(&value);
    assert_eq!(value["retained_original_reads"], 0);
    assert!(!session.metadata_completion_pending());
    parent
        .get_mut()
        .write_all(b"{\"op\":\"close\"}\n")
        .await
        .unwrap();
    actor.await.unwrap().unwrap();
    assert!(!session.is_live(std::time::Instant::now()));
    assert_no_credit(&session);
}

#[tokio::test]
async fn metadata_completion_retirement_and_later_wakeups_cannot_rearm_credit() {
    let (setup, _parent) = descriptor_scope().await;
    register_udp_requests(&setup.session);
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::ObservationDropped);
    setup.session.retire();
    setup.session.complete_pending_fulls();
    let held = setup.session.state.try_lock().unwrap();
    assert!(held.flows[0]
        .requests
        .iter()
        .all(|request| request.native_credit.is_none()));
    drop(held);
    assert_no_credit(&setup.session);

    let (setup, _parent) = descriptor_scope().await;
    register_udp_requests(&setup.session);
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::ObservationDropped);
    setup.session.complete_pending_fulls();
    let first = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    assert_unentered_unknown(&first);
    setup.session.pending_full.request_window();
    setup.session.pending_full.request();
    setup.session.complete_pending_fulls();
    let after = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    assert_eq!(after["requests"], first["requests"]);
    assert!(!setup.session.full_complete.load(Ordering::Acquire));
    assert!(!setup.session.metadata_completion_pending());
    assert_eq!(setup.session.gaps.load(Ordering::Relaxed), 1);
    assert_no_credit(&setup.session);
}

#[tokio::test]
async fn full_metadata_notification_without_original_facts_grants_no_credit() {
    let (setup, _parent) = descriptor_scope().await;
    setup.session.pending_full.request();
    setup.session.complete_pending_fulls();
    assert!(!setup.session.full_completion_pending());
    assert_no_credit(&setup.session);
}

#[tokio::test]
async fn full_metadata_contention_keeps_pending_until_original_lock_release() {
    let (setup, _parent) = descriptor_scope().await;
    let held = setup.session.state.try_lock().unwrap();
    setup.session.pending_full.request();
    setup.session.complete_pending_fulls();
    assert!(setup.session.full_completion_pending());
    assert!(setup.session.full_complete.load(Ordering::Acquire));
    drop(held);
    setup.session.full_metadata_released().await;
    setup.session.complete_pending_fulls();
    assert!(!setup.session.full_completion_pending());
    assert_no_credit(&setup.session);
}

#[tokio::test]
async fn full_metadata_retirement_cannot_resume_or_restore_a_lost_scope() {
    let (setup, _parent) = descriptor_scope().await;
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::ObservationDropped);
    setup.session.pending_full.request();
    setup.session.retire();
    setup.session.complete_pending_fulls();
    assert_eq!(
        setup.session.full_loss.snapshot(),
        Some(FullRetentionLossReason::ObservationDropped)
    );
    assert!(!setup.session.full_complete.load(Ordering::Acquire));
    assert_no_credit(&setup.session);
}

#[tokio::test]
async fn full_metadata_poison_is_terminal_and_never_waits_or_rearms() {
    let (setup, _parent) = descriptor_scope().await;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = setup.session.state.try_lock().unwrap();
        panic!("intentional full metadata poison control");
    }));
    assert!(result.is_err());
    setup.session.pending_full.request();
    setup.session.complete_pending_fulls();
    assert!(!setup.session.full_completion_pending());
    assert!(!setup.session.full_complete.load(Ordering::Acquire));
    assert_eq!(
        setup.session.full_loss.snapshot(),
        Some(FullRetentionLossReason::HistoryContended)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn full_metadata_actor_keeps_partial_command_and_closes_without_extra_task() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (setup, parent) = descriptor_scope().await;
    parent.set_nonblocking(true).unwrap();
    let mut parent = BufReader::new(tokio::net::UnixStream::from_std(parent).unwrap());
    let session = setup.session.clone();
    let actor = tokio::spawn(setup.channel.run());
    parent.get_mut().write_all(b"{\"op\":\"snap").await.unwrap();
    tokio::task::yield_now().await;
    let held = session.state.try_lock().unwrap();
    session.pending_full.request();
    tokio::task::yield_now().await;
    assert!(session.full_completion_pending());
    drop(held);
    tokio::task::yield_now().await;
    parent.get_mut().write_all(b"shot\"}\n").await.unwrap();
    let mut reply = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        parent.read_line(&mut reply),
    )
    .await
    .unwrap()
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(value["physical_send_verified"], false);
    assert_eq!(value["retained_original_reads"], 0);
    assert!(!session.full_completion_pending());
    parent
        .get_mut()
        .write_all(b"{\"op\":\"close\"}\n")
        .await
        .unwrap();
    actor.await.unwrap().unwrap();
    assert!(!session.is_live(std::time::Instant::now()));
    assert_no_credit(&session);
}
