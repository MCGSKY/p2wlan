//! Descriptor/scheduler and negative metadata only. No KernelRead, Full,
//! SystemTun write, current-owner permit or positive credit is constructed.
use super::*;
use crate::os_request_capture::plan::RegistrationPlan;
use serde_json::json;
use std::time::Duration;

const PRODUCER: [u8; 16] = [0x33; 16];

async fn scope() -> (
    crate::os_request_capture::control::CaptureSetup,
    std::os::unix::net::UnixStream,
) {
    let (setup, parent) = super::super::full::tests::descriptor_scope().await;
    let document = json!({"schema_version":1,"capture_id":"11".repeat(16),
        "producer_scope":"33".repeat(16),"flows":[{
            "protocol":"tcp","kind":"request","peer_id":"terminal-metadata-peer",
            "run_nonce":"44".repeat(16),"round_nonce":"55".repeat(16),
            "bind_ip":"10.21.1.2","bind_port":32123,"target_ip":"10.21.1.3","target_port":43210,
            "payload_bytes":128,"request_nonces":(1..=8).map(|i|format!("{i:032x}")).collect::<Vec<_>>()}]});
    setup
        .session
        .register(RegistrationPlan::decode(&serde_json::to_vec(&document).unwrap()).unwrap())
        .unwrap();
    (setup, parent)
}

fn refuse_all(session: &Arc<CaptureSession>) {
    let mut state = session.state.lock().unwrap();
    for request in &mut state.flows[0].requests {
        request.native_credit.get_or_insert_with(|| {
            NativeFrameOutcome::failure(Outcome::Unknown(Unknown::OriginalSource))
        });
    }
    session.record_native_terminal_progress();
}

fn no_credit(session: &CaptureSession) {
    let value = serde_json::to_value(session.snapshot().unwrap()).unwrap();
    assert_eq!(value["historical_full_packets"], json!([]));
    assert_eq!(value["system_tun_full_writes"], json!([]));
    assert_eq!(value["physical_send_verified"], false);
    assert_eq!(value["canonical_current_owner_verified"], false);
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_handoff_waits_for_first_negative_rows_and_yields_without_credit() {
    let (setup, _parent) = scope().await;
    let session = setup.session.clone();
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    let child = tokio::spawn(async move { session.wait_original_outcomes(PRODUCER, end).await });
    tokio::task::yield_now().await;
    assert!(!child.is_finished());
    refuse_all(&setup.session);
    let receipt = tokio::time::timeout_at(end, child)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let value = serde_json::to_value(receipt).unwrap();
    assert_eq!(value["completed_requests"], 8);
    for key in [
        "physical_send_verified",
        "native_os_write_verified",
        "canonical_current_owner_verified",
    ] {
        assert_eq!(value[key], false);
    }
    no_credit(&setup.session);
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_handoff_progress_labels_cannot_refill_original_end_or_make_rows() {
    let (setup, _parent) = scope().await;
    setup.session.record_native_terminal_progress();
    let end = tokio::time::Instant::now() + Duration::from_millis(20);
    assert!(matches!(
        setup.session.wait_original_outcomes(PRODUCER, end).await,
        Err(CaptureFailure::ControlNotReady)
    ));
    refuse_all(&setup.session);
    assert!(matches!(
        setup.session.wait_original_outcomes(PRODUCER, end).await,
        Err(CaptureFailure::ControlNotReady)
    ));
    no_credit(&setup.session);
}

#[tokio::test]
async fn terminal_handoff_keeps_recorded_failure_and_once_false_across_later_metadata() {
    let (setup, _parent) = scope().await;
    refuse_all(&setup.session);
    let before = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    setup
        .session
        .wait_original_outcomes(PRODUCER, end)
        .await
        .unwrap();
    {
        let mut state = setup.session.state.lock().unwrap();
        setup
            .session
            .try_complete_original_frames(&mut state, 0, &[0, 1, 2, 3, 4, 5, 6, 7]);
    }
    setup
        .session
        .wait_original_outcomes(PRODUCER, end)
        .await
        .unwrap();
    let after = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    assert_eq!(before["requests"], after["requests"]);
    for row in after["requests"].as_array().unwrap() {
        assert_eq!(row["native_credit"]["status"], "unknown");
        assert_eq!(row["native_credit"]["once_committed"], false);
    }
    no_credit(&setup.session);
}

#[tokio::test]
async fn terminal_handoff_wrong_scope_capacity_and_retirement_never_grant_receipt() {
    let (setup, _parent) = scope().await;
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    assert!(matches!(
        setup.session.wait_original_outcomes([0x44; 16], end).await,
        Err(CaptureFailure::InvalidPlan)
    ));
    setup.session.state.lock().unwrap().flows[0].requests.pop();
    assert!(matches!(
        setup.session.wait_original_outcomes(PRODUCER, end).await,
        Err(CaptureFailure::InvalidPlan)
    ));
    setup.session.retire();
    assert!(matches!(
        setup.session.wait_original_outcomes(PRODUCER, end).await,
        Err(CaptureFailure::Expired)
    ));
    no_credit(&setup.session);
}
