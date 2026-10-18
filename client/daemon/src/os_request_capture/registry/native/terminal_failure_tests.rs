//! Actual descriptor/registry metadata only. No read, Full, SystemTun write,
//! current-owner permit or positive native transaction is constructed.
use super::*;
use serde_json::{json, Value};
use std::time::Duration;

const PRODUCER: [u8; 16] = [0x33; 16];

async fn scope() -> (
    crate::os_request_capture::control::CaptureSetup,
    std::os::unix::net::UnixStream,
) {
    let (setup, parent) = super::super::full::tests::descriptor_scope().await;
    let document = json!({"schema_version":1,"capture_id":"11".repeat(16),
        "producer_scope":"33".repeat(16),"flows":[{
            "protocol":"tcp","kind":"request","peer_id":"failed-wait-metadata-peer",
            "run_nonce":"44".repeat(16),"round_nonce":"55".repeat(16),
            "bind_ip":"10.21.1.2","bind_port":32123,"target_ip":"10.21.1.3","target_port":43210,
            "payload_bytes":128,"request_nonces":(1..=8).map(|i|format!("{i:032x}")).collect::<Vec<_>>()}]});
    setup
        .session
        .register(RegistrationPlan::decode(&serde_json::to_vec(&document).unwrap()).unwrap())
        .unwrap();
    (setup, parent)
}

fn observed(session: &CaptureSession, producer: [u8; 16]) -> Value {
    let metadata =
        session.terminal_failure_metadata(producer, 17, &CaptureFailure::ControlNotReady);
    let raw = metadata.encoded().unwrap();
    assert!(raw.len() <= 16 * 1024);
    let value: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        value["scope"],
        "original_terminal_wait_failure_metadata_only"
    );
    for key in [
        "native_os_write_verified",
        "physical_send_verified",
        "canonical_current_owner_verified",
    ] {
        assert_eq!(value[key], false);
    }
    value
}

#[tokio::test]
async fn terminal_failure_metadata_actual_timeout_preserves_error_and_missing_rows() {
    let (setup, _parent) = scope().await;
    let before = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    let end = tokio::time::Instant::now() + Duration::from_millis(20);
    assert!(matches!(
        setup
            .session
            .wait_original_outcomes_observed(PRODUCER, end, 17)
            .await,
        Err(CaptureFailure::ControlNotReady)
    ));
    let diagnostic = observed(&setup.session, PRODUCER);
    assert_eq!(diagnostic["observation"], "observed");
    assert_eq!(diagnostic["requests"].as_array().unwrap().len(), 8);
    for row in diagnostic["requests"].as_array().unwrap() {
        assert_eq!(row["terminal_outcome_recorded"], false);
        assert_eq!(row["read_events"], 0);
        assert_eq!(row["first_read_ordinal"], Value::Null);
    }
    let after = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    for key in [
        "requests",
        "historical_full_packets",
        "system_tun_full_writes",
    ] {
        assert_eq!(before[key], after[key]);
    }
}

#[tokio::test]
async fn terminal_failure_metadata_actual_contended_registry_returns_unknown_without_wait() {
    let (setup, _parent) = scope().await;
    let held = setup.session.state.lock().unwrap();
    let diagnostic = observed(&setup.session, PRODUCER);
    assert_eq!(diagnostic["observation"], "registry_contended");
    assert_eq!(diagnostic["requests"], json!([]));
    drop(held);
    assert_eq!(
        observed(&setup.session, PRODUCER)["requests"]
            .as_array()
            .unwrap()
            .len(),
        8
    );
}

#[tokio::test]
async fn terminal_failure_metadata_existing_negative_outcomes_and_once_are_not_reentered() {
    let (setup, _parent) = scope().await;
    {
        let mut state = setup.session.state.lock().unwrap();
        for row in &mut state.flows[0].requests {
            row.native_credit = Some(NativeFrameOutcome::failure(Outcome::Unknown(
                Unknown::OriginalSource,
            )));
        }
    }
    let before = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    let receipt = setup
        .session
        .wait_original_outcomes_observed(PRODUCER, end, 17)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(receipt).unwrap()["completed_requests"],
        8
    );
    let diagnostic = observed(&setup.session, PRODUCER);
    assert!(diagnostic["requests"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["terminal_outcome_recorded"] == true));
    let after = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    assert_eq!(before["requests"], after["requests"]);
    assert!(after["requests"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["native_credit"]["once_committed"] == false));
}

#[tokio::test]
async fn terminal_failure_metadata_wrong_scope_capacity_and_retirement_do_not_create_rows() {
    let (setup, _parent) = scope().await;
    assert_eq!(
        observed(&setup.session, [0x44; 16])["observation"],
        "flow_unavailable"
    );
    setup.session.state.lock().unwrap().flows[0].requests.pop();
    let invalid = observed(&setup.session, PRODUCER);
    assert_eq!(invalid["observation"], "invalid_fixed_eight");
    assert_eq!(invalid["requests"], json!([]));
    setup.session.retire();
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    assert!(matches!(
        setup
            .session
            .wait_original_outcomes_observed(PRODUCER, end, 17)
            .await,
        Err(CaptureFailure::Expired)
    ));
    assert_eq!(observed(&setup.session, PRODUCER)["capture_active"], false);
}
