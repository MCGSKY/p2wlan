//! Real descriptor and the original registry try only. No KernelRead, Full,
//! SystemTun write, owner permission or native positive credit is constructed.
use super::*;
use serde_json::json;
use std::time::Duration;

pub(super) async fn scope() -> (
    super::super::control::CaptureSetup,
    std::os::unix::net::UnixStream,
) {
    let (setup, parent) = full::tests::descriptor_scope().await;
    let document = json!({"schema_version":1,"capture_id":"11".repeat(16),
        "producer_scope":"67".repeat(16),"flows":[{
            "protocol":"udp","kind":"request","peer_id":"snapshot-projection-peer",
            "run_nonce":"44".repeat(16),"round_nonce":"55".repeat(16),
            "bind_ip":"10.21.1.2","bind_port":32123,"target_ip":"10.21.1.3","target_port":43210,
            "payload_bytes":128,"request_nonces":["66".repeat(16)]}]});
    setup
        .session
        .register(RegistrationPlan::decode(&serde_json::to_vec(&document).unwrap()).unwrap())
        .unwrap();
    (setup, parent)
}

fn observe_original_input_try(scope: &Arc<CaptureSession>) -> Arc<AtomicBool> {
    let available = Arc::new(AtomicBool::new(false));
    let seen = available.clone();
    let scope = scope.clone();
    full::on_next_snapshot_coverage_for_test(move || {
        // Same concrete mutex and same one nonblocking input try. Ordinal 1
        // is metadata in this fixture; it never stands for an actual OS read.
        let attempted = scope.state.try_input_lock(1);
        seen.store(attempted.is_ok(), Ordering::Release);
    });
    available
}

fn assert_projection(snapshot: ReadSnapshot, available: &AtomicBool) {
    assert!(
        available.load(Ordering::Acquire),
        "coverage still owns original input registry mutex"
    );
    let value = serde_json::to_value(snapshot).unwrap();
    assert_eq!(value["requests"].as_array().unwrap().len(), 1);
    assert_eq!(
        value["requests"][0]["native_credit"],
        serde_json::Value::Null
    );
    assert_eq!(value["historical_full_packets"], json!([]));
    assert_eq!(value["system_tun_full_writes"], json!([]));
    assert_eq!(value["physical_send_verified"], false);
    assert_eq!(value["canonical_current_owner_verified"], false);
    assert_eq!(value["original_full_retention_complete"], true);
}

#[tokio::test]
async fn snapshot_projection_sync_releases_real_input_mutex_before_coverage() {
    let (setup, _parent) = scope().await;
    let available = observe_original_input_try(&setup.session);
    let snapshot = setup.session.snapshot().unwrap();
    assert_projection(snapshot, &available);
    assert!(setup.session.state.input_refusal_snapshot().is_none());
    assert!(setup.session.full_loss.snapshot().is_none());
}

#[tokio::test]
async fn snapshot_projection_control_releases_real_input_mutex_before_coverage() {
    let (setup, _parent) = scope().await;
    let available = observe_original_input_try(&setup.session);
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    let snapshot = setup.session.snapshot_control(end).await.unwrap();
    assert_projection(snapshot, &available);
    assert!(setup.session.state.input_refusal_snapshot().is_none());
    assert!(setup.session.full_loss.snapshot().is_none());
}
