//! Same actual input mutex and original nonblocking authenticated try only.
//! Registration labels never construct KernelRead, Full or native authority.
use super::*;
use serde_json::{json, Value};

thread_local! {
    static PREPARING: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const {
        std::cell::RefCell::new(None)
    };
}
pub(super) fn preparing() {
    let probe = PREPARING.with(|slot| slot.borrow_mut().take());
    if let Some(probe) = probe {
        probe();
    }
}
fn on_prepare(probe: impl FnOnce() + 'static) {
    PREPARING.with(|slot| assert!(slot.borrow_mut().replace(Box::new(probe)).is_none()));
}
fn plan() -> RegistrationPlan {
    RegistrationPlan::decode(
        &serde_json::to_vec(&json!({
            "schema_version":1,"capture_id":"11".repeat(16),
            "producer_scope":"67".repeat(16),"flows":[{
                "protocol":"udp","kind":"request","peer_id":"registration-peer",
                "run_nonce":"44".repeat(16),"round_nonce":"55".repeat(16),
                "bind_ip":"10.21.1.2","bind_port":32123,"target_ip":"10.21.1.3","target_port":43210,
                "payload_bytes":128,"request_nonces":["66".repeat(16)]}]
        }))
        .unwrap(),
    )
    .unwrap()
}
fn observe_original_try(scope: &Arc<CaptureSession>) -> Arc<AtomicBool> {
    let available = Arc::new(AtomicBool::new(false));
    let scope = scope.clone();
    let observed = available.clone();
    on_prepare(move || {
        // One real original authenticated-input mutex try; no fake IO.
        observed.store(
            scope.state.try_authenticated_lock().is_ok(),
            Ordering::Release,
        );
    });
    available
}
fn snapshot(scope: &CaptureSession) -> Value {
    serde_json::to_value(scope.snapshot().unwrap()).unwrap()
}
fn assert_labels_only(scope: &CaptureSession, available: &AtomicBool) {
    assert!(
        available.load(Ordering::Acquire),
        "registration preparation still owns original input mutex"
    );
    let value = snapshot(scope);
    assert_eq!(value["registration_revision"], 1);
    assert_eq!(value["registration_sets"], 1);
    assert_eq!(value["requests"].as_array().unwrap().len(), 1);
    assert_eq!(value["requests"][0]["native_credit"], Value::Null);
    assert_eq!(value["requests"][0]["read_events"], 0);
    assert_eq!(value["historical_full_packets"], json!([]));
    assert_eq!(value["system_tun_full_writes"], json!([]));
    assert_eq!(value["physical_send_verified"], false);
    assert_eq!(value["canonical_current_owner_verified"], false);
    assert!(scope.state.authenticated_refusal_snapshot().is_none());
}
#[tokio::test]
async fn registration_sync_prepares_labels_without_owning_actual_input_mutex() {
    let (setup, _parent) = full::tests::descriptor_scope().await;
    let available = observe_original_try(&setup.session);
    setup.session.register(plan()).unwrap();
    assert_labels_only(&setup.session, &available);
}
#[tokio::test]
async fn registration_control_prepares_labels_without_owning_actual_input_mutex() {
    let (setup, _parent) = full::tests::descriptor_scope().await;
    let available = observe_original_try(&setup.session);
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    setup.session.register_control(plan(), end).await.unwrap();
    assert_labels_only(&setup.session, &available);
}

fn assert_empty(scope: &CaptureSession, revision: u64) {
    let value = snapshot(scope);
    assert_eq!(value["registration_revision"], revision);
    assert_eq!(value["registration_sets"], 0);
    assert_eq!(value["requests"], json!([]));
    assert_eq!(scope.sources.flows.len(), 0);
}

#[tokio::test]
async fn registration_rechecks_actual_retirement_after_preparation() {
    let (setup, _parent) = full::tests::descriptor_scope().await;
    let session = setup.session.clone();
    on_prepare(move || session.retire());
    assert!(matches!(
        setup.session.register(plan()),
        Err(CaptureFailure::Expired)
    ));
    assert_empty(&setup.session, 0);
}

#[tokio::test]
async fn registration_rechecks_competing_append_without_replacing_original_cells() {
    let (setup, _parent) = full::tests::descriptor_scope().await;
    let session = setup.session.clone();
    let original = Arc::new(std::sync::Mutex::new(None));
    let recorded = original.clone();
    on_prepare(move || {
        session.register(plan()).unwrap();
        let state = session.state.lock().unwrap();
        *recorded.lock().unwrap() = Some((
            state.flows[0].plan.clone(),
            state.flows[0].invalid.clone(),
            state.flows[0].inbound.invalid.clone(),
        ));
    });
    assert!(matches!(
        setup.session.register(plan()),
        Err(CaptureFailure::RegistrationConflict)
    ));
    let value = snapshot(&setup.session);
    assert_eq!(value["registration_revision"], 1);
    assert_eq!(value["registration_sets"], 1);
    assert_eq!(value["requests"].as_array().unwrap().len(), 1);
    let state = setup.session.state.lock().unwrap();
    let recorded = original.lock().unwrap();
    let (plan, invalid, inbound_invalid) = recorded.as_ref().unwrap();
    assert_eq!(setup.session.sources.flows.len(), 1);
    assert!(Arc::ptr_eq(plan, &state.flows[0].plan));
    assert!(Arc::ptr_eq(invalid, &state.flows[0].invalid));
    assert!(Arc::ptr_eq(
        inbound_invalid,
        &state.flows[0].inbound.invalid
    ));
}

#[tokio::test]
async fn registration_rechecks_original_global_capacity_after_competing_preparation() {
    let (setup, _parent) = full::tests::descriptor_scope().await;
    let session = setup.session.clone();
    on_prepare(move || {
        let mut full = plan();
        full.producer_scope = [0x68; 16];
        full.flows[0].flow.src_port += 1;
        let key = full.flows[0].requests[0];
        full.flows[0].requests = (0..MAX_REQUESTS)
            .map(|n| crate::business_evidence::OsUdpReqKey {
                sequence: n as u32,
                request_nonce: (n as u128).to_be_bytes(),
                ..key
            })
            .collect();
        session.register(full).unwrap();
    });
    assert!(matches!(
        setup.session.register(plan()),
        Err(CaptureFailure::Capacity)
    ));
    let value = snapshot(&setup.session);
    assert_eq!(value["registration_revision"], 1);
    assert_eq!(value["registration_sets"], 1);
    assert_eq!(value["requests"].as_array().unwrap().len(), MAX_REQUESTS);
    assert!(value["requests"]
        .as_array()
        .unwrap()
        .iter()
        .all(|q| q["native_credit"].is_null()));
    assert_eq!(setup.session.sources.flows.len(), 1);
}

#[tokio::test]
async fn registration_rechecks_original_revision_exhaustion_without_partial_append() {
    let (setup, _parent) = full::tests::descriptor_scope().await;
    let session = setup.session.clone();
    on_prepare(move || {
        session.state.lock().unwrap().revision = u64::MAX;
    });
    assert!(matches!(
        setup.session.register(plan()),
        Err(CaptureFailure::CounterExhausted)
    ));
    assert_empty(&setup.session, u64::MAX);
}

#[tokio::test]
async fn registration_control_keeps_original_absolute_deadline_after_preparation() {
    let (setup, _parent) = full::tests::descriptor_scope().await;
    let available = observe_original_try(&setup.session);
    let end = tokio::time::Instant::now();
    assert!(matches!(
        setup.session.register_control(plan(), end).await,
        Err(CaptureFailure::ControlNotReady)
    ));
    assert!(available.load(Ordering::Acquire));
    assert_empty(&setup.session, 0);
}

#[tokio::test]
async fn registration_sync_keeps_busy_original_try_before_invalid_plan_error() {
    let (setup, _parent) = full::tests::descriptor_scope().await;
    let held = setup.session.state.lock().unwrap();
    assert!(held.flows.capacity() >= MAX_REQUESTS);
    let mut foreign = plan();
    foreign.capture_id = [0xee; 16];
    assert!(matches!(
        setup.session.register(foreign),
        Err(CaptureFailure::Contended)
    ));
    drop(held);
    assert_empty(&setup.session, 0);
}
