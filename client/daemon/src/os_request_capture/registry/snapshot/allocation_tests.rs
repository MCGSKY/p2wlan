//! Observe actual allocation in the real snapshot entry points. No production
//! hook, synthetic KernelRead/Full, native owner or positive IO credit is added.
use super::*;
use serde_json::json;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::RefCell;
use std::future::{poll_fn, Future};
use std::task::Poll;
use std::time::Duration;

struct TestAllocator;
#[global_allocator]
static ALLOCATOR: TestAllocator = TestAllocator;

// SAFETY: Every allocation operation is forwarded unchanged to System. The
// observer never allocates, panics, waits, or dereferences an allocation pointer.
unsafe impl GlobalAlloc for TestAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        observe(layout, false);
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        observe(layout, false);
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        observe(layout, true);
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let pointer = unsafe { System.realloc(pointer, layout, size) };
        if let Ok(layout) = Layout::from_size_align(size, layout.align()) {
            observe(layout, false);
        }
        pointer
    }
}

#[derive(Clone, Copy, Default)]
struct Observation {
    bytes: usize,
    registry_free: bool,
}
#[derive(Clone, Copy, Default)]
struct Observations {
    allocations: usize,
    deallocations: usize,
    overflow: bool,
    rows: [Observation; 16],
}
struct ActiveProbe {
    scope: Weak<CaptureSession>,
    observed: Observations,
}
thread_local! {
    static ACTIVE: RefCell<Option<ActiveProbe>> = const { RefCell::new(None) };
}

fn observe(layout: Layout, deallocate: bool) {
    let unit = std::mem::size_of::<RequestSnapshot>();
    // The original empty Vec first grows to four requests. The candidate
    // reserves the existing 1000-request bound. Filtering these actual layouts
    // excludes unrelated runtime and intentionally unchanged nested allocations.
    if layout.align() != std::mem::align_of::<RequestSnapshot>()
        || ![unit * 4, unit * crate::business_evidence::MAX_REQUESTS].contains(&layout.size())
    {
        return;
    }
    let _ = ACTIVE.try_with(|active| {
        let Ok(mut active) = active.try_borrow_mut() else {
            return;
        };
        let Some(probe) = active.as_mut() else { return };
        if deallocate {
            probe.observed.deallocations = probe.observed.deallocations.saturating_add(1);
            return;
        }
        let Some(scope) = probe.scope.upgrade() else {
            return;
        };
        let index = probe.observed.allocations;
        if index < probe.observed.rows.len() {
            probe.observed.rows[index] = Observation {
                bytes: layout.size(),
                registry_free: scope.state.actual_mutex_is_available_for_test(),
            };
        } else {
            probe.observed.overflow = true;
        }
        probe.observed.allocations = probe.observed.allocations.saturating_add(1);
    });
}

struct Probe;
impl Probe {
    fn start(scope: &Arc<CaptureSession>) -> Self {
        ACTIVE.with(|active| {
            assert!(active.borrow().is_none());
            *active.borrow_mut() = Some(ActiveProbe {
                scope: Arc::downgrade(scope),
                observed: Observations::default(),
            });
        });
        Self
    }
    fn current(&self) -> Observations {
        ACTIVE.with(|active| active.borrow().as_ref().unwrap().observed)
    }
    fn finish(self) -> Observations {
        ACTIVE.with(|active| active.borrow_mut().take().unwrap().observed)
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        ACTIVE.with(|active| *active.borrow_mut() = None);
    }
}

fn assert_reserved_once(observed: Observations, available: bool) {
    assert!(!observed.overflow);
    assert_eq!(
        observed.allocations, 1,
        "outer request storage was not prepared once before the original lock wait"
    );
    assert_eq!(
        observed.rows[0].registry_free, available,
        "request-vector allocation still owns the actual input registry mutex"
    );
    assert_eq!(
        observed.rows[0].bytes,
        std::mem::size_of::<RequestSnapshot>() * crate::business_evidence::MAX_REQUESTS
    );
}

async fn scope() -> (
    super::super::super::control::CaptureSetup,
    std::os::unix::net::UnixStream,
) {
    super::super::snapshot_projection_tests::scope().await
}

fn assert_metadata_only(snapshot: ReadSnapshot, count: usize) {
    let value = serde_json::to_value(snapshot).unwrap();
    assert_eq!(value["requests"].as_array().unwrap().len(), count);
    assert_eq!(value["total_registered_requests"], count);
    assert_eq!(value["historical_full_packets"], json!([]));
    assert_eq!(value["system_tun_full_writes"], json!([]));
    assert_eq!(value["physical_send_verified"], false);
    assert_eq!(value["canonical_current_owner_verified"], false);
    assert!(value["requests"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["native_credit"].is_null()));
}

#[tokio::test(flavor = "current_thread")]
async fn snapshot_sync_allocates_request_storage_before_real_registry_try() {
    let (setup, _parent) = scope().await;
    let probe = Probe::start(&setup.session);
    let snapshot = setup.session.snapshot().unwrap();
    let observed = probe.finish();
    assert_reserved_once(observed, true);
    assert_metadata_only(snapshot, 1);
    assert!(setup.session.state.input_refusal_snapshot().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn snapshot_control_allocates_request_storage_before_real_registry_wait() {
    let (setup, _parent) = scope().await;
    let probe = Probe::start(&setup.session);
    let snapshot = setup
        .session
        .snapshot_control(tokio::time::Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    let observed = probe.finish();
    assert_reserved_once(observed, true);
    assert_metadata_only(snapshot, 1);
    assert!(setup.session.full_loss.snapshot().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn snapshot_control_cancelled_original_wait_releases_prepared_storage() {
    let (setup, _parent) = scope().await;
    let held = setup.session.state.try_lock().unwrap();
    let mut snapshot = Box::pin(
        setup
            .session
            .snapshot_control(tokio::time::Instant::now() + Duration::from_secs(1)),
    );
    let probe = Probe::start(&setup.session);
    assert!(poll_fn(|cx| Poll::Ready(snapshot.as_mut().poll(cx).is_pending())).await);
    let before = probe.current();
    drop(snapshot);
    let after = probe.finish();
    drop(held);
    assert_reserved_once(before, false);
    assert_eq!(before.deallocations, 0);
    assert_eq!(after.allocations, 1);
    assert_eq!(after.deallocations, 1);
    assert!(setup.session.state.actual_mutex_is_available_for_test());
    assert_metadata_only(
        setup
            .session
            .snapshot_control(tokio::time::Instant::now() + Duration::from_secs(1))
            .await
            .unwrap(),
        1,
    );
}

fn plan(count: usize, producer: &str) -> RegistrationPlan {
    RegistrationPlan::decode(&serde_json::to_vec(&json!({
        "schema_version":1,"capture_id":"11".repeat(16),"producer_scope":producer.repeat(16),"flows":[{
            "protocol":"udp","kind":"request","peer_id":"snapshot-buffer-peer",
            "run_nonce":"91".repeat(16),"round_nonce":"92".repeat(16),
            "bind_ip":"10.21.1.2","bind_port":32124,"target_ip":"10.21.1.4","target_port":43211,
            "payload_bytes":128,"request_nonces":(1..=count).map(|n|format!("{n:032x}")).collect::<Vec<_>>()
        }]
    })).unwrap()).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn snapshot_control_prepared_storage_does_not_freeze_registration_early() {
    let (setup, _parent) = scope().await;
    let later = plan(1, "89");
    let held = setup.session.state.try_lock().unwrap();
    let mut snapshot = Box::pin(
        setup
            .session
            .snapshot_control(tokio::time::Instant::now() + Duration::from_secs(1)),
    );
    let probe = Probe::start(&setup.session);
    assert!(poll_fn(|cx| Poll::Ready(snapshot.as_mut().poll(cx).is_pending())).await);
    let before = probe.current();
    drop(held);
    setup.session.register(later).unwrap();
    let captured = snapshot.await.unwrap();
    let after = probe.finish();
    assert_reserved_once(before, false);
    assert_eq!(after.allocations, 1);
    assert_eq!(captured.registration_revision, 2);
    assert_metadata_only(captured, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn snapshot_control_prepared_storage_keeps_actual_later_loss_and_clock() {
    let (setup, _parent) = scope().await;
    let held = setup.session.state.try_lock().unwrap();
    let mut snapshot = Box::pin(
        setup
            .session
            .snapshot_control(tokio::time::Instant::now() + Duration::from_secs(1)),
    );
    let probe = Probe::start(&setup.session);
    assert!(poll_fn(|cx| Poll::Ready(snapshot.as_mut().poll(cx).is_pending())).await);
    let before = probe.current();
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::InputRegistryContended);
    let clock = monotonic_ns();
    drop(held);
    let captured = snapshot.await.unwrap();
    let after = probe.finish();
    assert_reserved_once(before, false);
    assert_eq!(after.allocations, 1);
    match (clock, captured.observed_monotonic_ns) {
        (Some(before), Some(observed)) => assert!(observed >= before),
        (None, None) => {}
        _ => panic!("snapshot must preserve the original platform clock availability"),
    }
    assert_eq!(captured.gaps, 1);
    assert!(!captured.original_full_retention_complete);
    assert_metadata_only(captured, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn snapshot_control_original_expired_deadline_drops_prepared_storage() {
    let (setup, _parent) = scope().await;
    let probe = Probe::start(&setup.session);
    let result = setup
        .session
        .snapshot_control(tokio::time::Instant::now())
        .await;
    let observed = probe.finish();
    assert!(matches!(result, Err(CaptureFailure::ControlNotReady)));
    assert_reserved_once(observed, true);
    assert_eq!(observed.deallocations, 1);
    assert!(setup.session.state.actual_mutex_is_available_for_test());
}

#[tokio::test(flavor = "current_thread")]
async fn snapshot_control_existing_max_requests_needs_one_bounded_outer_allocation() {
    let (setup, _parent) = full::tests::descriptor_scope().await;
    setup
        .session
        .register(plan(crate::business_evidence::MAX_REQUESTS, "89"))
        .unwrap();
    let probe = Probe::start(&setup.session);
    let captured = setup
        .session
        .snapshot_control(tokio::time::Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    let observed = probe.finish();
    assert_reserved_once(observed, true);
    assert_metadata_only(captured, crate::business_evidence::MAX_REQUESTS);
}
