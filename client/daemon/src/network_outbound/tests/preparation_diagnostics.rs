//! Actual loopback ciphertext and original counter order, without NIC/ACK credit.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tracing_subscriber::prelude::*;

#[derive(Default)]
struct Name(bool);
impl tracing::field::Visit for Name {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "event" && value == "outbound_business_emit_lock_acquired" {
            self.0 = true;
        }
    }
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
}

struct Probe {
    transport: Arc<WireGuardTransport>,
    calls: Arc<AtomicUsize>,
    free: Arc<AtomicBool>,
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Probe {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let mut name = Name::default();
        event.record(&mut name);
        if name.0 {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.free.store(
                self.transport
                    .try_acquire_outbound_emit_guard(PEER)
                    .is_some(),
                Ordering::Release,
            );
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn outbound_emit_preparation_log_releases_actual_guard_after_real_udp_handoff() {
    let (f, transport, udp, receiver, mut remote) = direct_fixture(false).await;
    let transport = Arc::new(transport);
    let calls = Arc::new(AtomicUsize::new(0));
    let free = Arc::new(AtomicBool::new(false));
    let subscriber = tracing_subscriber::registry().with(Probe {
        transport: transport.clone(),
        calls: calls.clone(),
        free: free.clone(),
    });
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let udps = RwLock::new(Some(udp));
    let relays = RwLock::new(None);
    let outcome = encrypt_then_send_with_deadline(
        f.delivery.clone(),
        &transport,
        &f.peers,
        f.record.generation,
        true,
        &udps,
        &relays,
        false,
        Some(Instant::now() + Duration::from_secs(1)),
        None,
    )
    .await;
    assert!(matches!(outcome, EncryptSendOutcome::Sent));
    let mut wire = [0; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut wire))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(crate::transport::wire_counter(&wire[..n]), Some(0));
    assert_eq!(
        remote.decrypt_from_bytes(&wire[..n]).unwrap(),
        f.record.original_packet()
    );
    assert!(
        matches!(receiver.try_recv_from(&mut wire), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    );
    assert_eq!(
        f.record
            .physical_publication
            .record()
            .unwrap()
            .qualify(&f.record, Instant::now()),
        PhysicalInputQualification::UnknownUdpPublication
    );
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert!(
        free.load(Ordering::Acquire),
        "successful handoff logger still owns actual emit mutex"
    );
}
