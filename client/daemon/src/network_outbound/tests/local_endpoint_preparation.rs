//! Real UDP handoff and actual existing guards; no kernel TUN qualification.
use super::*;
use std::{cell::Cell, rc::Rc};

#[tokio::test(flavor = "current_thread")]
async fn outbound_primary_endpoint_query_keeps_emit_owner_without_holding_epoch() {
    let (f, transport, udp, receiver, mut remote) = direct_fixture(false).await;
    let transport = Arc::new(transport);
    let observed = Rc::new(Cell::new([None; 2]));
    let calls = Rc::new(Cell::new(0usize));
    let probe = crate::udp::local_addr_test::install(&udp, {
        let peers = f.peers.clone();
        let transport = transport.clone();
        let observed = observed.clone();
        let calls = calls.clone();
        move || {
            let index = calls.get();
            calls.set(index.saturating_add(1));
            if index < 2 {
                let epoch_free = peers.network_epoch_gate().try_lock_owned().is_ok();
                let emit_owned = transport.try_acquire_outbound_emit_guard(PEER).is_none();
                let mut points = observed.get();
                points[index] = Some((epoch_free, emit_owned));
                observed.set(points);
            }
        }
    });
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
    drop(probe);
    assert!(matches!(outcome, EncryptSendOutcome::Sent));
    let mut wire = [0u8; 2048];
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
    // Preparation moves outside epoch; the later original handoff snapshot
    // still owns epoch. Both retain the same real emit owner.
    assert_eq!(observed.get(), [Some((true, true)), Some((false, true))]);
    assert_eq!(calls.get(), 2);
    assert_eq!(
        f.record
            .physical_publication
            .record()
            .unwrap()
            .qualify(&f.record, Instant::now()),
        PhysicalInputQualification::UnknownUdpPublication,
    );
}
