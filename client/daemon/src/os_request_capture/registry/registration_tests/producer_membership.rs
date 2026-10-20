//! Exercise the original bounded producer table through actual registration.
//! Expected input labels grant no read, Full, SystemTun or native authority.
use super::*;

fn distinct(index: usize) -> RegistrationPlan {
    let mut value = plan();
    value.producer_scope = (index as u128).to_be_bytes();
    value.flows[0].flow.src_port += index as u16;
    value.flows[0].requests[0].request_nonce = (index as u128).to_be_bytes();
    value
}

#[tokio::test]
async fn producer_membership_preallocates_all_original_slots_without_table_growth() {
    let (setup, _parent) = full::tests::descriptor_scope().await;
    let capacity = setup.session.state.lock().unwrap().producers.capacity();
    assert!(capacity >= MAX_REQUESTS);
    for index in 0..MAX_REQUESTS {
        let receipt = if index % 2 == 0 {
            setup.session.register(distinct(index)).unwrap()
        } else {
            setup
                .session
                .register_control(
                    distinct(index),
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await
                .unwrap()
        };
        assert_eq!(receipt.total_requests, index + 1);
        let state = setup.session.state.lock().unwrap();
        assert_eq!(state.producers.len(), index + 1);
        assert_eq!(state.producers.capacity(), capacity);
        assert!(state.producers.contains(&(index as u128).to_be_bytes()));
    }
    assert!(matches!(
        setup.session.register(distinct(MAX_REQUESTS)),
        Err(CaptureFailure::Capacity)
    ));
    let value = snapshot(&setup.session);
    assert_eq!(value["registration_sets"], MAX_REQUESTS);
    assert_eq!(value["registration_revision"], MAX_REQUESTS);
    assert_eq!(value["requests"].as_array().unwrap().len(), MAX_REQUESTS);
    assert!(value["requests"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["native_credit"].is_null() && row["read_events"] == 0));
    assert_eq!(value["physical_send_verified"], false);
    assert_eq!(value["canonical_current_owner_verified"], false);
    assert_eq!(value["historical_full_packets"], json!([]));
    assert_eq!(value["system_tun_full_writes"], json!([]));
}

#[tokio::test]
async fn producer_membership_competing_append_keeps_original_duplicate_authority() {
    for control in [false, true] {
        let (setup, _parent) = full::tests::descriptor_scope().await;
        let session = setup.session.clone();
        on_prepare(move || {
            session.register(distinct(0)).unwrap();
        });
        let mut incoming = distinct(1);
        // Flow and request labels differ: only the canonical producer table
        // can reject the registration that raced this preparation.
        incoming.producer_scope = [0; 16];
        let result = if control {
            setup
                .session
                .register_control(
                    incoming,
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await
        } else {
            setup.session.register(incoming)
        };
        assert!(matches!(result, Err(CaptureFailure::RegistrationConflict)));
        let value = snapshot(&setup.session);
        assert_eq!(value["registration_sets"], 1);
        assert_eq!(value["registration_revision"], 1);
        assert_eq!(value["requests"].as_array().unwrap().len(), 1);
        assert!(value["requests"][0]["native_credit"].is_null());
        assert_eq!(setup.session.sources.flows.len(), 1);
    }
}

#[tokio::test]
async fn producer_membership_full_registry_keeps_capacity_before_duplicate_error() {
    let (setup, _parent) = full::tests::descriptor_scope().await;
    let mut incoming = distinct(0);
    let key = incoming.flows[0].requests[0];
    incoming.flows[0].requests = (0..MAX_REQUESTS)
        .map(|index| crate::business_evidence::OsUdpReqKey {
            sequence: index as u32,
            request_nonce: (index as u128).to_be_bytes(),
            ..key
        })
        .collect();
    setup.session.register(incoming).unwrap();
    let mut duplicate = distinct(1);
    duplicate.producer_scope = [0; 16];
    assert!(matches!(
        setup.session.register(duplicate),
        Err(CaptureFailure::Capacity)
    ));
    let state = setup.session.state.lock().unwrap();
    assert_eq!(state.producers.len(), 1);
    assert_eq!(state.requests, MAX_REQUESTS);
    assert_eq!(state.revision, 1);
    assert_eq!(state.flows.len(), 1);
}
