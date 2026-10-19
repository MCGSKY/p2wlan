//! Pure coverage controls only; no SystemTun read/write or owner is minted.
use super::*;
use crate::os_request_capture::plan::RegistrationPlan;
use serde_json::json;

pub(in crate::os_request_capture::registry) async fn descriptor_scope() -> (
    crate::os_request_capture::control::CaptureSetup,
    std::os::unix::net::UnixStream,
) {
    use std::io::Write;
    let value = json!({"schema_version":1,"capture_id":"11111111111111111111111111111111",
        "producer_scope":"22222222222222222222222222222222","flows":[]});
    let peers = Arc::new(PeerManager::new(
        crate::Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    let (mut parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
    child.set_nonblocking(true).unwrap();
    let mut encoded = serde_json::to_vec(&value).unwrap();
    encoded.push(b'\n');
    parent.write_all(&encoded).unwrap();
    let setup = crate::os_request_capture::control::CaptureSetup::from_owned_descriptor(
        child.into(),
        &peers,
    )
    .await
    .unwrap();
    (setup, parent)
}

// These guards can only record a missing observation. No fixture constructs a
// KernelRead, physical publication, SystemTun write or native positive fact.
fn negative_observer(scope: &Arc<CaptureSession>) -> OriginalFullObservation {
    OriginalFullObservation {
        scope: Arc::downgrade(scope),
        armed: false,
    }
}

fn assert_no_full_credit(scope: &CaptureSession, complete: bool) {
    let value = serde_json::to_value(scope.snapshot().unwrap()).unwrap();
    assert_eq!(value["original_full_retention_complete"], complete);
    assert_eq!(value["historical_full_packets"], json!([]));
    assert_eq!(value["system_tun_full_writes"], json!([]));
    assert_eq!(value["physical_send_verified"], false);
    assert_eq!(value["canonical_current_owner_verified"], false);
}

#[tokio::test]
async fn original_full_unknown_cannot_rearm_after_later_completion_or_registration() {
    let (setup, _parent) = descriptor_scope().await;
    drop(negative_observer(&setup.session));
    let mut not_handed = negative_observer(&setup.session);
    not_handed.arm();
    not_handed.complete();
    drop(not_handed);
    assert_no_full_credit(&setup.session, true);
    let mut lost = negative_observer(&setup.session);
    lost.arm();
    drop(lost);
    let mut later = negative_observer(&setup.session);
    later.arm();
    later.complete();
    drop(later);
    let value = json!({"schema_version":1,"capture_id":"11111111111111111111111111111111",
        "producer_scope":"33333333333333333333333333333333","flows":[{
            "protocol":"udp","kind":"request","peer_id":"full-negative-peer",
            "run_nonce":"44444444444444444444444444444444","round_nonce":"55555555555555555555555555555555",
            "bind_ip":"10.21.1.2","bind_port":32123,"target_ip":"10.21.1.3","target_port":43210,
            "payload_bytes":128,"request_nonces":["66666666666666666666666666666666"]}]});
    let receipt = setup
        .session
        .register(RegistrationPlan::decode(&serde_json::to_vec(&value).unwrap()).unwrap())
        .unwrap();
    assert_eq!(serde_json::to_value(receipt).unwrap()["added_requests"], 1);
    assert_no_full_credit(&setup.session, false);
    assert_eq!(setup.session.gaps.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn original_full_loss_does_not_wait_for_the_contended_history_mutex() {
    let (setup, _parent) = descriptor_scope().await;
    let held = setup.session.state.try_lock().unwrap();
    let mut observer = negative_observer(&setup.session);
    observer.arm();
    drop(observer);
    assert!(!setup.session.full_complete.load(Ordering::Acquire));
    assert!(setup.session.read_complete.load(Ordering::Acquire));
    assert!(setup.session.inbound_complete.load(Ordering::Acquire));
    drop(held);
    assert_no_full_credit(&setup.session, false);
}

#[tokio::test]
async fn original_full_observer_cannot_keep_retired_descriptor_scope_alive() {
    let (setup, parent) = descriptor_scope().await;
    let weak = Arc::downgrade(&setup.session);
    let mut observer = negative_observer(&setup.session);
    observer.arm();
    drop(setup);
    drop(parent);
    assert!(weak.upgrade().is_none());
    drop(observer);
}

#[tokio::test]
async fn original_full_loss_is_scoped_and_never_restored_by_another_observer() {
    let (first, _first_parent) = descriptor_scope().await;
    let (second, _second_parent) = descriptor_scope().await;
    let mut observer = negative_observer(&first.session);
    observer.arm();
    drop(observer);
    let mut other = negative_observer(&second.session);
    other.arm();
    other.complete();
    drop(other);
    assert_no_full_credit(&first.session, false);
    assert_no_full_credit(&second.session, true);
}

fn plan(protocol: &str, count: usize) -> RegisteredFlowPlan {
    let value = json!({"schema_version":1,"capture_id":"11111111111111111111111111111111",
        "producer_scope":"22222222222222222222222222222222","flows":[{
            "protocol":protocol,"kind":"response","peer_id":"frame-span-peer",
            "run_nonce":"33333333333333333333333333333333","round_nonce":"44444444444444444444444444444444",
            "bind_ip":"10.21.1.2","bind_port":32123,"target_ip":"10.21.1.3","target_port":43210,"payload_bytes":128,
            "request_nonces":(1..=count).map(|n| format!("{n:032x}")).collect::<Vec<_>>()}]});
    RegistrationPlan::decode(&serde_json::to_vec(&value).unwrap())
        .unwrap()
        .flows
        .remove(0)
}

#[test]
fn original_frame_spans_accumulate_split_coalesced_and_duplicate_ranges() {
    let plan = plan("tcp", 3);
    let mut coverage = FrameSpanCoverage::new(&plan, 1).unwrap();
    assert!(!coverage.add(&ReadFrameSpan::new(0, 0, 195)).unwrap());
    assert!(coverage.add(&ReadFrameSpan::new(1, 100, 195)).unwrap());
    assert!(!coverage.add(&ReadFrameSpan::new(1, 100, 195)).unwrap());
    assert!(!coverage.is_complete());
    assert!(coverage.add(&ReadFrameSpan::new(1, 0, 120)).unwrap());
    assert!(coverage.is_complete());
    assert!(!coverage.add(&ReadFrameSpan::new(2, 0, 195)).unwrap());
    assert!(spans_complete(
        [
            ReadFrameSpan::new(1, 100, 195),
            ReadFrameSpan::new(1, 0, 120)
        ]
        .iter(),
        1,
        &plan
    ));
}

#[test]
fn original_frame_spans_reject_gap_empty_overlong_and_unknown_slot() {
    let plan = plan("tcp", 1);
    let mut coverage = FrameSpanCoverage::new(&plan, 0).unwrap();
    assert!(coverage.add(&ReadFrameSpan::new(0, 0, 194)).unwrap());
    assert!(!coverage.is_complete());
    assert_eq!(
        coverage.add(&ReadFrameSpan::new(0, 0, 0)),
        Err(CaptureFailure::InvalidPlan)
    );
    assert_eq!(
        coverage.add(&ReadFrameSpan::new(0, 190, 196)),
        Err(CaptureFailure::InvalidPlan)
    );
    assert!(FrameSpanCoverage::new(&plan, 1).is_none());
    assert!(!spans_complete(
        [ReadFrameSpan::new(0, 0, 194)].iter(),
        0,
        &plan
    ));
}

#[test]
fn original_frame_spans_keep_udp_slots_distinct_and_bound_tcp_bitmap() {
    let plan = plan("udp", 2);
    let mut coverage = FrameSpanCoverage::new(&plan, 0).unwrap();
    assert!(!coverage.add(&ReadFrameSpan::new(1, 0, 1)).unwrap());
    assert!(!coverage.is_complete());
    assert!(coverage.add(&ReadFrameSpan::new(0, 0, 1)).unwrap());
    assert!(coverage.is_complete());
    assert!(!coverage.add(&ReadFrameSpan::new(0, 0, 1)).unwrap());
    let mut oversized = plan;
    oversized.protocol = Protocol::Tcp;
    oversized.payload_bytes = MAX_FRAME_WIRE_BYTES as u16;
    assert!(FrameSpanCoverage::new(&oversized, 0).is_none());
}

// Independent byte membership oracle: this never constructs a read or a Full.
fn compare_span_with_byte_membership(
    coverage: &mut FrameSpanCoverage,
    bytes: &mut [bool],
    span: ReadFrameSpan,
) {
    let start = usize::from(span.start);
    let end = usize::from(span.end);
    let expected = if span.slot != coverage.slot {
        Ok(false)
    } else if start >= end || end > bytes.len() {
        Err(CaptureFailure::InvalidPlan)
    } else {
        let changed = bytes[start..end].iter().any(|covered| !covered);
        bytes[start..end].fill(true);
        Ok(changed)
    };
    assert_eq!(coverage.add(&span), expected);
    assert_eq!(coverage.covered, bytes.iter().filter(|b| **b).count());
    assert_eq!(coverage.is_complete(), bytes.iter().all(|b| *b));
    for byte in 0..coverage.seen.len() * 64 {
        assert_eq!(
            coverage.seen[byte / 64] & (1 << (byte % 64)) != 0,
            bytes.get(byte).copied().unwrap_or(false)
        );
    }
}

fn pure_span_coverage(length: usize) -> FrameSpanCoverage {
    assert!((1..=MAX_FRAME_WIRE_BYTES).contains(&length));
    FrameSpanCoverage {
        slot: 1,
        length,
        seen: [0; MAX_FRAME_WIRE_BYTES.div_ceil(64)],
        covered: 0,
    }
}

#[test]
fn word_span_coverage_matches_byte_membership_for_original_frame_ranges() {
    for protocol in ["udp", "tcp"] {
        let empty = FrameSpanCoverage::new(&plan(protocol, 2), 1).unwrap();
        for start in 0..empty.length {
            for end in start + 1..=empty.length {
                let mut coverage = empty.clone();
                let mut bytes = vec![false; coverage.length];
                compare_span_with_byte_membership(
                    &mut coverage,
                    &mut bytes,
                    ReadFrameSpan::new(1, start as u16, end as u16),
                );
            }
        }
    }
}

#[test]
fn word_span_coverage_matches_byte_membership_at_all_maximum_frame_word_edges() {
    for start in 0..MAX_FRAME_WIRE_BYTES {
        for end in (64..MAX_FRAME_WIRE_BYTES)
            .step_by(64)
            .flat_map(|edge| [edge - 1, edge, edge + 1])
            .chain([MAX_FRAME_WIRE_BYTES])
            .filter(|end| *end > start)
        {
            let mut coverage = pure_span_coverage(MAX_FRAME_WIRE_BYTES);
            let mut bytes = vec![false; MAX_FRAME_WIRE_BYTES];
            compare_span_with_byte_membership(
                &mut coverage,
                &mut bytes,
                ReadFrameSpan::new(1, start as u16, end as u16),
            );
        }
    }
}

#[test]
fn word_span_coverage_preserves_overlaps_duplicates_invalid_and_other_slot_order() {
    for length in [1, 63, 64, 65, 127, 128, 129, 195, MAX_FRAME_WIRE_BYTES] {
        let mut coverage = pure_span_coverage(length);
        let mut bytes = vec![false; length];
        for start in (0..length).rev().step_by(3) {
            let end = (start + 67).min(length);
            for slot in [0, 1, 1, 2] {
                compare_span_with_byte_membership(
                    &mut coverage,
                    &mut bytes,
                    ReadFrameSpan::new(slot, start as u16, end as u16),
                );
            }
        }
        for slot in [1, 0, 2] {
            for (start, end) in [(0, 0), (1, 0), (length, length + 1), (0, length + 1)] {
                compare_span_with_byte_membership(
                    &mut coverage,
                    &mut bytes,
                    ReadFrameSpan::new(slot, start as u16, end as u16),
                );
            }
        }
        compare_span_with_byte_membership(
            &mut coverage,
            &mut bytes,
            ReadFrameSpan::new(1, 0, length as u16),
        );
        compare_span_with_byte_membership(
            &mut coverage,
            &mut bytes,
            ReadFrameSpan::new(1, 0, length as u16),
        );
        assert!(coverage.is_complete());
    }
}

#[tokio::test]
async fn full_loss_diagnostic_keeps_first_site_without_restoring_credit() {
    let (setup, _parent) = descriptor_scope().await;
    assert!(setup.session.full_loss.snapshot().is_none());
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::HistoryContended);
    let mut later = negative_observer(&setup.session);
    later.arm();
    drop(later);
    let value = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    assert_eq!(
        value["first_original_full_retention_loss"],
        "history_contended"
    );
    assert_eq!(setup.session.gaps.load(Ordering::Relaxed), 2);
    assert_no_full_credit(&setup.session, false);
}

#[tokio::test]
async fn full_loss_diagnostic_is_nonblocking_scoped_and_survives_retirement() {
    let (first, _first_parent) = descriptor_scope().await;
    let (second, _second_parent) = descriptor_scope().await;
    let held = first.session.state.try_lock().unwrap();
    let mut observer = negative_observer(&first.session);
    observer.arm();
    drop(observer);
    first.session.retire();
    assert_eq!(
        first.session.full_loss.snapshot(),
        Some(FullRetentionLossReason::ObservationDropped)
    );
    assert!(second.session.full_loss.snapshot().is_none());
    drop(held);
    assert_no_full_credit(&first.session, false);
    assert_no_full_credit(&second.session, true);
}

#[test]
fn full_loss_diagnostic_serializes_all_sites_without_publication_authority() {
    use super::super::FullRetentionLoss;
    use FullRetentionLossReason::*;
    for (reason, expected) in [
        (ObservationDropped, "observation_dropped"),
        (EncryptionCaptureFailed, "encryption_capture_failed"),
        (PublicationClockUnavailable, "publication_clock_unavailable"),
        (
            PublicationClockAlreadyRecorded,
            "publication_clock_already_recorded",
        ),
        (PublicationMissing, "publication_missing"),
        (PublicationIdentityMismatch, "publication_identity_mismatch"),
        (
            PublicationObservationMissing,
            "publication_observation_missing",
        ),
        (RetentionClockUnavailable, "retention_clock_unavailable"),
        (HistoryContended, "history_contended"),
        (HistoryCapacity, "history_capacity"),
        (HistoryInvalid, "history_invalid"),
    ] {
        let loss = FullRetentionLoss::new();
        loss.record(reason);
        loss.record(HistoryInvalid);
        assert_eq!(serde_json::to_value(loss.snapshot()).unwrap(), expected);
    }
    assert_eq!(
        FullRetentionLossReason::history(CaptureFailure::Capacity),
        HistoryCapacity
    );
    assert_eq!(
        FullRetentionLossReason::history(CaptureFailure::InvalidPlan),
        HistoryInvalid
    );
}

#[test]
fn encryption_capture_diagnostic_serializes_rejection_sites_without_authority() {
    use super::super::FullRetentionLoss;
    use FullRetentionLossReason::*;
    for (reason, expected) in [
        (InputScopeUnavailable, "input_scope_unavailable"),
        (InputScopeNotLive, "input_scope_not_live"),
        (
            InputReadObservationIncomplete,
            "input_read_observation_incomplete",
        ),
        (InputDeviceRetired, "input_device_retired"),
        (InputClockBeforeRead, "input_clock_before_read"),
        (InputRegistryContended, "input_registry_contended"),
        (InputRegistryPoisoned, "input_registry_poisoned"),
        (InputFlowInvalid, "input_flow_invalid"),
        (InputRouteMismatch, "input_route_mismatch"),
        (InputPeerMismatch, "input_peer_mismatch"),
        (InputPeerOwnerUnavailable, "input_peer_owner_unavailable"),
        (PeerEncryptionMismatch, "peer_encryption_mismatch"),
        (ResponseEncryptionMismatch, "response_encryption_mismatch"),
        (RoomPermitMismatch, "room_permit_mismatch"),
        (CipherOwnerMismatch, "cipher_owner_mismatch"),
        (EncryptionCopyFailed, "encryption_copy_failed"),
        (InputBindingNotRouted, "input_binding_not_routed"),
        (InputOwnerMismatch, "input_owner_mismatch"),
        (InputReadPeerRejected, "input_read_peer_rejected"),
        (InputPacketLengthMismatch, "input_packet_length_mismatch"),
        (InputPacketDigestMismatch, "input_packet_digest_mismatch"),
        (InputFrameBindingsInvalid, "input_frame_bindings_invalid"),
        (RoutedPeerMismatch, "routed_peer_mismatch"),
        (RoutedDestinationMismatch, "routed_destination_mismatch"),
        (RoutedRoomPermitRejected, "routed_room_permit_rejected"),
    ] {
        let loss = FullRetentionLoss::new();
        loss.record(reason);
        assert_eq!(serde_json::to_value(loss.snapshot()).unwrap(), expected);
    }
}

#[tokio::test]
async fn encryption_capture_diagnostic_keeps_first_rejection_after_later_loss() {
    let (setup, _parent) = descriptor_scope().await;
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::InputRegistryContended);
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::PeerEncryptionMismatch);
    let value = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    assert_eq!(
        value["first_original_full_retention_loss"],
        "input_registry_contended"
    );
    assert_eq!(setup.session.gaps.load(Ordering::Relaxed), 2);
    assert_no_full_credit(&setup.session, false);
}

#[tokio::test]
async fn encryption_capture_diagnostic_records_without_registry_lock_or_rearm() {
    let (setup, _parent) = descriptor_scope().await;
    let held = setup.session.state.try_lock().unwrap();
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::InputRegistryContended);
    assert!(!setup.session.full_complete.load(Ordering::Acquire));
    assert!(setup.session.read_complete.load(Ordering::Acquire));
    assert!(setup.session.inbound_complete.load(Ordering::Acquire));
    drop(held);
    assert_no_full_credit(&setup.session, false);
}

#[test]
fn read_peer_revalidation_diagnostic_codes_append_without_changing_old_codes_or_first_loss() {
    use super::super::FullRetentionLoss;
    use crate::overlay_requests::{
        OverlayCreditLockSite as Lock, OverlayCreditOutcome as Outcome, OverlayCreditStale as Stale,
    };
    use FullRetentionLossReason::*;
    assert_eq!(RoutedRoomPermitRejected as u8, 36);
    assert_eq!(InputReadPeerRejected as u8, 30);
    assert_eq!(InputRegistryContended as u8, 17);
    for (code, reason, text) in [
        (37, ReadPeerOwnerUnavailable, "read_peer_owner_unavailable"),
        (38, ReadPeerBindingsInvalid, "read_peer_bindings_invalid"),
        (39, ReadPeerIdentityRejected, "read_peer_identity_rejected"),
        (40, ReadPeerEpochContended, "read_peer_epoch_contended"),
        (
            41,
            ReadPeerConnectionsContended,
            "read_peer_connections_contended",
        ),
        (
            42,
            ReadPeerMembershipContended,
            "read_peer_membership_contended",
        ),
        (
            43,
            ReadPeerGenerationChanged,
            "read_peer_generation_changed",
        ),
        (44, ReadPeerLifecycleChanged, "read_peer_lifecycle_changed"),
        (45, ReadPeerStateRejected, "read_peer_state_rejected"),
    ] {
        assert_eq!(reason as u8, code);
        let first = FullRetentionLoss::new();
        first.record(reason);
        first.record(InputReadPeerRejected);
        assert_eq!(serde_json::to_value(first.snapshot()).unwrap(), text);
    }
    assert_eq!(
        FullRetentionLossReason::read_peer(Outcome::Contended(Lock::Emit)),
        InputReadPeerRejected
    );
    assert_eq!(
        FullRetentionLossReason::read_peer(Outcome::Stale(Stale::PeerState)),
        ReadPeerStateRejected
    );
}
