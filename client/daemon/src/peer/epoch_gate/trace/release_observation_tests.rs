//! Real-gate metadata only. A queued fair handoff can reject the original
//! single actual try after the preceding guard has actually been released.
use super::*;
use crate::peer::NetworkEpochGate;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn epoch_release_after_unlock_cannot_attribute_reserved_handoff_to_old_holder() {
    let gate = Arc::new(NetworkEpochGate::new(()));
    let lease = gate.capture_diagnostics(7, [1; 16], Instant::now() + Duration::from_secs(30));
    let held = gate.lock().await;
    let token = held.token.unwrap();
    let mut queued = Box::pin(gate.lock());
    assert!(futures_util::poll!(queued.as_mut()).is_pending());
    drop(held);
    let context = EpochTryContext {
        capture_owner: 7,
        capture_id: [1; 16],
        run: [2; 16],
        round: [3; 16],
        request_nonce: [4; 16],
        sequence: 0,
        protocol: "tcp",
        kind: "request",
        first_read_ordinal: 25,
        read_peer_input_ordinal: None,
    };
    // Keep Tokio fairness and the one actual try. This must still refuse:
    // recording a release is no permission to bypass the reserved mutex.
    assert!(gate.try_lock_original(Some(context)).is_err());
    let value = serde_json::to_value(lease.snapshot().unwrap()).unwrap();
    assert!(value["holder"].is_null());
    assert_eq!(value["last_completed_holder"]["token"], token);
    assert_eq!(
        value["last_completed_holder_interval_covers_failed_try"],
        false
    );
    if cfg!(target_os = "linux") {
        let release = &value["release_after_unlock_observation"];
        assert_eq!(release["token"], token);
        assert_eq!(release["matches_recorded_first_holder"], false);
        assert_eq!(release["matches_recorded_last_completed_holder"], true);
        assert_eq!(release["definitely_before_failed_try"], true);
    } else {
        assert!(value.get("release_after_unlock_observation").is_none());
    }
    for key in [
        "native_os_write_verified",
        "physical_send_verified",
        "canonical_current_owner_verified",
    ] {
        assert_eq!(value[key], false);
    }
    let first = value.to_string();
    let later = queued.await;
    drop(later);
    assert_eq!(
        serde_json::to_value(lease.snapshot().unwrap())
            .unwrap()
            .to_string(),
        first
    );
}
