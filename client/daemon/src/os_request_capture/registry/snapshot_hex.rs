//! Immutable snapshot bytes. Formatting runs only when the DTO is serialized,
//! after the sole registry guard is released; it never re-reads live state.
use serde::Serializer;

pub(super) fn serialize<S: Serializer, const N: usize>(
    bytes: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    // The only supported snapshot widths are fixed identifiers and SHA256.
    // This function has no clock, owner, metadata-lock or publication access.
    let encoded = hex::encode(bytes);
    serializer.serialize_str(&encoded)
}

// These serializers receive copied outcomes only. Debug text is wire-format
// metadata, never parsed for admission, and must not run under the registry.
#[cfg(any(target_os = "linux", all(unix, test)))]
pub(super) fn serialize_debug<S: Serializer, T: std::fmt::Debug>(
    value: &T,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format!("{value:?}"))
}

pub(super) fn serialize_optional_debug<S: Serializer, T: std::fmt::Debug>(
    value: &Option<T>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.serialize_some(&format!("{value:?}")),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::os_request_capture::plan::RegistrationPlan;
    use serde_json::json;

    #[tokio::test]
    async fn original_snapshot_hex_is_frozen_before_serialization_without_owner_or_rearm() {
        let (setup, _parent) = full::tests::descriptor_scope().await;
        let plan = json!({"schema_version":1,
            "capture_id":"11111111111111111111111111111111",
            "producer_scope":"dededededededededededededededede", "flows":[{
            "protocol":"udp", "kind":"request", "peer_id":"hex-snapshot-peer",
            "run_nonce":"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
            "round_nonce":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "bind_ip":"10.21.1.2", "bind_port":32123,
            "target_ip":"10.21.1.3", "target_port":43210, "payload_bytes":128,
            "request_nonces":["bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc"]}]});
        setup
            .session
            .register(RegistrationPlan::decode(&serde_json::to_vec(&plan).unwrap()).unwrap())
            .unwrap();
        let captured = setup.session.snapshot().unwrap();
        assert_eq!(captured.capture_id, [0x11; 16]);
        assert_eq!(captured.requests[0].producer_scope, [0xde; 16]);
        assert_eq!(captured.requests[0].run_nonce, [0x0f; 16]);
        assert_eq!(captured.requests[0].round_nonce, [0xa1; 16]);
        assert_eq!(captured.requests[0].request_nonce, [0xbc; 16]);
        setup
            .session
            .original_full_retention_lost(FullRetentionLossReason::InputRegistryContended);
        // Serialize the already captured value while the actual sole registry
        // is held. No later mutation, try-lock or owner lookup may refill it.
        let held = setup.session.state.try_lock().unwrap();
        let encoded = serde_json::to_value(captured).unwrap();
        assert_eq!(encoded["capture_id"], plan["capture_id"]);
        for key in ["producer_scope", "run_nonce", "round_nonce"] {
            let expected = if key == "producer_scope" {
                &plan[key]
            } else {
                &plan["flows"][0][key]
            };
            assert_eq!(&encoded["requests"][0][key], expected);
        }
        assert_eq!(
            encoded["requests"][0]["request_nonce"],
            plan["flows"][0]["request_nonces"][0]
        );
        assert_eq!(encoded["original_full_retention_complete"], true);
        assert_eq!(
            encoded["first_original_full_retention_loss"],
            serde_json::Value::Null
        );
        for key in [
            "daemon_registration_verified",
            "physical_send_verified",
            "canonical_current_owner_verified",
        ] {
            assert_eq!(encoded[key], false);
        }
        assert_eq!(encoded["historical_full_packets"], json!([]));
        assert_eq!(encoded["system_tun_full_writes"], json!([]));
        assert_eq!(setup.session.gaps.load(Ordering::Relaxed), 1);
        drop(held);
        let later = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
        assert_eq!(later["original_full_retention_complete"], false);
        assert_eq!(
            later["first_original_full_retention_loss"],
            "input_registry_contended"
        );
        assert_eq!(later["gaps"], 1);
    }
}
