//! Output storage without keys, counters or session authority.

use super::{Result, TransportSession, WireGuardError};
use crate::types::{AEAD_TAG_SIZE, TRANSPORT_MSG_MIN_SIZE, TYPE_TRANSPORT};
use p2pnet_crypto::aead::encrypt_in_place_with_counter;

const HEADER_SIZE: usize = TRANSPORT_MSG_MIN_SIZE - AEAD_TAG_SIZE;

/// One zeroed wire buffer that may be allocated before acquiring session locks.
/// Preparing it neither encrypts plaintext nor consumes a session counter.
pub struct PreparedTransportBuffer {
    wire: Vec<u8>,
}

impl PreparedTransportBuffer {
    pub fn new(plaintext_len: usize) -> Result<Self> {
        let wire_len = plaintext_len
            .checked_add(TRANSPORT_MSG_MIN_SIZE)
            .ok_or_else(|| {
                WireGuardError::InvalidPacket("transport buffer length overflow".into())
            })?;
        let mut wire = Vec::new();
        wire.try_reserve_exact(wire_len).map_err(|error| {
            WireGuardError::InvalidPacket(format!("transport buffer allocation failed: {error}"))
        })?;
        wire.resize(wire_len, 0);
        Ok(Self { wire })
    }

    /// Read-only access for observing the concrete allocation's length/capacity.
    pub fn buffer(&self) -> &Vec<u8> {
        &self.wire
    }
}

impl TransportSession {
    /// Use prepared storage with this session's current key, index and counter.
    /// Plaintext is copied only here, at the original encryption boundary.
    pub fn encrypt_into_prepared(
        &mut self,
        packet: &[u8],
        mut prepared: PreparedTransportBuffer,
    ) -> Result<Vec<u8>> {
        let ((), counter) = self.encrypt_payload(|key, counter| {
            if prepared.wire.len().checked_sub(TRANSPORT_MSG_MIN_SIZE) != Some(packet.len()) {
                return Err(WireGuardError::InvalidPacket(
                    "prepared transport buffer length mismatch".into(),
                ));
            }
            let payload_end = HEADER_SIZE + packet.len();
            let payload = &mut prepared.wire[HEADER_SIZE..payload_end];
            payload.copy_from_slice(packet);
            let tag = encrypt_in_place_with_counter(key, counter, b"", payload)?;
            prepared.wire[payload_end..].copy_from_slice(&tag);
            Ok(())
        })?;
        prepared.wire[..4].copy_from_slice(&u32::from(TYPE_TRANSPORT).to_le_bytes());
        prepared.wire[4..8].copy_from_slice(&self.peer_index.to_le_bytes());
        prepared.wire[8..HEADER_SIZE].copy_from_slice(&counter.to_le_bytes());
        Ok(prepared.wire)
    }
}
