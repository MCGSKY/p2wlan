//! A bounded preparation lease into the original socket owner, never a path,
//! generation or budget authority. Rejected resources stay with the outer
//! preparation future so their final drop follows its actual epoch guard.
use super::*;

pub(crate) struct PreparedCommittedSocket {
    transport_instance_id: u64,
    peer_id: String,
    local_endpoint: SocketAddr,
    generation: u64,
    socket_index: usize,
    socket: Arc<UdpSocket>,
    lease: DynamicSocketSendLease,
}

impl UdpTransport {
    pub(crate) fn try_prepare_direct_business_socket_resource(
        &self,
        peer_id: &str,
    ) -> Option<PreparedCommittedSocket> {
        let session = self.peers.peer_session_generation_sync(peer_id)?;
        if !self.peers.peer_supports_dplpmtud_sync(peer_id, session) {
            return None;
        }
        let pair = self.peers.direct_commit_pair_snapshot_sync(peer_id)?;
        let local_endpoint = pair.local_endpoint?;
        let generation = self.peers.current_network_generation_sync();
        if pair.generation != generation {
            return None;
        }
        self.try_prepare_committed_socket_resource(peer_id, local_endpoint, generation)
    }

    pub(super) fn try_prepare_committed_socket_resource(
        &self,
        peer_id: &str,
        local_endpoint: SocketAddr,
        generation: u64,
    ) -> Option<PreparedCommittedSocket> {
        if generation != self.peers.current_network_generation_sync() {
            return None;
        }
        let (socket_index, socket, lease) =
            if let Some(fixed) = self.resolve_committed_fixed_socket_with_lease(local_endpoint) {
                fixed
            } else {
                let state = self.socket_state.try_lock().ok()?;
                self.resolve_committed_dynamic_socket_with_lease(
                    &state,
                    peer_id,
                    local_endpoint,
                    generation,
                )?
            };
        Some(PreparedCommittedSocket {
            transport_instance_id: self.transport_instance_id,
            peer_id: peer_id.to_owned(),
            local_endpoint,
            generation,
            socket_index,
            socket,
            lease,
        })
    }

    pub(super) fn try_take_prepared_committed_socket(
        &self,
        peer_id: &str,
        local_endpoint: SocketAddr,
        generation: u64,
        resource: &mut Option<PreparedCommittedSocket>,
    ) -> Option<(usize, Arc<UdpSocket>, DynamicSocketSendLease)> {
        let prepared = resource.as_ref()?;
        if prepared.transport_instance_id != self.transport_instance_id
            || prepared.peer_id != peer_id
            || prepared.local_endpoint != local_endpoint
            || prepared.generation != generation
            || generation != self.peers.current_network_generation_sync()
            || prepared.socket.local_addr().ok() != Some(local_endpoint)
        {
            return None;
        }
        let current = if prepared.socket_index == IPV6_SOCKET_INDEX {
            self.ipv6_socket
                .as_ref()
                .is_some_and(|socket| Arc::ptr_eq(socket, &prepared.socket))
        } else if prepared.socket_index < DYNAMIC_SOCKET_INDEX_BASE {
            self.active_sockets()
                .get(prepared.socket_index)
                .is_some_and(|socket| Arc::ptr_eq(socket, &prepared.socket))
        } else {
            // A busy or changed dynamic owner uses the unchanged resolver.
            // There is no second wait policy, retry or independently trusted
            // registry mirror. The original lease owner must match too.
            let state = self.socket_state.try_lock().ok()?;
            state
                .dynamic
                .get(&prepared.socket_index)
                .is_some_and(|entry| {
                    entry.peer_id == peer_id
                        && entry.network_generation == generation
                        && entry.phase.is_usable()
                        && entry.permits_ordinary_traffic()
                        && Arc::ptr_eq(&entry.socket, &prepared.socket)
                        && Arc::ptr_eq(&entry.send_leases, &prepared.lease.state)
                })
        };
        if !current {
            return None;
        }
        let prepared = resource.take()?;
        Some((prepared.socket_index, prepared.socket, prepared.lease))
    }
}
