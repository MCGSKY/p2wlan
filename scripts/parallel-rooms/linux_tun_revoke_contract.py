"""Bounded supplemental room-revocation metadata; dictionaries grant no authority."""
from collections import Counter

from linux_tun_contract import manifest as original_manifest
from linux_tun_live_window import OriginalWriteWindows
import linux_tun_native_transaction as native

SCOPE = "linux_same_host_kernel_tun_original_room_revocation"


def kernel_evidence_passed(report, *, room_revocation):
    """One report/exit rule; a negative scope grants no all-positive credit."""
    if room_revocation:
        negative = report.get("room_revocation")
        return (report.get("scope") == SCOPE and isinstance(negative, dict)
                and negative.get("scope") == "actual_survivor_original_room_refusal"
                and negative.get("passed") is True)
    original = report.get("original_kernel_read_observations")
    return (isinstance(original, dict) and original.get("passed") is True
            and original.get("full128_owner_evidence_complete") is True)


def exit_status(report, *, write_facts, kernel_read_facts, room_revocation):
    if room_revocation and not (write_facts and kernel_read_facts):
        return 1
    writes = report.get("original_write_observations") or {}
    control = report.get("kernel_control_cleanup") or {}
    write_ok = not write_facts or writes.get("passed") is True
    kernel_ok = not kernel_read_facts or (
        kernel_evidence_passed(report, room_revocation=room_revocation)
        and control.get("complete") is True)
    return int(report.get("passed") is not True or not write_ok or not kernel_ok)


def require(value, reason):
    if not value:
        raise ValueError(reason)


def manifest(run_nonce, round_nonce):
    return [e for e in original_manifest(run_nonce, round_nonce) if e["protocol"] == "udp"]


def summarize(entries):
    require([(e["protocol"], e["direction"], e["count"]) for e in entries]
            == [("udp", "a-to-b", 8), ("udp", "b-to-a", 8)], "revocation_original16_manifest")
    counts = Counter()
    for entry in entries:
        rows = entry.get("records")
        if rows is None:
            counts["not_started" if entry["outcome"] == "not_started" else "unknown"] += 8
        else:
            require(len(rows) == 8, "revocation_original_eight_records")
            counts.update(r["status"] for r in rows)
    return dict(denominator="all_16_prescheduled_supplementary_revocation_requests_including_missing",
                prescheduled_requests=16, success_requests=counts["success"], terminal_counts=dict(counts),
                all_responses_observed=counts["success"] == 16,
                canonical_current_owner_verified=False, no_native_credit_from_summary=True)


class DeferredLastWindow(OriginalWriteWindows):
    """Defer only original slot7 metadata; application writes/times never change."""
    def __init__(self, capture, endpoints):
        super().__init__(capture, endpoints)
        self.pending = None
        self.release_attempted = False
        self.released_monotonic_ns = None

    def deliver(self, window, observed_ns):
        if window["sequence"] != 7:
            return super().deliver(window, observed_ns)
        require(self.pending is None and not self.release_attempted, "revocation_window_already_retained")
        self.pending = dict(window)
        return dict(sequence=7, delivered=False, delivered_endpoints=0, window=dict(window),
                    controller_observed_ns=observed_ns, reason="original_window_deferred_before_revoke")

    def release_to_survivor(self, endpoint, observed_ns):
        require(not self.release_attempted, "revocation_window_release_once")
        self.release_attempted = True  # Even a refused/partial first write is terminal.
        window, self.pending = self.pending, None
        require(not self.closed and self.gap is None and window is not None
                and any(endpoint is owned for owned in self.endpoints), "revocation_original_endpoint_or_window_missing")
        require(window["complete_returned_ns"] <= observed_ns < window["original_deadline_ns"],
                "revocation_original_window_expired")
        try:
            endpoint.observe_original_write_window(window)
        except (OSError, ValueError):
            self.gap = "revocation_original_nonblocking_write_failed"
            raise
        self.released_monotonic_ns = observed_ns
        self.requests[7].update(delivered_endpoints=1,
                                reason="original_window_withheld_from_departed_endpoint")
        return dict(window)

    def seal(self):
        self.pending = None
        self.release_attempted = True
        super().seal()


def rows(snapshot, producer):
    selected = [r for r in snapshot["requests"] if r["producer_scope"] == producer]
    require(len(selected) == 8 and {r["sequence"] for r in selected} == set(range(8)),
            "revocation_original_eight_slots")
    return sorted(selected, key=lambda r: r["sequence"])


def historical_last_sources(snapshot, row, window):
    """Compare retained original sources, without inventing a native commit."""
    require(all(snapshot[k] is True for k in ["original_read_observation_complete",
            "original_full_retention_complete", "incoming_provenance_complete"]), "revocation_source_gap")
    require(row["sequence"] == 7 and row["protocol"] == "udp"
            and row["kernel_frame_read_complete"] is True and row["flow_invalid"] is False
            and row["historical_frame_full_complete"] is True
            and row["incoming_frame_system_write_complete"] is True
            and row["incoming_flow_invalid"] is False, "revocation_original_last_sources_missing")
    sent, end = window["original_sent_ns"], window["original_deadline_ns"]
    require(sent <= row["first_read_monotonic_ns"] <= row["last_read_monotonic_ns"] < end
            and window["complete_returned_ns"] <= snapshot["observed_monotonic_ns"] < end,
            "revocation_original_source_deadline")
    peer = row["original_peer"]
    require(peer["known"] is True and peer["capture_failure"] is None, "revocation_original_peer_missing")
    if row["kind"] == "request":
        room = row["original_request_room"]
        require(room["known"] is True and room["restricted"] is True
                and room["capture_failure"] is None, "revocation_original_request_room_missing")
    else:
        source = row["original_response_input"]
        require(row["kind"] == "response" and source["known"] is True
                and source["original_room_captured"] is True and source["original_room_restricted"] is True
                and source["original_system_write_contributors"] > 0
                and source["capture_failure"] is None, "revocation_original_response_room_missing")
    histories = []
    sessions = set()
    for name, ordinal in [("historical_full_packets", "read_ordinal"),
                          ("system_tun_full_writes", "write_ordinal")]:
        packets = snapshot[name]
        require(isinstance(packets, list) and len(packets) <= 1024, "revocation_history_capacity")
        chosen = [p for p in packets if p["flow"] == row["flow"]
                  and any(s["slot"] == 7 for s in p["spans"])]
        require(chosen and len({p[ordinal] for p in chosen}) == len(chosen), "revocation_history_missing_or_duplicate")
        covered = set()
        for packet in chosen:
            require(native.integer(packet[ordinal], 1) and packet["packet_len"] > 0
                    and len(packet["packet_sha256"]) == 64, "revocation_source_identity_missing")
            native.add_spans(packet, 7, 1, covered)
            if name == "historical_full_packets":
                require(sent <= packet["read_monotonic_ns"] <= packet["publication_observed_monotonic_ns"]
                        <= packet["full_observed_monotonic_ns"] <= snapshot["observed_monotonic_ns"]
                        and packet["encryption_generation"] == peer["network_generation"]
                        and packet["encryption_peer_lifecycle"] == peer["peer_lifecycle"]
                        and packet["physical_path"] == "udp", "revocation_historical_full_identity")
                sessions.add(packet["encryption_session_instance"])
            else:
                require(packet["scope"] == "original_authenticated_system_tun_full_history_only"
                        and sent <= packet["authenticated_observed_monotonic_ns"]
                        <= packet["write_observed_monotonic_ns"] <= snapshot["observed_monotonic_ns"]
                        and packet["network_generation"] == peer["network_generation"]
                        and packet["peer_lifecycle"] == peer["peer_lifecycle"]
                        and packet["original_session_role"] == "active"
                        and len(packet["original_room_captured"]) == len(packet["spans"])
                        == len(packet["original_room_restricted"])
                        and all(value is True for value in packet["original_room_captured"])
                        and all(value is True for value in packet["original_room_restricted"])
                        and packet["canonical_current_owner_verified"] is False,
                        "revocation_historical_write_identity")
                sessions.add(packet["session_instance"])
        require(covered == {0}, "revocation_original_full_byte_coverage")
        histories.append(chosen)
    require(len(sessions) == 1 and next(iter(sessions)) > 0, "revocation_mixed_original_sessions")
    if row["kind"] == "request":
        require(max(p["publication_observed_monotonic_ns"] for p in histories[0])
                <= min(p["authenticated_observed_monotonic_ns"] for p in histories[1]),
                "revocation_response_precedes_original_publication")
    else:
        require(max(p["write_observed_monotonic_ns"] for p in histories[1])
                <= min(p["read_monotonic_ns"] for p in histories[0]),
                "revocation_response_precedes_original_write")
    return dict(full=histories[0], writes=histories[1])


def refused_credit(value):
    require(isinstance(value, dict) and value["status"] == "stale"
            and value["owner_check"] == "room" and value["outcome"] == "Stale(RoomAuthority)"
            and all(value[k] is False for k in ["once_committed", "physical_send_verified",
                    "canonical_current_owner_verified", "native_os_write_verified"])
            and value["commit_monotonic_ns"] is None, "revocation_original_room_not_refused")
