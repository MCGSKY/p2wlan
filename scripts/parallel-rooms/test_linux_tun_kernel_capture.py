"""Control-stream and pure deadline controls; no simulated kernel-read credit."""
import copy
import json
from pathlib import Path
import socket
import sys
import threading
import time
from types import SimpleNamespace
import unittest

import linux_tun_kernel_capture as kernel


class DeadlineControls(unittest.TestCase):
    def setUp(self):
        self.write = dict(sequence=0, request_nonce="f" * 32, original_sent_ns=100,
                          original_deadline_ns=200, accepted_in_original_deadline=True)
        self.row = dict(kernel_frame_read_complete=True, flow_invalid=False,
                        first_read_monotonic_ns=101, last_read_monotonic_ns=199)

    def test_full128_and_original_half_open_deadline_are_retained_as_data_only(self):
        value = kernel.read_pair(self.row, self.row, self.write)
        self.assertEqual(value["request_nonce"], "f" * 32)
        self.assertTrue(value["source_kernel_read_in_original_deadline"])
        self.assertFalse(any("verified" in k for k in value))
        for first, last in [(99, 199), (101, 200), (102, 101), (True, 199), (None, None)]:
            bad = dict(self.row, first_read_monotonic_ns=first, last_read_monotonic_ns=last)
            self.assertFalse(kernel.read_pair(bad, self.row, self.write)["source_kernel_read_in_original_deadline"])

    def test_conflict_partial_and_late_response_do_not_borrow_a_fresh_window(self):
        for change in [dict(flow_invalid=True), dict(kernel_frame_read_complete=False),
                       dict(first_read_monotonic_ns=201, last_read_monotonic_ns=202)]:
            bad = dict(self.row, **change)
            value = kernel.read_pair(self.row, bad, self.write)
            self.assertTrue(value["source_kernel_read_in_original_deadline"])
            self.assertFalse(value["response_kernel_read_in_original_deadline"])

    def test_missing_original_write_time_cannot_be_replaced_by_read_time(self):
        for name in ["original_sent_ns", "original_deadline_ns"]:
            write = dict(self.write, **{name: None})
            self.assertFalse(kernel.read_pair(self.row, self.row, write)["source_kernel_read_in_original_deadline"])

    def test_capacity_failure_precedes_endpoint_or_child_access(self):
        captures = kernel.KernelCaptures.__new__(kernel.KernelCaptures)
        captures.entries, captures.expected_entries = [None] * 4, 4
        record = captures.prepare(None, {}, None, None, None, None)
        self.assertEqual(record["gap"], "original_kernel_probe_capacity")
        self.assertEqual(len(captures.entries), 4)

    def test_interrupted_collection_never_queries_a_process_or_control_connection(self):
        captures = kernel.KernelCaptures.__new__(kernel.KernelCaptures)
        entry = {"records": [{"status": "not_sent"}] * 8}
        captures.expected_entries, captures.entries = 2, [{"entry": entry, "capture": None,
                                                         "endpoints": None, "result": None}]
        before = copy.deepcopy(entry["records"])
        result = captures.finish(captures.entries[0])
        self.assertFalse(result["passed"])
        self.assertFalse(result["physical_send_verified"])
        self.assertFalse(result["canonical_current_owner_verified"])
        self.assertEqual(entry["records"], before)
        self.assertEqual(result["request_count"], 8)
        self.assertEqual(result["gap_reason"], "original_kernel_collection_failed:original_kernel_registration_unavailable")


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "actual Unix control sockets required")
class ActualStreamControls(unittest.TestCase):
    def exchange(self, response, *, close=False, operation=None, inspect_request=None):
        parent, peer = socket.socketpair()
        endpoint = kernel.Endpoint(parent, None, None, "a" * 32, "b" * 32)
        failures = []
        def serve():
            try:
                peer.settimeout(2)
                data = bytearray()
                while b"\n" not in data:
                    block = peer.recv(4096)
                    if not block:
                        return
                    data.extend(block)
                if inspect_request is not None:
                    inspect_request(json.loads(data), time.monotonic_ns())
                if not close:
                    peer.sendall(response)
            except BaseException as error:
                failures.append(error)
            finally:
                peer.close()
        worker = threading.Thread(target=serve)
        worker.start()
        try:
            return endpoint.exchange({"op": "snapshot"}) if operation is None else operation(endpoint)
        finally:
            endpoint.close()
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])

    def test_actual_socket_reply_retains_labels_without_minting_kernel_authority(self):
        value, _ = self.exchange(kernel.encode(dict(capture_id="a" * 32, owner=1, scope="registered_expected_inputs_only")))
        self.assertEqual(value["scope"], "registered_expected_inputs_only")
        self.assertNotIn("kernel_frame_read_complete", value)

    def test_actual_control_exchange_supplies_only_its_original_one_second_deadline(self):
        def inspect(value, received):
            self.assertEqual(value["op"], "snapshot")
            self.assertIs(type(value["original_deadline_ns"]), int)
            self.assertGreater(value["original_deadline_ns"], received)
            self.assertLessEqual(value["original_deadline_ns"] - received, 1_000_000_000)
        self.exchange(kernel.encode(dict(capture_id="a" * 32, owner=1)), inspect_request=inspect)

    def test_actual_reply_rejected_before_birth_validation_is_still_retained_as_raw_data(self):
        raw = kernel.encode(dict(capture_id="a" * 32, owner=1, scope="registered_expected_inputs_only"))
        def reject(endpoint):
            with self.assertRaises(kernel.CaptureError) as caught:
                endpoint.snapshot()
            self.assertEqual(caught.exception.code, "kernel_original_daemon_birth_namespace_clock_mismatch")
            self.assertEqual(endpoint.raw_snapshots, [raw])
        self.exchange(raw, operation=reject)

    def test_expired_original_exchange_sends_no_control_bytes(self):
        parent, peer = socket.socketpair()
        endpoint = kernel.Endpoint(parent, None, None, "a" * 32, "b" * 32)
        try:
            with self.assertRaises(kernel.CaptureError) as caught:
                endpoint.exchange({"op": "snapshot"}, deadline=time.monotonic() - 1)
            self.assertEqual(caught.exception.code, "kernel_control_original_deadline")
            peer.setblocking(False)
            with self.assertRaises(BlockingIOError):
                peer.recv(1)
        finally:
            endpoint.close()
            peer.close()

    def test_actual_socket_EOF_wrong_scope_and_duplicate_JSON_are_rejected(self):
        for raw, close in [(b"", True), (kernel.encode(dict(capture_id="c" * 32, owner=1)), False),
                           (b'{"capture_id":"' + b'a' * 32 + b'","owner":1,"owner":2}\n', False)]:
            with self.assertRaises(ValueError):
                self.exchange(raw, close=close)


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "actual Unix control sockets required")
class ActualSnapshotPairControls(unittest.TestCase):
    """Actual socket replies containing labels only, with no native fact rows."""

    def collect(self, *, invalid_first=False):
        original = SimpleNamespace(boot_id="metadata-only", pid=1, parent_pid=2,
                                   uid=3, start_ticks=4, net_namespace="metadata-only")
        clock = dict(clock_name="CLOCK_MONOTONIC", boot_id=original.boot_id,
                     process_id=original.pid, parent_pid=original.parent_pid,
                     uid=original.uid, start_ticks=original.start_ticks,
                     net_namespace=original.net_namespace)
        value = dict(schema_version=2, capture_id="a" * 32, owner=1,
                     scope="registered_native_frame_capture", active=True,
                     producer_scope="b" * 32, registration_revision=0,
                     observed_monotonic_ns=1, requests=[], clock_scope=clock,
                     daemon_registration_verified=False, physical_send_verified=False,
                     canonical_current_owner_verified=False)
        endpoints, workers, requests, errors = [], [], [], []

        def serve(peer, response):
            try:
                peer.settimeout(2)
                data = bytearray()
                while b"\n" not in data:
                    block = peer.recv(4096)
                    if not block:
                        return
                    data.extend(block)
                requests.append(json.loads(data))
                peer.sendall(kernel.encode(response))
            except BaseException as error:
                errors.append(error)
            finally:
                peer.close()

        for index in range(2):
            parent, peer = socket.socketpair()
            endpoint = kernel.Endpoint(parent, None, original, "a" * 32, "b" * 32)
            endpoints.append(endpoint)
            response = copy.deepcopy(value)
            response["incoming_provenance_complete"] = index == 1
            if invalid_first and index == 0:
                response["clock_scope"]["start_ticks"] += 1
            worker = threading.Thread(target=serve, args=(peer, response))
            worker.start()
            workers.append(worker)
        deadline = time.monotonic() + 1
        try:
            if invalid_first:
                with self.assertRaises(kernel.CaptureError) as caught:
                    kernel.snapshot_pair(endpoints, deadline=deadline)
                self.assertEqual(caught.exception.code, "kernel_original_daemon_birth_namespace_clock_mismatch")
            else:
                snapshots = kernel.snapshot_pair(endpoints, deadline=deadline)
                self.assertFalse(snapshots[0]["incoming_provenance_complete"])
                self.assertTrue(snapshots[1]["incoming_provenance_complete"])
                self.assertTrue(all(not s["requests"] and not s["canonical_current_owner_verified"]
                                    and not s["physical_send_verified"] for s in snapshots))
            self.assertEqual([len(endpoint.raw_snapshots) for endpoint in endpoints], [1, 1])
        finally:
            for endpoint in endpoints:
                endpoint.close()
            for worker in workers:
                worker.join(timeout=3)
                self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(requests), 2)
        self.assertTrue(all(request["op"] == "snapshot" and
                            request["original_deadline_ns"] <= int(deadline * 1_000_000_000)
                            for request in requests))

    def test_first_provenance_gap_retains_both_replies_without_native_credit(self):
        self.collect()

    def test_first_birth_failure_keeps_original_error_and_second_raw_reply(self):
        self.collect(invalid_first=True)

    def test_expired_shared_deadline_sends_neither_endpoint_and_never_retries(self):
        endpoints, peers = [], []
        for _ in range(2):
            parent, peer = socket.socketpair()
            endpoints.append(kernel.Endpoint(parent, None, None, "a" * 32, "b" * 32))
            peers.append(peer)
        try:
            with self.assertRaises(kernel.CaptureError) as caught:
                kernel.snapshot_pair(endpoints, deadline=time.monotonic() - 1)
            self.assertEqual(caught.exception.code, "kernel_control_original_deadline")
            self.assertTrue(all(e.output_bytes == 0 and not e.raw_snapshots for e in endpoints))
            for peer in peers:
                peer.setblocking(False)
                with self.assertRaises(BlockingIOError):
                    peer.recv(1)
        finally:
            for endpoint in endpoints:
                endpoint.close()
            for peer in peers:
                peer.close()


if __name__ == "__main__":
    unittest.main()
