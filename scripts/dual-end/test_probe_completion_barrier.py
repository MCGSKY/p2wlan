"""Real TCP/control sockets and metadata negatives; no TUN/native facts."""
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import probe_completion_barrier as barrier
import tcp_business_probe as tcp
from udp_business_probe import Config, UNVERIFIED

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "parallel-rooms"))
from linux_tun_kernel_capture import Endpoint
import test_linux_tun_live_window as live_controls


class HandoffControls(unittest.TestCase):
    def test_actual_TCP_endpoints_stay_open_until_handoff_then_keep_original_responses(self):
        client, listener = socket.socket(), socket.socket()
        client.bind(("127.0.0.1", 0)); listener.bind(("127.0.0.1", 0))
        a, b = client.getsockname(), listener.getsockname(); client.close()
        probe = Config(a, b, "11" * 16, "22" * 16, 2, 20, 1000, 3000, 16)
        echo = Config(b, a, probe.run_nonce, probe.round_nonce, 2, 20, 1000, 3000, 16)
        ready = threading.Event(); entered = {role: threading.Event() for role in ["probe", "echo"]}
        reports, errors, sockets = {}, [], {}
        original_wait, original_bound = barrier.wait, tcp.bound_socket
        def wait(*args):
            entered[threading.current_thread().name].set()
            return original_wait(*args)
        def bound(config, supplied):
            result = original_bound(config, supplied)
            if config is probe: sockets["probe"] = result
            return result
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "handoff.json"
            def run(role):
                try:
                    reports[role] = (tcp.run_echo(echo, listener, ready.set, completion_barrier=path)
                                     if role == "echo" else tcp.run_probe(probe, completion_barrier=path))
                except BaseException as error: errors.append(error)
            workers = [threading.Thread(name=role, target=run, args=(role,)) for role in ["echo", "probe"]]
            try:
                with patch.object(barrier, "wait", side_effect=wait), patch.object(tcp, "bound_socket", side_effect=bound):
                    workers[0].start(); self.assertTrue(ready.wait(1)); workers[1].start()
                    for event in entered.values(): self.assertTrue(event.wait(.7))
                    self.assertTrue(all(worker.is_alive() for worker in workers))
                    current = sockets["probe"]; self.assertGreaterEqual(current.fileno(), 0)
                    current.settimeout(.02)
                    with self.assertRaises(TimeoutError): current.recv(1, socket.MSG_PEEK)
                    barrier.publish(path, probe.run_nonce, probe.round_nonce)
                    for worker in workers: worker.join(2)
            finally:
                for worker in workers:
                    if worker.ident is not None: worker.join(2)
                listener.close()
            self.assertFalse(any(worker.is_alive() for worker in workers)); self.assertEqual(errors, [])
            self.assertEqual(sockets["probe"].fileno(), -1)
            self.assertEqual([r["status"] for r in tcp.validate_probe(reports["probe"])], ["success"] * 2)
            self.assertEqual(reports["echo"]["responses_sent"], 2)
            for report in reports.values():
                self.assertTrue(report["connection_handoff"]["acknowledged"])
                self.assertEqual(report["evidence"], UNVERIFIED)

    def test_foreign_duplicate_oversized_and_nonregular_files_cannot_acknowledge_or_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); valid = root / "valid.json"
            barrier.publish(valid, "11" * 16, "22" * 16); before = valid.read_bytes()
            with self.assertRaises(ValueError): barrier.publish(valid, "11" * 16, "22" * 16)
            self.assertEqual(valid.read_bytes(), before)
            cases = [barrier.document("33" * 16, "22" * 16), {**barrier.document("11" * 16, "22" * 16), "native_os_write_verified": True}]
            raws = [json.dumps(value).encode() for value in cases] + [b'{"scope":"x","scope":"y"}', b'x' * (barrier.MAX_BYTES + 1)]
            for i, raw in enumerate(raws):
                path = root / str(i); path.write_bytes(raw)
                result = barrier.wait(path, "11" * 16, "22" * 16, time.monotonic_ns() + 1_000_000_000)
                self.assertFalse(result["acknowledged"]); self.assertEqual(result["reads"], 1)
            path = root / "directory"; path.mkdir()
            self.assertFalse(barrier.wait(path, "11" * 16, "22" * 16, time.monotonic_ns() + 1_000_000_000)["acknowledged"])
            if os.name == "posix":
                fifo = root / "fifo"; os.mkfifo(fifo)
                self.assertFalse(barrier.wait(fifo, "11" * 16, "22" * 16, time.monotonic_ns() + 1_000_000_000)["acknowledged"])

    def test_original_absolute_end_read_capacity_and_cancellation_never_refill(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.json"
            for duration, expected in [(25_000_000, "original_deadline"), (20_000_000_000, "metadata_read_limit")]:
                now = [100]
                with patch.object(barrier.time, "monotonic_ns", side_effect=lambda: now[0]), patch.object(barrier.time, "sleep", side_effect=lambda seconds: now.__setitem__(0, now[0] + round(seconds * 1_000_000_000))):
                    result = barrier.wait(missing, "11" * 16, "22" * 16, 100 + duration)
                self.assertFalse(result["acknowledged"]); self.assertEqual(result["reason"], expected)
                self.assertEqual(result["original_deadline_ns"], 100 + duration)
                self.assertLessEqual(result["reads"], barrier.MAX_READS)
            with patch.object(barrier, "read", side_effect=KeyboardInterrupt):
                result = barrier.wait(missing, "11" * 16, "22" * 16, time.monotonic_ns() + 1_000_000_000)
            self.assertEqual(result["reason"], "interrupted"); self.assertFalse(result["acknowledged"])

    def test_actual_control_receipt_is_metadata_only_and_failed_first_wait_cannot_rearm(self):
        if not hasattr(socket, "socketpair"): self.skipTest("local socketpair required")
        for completed in [8, 7]:
            left, right = socket.socketpair(); endpoint = Endpoint(left, None, None, "11" * 16, "22" * 16)
            endpoint.receipts.append(dict(receipt=dict(producer_scope="33" * 16)))
            observed, errors = [], []
            def peer():
                try:
                    with right:
                        right.settimeout(1); raw = bytearray()
                        for _ in range(4):
                            data = right.recv(4096)
                            if not data: return
                            raw.extend(data)
                            if b"\n" in raw: break
                        observed.append(json.loads(raw))
                        right.sendall(json.dumps(dict(scope="original_window_terminal_metadata_only", owner=1,
                            capture_id="11" * 16, producer_scope="33" * 16, completed_requests=completed,
                            native_os_write_verified=False, physical_send_verified=False,
                            canonical_current_owner_verified=False)).encode() + b"\n")
                except BaseException as error: errors.append(error)
            worker = threading.Thread(target=peer); worker.start(); end = time.monotonic_ns() + 1_000_000_000
            try:
                if completed == 8:
                    value = endpoint.wait_original_outcomes("33" * 16, end)
                    self.assertFalse(value["canonical_current_owner_verified"])
                else:
                    with self.assertRaises(ValueError): endpoint.wait_original_outcomes("33" * 16, end)
                with self.assertRaises(ValueError): endpoint.wait_original_outcomes("33" * 16, end)
            finally:
                endpoint.close(); worker.join(2)
            self.assertFalse(worker.is_alive()); self.assertEqual(errors, []); self.assertEqual(len(observed), 1)
            self.assertEqual(observed[0]["op"], "wait_original_outcomes")
            self.assertLessEqual(observed[0]["original_deadline_ns"], end)

    def test_controller_waits_for_both_terminals_without_testing_success_and_never_retries_failure(self):
        # Hypothetical validated inputs exercise only controller metadata.
        for fail in [False, True]:
            capture, bridge, _ = live_controls.MetadataControls().bridge()
            capture.config = SimpleNamespace(run_nonce="11" * 16, round_nonce="22" * 16)
            for i in range(8):
                capture.stream.requests[i] = dict(sequence=i, complete=True, original_sent_ns=100,
                    original_deadline_ns=200, last_returned_ns=101)
            events = []
            def terminal(producer, end):
                events.append((producer, end))
                if fail: raise ValueError("first_terminal_metadata_refused")
                return dict(canonical_current_owner_verified=False, physical_send_verified=False)
            for endpoint in bridge.endpoints: endpoint.wait_original_outcomes = terminal
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "handoff.json"; capture.completion_barrier_path = path
                bridge.observe(capture, 102); bridge.observe(capture, 103)
                self.assertEqual(len(events), 1 if fail else 2)
                self.assertEqual(path.exists(), not fail)
                self.assertFalse(bridge.summary()["canonical_current_owner_verified"])


if __name__ == "__main__":
    unittest.main()
