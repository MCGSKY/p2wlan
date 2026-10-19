"""Pure cleanup metadata controls; never manufacture system or owner facts."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

import linux_tun_cleanup_gate as gate


class CleanupAdmissionTests(unittest.TestCase):
    def reports(self):
        return {name: dict(scope=scope, source_commit="a" * 40,
            github_run_id="123", github_run_attempt="1", run_id=name,
            passed=False, cleanup_complete=True,
            network_cleanup=dict(admitted=True, complete=True, remaining=[]),
            kernel_control_cleanup=dict(complete=True, errors=[]),
            limits=dict(process_groups=11), process_cleanup=[dict(
                complete=True, group_absent=True, child_reaped=True, anchor_reaped=True,
                original_child_pid=10, original_anchor_pid=9)])
            for name, scope in gate.SCOPES.items()}

    def admit(self, reports):
        return gate.admit(reports, "a" * 40, "123", "1")

    def test_failed_measurements_admit_only_after_cleanup_without_changing_any_result(self):
        reports = self.reports(); before = deepcopy(reports)
        result = self.admit(reports)
        self.assertTrue(result["allowed"])
        self.assertEqual(reports, before)
        for key in ["canonical_current_owner_verified", "physical_send_verified",
                    "native_os_write_verified"]:
            self.assertFalse(result[key])

    def test_missing_scope_duplicate_experiment_and_foreign_identity_are_rejected(self):
        first, second = list(gate.SCOPES)[:2]
        for change in ["missing", "duplicate", "scope", "head", "run", "attempt"]:
            reports = self.reports()
            if change == "missing": reports.pop(first)
            elif change == "duplicate": reports[first]["run_id"] = reports[second]["run_id"]
            else:
                key = dict(scope="scope", head="source_commit", run="github_run_id",
                           attempt="github_run_attempt")[change]
                reports[first][key] = "foreign"
            with self.subTest(change=change), self.assertRaises(gate.AdmissionFailure):
                self.admit(reports)

    def test_missing_unknown_or_partial_cleanup_cannot_admit_another_measurement(self):
        for change in ["top", "admitted", "remaining", "network", "control", "errors"]:
            reports = self.reports(); report = next(iter(reports.values()))
            if change == "top": report["cleanup_complete"] = 1
            elif change == "admitted": report["network_cleanup"]["admitted"] = False
            elif change == "remaining": report["network_cleanup"]["remaining"] = ["unknown"]
            elif change == "network": report["network_cleanup"] = None
            elif change == "control": report["kernel_control_cleanup"]["complete"] = None
            else: report["kernel_control_cleanup"]["errors"] = ["not_closed"]
            with self.subTest(change=change), self.assertRaises(gate.AdmissionFailure):
                self.admit(reports)

    def test_original_group_caps_waits_and_positive_process_birth_labels_are_required(self):
        for change in ["cap", "empty", "oversized", "absent", "wait", "pid"]:
            reports = self.reports(); report = next(iter(reports.values()))
            if change == "cap": report["limits"]["process_groups"] = 12
            elif change == "empty": report["process_cleanup"] = []
            elif change == "oversized": report["process_cleanup"] *= 12
            elif change == "absent": report["process_cleanup"][0]["group_absent"] = False
            elif change == "wait": report["process_cleanup"][0]["child_reaped"] = None
            else: report["process_cleanup"][0]["original_child_pid"] = True
            with self.subTest(change=change), self.assertRaises(gate.AdmissionFailure):
                self.admit(reports)

    def test_bounded_file_read_retains_inputs_and_rejects_missing_oversized_and_duplicate_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, report in self.reports().items():
                path = root / name / "report.json"; path.parent.mkdir()
                path.write_text(json.dumps(report))
            self.assertEqual(gate.read_reports(root), self.reports())
            path = root / next(iter(gate.SCOPES)) / "report.json"
            for content in [b"x" * (gate.MAX_REPORT_BYTES + 1), b'{"x":1,"x":2}']:
                path.write_bytes(content)
                with self.assertRaises(gate.AdmissionFailure): gate.read_reports(root)
                self.assertEqual(path.read_bytes(), content)
            path.unlink()
            with self.assertRaises(gate.AdmissionFailure): gate.read_reports(root)
            path.mkdir()
            with self.assertRaises(gate.AdmissionFailure): gate.read_reports(root)

    def test_invocation_identity_requires_exact_source_run_and_attempt_syntax(self):
        for head, run, attempt in [("A" * 40, "123", "1"), ("a" * 39, "123", "1"),
                                   ("a" * 40, "0", "1"), ("a" * 40, "123", "unknown")]:
            with self.subTest(head=head, run=run, attempt=attempt), self.assertRaises(gate.AdmissionFailure):
                gate.admit(self.reports(), head, run, attempt)

    def test_workflow_requires_cleanup_before_room_probe_and_keeps_upstream_failure_fatal(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github/workflows/parallel-rooms.yml").read_text()
        step = workflow.split("      - name: Real kernel TUN original room revocation\n", 1)[1]
        step = step.split("      - name:", 1)[0]
        self.assertIn("if: ${{ !cancelled() }}", step)
        self.assertLess(step.index("linux_tun_cleanup_gate.py"), step.index("--room-revocation"))
        self.assertIn('test "$LINUX_LIVE_RESULT" = success', workflow)
        self.assertNotIn("continue-on-error", workflow.split("  linux_live:", 1)[1])


if __name__ == "__main__":
    unittest.main()
