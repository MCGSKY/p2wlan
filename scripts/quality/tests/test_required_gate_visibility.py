import io
import sys
import unittest
from collections import deque
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_required_gates as gates

SHA = 'a' * 40
OTHER = 'b' * 40


def metadata(run_id=1, workflow='CI', *, head=SHA, event='pull_request', complete=False):
    return dict(id=run_id, name=workflow, head_sha=head, event=event,
                status='completed' if complete else 'in_progress',
                conclusion='success' if complete else None,
                run_attempt=1, created_at='2026-10-21T00:00:00Z')


def job(name='CI Required', status='in_progress', conclusion=None):
    return dict(name=name, status=status, conclusion=conclusion)


class Client(gates.GitHubClient):
    def __init__(self, pages, jobs, *, retries=3):
        super().__init__('owner/repo', 'unused', retries=retries)
        self.pages = deque(pages)
        self.replies = {key: deque(value) for key, value in jobs.items()}
        self.metadata_reads = 0
        self.job_reads = 0

    def _paginate(self, path, key, params):
        if key == 'workflow_runs':
            self.metadata_reads += 1
            return self.pages.popleft()
        self.job_reads += 1
        parts = path.split('/')
        run_id = int(parts[parts.index('runs') + 1])
        return self.replies[run_id].popleft()


class RunVisibilityTests(unittest.TestCase):
    def test_transient_empty_list_requeries_and_uses_fresh_result(self):
        client = Client([[metadata()], [], [metadata(complete=True)]],
                        {1: [[job()], [job(status='completed', conclusion='success')]]})
        self.assertEqual(gates.evaluate(['CI Required'], client.runs_for(SHA))[0].state,
                         gates.GateState.PENDING)
        findings = gates.evaluate(['CI Required'], client.runs_for(SHA))
        self.assertTrue(gates.authorized(findings))
        self.assertEqual((client.metadata_reads, client.job_reads), (3, 2))

    def test_repeated_disappearance_does_not_reuse_previous_success(self):
        client = Client([[metadata(complete=True)], [], [], []],
                        {1: [[job(status='completed', conclusion='success')]]})
        self.assertTrue(gates.authorized(gates.evaluate(['CI Required'], client.runs_for(SHA))))
        with self.assertRaisesRegex(gates.GateRequestError, 'after 3 metadata reads'):
            client.runs_for(SHA)
        self.assertEqual((client.metadata_reads, client.job_reads), (4, 1))

    def test_partial_list_cannot_hide_previous_authoritative_failure(self):
        failed = metadata(1, complete=True)
        failed['conclusion'] = 'failure'
        passed = metadata(2, complete=True)
        client = Client([[failed, passed], [passed], [passed], [passed]],
                        {1: [[job(status='completed', conclusion='failure')]],
                         2: [[job(status='completed', conclusion='success')]]})
        self.assertEqual(gates.evaluate(['CI Required'], client.runs_for(SHA))[0].state,
                         gates.GateState.FAIL)
        with self.assertRaises(gates.GateRequestError):
            client.runs_for(SHA)
        self.assertEqual(client.job_reads, 2)

    def test_partial_list_recovery_keeps_other_gate_pending(self):
        ci, nat = metadata(), metadata(2, 'NAT Topology Gate')
        client = Client([[ci, nat], [metadata(complete=True)], [metadata(complete=True), nat]],
                        {1: [[job()], [job(status='completed', conclusion='success')]],
                         2: [[job('NAT Topology Required')], [job('NAT Topology Required')]]})
        required = {'CI', 'NAT Topology Gate'}
        client.runs_for(SHA, required_workflows=required)
        findings = gates.evaluate(['CI Required', 'NAT Topology Required'],
                                  client.runs_for(SHA, required_workflows=required))
        self.assertEqual([f.state for f in findings], [gates.GateState.PASS, gates.GateState.PENDING])
        self.assertFalse(gates.authorized(findings))

    def test_first_missing_snapshot_remains_missing(self):
        client = Client([[]], {})
        findings = gates.evaluate(['CI Required'], client.runs_for(SHA))
        self.assertEqual(findings[0].state, gates.GateState.MISSING)
        self.assertFalse(gates.authorized(findings))
        self.assertEqual(client.metadata_reads, 1)

    def test_foreign_head_is_rejected_without_consistency_retries(self):
        client = Client([[metadata()], [metadata(head=OTHER)], [metadata()]], {1: [[job()]]})
        client.runs_for(SHA)
        with self.assertRaisesRegex(gates.GateRequestError, 'returned head_sha'):
            client.runs_for(SHA)
        self.assertEqual(client.metadata_reads, 2)

    def test_visibility_identity_does_not_cross_target_sha(self):
        client = Client([[metadata()], [metadata(2, head=OTHER)]], {1: [[job()]], 2: [[job()]]})
        client.runs_for(SHA)
        result = client.runs_for(OTHER)
        self.assertEqual([r.run_id for r in result], [2])
        self.assertEqual(client.metadata_reads, 2)

    def test_changed_workflow_scope_does_not_require_unrelated_runs(self):
        ci, nat = metadata(), metadata(2, 'NAT Topology Gate')
        client = Client([[ci, nat], [ci]],
                        {1: [[job()], [job()]], 2: [[job('NAT Topology Required')]]})
        client.runs_for(SHA, required_workflows={'CI', 'NAT Topology Gate'})
        result = client.runs_for(SHA, required_workflows={'CI'})
        self.assertEqual([r.run_id for r in result], [1])
        self.assertEqual(client.metadata_reads, 2)

    def test_manual_event_cannot_replace_seen_authoritative_identity(self):
        manual = metadata(event='workflow_dispatch', complete=True)
        client = Client([[metadata()], [manual], [manual], [manual]], {1: [[job()]]})
        client.runs_for(SHA)
        with self.assertRaises(gates.GateRequestError):
            client.runs_for(SHA)
        self.assertEqual(client.job_reads, 1)

    def test_configured_single_read_bound_is_preserved(self):
        client = Client([[metadata()], [], [metadata()]], {1: [[job()]]}, retries=1)
        client.runs_for(SHA)
        with self.assertRaisesRegex(gates.GateRequestError, 'after 1 metadata reads'):
            client.runs_for(SHA)
        self.assertEqual(client.metadata_reads, 2)


class VisibilityDeadlineTests(unittest.TestCase):
    @staticmethod
    def run_result(workflow, name, *, outcome=None, run_id=1):
        return gates.WorkflowRun(
            run_id=run_id, workflow_name=workflow, event='pull_request', head_sha=SHA,
            status='completed' if outcome else 'in_progress', conclusion=outcome,
            run_attempt=1, created_at='2026-10-21T00:00:00Z',
            jobs=(gates.JobResult(name, 'completed' if outcome else 'in_progress', outcome),),
        )

    def test_visibility_gap_does_not_reuse_partial_success_or_hide_fresh_failure(self):
        ci_ok = self.run_result('CI', 'CI Required', outcome='success')
        ci_fail = self.run_result('CI', 'CI Required', outcome='failure')
        nat_pending = self.run_result('NAT Topology Gate', 'NAT Topology Required', run_id=2)
        nat_ok = self.run_result('NAT Topology Gate', 'NAT Topology Required', outcome='success', run_id=2)
        client = Mock()
        client.runs_for.side_effect = [
            [ci_ok, nat_pending], gates.GateVisibilityError('known run vanished'), [ci_fail, nat_ok],
        ]
        with patch.object(gates, '_client', return_value=client), \
             patch.object(gates.time, 'monotonic', side_effect=[0, 1, 2]) as clock, \
             patch.object(gates.time, 'sleep') as sleep, \
             patch('sys.stdout', new_callable=io.StringIO) as out, \
             patch('sys.stderr', new_callable=io.StringIO) as err:
            result = gates.main(['--sha', SHA, '--require', 'CI Required', '--require',
                                 'NAT Topology Required', '--timeout-seconds', '10', '--poll-seconds', '1'])
        self.assertEqual(result, 1)
        self.assertEqual(client.runs_for.call_count, 3)
        self.assertEqual((clock.call_count, sleep.call_count), (3, 2))
        self.assertNotIn('PASS required gates', out.getvalue())
        self.assertIn('CI Required: fail', err.getvalue())

    def test_persistent_visibility_gap_expires_at_original_deadline(self):
        pending = self.run_result('CI', 'CI Required')
        client = Mock()
        client.runs_for.side_effect = [
            [pending], gates.GateVisibilityError('gap one'), gates.GateVisibilityError('gap two'),
        ]
        with patch.object(gates, '_client', return_value=client), \
             patch.object(gates.time, 'monotonic', side_effect=[10, 10.1, 11, 13]) as clock, \
             patch.object(gates.time, 'sleep') as sleep, \
             patch('sys.stdout', new_callable=io.StringIO) as out, \
             patch('sys.stderr', new_callable=io.StringIO) as err:
            result = gates.main(['--sha', SHA, '--require', 'CI Required',
                                 '--timeout-seconds', '2', '--poll-seconds', '1'])
        self.assertEqual(result, 1)
        self.assertEqual(client.runs_for.call_count, 3)
        self.assertEqual((clock.call_count, sleep.call_count), (4, 2))
        self.assertIn('api_error: gap two', err.getvalue())
        self.assertNotIn('PASS required gates', out.getvalue())


if __name__ == '__main__':
    unittest.main()
