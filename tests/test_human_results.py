import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mano_broker.approvals import Approvals
from mano_broker.control import dispatch_control
from mano_broker.human_results import preview
from mano_broker.ipc import Peer, dispatch
from mano_broker.prompts import Prompts
from mano_broker.state import Denied, State
from mano_broker.verifier import check, declare
from mano_prompt.results import display, packet, parse_result, read_result
from mano_protocol.actions import ActionRequest, canonical


class HumanResultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / 'journal')
        prompts = Prompts(self.state)
        self.prompt = prompts.submit(human_uid=1002, request_key='a' * 32,
            prompt='Create a result', boot_id='boot')['id']
        self.task = self.state.create_task(human_uid=1002, caller_uid=1004,
            mode='supervised', resource_id='b' * 32, classification='internal', boot_id='boot')
        prompts.claim(self.prompt, human_uid=1002, boot_id='boot')
        prompts.attach(self.prompt, self.task, human_uid=1002, boot_id='boot')

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def read(self, **changes):
        return preview(self.state, **(dict(human_uid=1002, prompt_id=self.prompt,
                                          boot_id='boot') | changes))

    def publish(self, data=b'answer = 42\n', *, verified=True):
        proposal = dict(schema_version='1.0', task_id=self.task, resource_id='b' * 32,
            capability='terminal.run', args=dict(argv=['true'], cwd='.', timeout_seconds=1),
            reason='Create result', idempotency_key='one')
        queue = Approvals(self.state)
        approval = queue.request(proposal, caller_uid=1004, now=10,
                                  boot_id='boot')['approval_id']
        digest = hashlib.sha256(data).hexdigest()
        declare(self.state, approval, path='result.py', sha256=digest, size=len(data),
                now=11, boot_id='boot')
        view = queue.view(approval, human_uid=1002)
        grant = queue.approve(approval, authenticated_human_uid=1002, nonce=view['nonce'],
            operation_digest=view['operation_digest'], now=12, boot_id='boot')
        action, _ = self.state.authorize(ActionRequest.parse(canonical(
            proposal | dict(grant_id=grant)).encode()), caller_uid=1004, now=12, boot_id='boot')
        self.action = action['id']
        self.artifact = 'c' * 32
        self.state.start(self.action, now=12, boot_id='boot')
        self.state.transition(self.action, 'done', exit_code=0)
        self.metadata = dict(artifact_id=self.artifact, action_id=self.action,
            task_id=self.task, boot_id='boot', relative_path='result.py',
            sha256=digest, size=len(data), effect_verified=False)
        self.state.db.execute('INSERT INTO artifacts VALUES(?,?,?,?)',
            (self.artifact, self.action, canonical(self.metadata), data))
        if verified:
            check(self.state, self.action, self.artifact, boot_id='boot')

    def test_only_verified_snapshot_is_visible_and_reads_never_replay_or_grant(self):
        self.assertIsNone(self.read()['result'])
        self.publish(verified=False)
        self.assertIsNone(self.read()['result'])
        check(self.state, self.action, self.artifact, boot_id='boot')
        before = self.state.db.total_changes
        value = parse_result(self.read(), self.prompt)
        self.assertEqual(base64.b64decode(value['result']['data']), b'answer = 42\n')
        self.assertEqual(value['result']['action_id'], self.action)
        self.assertIn('workspace may have changed', display(value)[0])
        self.assertEqual(display(value)[1], 'answer = 42\n')
        self.assertEqual(self.state.db.total_changes, before)
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM actions').fetchone()[0], 1)
        self.state.emergency_stop()
        self.assertEqual(self.read(), value)  # Historical reads grant no continuation rights.

    def test_bounded_prefix_and_binary_preview_have_honest_labels(self):
        self.publish(b'a' * 4095 + '€'.encode())
        value = parse_result(self.read(), self.prompt)
        self.assertTrue(value['result']['truncated'])
        self.assertEqual(len(base64.b64decode(value['result']['data'])), 4096)
        self.assertIn('first 4096 bytes', display(value)[0])
        self.assertEqual(display(value)[1], 'a' * 4095)
        for mutation in (dict(size=4096), dict(truncated=False), dict(data='!'),
                         dict(preview_sha256='0' * 64), dict(sha256='bad')):
            with self.assertRaises(ValueError):
                parse_result(value | dict(result=value['result'] | mutation), self.prompt)

    def test_binary_content_has_no_text_preview(self):
        self.publish(b'\xff\x00')
        value = parse_result(self.read(), self.prompt)
        self.assertIn('Binary snapshot', display(value)[1])

    def test_long_untrusted_path_cannot_fill_the_result_header(self):
        self.publish()
        value = self.read()
        value['result']['path'] = '/'.join(['long-name' * 20] * 10)
        checked = parse_result(value, self.prompt)
        summary, content = display(checked)
        self.assertIn('(path shortened)', summary)
        self.assertLess(len(summary), 600)
        self.assertEqual(content, 'answer = 42\n')

    def test_cross_human_boot_task_and_corrupt_custody_are_denied(self):
        self.publish()
        for changes in (dict(human_uid=1003), dict(human_uid=True), dict(boot_id='old')):
            with self.assertRaises((ValueError, Denied)):
                self.read(**changes)
        self.state.db.execute('UPDATE artifacts SET data=?', (b'changed after capture',))
        with self.assertRaises(Denied):
            self.read()
        self.state.db.execute('UPDATE artifacts SET data=?,metadata_json=?',
            (b'answer = 42\n', canonical(self.metadata | dict(task_id='d' * 32))))
        with self.assertRaises(Denied):
            self.read()

    def test_only_root_control_can_request_result_and_cannot_select_a_path(self):
        self.publish()
        body = dict(human_uid=1002, prompt_id=self.prompt)
        wire = canonical(dict(schema_version='1.0', operation='human_task_result',
                              body=body)).encode()
        self.assertEqual(dispatch_control(self.state, wire, peer=Peer(1, 0, 0), now=12,
                                         boot_id='boot')['result'], self.read()['result'])
        for uid in (1002, 1004):
            with self.assertRaises(Denied):
                dispatch_control(self.state, wire, peer=Peer(1, uid, uid), now=12, boot_id='boot')
            with self.assertRaises(Denied):
                dispatch(self.state, wire, peer=Peer(1, uid, uid), now=12, boot_id='boot')
        for extra in (dict(path='/etc/shadow'), dict(task_id=self.task),
                      dict(artifact_id=self.artifact)):
            wire = canonical(dict(schema_version='1.0', operation='human_task_result',
                                  body=body | extra)).encode()
            with self.assertRaises(Denied):
                dispatch_control(self.state, wire, peer=Peer(1, 0, 0), now=12, boot_id='boot')

    def test_native_client_is_one_read_and_checks_prompt_and_full_content_digest(self):
        self.publish()
        value = self.read()
        with patch('mano_prompt.results.rpc', return_value=dict(ok=True, **value)) as transport:
            self.assertEqual(read_result(self.prompt), value)
            transport.assert_called_once_with(b'\x01\x0a' + self.prompt.encode())
        with self.assertRaises(ValueError):
            packet('../etc/shadow')
        with self.assertRaises(ValueError):
            parse_result(value, 'd' * 32)
        altered = value | dict(result=value['result'] | dict(sha256='0' * 64))
        with self.assertRaises(ValueError):
            parse_result(altered, self.prompt)
        with patch('mano_prompt.results.rpc', side_effect=TimeoutError()) as transport:
            with self.assertRaises(TimeoutError):
                read_result(self.prompt)
            self.assertEqual(transport.call_count, 1)

    def test_verified_flag_without_original_evidence_cannot_expose_unverified_capture(self):
        self.publish()
        self.state.db.execute('UPDATE actions SET evidence_json=?', (json.dumps([
            dict(artifact_id='d' * 32, sha256=self.metadata['sha256'])]),))
        with self.assertRaises(Denied):
            self.read()
