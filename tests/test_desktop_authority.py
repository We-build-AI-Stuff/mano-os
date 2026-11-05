import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mano_broker.limits import DesktopLimits, Limits, approved_limits, limit_type
from mano_broker.state import Denied, State
from mano_core.desktop import DesktopSession, proposal
from mano_desktop import protocol
from mano_protocol.actions import ActionRequest, Capability, canonical


def request():
    value = proposal(task_id='a' * 32, resource_id='b' * 32, key='desktop', reason='test')
    return ActionRequest.parse(canonical(value | dict(grant_id='c' * 32)).encode())


def response(expected_id, expected_command, **changes):
    value = dict(schema_version='1.0', id=expected_id, command=expected_command, ok=True,
                 untrusted=True, effect_verified=False, result={}, error=None)
    return (json.dumps(value | changes) + '\n').encode()


class DesktopAuthorityTests(unittest.TestCase):
    def test_native_approval_issues_the_exact_visible_desktop_budget(self):
        from mano_broker.approvals import Approvals

        with tempfile.TemporaryDirectory() as directory:
            state = State(Path(directory).resolve() / 'state')
            try:
                resource = 'a' * 32
                task = state.create_task(human_uid=1002, caller_uid=1004, mode='auto',
                    resource_id=resource, classification='internal', boot_id='boot')
                value = proposal(task_id=task, resource_id=resource, key='gui', reason='test',
                                 memory_bytes=256 * 1024**2, pids=64, cpu_percent=30)
                queue = Approvals(state)
                pending = queue.request(value, caller_uid=1004, now=10, boot_id='boot')
                self.assertEqual(pending['state'], 'pending')
                view = queue.view(pending['approval_id'], human_uid=1002)
                self.assertEqual(view['args'], value['args'])
                grant = queue.approve(pending['approval_id'], authenticated_human_uid=1002,
                    nonce=view['nonce'], operation_digest=view['operation_digest'],
                    now=11, boot_id='boot')
                row = state.db.execute('SELECT budget_json FROM grants WHERE id=?',
                                       (grant,)).fetchone()
                budget = json.loads(row[0])
                parsed = ActionRequest.parse(canonical(value | dict(grant_id=grant)).encode())
                self.assertEqual(approved_limits(parsed, budget).body(),
                    dict(memory_bytes=256 * 1024**2, pids=64, cpu_percent=30))
            finally:
                state.close()

    def test_only_desktop_selects_the_separate_budget_and_must_match_approval(self):
        value = request()
        self.assertEqual(value.capability, Capability.DESKTOP)
        self.assertIs(limit_type(value.capability), DesktopLimits)
        for capability in Capability:
            if capability != Capability.DESKTOP:
                self.assertIs(limit_type(capability), Limits)
        budget = DesktopLimits().body()
        self.assertEqual(approved_limits(value, budget).body(), budget)
        for key in budget:
            with self.subTest(key=key), self.assertRaises(Denied):
                approved_limits(value, budget | {key: budget[key] - 1})
        with self.assertRaises(Denied):
            Limits.parse(budget)
        for change in (dict(pids=97), dict(cpu_percent=True), dict(memory_bytes=0)):
            with self.assertRaises(Denied):
                DesktopLimits.parse(budget | change)

    def test_fixed_worker_translation_does_not_change_approval_identity(self):
        value = request()
        digest = value.digest
        translated = protocol.launch_arguments(json.loads(value.args_json))
        self.assertEqual(translated['argv'][:3], ['/usr/bin/python3', '-I', protocol.WORKER])
        self.assertEqual(value.digest, digest)
        self.assertNotIn('argv', value.body()['args'])

    def test_partial_or_lost_input_acknowledgement_never_repeats_input(self):
        for reply in (dict(state='acknowledged', written=1, effect_verified=False),
                      ValueError('lost')):
            with self.subTest(reply=reply):
                transport = Mock()
                transport.write.side_effect = [reply] if isinstance(reply, Exception) else None
                transport.write.return_value = reply
                desktop = DesktopSession(transport, json.loads(request().args_json))
                desktop.ready = True
                with self.assertRaises(ValueError):
                    desktop.command('type', text='hello')
                with self.assertRaises(ValueError):
                    desktop.command('type', text='hello')
                self.assertEqual(transport.write.call_count, 1)
                desktop.stop()
                transport.close.assert_called_once()

    def test_output_frames_require_expected_identity_and_untrusted_effect_boundary(self):
        for change in (dict(id='f' * 32), dict(command='close'), dict(effect_verified=True),
                       dict(untrusted=False), dict(ok=False), dict(extra=1)):
            desktop = DesktopSession(Mock(), json.loads(request().args_json))
            desktop.pending.extend(response('d' * 32, 'status', **change))
            with self.subTest(change=change), self.assertRaises(ValueError):
                desktop.frame('d' * 32, 'status', float('inf'))

    def test_readiness_geometry_checked_before_any_input(self):
        transport = Mock()
        desktop = DesktopSession(transport, json.loads(request().args_json))
        desktop.pending.extend(response('0' * 32, 'ready', result=dict(width=640, height=480)))
        with self.assertRaises(ValueError):
            desktop.command('type', text='hello')
        self.assertTrue(desktop.uncertain)
        transport.write.assert_not_called()

    def test_unicode_frame_fits_a_single_linux_canonical_input_line(self):
        raw = protocol.request('a' * 32, 'type', dict(text='☃' * 680), width=1024, height=720)
        self.assertLessEqual(len(raw), 4000)
        self.assertEqual(protocol.decode(raw)['args']['text'], '☃' * 680)

    def test_root_probe_refuses_mac_before_any_reads_or_processes(self):
        path = Path(__file__).resolve().parents[1] / 'scripts/probe_private_desktop.py'
        spec = importlib.util.spec_from_file_location('private_desktop_probe', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with (patch.object(module.sys, 'platform', 'darwin'),
              patch.object(module.Path, 'read_text') as read,
              patch.object(module.subprocess, 'check_output') as process):
            with self.assertRaises(PermissionError):
                module.run(rpc=None, human=None, password=None, identity=None,
                           task=None, workspace=None)
            read.assert_not_called()
            process.assert_not_called()

    def test_failed_gui_exercise_cancels_the_owned_action_and_keeps_original_error(self):
        path = Path(__file__).resolve().parents[1] / 'scripts/probe_private_desktop_client.py'
        spec = importlib.util.spec_from_file_location('private_desktop_client', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        desktop = Mock()
        desktop.wait_ready.side_effect = ValueError('original desktop failure')
        desktop.stop.side_effect = ConnectionResetError('lost cancellation acknowledgement')
        with (patch.object(module.sys, 'platform', 'linux'),
              patch.object(module.os, 'geteuid', return_value=1004),
              patch.object(module.Path, 'read_text', return_value='mano-phase0-ci'),
              patch.object(module.sys, 'stdin', io.StringIO('{"proposal":{},"grant_id":"id"}')),
              patch.object(module, 'BrokerClient') as client,
              patch.object(module.DesktopSession, 'open', return_value=desktop)):
            with self.assertRaisesRegex(ValueError, 'original desktop failure'):
                module.main()
        desktop.stop.assert_called_once_with()
        client.return_value.close.assert_called_once_with()
