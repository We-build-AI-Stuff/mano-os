"""Approved private desktop SDK. Never repeat uncertain input or certify effects."""

import secrets
import time

from mano_desktop import protocol
from mano_protocol.actions import ActionRequest, canonical

from .pty import PTYSession


def proposal(*, task_id, resource_id, key, reason, width=1024, height=720,
             timeout_seconds=120, input_limit_bytes=65536,
             memory_bytes=protocol.MEMORY_MAX, pids=protocol.PIDS_MAX, cpu_percent=50,
             browser_path=None):
    """Build the exact request that must be shown through native approval."""
    value = dict(schema_version='1.0', task_id=task_id, resource_id=resource_id,
                 capability='desktop.open', idempotency_key=key, reason=reason,
                 args=dict(width=width, height=height, cwd='.', timeout_seconds=timeout_seconds,
                           input_limit_bytes=input_limit_bytes, memory_bytes=memory_bytes,
                           pids=pids, cpu_percent=cpu_percent))
    if browser_path is not None:
        value['args']['browser_path'] = browser_path
    ActionRequest.parse(canonical(value | dict(grant_id='0' * 32)).encode())
    return value


class DesktopSession:
    def __init__(self, transport, config):
        self.transport = transport
        original = transport.client
        self.next_request = 0.0

        def paced(envelope):
            delay = self.next_request - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self.next_request = time.monotonic() + .12
            return original(envelope)

        transport.client = paced
        self.config = protocol.opening(config)
        self.pending = bytearray()
        self.ready = self.uncertain = self.closed = False

    @staticmethod
    def request(client, **kwargs):
        """Request approval without acquiring authority or opening a desktop."""
        value = proposal(**kwargs)
        response = client(dict(schema_version='1.0', operation='request_approval', body=value))
        if response.get('schema_version') != '1.0' or response.get('ok') is not True:
            raise ValueError('Desktop approval request denied')
        return response

    @classmethod
    def open(cls, client, *, proposal, grant_id):
        """Submit the exact approved proposal and bind the transport to its owned action."""
        request = ActionRequest.parse(canonical(proposal | dict(grant_id=grant_id)).encode())
        if request.capability != 'desktop.open':
            raise ValueError('Expected exact approved desktop proposal')
        response = client(dict(schema_version='1.0', operation='propose', body=request.body()))
        action = response.get('action', {})
        if (response.get('schema_version') != '1.0' or response.get('ok') is not True
                or action.get('task_id') != request.task_id):
            raise ValueError('Desktop open denied or unbound')
        transport = PTYSession(client, task_id=request.task_id, action_id=action['id'])
        return cls(transport, proposal['args'])

    def frame(self, identifier, command, deadline):
        """Read one correlated observation without resending any control input."""
        while time.monotonic() < deadline:
            if b'\n' in self.pending:
                line, _, tail = self.pending.partition(b'\n')
                self.pending = bytearray(tail)
                value = protocol.decode(bytes(line) + b'\n')
                if (set(value) != {'schema_version', 'id', 'command', 'ok', 'untrusted',
                                   'effect_verified', 'result', 'error'}
                        or value['schema_version'] != '1.0' or value['id'] != identifier
                        or value['command'] != command or value['untrusted'] is not True
                        or value['effect_verified'] is not False or value['ok'] is not True
                        or value['error'] is not None or not isinstance(value['result'], dict)):
                    diagnostic = (repr(value.get('result'))[:2300]
                                  if command == 'ready' else '')
                    raise ValueError('Desktop response failed, changed or uncertain: ' + diagnostic)
                return value
            if len(self.pending) >= protocol.MAX_FRAME:
                raise ValueError('Desktop frame exceeds its bound')
            # Launch is queued. Do not request PTY data until the journal exists.
            response = self.transport.client(dict(schema_version='1.0', operation='status',
                body=dict(task_id=self.transport.task_id, action_id=self.transport.action_id)))
            action = response.get('action', {})
            if (response.get('ok') is not True or action.get('id') != self.transport.action_id
                    or action.get('task_id') != self.transport.task_id):
                raise ValueError('Desktop process status is unbound')
            if action.get('state') == 'intent':
                time.sleep(0.1)
                continue
            result = self.transport.read()
            self.pending.extend(result['data'])
            if result['eof'] and not result['data']:
                raise ValueError('Desktop exited before the expected response')
            if not result['data']:
                time.sleep(0.1)
        raise TimeoutError('Desktop response uncertain; input must not be repeated')

    def wait_ready(self, *, timeout=15):
        """Require the worker to report the approved dimensions before sending input."""
        if self.closed or self.uncertain:
            raise ValueError('Desktop session unavailable')
        if not self.ready:
            try:
                value = self.frame('0' * 32, 'ready', time.monotonic() + timeout)
                if value['result'] != {key: self.config[key] for key in ('width', 'height')}:
                    raise ValueError('Desktop geometry changed')
                self.ready = True
            except BaseException:
                self.uncertain = True
                raise

    def command(self, command, *, timeout=None, **args):
        """Send a single validated operation and fail closed on uncertain delivery."""
        if timeout is None:
            timeout = 15 if command == 'type' else 5
        # Validation happens before any effect or uncertainty latch.
        identifier = secrets.token_hex(16)
        browser = 'browser_path' in self.config
        raw = protocol.request(identifier, command, args, width=self.config['width'],
                               height=self.config['height'], browser=browser)
        self.wait_ready(timeout=40 if browser else 15)
        try:
            acknowledgement = self.transport.write(raw, key=identifier)
            if (acknowledgement.get('state') != 'acknowledged'
                    or acknowledgement.get('written') != len(raw)
                    or acknowledgement.get('effect_verified') is not False):
                raise ValueError('Desktop input delivery uncertain; do not resend')
            value = self.frame(identifier, command, time.monotonic() + timeout)
            if command == 'close':
                self.closed = True
            return value
        except BaseException:
            self.uncertain = True
            raise

    def stop(self):
        """Cancel this owned action, including when desktop input is uncertain."""
        try:
            return self.transport.close(key=secrets.token_hex(16))
        finally:
            self.closed = True
