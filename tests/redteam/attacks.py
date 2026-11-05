"""Deliberate attack attempts; never execute on the host or as Root."""

import errno
import json
import os
import socket
import sys
from pathlib import Path


def exercise(name):
    if (sys.platform != 'linux' or os.geteuid() == 0
            or os.environ.get('MANO_REDTEAM_CI') != 'granted-guest-fixture'):
        raise PermissionError('Approved unprivileged disposable guest fixture required')
    records = {}

    def attempt(label, operation):
        try:
            operation()
        except OSError as error:
            if error.errno not in {errno.EACCES, errno.EPERM, errno.EROFS, errno.ENOENT}:
                raise
            records[label] = dict(blocked_or_unavailable=True, errno=error.errno)
        else:
            raise AssertionError('Unexpected attack success: ' + label)

    attempt('protected-policy-write', lambda: Path('/etc/mano/human.uid').write_text('attacker'))
    attempt('private-journal-read', lambda: Path(
        '/var/lib/mano-broker/runtime/state.sqlite3').read_bytes())
    attempt('synthetic-host-secret-read', lambda: Path(
        os.environ['MANO_REDTEAM_CANARY']).read_bytes())
    attempt('human-config-write', lambda: Path(
        '/home/mano-human/.gemini/antigravity-cli/settings.json').write_text('{}'))

    def network():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as channel:
            channel.settimeout(.2)
            channel.connect(('192.0.2.1', 443))

    attempt('network', network)
    forbidden = ('OPENAI_API_KEY', 'CODEX_API_KEY', 'GEMINI_API_KEY', 'GOOGLE_API_KEY',
                 'SSH_AUTH_SOCK', 'DISPLAY', 'WAYLAND_DISPLAY', 'DBUS_SESSION_BUS_ADDRESS')
    assert not any(key in os.environ for key in forbidden)
    # Workspace writes are a required positive control, not an escape attempt.
    marker = Path(name + '.workspace-control')
    marker.write_text('allowed workspace write\n')
    assert marker.read_text() == 'allowed workspace write\n'
    print(json.dumps(dict(case=name, attempts=records, workspace_positive_control=True,
                         host_environment_absent=True)), flush=True)
