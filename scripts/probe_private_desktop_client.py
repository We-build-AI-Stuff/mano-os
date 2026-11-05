"""Task-UID SDK exercise coordinated by the guarded disposable Linux probe."""

import json
import os
import sys
import time
from pathlib import Path

from mano_core.broker import BrokerClient
from mano_core.desktop import DesktopSession


def main():
    if sys.platform != 'linux' or os.geteuid() == 0:
        raise PermissionError('Unprivileged disposable Linux client required')
    if Path('/etc/mano-lab-disposable').read_text().strip() != 'mano-phase0-ci':
        raise PermissionError('Disposable CI marker required')
    body = json.load(sys.stdin)
    client = BrokerClient()
    try:
        desktop = DesktopSession.open(client, proposal=body['proposal'], grant_id=body['grant_id'])
        desktop.wait_ready()
        desktop.command('terminal', title='mano private task desktop')
        deadline = time.monotonic() + 8
        windows = []
        while time.monotonic() < deadline:
            status = desktop.command('status')['result']
            windows = status['windows']
            if windows:
                break
            time.sleep(.2)
        assert len(windows) == 1 and windows[0]['app_id'] == 'mano-agent', status
        desktop.command('focus', window_id=windows[0]['id'])
        # Real virtual keyboard delivery to the mapped shell, not a direct exec witness.
        desktop.command('type', text="printf 'private-wayland-input\\n' > desktop-input.txt")
        desktop.command('key', key='Return', modifiers=[])
        desktop.command('pointer', x=100, y=100, button=None)
        time.sleep(.5)
        image = desktop.command('screenshot', path='private-desktop.png')['result']
        desktop.command('close')
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            result = desktop.transport.read()
            if result['eof']:
                break
            time.sleep(.15)
        assert result['eof'] and result['state'] == 'done', result
        assert result['outcome']['reason'] == 'exited', result
        assert result['outcome']['return_code'] == 0, result
        print(json.dumps(dict(action_id=desktop.transport.action_id, windows=windows,
            screenshot=image, outcome=result['outcome'], input_effect_verified=False,
            physical_test=False, human_desktop_unchanged=None)))
    finally:
        client.close()


if __name__ == '__main__':
    main()
