"""Task-UID SDK exercise coordinated by the guarded disposable Linux probe."""

import json
import os
import sys
import time
import zipfile
from pathlib import Path

from mano_core.broker import BrokerClient
from mano_core.desktop import DesktopSession


def main():
    """Exercise the private GUI as its Task UID and stop the action on a failed step."""
    if sys.platform != 'linux' or os.geteuid() == 0:
        raise PermissionError('Unprivileged disposable Linux client required')
    if Path('/etc/mano-lab-disposable').read_text().strip() != 'mano-phase0-ci':
        raise PermissionError('Disposable CI marker required')
    body = json.load(sys.stdin)
    client = BrokerClient()
    desktop = None
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
        desktop.command('writer', path='private-writer.odt')
        deadline = time.monotonic() + 20
        writer = None
        while time.monotonic() < deadline:
            windows_now = desktop.command('status')['result']['windows']
            writer = next((window for window in windows_now
                           if 'libreoffice' in window['app_id'].lower()
                           and 'private-writer' in window['title']), None)
            if writer is not None:
                break
            time.sleep(.3)
        assert writer is not None, 'Writer did not map the approved document'
        desktop.command('focus', window_id=writer['id'])
        desktop.command('key', key='End', modifiers=['ctrl'])
        desktop.command('key', key='Return', modifiers=[])
        desktop.command('type', text='Saved through the private Wayland session')
        desktop.command('key', key='s', modifiers=['ctrl'])
        deadline = time.monotonic() + 10
        document = Path(body['writer_fixture_path'])
        while time.monotonic() < deadline:
            try:
                with zipfile.ZipFile(document) as archive:
                    if b'Saved through the private Wayland session' in archive.read('content.xml'):
                        break
            except (FileNotFoundError, zipfile.BadZipFile):
                pass
            time.sleep(.2)
        else:
            raise AssertionError('Writer did not save the keyboard edit')
        writer_image = desktop.command('screenshot', path='private-writer.png')['result']
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
            screenshot=image, writer_window=writer, writer_image=writer_image,
            outcome=result['outcome'], input_effect_verified=False,
            physical_test=False, human_desktop_unchanged=None)))
    except BaseException:
        if desktop is not None:
            try:
                desktop.stop()
            except (OSError, ValueError, KeyError, TypeError):
                pass  # Preserve the original failure; the Root fixture also tears down units.
        raise
    finally:
        client.close()


if __name__ == '__main__':
    main()
