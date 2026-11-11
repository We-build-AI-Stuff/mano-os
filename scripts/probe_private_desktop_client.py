"""Task-UID SDK exercise coordinated by the guarded disposable Linux probe."""

import json
import os
import shlex
import stat
import sys
import time
import zipfile
from pathlib import Path

from mano_core.broker import BrokerClient
from mano_core.desktop import DesktopSession


def exercise_writer(desktop, document):
    """Save a keyboard edit and export the edited document as a PDF."""
    desktop.command('writer', path='private-writer.odt')
    deadline = time.monotonic() + 20
    writer = None
    observation = {}
    while time.monotonic() < deadline:
        status = desktop.command('status')['result']
        windows_now = status['windows']
        observation = status.get('writer', {})
        writer = next((window for window in windows_now
                       if 'libreoffice' in window['app_id'].lower()
                       and 'private-writer' in window['title']), None)
        if writer is not None or observation.get('return_code') is not None:
            break
        time.sleep(.3)
    assert writer is not None, f'Writer did not map the approved document: {observation!r}'
    desktop.command('focus', window_id=writer['id'])
    # A mapped window can still be finishing its initial document load.
    time.sleep(.5)
    status = desktop.command('status')['result']
    assert any(w['id'] == writer['id'] and w['focused'] for w in status['windows']), status
    # The seeded document has one line. End moves within that line.
    desktop.command('key', key='End', modifiers=[])
    desktop.command('key', key='Return', modifiers=[])
    desktop.command('type', text='Saved through the private Wayland session')
    desktop.command('key', key='s', modifiers=['ctrl'])
    deadline = time.monotonic() + 10
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
    writer_pdf = desktop.command('writer_export_pdf', path='private-writer.pdf')['result']
    return dict(writer_window=writer, writer_image=writer_image, writer_pdf=writer_pdf)


def main():
    """Exercise the private GUI as its Task UID and stop the action on a failed step."""
    if sys.platform != 'linux' or os.geteuid() == 0:
        raise PermissionError('Unprivileged disposable Linux client required')
    # The Root coordinator verifies the marker contents before dropping privileges.
    marker = Path('/etc/mano-lab-disposable').lstat()
    if (not stat.S_ISREG(marker.st_mode) or marker.st_uid != 0
            or stat.S_IMODE(marker.st_mode) != 0o600):
        raise PermissionError('Protected disposable CI marker required')
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
        if body.get('hold_for_stop') is True:
            child = ("import os,time;from pathlib import Path;pid=os.fork();"
                     "os._exit(0) if pid else None;os.setsid();"
                     "Path('/workspace/private-desktop-stop').write_text(str(os.getpid()));"
                     "time.sleep(120)")
            desktop.command('type', text='python3 -c ' + shlex.quote(child) + ' &')
            desktop.command('key', key='Return', modifiers=[])
            print(json.dumps(dict(action_id=desktop.transport.action_id, windows=windows,
                                  held_for_native_stop=True, effect_verified=False)))
            return  # Keep the approved GUI action live; closing this client is not Stop.
        # Real virtual keyboard delivery to the mapped shell, not a direct exec witness.
        desktop.command('type', text="printf 'private-wayland-input\\n' > desktop-input.txt")
        desktop.command('key', key='Return', modifiers=[])
        desktop.command('pointer', x=100, y=100, button=None)
        time.sleep(.5)
        image = desktop.command('screenshot', path='private-desktop.png')['result']
        writer_result = {}
        if 'writer_fixture_path' in body:
            writer_result = exercise_writer(desktop, Path(body['writer_fixture_path']))
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
            screenshot=image, **writer_result,
            outcome=result['outcome'], input_effect_verified=False,
            physical_test=False, human_desktop_unchanged=None)))
    except BaseException:
        if desktop is not None:
            # This fixture handles synthetic content only. repr escapes terminal controls.
            tail = bytes(desktop.transport.output[-2048:])
            print(f'Private desktop PTY failure tail: {tail!r}', file=sys.stderr)
            try:
                desktop.stop()
            except (OSError, ValueError, KeyError, TypeError):
                pass  # Preserve the original failure; the Root fixture also tears down units.
        raise
    finally:
        client.close()


if __name__ == '__main__':
    main()
