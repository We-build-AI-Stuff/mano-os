"""Private Sway worker inside an approved task sandbox; never a host launcher."""

import hashlib
import importlib.util
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path


def require_task_context():
    """Fail before worker startup without the enforced unprivileged task context."""
    if sys.platform != 'linux' or os.geteuid() == 0:
        raise PermissionError('Unprivileged Linux task desktop required')
    fields = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines()
                  if ':' in line)
    if (fields.get('NoNewPrivs', '').strip() != '1'
            or fields.get('Seccomp', '').strip() != '2'
            or any(int(fields.get(key, '-1').strip(), 16) != 0
                   for key in ('CapEff', 'CapBnd', 'CapAmb'))):
        raise PermissionError('Enforcing task security context required')
    for name, identity in (('uid_map', os.geteuid()), ('gid_map', os.getegid())):
        rows = [list(map(int, line.split()))
                for line in Path('/proc/self', name).read_text().splitlines()]
        # Bubblewrap --dev maps the Task UID/GID to 0 in its setup namespace
        # for devpts, then maps back to the unprivileged task IDs in a child.
        # Self reads show the immediate parent's IDs, where 0 is the task.
        if rows != [[identity, 0, 1]]:
            raise PermissionError(f'Private single-identity task {name} required')
    guard = Path('/task-guard').lstat()
    if (not stat.S_ISREG(guard.st_mode) or guard.st_uid == os.geteuid()
            or guard.st_mode & 0o022):
        raise PermissionError('Read-only externally owned task guard required')


def wire():
    """Load the installed sibling protocol from the worker directory under Python -I."""
    spec = importlib.util.spec_from_file_location('_mano_desktop_protocol',
                                                 Path(__file__).with_name('protocol.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def save_image(path, data):
    """Create one new workspace file through pinned, non-symlink directories."""
    parts = Path(path).parts
    directory = os.open('/workspace', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            next_directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                     dir_fd=directory)
            os.close(directory)
            directory = next_directory
        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            remaining = memoryview(data)
            while remaining:
                count = os.write(fd, remaining)
                if count <= 0:
                    raise OSError('Incomplete desktop image write')
                remaining = remaining[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def process_security(pid):
    """Read the kernel security status of a process in the private PID namespace."""
    lines = Path(f'/proc/{pid}/status').read_text().splitlines()
    status = dict(line.split(':', 1) for line in lines if ':' in line)
    return tuple(int(status[key]) for key in ('Seccomp', 'NoNewPrivs', 'Seccomp_filters'))


class Desktop:
    def __init__(self, config):
        require_task_context()
        self.protocol = wire()
        self.config = self.protocol.opening(config)
        self.temporary = tempfile.TemporaryDirectory(prefix='mano-desktop-', dir='/tmp')
        self.runtime = Path(self.temporary.name)
        self.log = None
        self.compositor = None
        self.applications = []
        self.images = 0
        self.writer = None
        self.browser = ExitStack()
        try:
            self.start()
            if 'browser_path' in self.config:
                self.start_browser()
        except BaseException as error:
            diagnostic = ''
            log = self.runtime / 'compositor.log'
            if log.exists():
                with log.open('rb') as source:
                    source.seek(max(0, log.stat().st_size - 2048))
                    diagnostic = source.read(2048).decode('utf8', 'replace')
            self.close()
            raise RuntimeError(f'Private desktop startup failed ({error}): {diagnostic}') from error

    def start(self):
        """Start Sway with only private sockets, configuration and a fixed headless output."""
        width, height = self.config['width'], self.config['height']
        config = self.runtime / 'sway.conf'
        config.write_text(f'output HEADLESS-1 mode {width}x{height}\n'
            'output * bg #101827 solid_color\nxwayland disable\n'
            'seat seat0 fallback true\nfocus_follows_mouse no\n'
            'default_border pixel 1\nfont monospace 10\n')
        fonts = self.runtime / 'fonts.conf'
        fonts.write_text('<fontconfig><dir>/usr/share/fonts</dir><cachedir>'
                         + str(self.runtime / 'font-cache') + '</cachedir></fontconfig>')
        self.ipc_path = self.runtime / 'ipc.sock'
        self.environment = dict(PATH='/usr/bin:/bin', HOME='/home/task', LANG='C.UTF-8',
            SHELL='/bin/sh', XDG_RUNTIME_DIR=str(self.runtime), XDG_SESSION_TYPE='wayland',
            XDG_CACHE_HOME=str(self.runtime / 'cache'), FONTCONFIG_FILE=str(fonts),
            WLR_BACKENDS='headless', WLR_HEADLESS_OUTPUTS='1', WLR_RENDERER='pixman',
            WLR_LIBINPUT_NO_DEVICES='1', SWAYSOCK=str(self.ipc_path))
        self.log = (self.runtime / 'compositor.log').open('wb')
        self.compositor = subprocess.Popen(['/usr/bin/sway', '--config', str(config)],
            stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT,
            env=self.environment, close_fds=True)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.compositor.poll() is not None:
                raise RuntimeError('Private compositor exited before readiness')
            sockets = [p for p in self.runtime.glob('wayland-*')
                       if stat.S_ISSOCK(p.lstat().st_mode)]
            if self.ipc_path.exists() and len(sockets) == 1:
                info = sockets[0].lstat()
                if info.st_uid != os.geteuid():
                    raise PermissionError('Private Wayland socket owner changed')
                self.environment['WAYLAND_DISPLAY'] = sockets[0].name
                self.canvas()
                return
            time.sleep(.05)
        raise TimeoutError('Private compositor did not become ready')

    def start_browser(self):
        """Launch the package-owned driver on the private Wayland socket."""
        document = Path('/workspace') / self.config['browser_path']
        if document.resolve(strict=True) != document or not document.is_file():
            raise ValueError('Browser requires a regular workspace HTML document')
        sys.path.append('/usr/lib/mano-runtime/vendor')
        from playwright.sync_api import Error, sync_playwright

        try:
            driver = self.browser.enter_context(sync_playwright())
            browser = driver.chromium.launch(
                executable_path='/usr/lib/chromium/chromium', headless=False,
                chromium_sandbox=True, args=['--ozone-platform=wayland'],
                env={key: value for key, value in self.environment.items() if key != 'SWAYSOCK'},
                timeout=20000,
            )
            self.browser.callback(browser.close)
            self.page = browser.new_page()
            self.page.set_default_timeout(2500)
            self.browser_url = document.as_uri()
            self.page.goto(self.browser_url, wait_until='domcontentloaded', timeout=8000)
            if self.page.url != self.browser_url:
                raise PermissionError('Browser left the approved workspace page')
            process_info = browser.new_browser_cdp_session().send(
                'SystemInfo.getProcessInfo')['processInfo']
        except Error as error:
            # Preserve the process diagnostics without the lengthy launch command.
            details = str(error).splitlines()
            lines = [line for line in details if '[err]' in line]
            diagnostic = '\n'.join(lines or details)
            raise RuntimeError(diagnostic[-1500:]) from error
        browser_pids = [p['id'] for p in process_info if p['type'] == 'browser']
        if len(browser_pids) != 1:
            raise PermissionError('Chromium browser process could not be identified')
        browser_pid = browser_pids[0]
        browser_status = process_security(browser_pid)
        flags = Path(f'/proc/{browser_pid}/cmdline').read_bytes().split(b'\0')
        if (b'--remote-debugging-pipe' not in flags or b'--no-sandbox' in flags
                or any(flag.startswith(b'--remote-debugging-port') for flag in flags)):
            raise PermissionError('Chromium local sandboxed pipe could not be verified')
        for table in ('tcp', 'tcp6'):
            if any(line.split()[3] == '0A' for line in
                   Path('/proc/net', table).read_text().splitlines()[1:]):
                raise PermissionError('Unexpected TCP listener in the private browser')
        renderers = [process_security(p['id']) for p in process_info if p['type'] == 'renderer']
        if (not renderers
                or any(mode != 2 or nnp != 1 or count <= browser_status[2]
                       for mode, nnp, count in renderers)):
            raise PermissionError('Chromium renderer sandbox filters could not be verified')
        self.browser_report = dict(version=browser.version,
                                   browser_filter_count=browser_status[2],
                                   renderer_filter_counts=[count for _, _, count in renderers],
                                   renderer_filters_verified=True, local_pipe=True)

    def browser_control(self, command, args):
        """Use only bounded semantic operations in the approved private browser."""
        from playwright.sync_api import Error

        if self.page.url != self.browser_url:
            raise PermissionError('Browser left the approved workspace page')
        try:
            if command == 'browser_click':
                self.page.get_by_role('button', name=args['name'], exact=True).click()
                return dict(submitted=True)
            return dict(text=self.page.get_by_test_id(args['test_id']).inner_text()[:512])
        except Error as error:
            raise RuntimeError('Private browser operation failed') from error

    def ipc(self, kind, command=None):
        """Send a bounded internal request to the compositor belonging to this desktop."""
        argv = ['/usr/bin/swaymsg', '--socket', str(self.ipc_path), '--raw', '--type', kind]
        if command is not None:
            argv.append(command)
        result = subprocess.run(argv, env=self.environment, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, check=True, timeout=3)
        value = json.loads(result.stdout)
        if kind == 'command' and (not isinstance(value, list)
                or not value or any(item.get('success') is not True for item in value)):
            raise RuntimeError('Private compositor command was not accepted')
        return value

    def canvas(self):
        """Require the actual compositor output to match the approved pixel geometry."""
        outputs = self.ipc('get_outputs')
        if len(outputs) != 1 or outputs[0]['name'] != 'HEADLESS-1':
            raise RuntimeError('Desktop output set changed')
        rect = outputs[0]['rect']
        if (rect['width'] != self.config['width'] or rect['height'] != self.config['height']
                or rect['x'] != 0 or rect['y'] != 0 or outputs[0]['scale'] != 1):
            raise RuntimeError('Approved desktop geometry changed')
        return dict(rect)

    def windows(self):
        """Return bounded untrusted window observations from the private compositor tree."""
        pending, result = [self.ipc('get_tree')], []
        while pending:
            node = pending.pop()
            if node.get('type') == 'con' and node.get('app_id'):
                result.append(dict(id=node['id'], app_id=str(node['app_id'])[:80],
                    title=str(node.get('name', ''))[:160], rect=node['rect'],
                    focused=node.get('focused') is True))
            pending.extend(node.get('nodes', []) + node.get('floating_nodes', []))
        return dict(windows=result[:8], total_windows=len(result), truncated=len(result) > 8)

    def dispatch(self, command, args):
        """Perform one validated control using only the owned desktop environment."""
        args = self.protocol.control(command, args, width=self.config['width'],
                                     height=self.config['height'],
                                     browser='browser_path' in self.config)
        self.canvas()
        if command in {'browser_click', 'browser_text'}:
            return self.browser_control(command, args)
        if command == 'status':
            result = dict(canvas=self.canvas(), **self.windows())
            if 'browser_path' in self.config:
                result['browser'] = self.browser_report
            if self.writer is not None:
                with (self.runtime / 'writer.log').open('rb') as log:
                    log.seek(max(0, os.fstat(log.fileno()).st_size - 512))
                    diagnostic = log.read(512).decode('utf8', errors='replace')
                result['writer'] = dict(return_code=self.writer.poll(), diagnostic=diagnostic)
            return result
        if command in {'terminal', 'writer'}:
            if len(self.applications) >= 4:
                raise ValueError('Desktop application quota exhausted')
            if command == 'terminal':
                argv = ['/usr/bin/foot', '--config=/dev/null', '--app-id=mano-agent',
                        '--title=' + args['title'], '/bin/sh']
            else:
                if self.writer is not None:
                    raise ValueError('Only one Writer launch is allowed per desktop')
                document = Path('/workspace') / args['path']
                resolved = document.resolve(strict=True)
                if resolved != document or not resolved.is_file():
                    raise ValueError('Writer requires a regular workspace document')
                profile = (self.runtime / 'writer-profile').as_uri()
                argv = ['/usr/bin/libreoffice', '--writer', '--nologo', '--norestore',
                        '-env:UserInstallation=' + profile, str(document)]
                env = self.environment | dict(GDK_BACKEND='wayland', SAL_USE_VCLPLUGIN='gtk3')
                with (self.runtime / 'writer.log').open('xb') as log:
                    self.writer = subprocess.Popen(
                        argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                        env=env, close_fds=True)
                self.applications.append(self.writer)
                return dict(submitted=True)
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=self.log,
                                     stderr=subprocess.STDOUT, env=self.environment, close_fds=True)
            self.applications.append(child)
            return dict(submitted=True)
        if command == 'type':
            # wtype 0.4 rejects -d 0 and sleeps 4 ms per character even by default.
            # The maximum 2048 ASCII characters therefore take over eight seconds.
            subprocess.run(['/usr/bin/wtype', '-'], input=args['text'],
                text=True, capture_output=True, check=True, env=self.environment, timeout=13)
            return dict(submitted=True)
        if command == 'key':
            # wtype creates a new virtual keyboard and keymap for each invocation.
            # Give the compositor time to publish that map and both key transitions
            # before the device or its modifier state goes away.
            argv = ['/usr/bin/wtype', '-s', '60']
            for modifier in args['modifiers']:
                argv += ['-M', modifier]
            argv += ['-s', '60', '-P', args['key'], '-s', '60', '-p', args['key'], '-s', '60']
            for modifier in reversed(args['modifiers']):
                argv += ['-m', modifier]
            subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, check=True,
                           env=self.environment, timeout=3)
            return dict(submitted=True)
        if command == 'pointer':
            self.ipc('command', f"seat seat0 cursor set {args['x']} {args['y']}")
            if args['button'] is not None:
                buttons = {'left': 'button1', 'right': 'button3', 'middle': 'button2'}
                button = buttons[args['button']]
                try:
                    self.ipc('command', 'seat seat0 cursor press ' + button)
                finally:
                    self.ipc('command', 'seat seat0 cursor release ' + button)
            return dict(submitted=True)
        if command == 'focus':
            if args['window_id'] not in {w['id'] for w in self.windows()['windows']}:
                raise ValueError('Unknown private desktop window')
            self.ipc('command', f"[con_id={args['window_id']}] focus")
            return dict(submitted=True)
        if command == 'screenshot':
            if self.images >= 8:
                raise ValueError('Desktop image quota exhausted')
            temporary = self.runtime / ('image-' + str(self.images) + '.png')
            self.images += 1
            subprocess.run(['/usr/bin/grim', '-o', 'HEADLESS-1', str(temporary)],
                stdin=subprocess.DEVNULL, capture_output=True, check=True,
                env=self.environment, timeout=3)
            with temporary.open('rb') as image:
                data = image.read(4 * 1024**2 + 1)
            temporary.unlink()
            if (not 33 <= len(data) <= 4 * 1024**2 or data[:8] != b'\x89PNG\r\n\x1a\n'
                    or data[12:16] != b'IHDR'
                    or struct.unpack('>II', data[16:24]) !=
                    (self.config['width'], self.config['height'])):
                raise ValueError('Unexpected private desktop image')
            save_image(args['path'], data)
            return dict(path=args['path'], bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                        width=self.config['width'], height=self.config['height'])
        if command == 'close':
            self.close()
            return dict(closed=True)
        raise ValueError('Unknown desktop command')

    def close(self):
        """Terminate the session-owned processes and remove its private runtime directory."""
        try:
            self.browser.close()
        finally:
            self.close_desktop()

    def close_desktop(self):
        """Drain the compositor and its other children even if browser cleanup fails."""
        for child in [*reversed(self.applications), self.compositor]:
            if child is None or child.poll() is not None:
                continue
            child.terminate()
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=1)
        if self.log is not None:
            self.log.close()
        self.temporary.cleanup()


def emit(identifier, command, *, result=None, error=None):
    """Return an untrusted observation without claiming verification of its effect."""
    value = dict(schema_version='1.0', id=identifier, command=command,
                 ok=error is None, untrusted=True, effect_verified=False,
                 result=result, error=error)
    raw = (json.dumps(value, separators=(',', ':'), allow_nan=False) + '\n').encode()
    if len(raw) > 8192:
        raise ValueError('Desktop response exceeds its bound')
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()
    return raw


def main():
    """Run the framed worker loop with bounded operation history and no effect replay."""
    try:
        require_task_context()
        if len(sys.argv) != 2:
            raise ValueError('Expected fixed approved desktop configuration')
        protocol = wire()
        config = protocol.opening(json.loads(sys.argv[1]))
        desktop = Desktop(config)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        emit('0' * 32, 'ready', error='startup-failed',
             result=dict(diagnostic=str(error)[-2048:]))
        return 1
    seen = {}
    try:
        emit('0' * 32, 'ready', result=dict(width=config['width'], height=config['height']))
        while True:
            raw = sys.stdin.buffer.readline(protocol.MAX_FRAME + 1)
            if not raw:
                break
            value = protocol.decode(raw)
            if set(value) != {'schema_version', 'id', 'command', 'args'}:
                raise ValueError('Unexpected desktop frame fields')
            if value['schema_version'] != '1.0':
                raise ValueError('Unsupported desktop protocol')
            canonical = protocol.request(value['id'], value['command'], value['args'],
                                         width=config['width'], height=config['height'],
                                         browser='browser_path' in config)
            old = seen.get(value['id'])
            if old is not None:
                if old[0] != canonical:
                    raise ValueError('Desktop request identity reused with changed arguments')
                sys.stdout.buffer.write(old[1])
                sys.stdout.buffer.flush()
                continue
            if len(seen) >= 64:
                raise ValueError('Desktop request history quota exhausted')
            seen[value['id']] = (canonical, b'')  # Never redeliver an interrupted request.
            try:
                result = desktop.dispatch(value['command'], value['args'])
                response = emit(value['id'], value['command'], result=result)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                diagnostic = type(error).__name__
                if isinstance(error, subprocess.CalledProcessError):
                    stderr = error.stderr or ''
                    if isinstance(stderr, bytes):
                        stderr = stderr[:512].decode('utf8', errors='replace')
                    diagnostic = f'exit {error.returncode}: {stderr[:512]}'
                response = emit(value['id'], value['command'],
                                result=dict(diagnostic=diagnostic),
                                error='operation-failed-or-uncertain')
            seen[value['id']] = (canonical, response)
            if value['command'] == 'close':
                break
    finally:
        desktop.close()


if __name__ == '__main__':
    raise SystemExit(main())
