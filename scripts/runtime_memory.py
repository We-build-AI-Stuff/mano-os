"""Disposable-CI observer of fixed runtime groups; no execution or grant endpoint."""

import math
import os
import re
import stat
import subprocess
import sys
import threading
import time
from contextlib import ExitStack
from pathlib import Path

GROUPS = {
    'broker': '/system.slice/mano-broker.service',
    'launcher_and_tasks': '/system.slice/mano-launcher.service',
    'core': '/mano.slice/mano-core.slice',
    'approval': '/system.slice/mano-approve.service',
    'stop': '/system.slice/mano-stopd.service',
}
INTERVAL = 0.05
MAX_SAMPLES = 4096


def counter(raw):
    if (not isinstance(raw, bytes) or not re.fullmatch(rb'(0|[1-9][0-9]{0,18})\n', raw)
            or int(raw) > (1 << 63) - 1):
        raise ValueError('Invalid kernel memory counter')
    return int(raw)


def read_counter(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    return counter(os.read(fd, 64))


def summarize(idle, samples, peaks):
    if not idle or not samples or set(peaks) != set(GROUPS):
        raise ValueError('Incomplete runtime memory observations')
    for sample in idle + samples:
        if set(sample['bytes']) != set(GROUPS):
            raise ValueError('Changed runtime component set')
        if any(type(n) is not int or n < 0 for n in sample['bytes'].values()):
            raise ValueError('Invalid observed memory usage')
        if any(type(sample[key]) not in (int, float) or not math.isfinite(sample[key])
               or sample[key] < 0 for key in ('elapsed_seconds', 'read_seconds')):
            raise ValueError('Invalid observation clock')
    for name in GROUPS:
        if (type(peaks[name]) is not int or peaks[name] <
                max(sample['bytes'][name] for sample in samples)):
            raise ValueError('Kernel peak does not cover observed component usage')
    return dict(
        scope='fixed installed-runtime cgroups during the recorded workflow',
        groups=dict(GROUPS), sample_interval_target_seconds=INTERVAL,
        clock='monotonic; each sample list has its own origin',
        idle_sample_count=len(idle), workflow_sample_count=len(samples),
        idle_method='last pre-workflow sample; warm services, no recorded action launched',
        idle_component_sum_bytes=sum(idle[-1]['bytes'].values()),
        max_sampled_component_sum_bytes=max(sum(s['bytes'].values()) for s in samples),
        component_kernel_peak_bytes=dict(peaks),
        aggregate_method='maximum sum of sequential component readings, not an atomic total',
        max_sample_read_seconds=max(s['read_seconds'] for s in idle + samples),
        exact_aggregate_peak_bytes=None, whole_product_peak_bytes=None,
        exclusions=['human compositor and prompt', 'CI harness', 'other system services'],
        physical_hardware=False)


class RuntimeMemory:
    def __init__(self):
        self.stack = ExitStack()
        self.current, self.peak, self.directories = {}, {}, {}
        self.samples, self.idle = [], []
        self.stop = threading.Event()
        self.error = None
        self.thread = None
        self.result = None

    def opened(self, path, flags, **kwargs):
        fd = os.open(path, flags | os.O_CLOEXEC | os.O_NOFOLLOW, **kwargs)
        self.stack.callback(os.close, fd)
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Untrusted runtime cgroup counter or directory')
        return fd

    def sample(self):
        start = time.monotonic()
        values = {name: read_counter(fd) for name, fd in self.current.items()}
        end = time.monotonic()
        return dict(elapsed_seconds=end - self.started, read_seconds=end - start, bytes=values)

    def poll(self):
        try:
            while not self.stop.wait(INTERVAL):
                if len(self.samples) >= MAX_SAMPLES - 1:
                    raise ValueError('Runtime observation sample bound exceeded')
                self.samples.append(self.sample())
        except Exception as error:
            self.error = error

    def __enter__(self):
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise PermissionError('Disposable Linux Root observer required')
        if Path('/etc/mano-lab-disposable').read_text().strip() != 'mano-phase0-ci':
            raise PermissionError('Disposable CI marker required')
        group = Path('/proc/self/cgroup').read_text().strip()
        if not group.startswith('0::/') or '\n' in group:
            raise ValueError('Unified observer cgroup required')
        observer = group[3:]
        if any(observer == path or observer.startswith(path + '/') for path in GROUPS.values()):
            raise ValueError('Observer must remain outside measured runtime groups')
        self.observer = observer
        try:
            for name, relative in GROUPS.items():
                unit = relative.rsplit('/', 1)[1]
                observed = subprocess.check_output(['systemctl', 'show', unit,
                    '--property=ControlGroup', '--value'], text=True).strip()
                if observed != relative:
                    raise ValueError('Installed unit uses a different measurement cgroup')
                path = Path('/sys/fs/cgroup') / relative.lstrip('/')
                directory = self.opened(path, os.O_RDONLY | os.O_DIRECTORY)
                info = os.fstat(directory)
                self.directories[name] = (path, info.st_dev, info.st_ino)
                self.current[name] = self.opened('memory.current', os.O_RDONLY, dir_fd=directory)
                self.peak[name] = self.opened('memory.peak', os.O_RDWR, dir_fd=directory)
            self.started = time.monotonic()
            for _ in range(10):
                self.idle.append(self.sample())
                time.sleep(INTERVAL)
            for fd in self.peak.values():
                # Linux 6.12 resets the observation window only for this held FD.
                if os.write(fd, b'0') != 1:
                    raise OSError('Incomplete peak observation reset')
            self.started = time.monotonic()
            self.samples.append(self.sample())
            self.thread = threading.Thread(target=self.poll, daemon=True,
                                           name='mano-ci-memory-observer')
            self.thread.start()
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, kind, _value, _traceback):
        try:
            self.stop.set()
            self.thread.join(timeout=2)
            if self.thread.is_alive():
                raise RuntimeError('Memory observer did not stop')
            if kind is None:
                if self.error is not None:
                    raise self.error
                self.samples.append(self.sample())
                peaks = {name: read_counter(fd) for name, fd in self.peak.items()}
                for path, device, inode in self.directories.values():
                    info = path.stat(follow_symlinks=False)
                    if (not stat.S_ISDIR(info.st_mode)
                            or (info.st_dev, info.st_ino) != (device, inode)):
                        raise ValueError('Runtime cgroup changed during observation')
                self.result = dict(summary=summarize(self.idle, self.samples, peaks),
                                   observer_cgroup=self.observer,
                                   idle_samples=self.idle, workflow_samples=self.samples)
        finally:
            self.stack.close()
