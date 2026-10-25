"""CI-only static ELF dependency inventory before package-maintainer execution.

Fixed readelf and ldconfig -p tools run. Dependency targets are inspected as
bytes, without invoking them to infer their dependencies. Cache candidates are
not proof of actual resolution, dlopen/plugin completeness, immutability or a
trusted execution closure.
"""

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path

from probe_package_plans import guard
from probe_package_policy_names import HELPERS

ENV = {'PATH': '/usr/sbin:/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
ROOTS = tuple(sorted(set(HELPERS) | {
    '/usr/bin/python3', '/usr/bin/dpkg', '/usr/bin/apt-get',
    '/usr/bin/aa-exec', '/usr/sbin/ldconfig',
}))


def dynamic_names(text):
    result = dict(needed=[], soname=[], rpath=[], runpath=[])
    for line in text.splitlines():
        tag = re.search(r'\((NEEDED|SONAME|RPATH|RUNPATH)\)', line)
        if tag:
            value = re.search(r'\[([^\]\r\n]*)\]\s*$', line)
            if value is None or not value[1] or len(value[1]) > 4096:
                raise ValueError('Malformed readelf dynamic string')
            result[tag[1].lower()].append(value[1])
    for key in ('soname', 'rpath', 'runpath'):
        if len(result[key]) > 1:
            raise ValueError('Repeated singleton ELF dynamic tag')
    return result


def cache_entries(text):
    entries = {}
    for line in text.splitlines():
        if '=>' not in line:
            continue
        match = re.fullmatch(r'\s*(\S+)\s+\([^\n]+\)\s+=>\s+(/\S+)\s*', line)
        if match is None:
            raise ValueError('Malformed ldconfig cache entry')
        entries.setdefault(match[1], set()).add(match[2])
    return {key: sorted(value) for key, value in sorted(entries.items())}


def command(argv):
    value = subprocess.run(argv, env=ENV, cwd='/', capture_output=True,
                           text=True, timeout=15, check=True)
    if value.stderr or len(value.stdout.encode()) > 2 * 1024**2:
        raise ValueError('Unexpected static inventory command output')
    return value.stdout


def observed_file(name):
    path = Path(name)
    if not path.is_absolute() or len(path.parts) > 64:
        raise ValueError('Absolute bounded inventory path required')
    canonical = path.resolve(strict=True)
    info = canonical.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_size > 64 * 1024**2:
        raise ValueError('Bounded Root-owned regular inventory file required')
    data = canonical.read_bytes()
    if len(data) != info.st_size:
        raise ValueError('Inventory file changed while reading')
    links = {}
    for prefix in (path, *path.parents):
        if prefix.is_symlink():
            links[str(prefix)] = os.readlink(prefix)
    return dict(path=name, canonical=str(canonical), symlinks=links,
                size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest()), data


def main():
    guard()
    cache_raw = command(['/usr/sbin/ldconfig', '-p'])
    cache = cache_entries(cache_raw)
    extensions = sorted(str(path) for pattern in (
        '/usr/lib/python3.13/lib-dynload/*.so',
        '/usr/lib/python3/dist-packages/apt_pkg*.so',
        '/usr/lib/python3/dist-packages/apt_inst*.so')
        for path in Path('/').glob(pattern.removeprefix('/')))
    if not extensions or not any('/apt_pkg' in path for path in extensions):
        raise ValueError('Expected Debian Python extension inventory absent')
    pending = set(ROOTS) | set(extensions)
    files, unresolved = {}, {}
    total = 0
    while pending:
        name = min(pending)
        pending.remove(name)
        if name in files:
            continue
        if len(files) >= 512:
            raise ValueError('ELF candidate inventory quota')
        record, data = observed_file(name)
        total += len(data)
        if total > 256 * 1024**2 or not data.startswith(b'\x7fELF'):
            raise ValueError('Expected bounded ELF inventory input')
        raw = command(['/usr/bin/readelf', '--wide', '--program-headers', '--dynamic',
                       record['canonical']])
        names = dynamic_names(raw)
        interpreters = re.findall(r'\[Requesting program interpreter: ([^\]\n]+)\]', raw)
        if len(interpreters) > 1:
            raise ValueError('Multiple ELF interpreters')
        record.update(names, interpreters=interpreters, readelf=raw,
                      cache_candidates={needed: cache.get(needed, [])
                                        for needed in names['needed']})
        files[name] = record
        for interpreter in interpreters:
            if not interpreter.startswith('/'):
                raise ValueError('Absolute interpreter required')
            pending.add(interpreter)
        for needed, candidates in record['cache_candidates'].items():
            if not candidates:
                unresolved.setdefault(needed, []).append(name)
            pending.update(candidates)
    configuration = {}
    for path in sorted({Path('/etc/ld.so.cache'), Path('/etc/ld.so.conf')} |
                       set(Path('/etc/ld.so.conf.d').glob('*.conf'))):
        record, data = observed_file(str(path))
        if path.name != 'ld.so.cache':
            record['text'] = data.decode('utf-8')
        configuration[str(path)] = record
    revision = json.loads(Path('/opt/mano-lab/source-info.json').read_text())['revision']
    return dict(schema_version='1.0', source_revision=revision, roots=list(ROOTS),
                python_extension_roots=extensions, files=files,
                loader_configuration=configuration, unresolved_cache_names=unresolved,
                ldconfig_cache_listing_sha256=hashlib.sha256(cache_raw.encode()).hexdigest(),
                observed_input_bytes=total,
                scope='static ELF requirements and cache candidates before Broker probes',
                uses_target_execution_for_dependency_resolution=False,
                fixed_inventory_tools_executed=['/usr/bin/readelf', '/usr/sbin/ldconfig'],
                actual_resolution_verified=False,
                dlopen_plugin_closure_verified=False, write_protection_verified=False,
                complete_trusted_runtime_closure_verified=False)


if __name__ == '__main__':
    print(json.dumps(main(), sort_keys=True))
